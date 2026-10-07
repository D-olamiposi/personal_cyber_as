import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time

from flask import Flask,abort,jsonify,render_template,request,send_file,session
from werkzeug.exceptions import HTTPException

from .config import Settings,CHATBOT
from .engine import Engine
from .providers import ModelRouter
from .retrieval import Retriever
from .store import Store
from .tools import ToolRunner
from .uploads import ImageUploads

ID=re.compile(r'^[a-f0-9]{32}$')

def secret_file(path):
    try:
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as f:f.write(secrets.token_hex(32))
    except FileExistsError:pass
    return path.read_text().strip()

def create_app(settings=None,router=None):
    settings=settings or Settings.load()
    settings.data_dir.mkdir(parents=True,exist_ok=True,mode=0o700)
    if os.name!='nt':os.chmod(settings.data_dir,0o700)
    app=Flask(__name__,template_folder=str(CHATBOT/'templates'),static_folder=str(CHATBOT/'static'))
    app.config.update(SECRET_KEY=secret_file(settings.data_dir/'session.secret'),MAX_CONTENT_LENGTH=9_000_000,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Strict',SESSION_COOKIE_SECURE=settings.cookie_secure,TRUSTED_HOSTS=settings.trusted_hosts)
    store=Store(settings.data_dir);retriever=Retriever(settings.kb_root);tools=ToolRunner(settings,store)
    uploads=ImageUploads(settings,store);engine=Engine(settings,store,retriever,router or ModelRouter(settings),tools)
    app.extensions.update({'store':store,'engine':engine,'settings':settings,'tools':tools})
    login_attempts={};login_lock=threading.Lock()
    def authenticated():return not settings.access_token or session.get('owner')==hashlib.sha256(settings.access_token.encode()).hexdigest()
    def require_id(value):
        if not isinstance(value,str) or not ID.fullmatch(value):abort(400,description='Invalid identifier')
        return value
    def body():
        value=request.get_json(silent=True)
        if not isinstance(value,dict):abort(400,description='Expected a JSON object')
        return value
    def images(value):
        if not isinstance(value,list) or len(value)>3:abort(400,description='Attach at most three images')
        for key in value:store.get_upload(require_id(key))
        return value
    @app.before_request
    def guard():
        if not settings.access_token:
            try:loopback=ipaddress.ip_address(request.remote_addr or '').is_loopback
            except ValueError:loopback=False
            if not loopback:abort(403,description='Local mode accepts loopback clients only')
        if request.method in ('POST','PUT','DELETE','PATCH'):
            origin=request.headers.get('Origin')
            if origin and origin.rstrip('/')!=request.host_url.rstrip('/'):abort(403,description='Cross-origin request rejected')
            expected=session.get('csrf','')
            supplied=request.headers.get('X-CSRF-Token','')
            if not expected or not hmac.compare_digest(expected,supplied):abort(403,description='Refresh the page: CSRF token missing or expired')
        if request.path.startswith('/api/') and request.path not in ('/api/login','/api/session') and not authenticated():abort(401,description='Sign in with your owner access token')
    @app.after_request
    def security_headers(response):
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Permissions-Policy']='geolocation=(), camera=(), microphone=()'
        response.headers['X-Frame-Options']='DENY'
        if request.path.startswith('/api/') or request.path=='/':response.headers['Cache-Control']='no-store'
        return response
    @app.errorhandler(HTTPException)
    def http_error(exc):return jsonify({'error':exc.description}),exc.code
    @app.errorhandler(ValueError)
    def value_error(exc):return jsonify({'error':str(exc)[:500]}),400
    @app.get('/')
    def index():
        if 'csrf' not in session:session['csrf']=secrets.token_hex(24)
        return render_template('index.html',csrf=session['csrf'])
    @app.get('/health')
    def health():return jsonify({'status':'running'})
    @app.get('/api/session')
    def current_session():return jsonify({'authenticated':authenticated(),'login_required':bool(settings.access_token)})
    @app.post('/api/login')
    def login():
        token=body().get('token','')
        address=request.remote_addr
        with login_lock:
            stamps=[s for s in login_attempts.get(address,[]) if s>time.monotonic()-60]
            if len(stamps)>=10:abort(429,description='Too many login attempts; wait one minute')
            login_attempts[address]=stamps+[time.monotonic()]
        if not isinstance(token,str) or not settings.access_token or not hmac.compare_digest(settings.access_token,token):abort(401,description='Invalid owner token')
        session['owner']=hashlib.sha256(settings.access_token.encode()).hexdigest()
        return jsonify({'authenticated':True})
    @app.post('/api/logout')
    def logout():session.pop('owner',None);return jsonify({'authenticated':False})
    @app.get('/api/status')
    def status():
        return jsonify({'knowledge':retriever.status(),'models':{kind:[{'name':p.name,'model':p.model} for p in chain] for kind,chain in settings.providers.items()},'capabilities':tools.capabilities(),'pending_jobs':store.pending(),'mode':'single owner','vision_tools':False})
    @app.post('/api/targets')
    def manage_targets():
        data=body()
        if set(data)-{'action','kind','value','confirmed'}:abort(400,description='Unknown target fields')
        # Target management is an owner UI action, never an LLM tool.
        with engine.lock:
            if store.pending():abort(409,description='Finish or stop active jobs before changing targets')
            try:capabilities=tools.manage_target(data.get('action'),data.get('kind'),data.get('value'),data.get('confirmed',False))
            except OSError:abort(503,description='Targets could not be saved; the previous scope remains active')
        return jsonify({'capabilities':capabilities})
    @app.get('/api/chats')
    def chats():return jsonify({'chats':store.chats()})
    @app.post('/api/chats')
    def create_chat():return jsonify({'id':store.create_chat()}),201
    @app.get('/api/chats/<chat>')
    def get_chat(chat):
        require_id(chat)
        if not store.chat_exists(chat):abort(404)
        return jsonify({'id':chat,'messages':store.history(chat),'evidence':store.chat_evidence(chat),'jobs':[j for j in store.pending() if j['chat']==chat]})
    @app.post('/api/images')
    def upload():
        if 'image' not in request.files:abort(400,description='Select an image')
        return jsonify(uploads.save(request.files['image'])),201
    @app.get('/api/images/<key>')
    def image(key):
        row=store.get_upload(require_id(key))
        return send_file(row['preview'],mimetype='image/jpeg',max_age=0)
    @app.post('/api/chat')
    def chat():
        data=body();chat=require_id(data.get('chat_id'))
        if not store.chat_exists(chat):abort(404)
        message=data.get('message')
        if not isinstance(message,str) or not message.strip() or len(message)>12000:abort(400,description='Message must contain 1..12,000 characters')
        allow=data.get('allow_tools',False)
        if type(allow)!=bool:abort(400,description='allow_tools must be a boolean')
        payload={'kind':'chat','message':message.strip(),'image_ids':images(data.get('image_ids',[])),'allow_tools':allow}
        return jsonify({'job_id':engine.submit(chat,payload)}),202
    @app.post('/api/tools')
    def run_tool():
        data=body();chat=require_id(data.get('chat_id'))
        if not store.chat_exists(chat):abort(404)
        if data.get('confirmed') is not True:abort(403,description='Explicit tool authorization is required for this request')
        image_ids=images(data.get('image_ids',[]));name=data.get('tool');args=data.get('arguments')
        tools.validate(name,args,image_ids)
        payload={'kind':'tool','tool':name,'arguments':args,'image_ids':image_ids}
        return jsonify({'job_id':engine.submit(chat,payload)}),202
    @app.get('/api/jobs/<key>')
    def get_job(key):
        row=store.job(require_id(key))
        if not row:abort(404)
        row.pop('payload',None)
        return jsonify(row)
    @app.post('/api/jobs/<key>/cancel')
    def cancel_job(key):
        if not store.job(require_id(key)):abort(404)
        return jsonify({'requested':engine.cancel(key)})
    @app.get('/api/evidence/<key>')
    def evidence(key):
        file=tools.evidence_dir/(require_id(key)+'.json')
        if not file.is_file():abort(404)
        return send_file(file,mimetype='application/json',as_attachment=True,download_name='evidence-'+key+'.json')
    @app.get('/api/chats/<chat>/export')
    def export(chat):
        require_id(chat)
        if not store.chat_exists(chat):abort(404)
        response=jsonify({'chat':chat,'messages':store.history(chat),'evidence':store.chat_evidence(chat)})
        response.headers['Content-Disposition']='attachment; filename="conversation-'+chat+'.json"'
        return response
    return app
