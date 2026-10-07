import base64
from io import BytesIO
import json
from pathlib import Path
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch,Mock
import urllib.error

from PIL import Image
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from app.config import Settings,Provider
from app.web import create_app
from app.providers import ModelRouter,ProviderError
from app.tools import Scope,ScopeError,public_addresses,PinnedHTTPS
from app.retrieval import kb

PROJECT=Path(__file__).resolve().parents[2]

def settings(directory,token=''):
    return Settings(Path(directory),PROJECT/'knowledge_base',token,'127.0.0.1',['localhost','127.0.0.1'],False,{'text':[],'vision':[]},{'web_origins':['https://example.com'],'nmap_targets':['127.0.0.1'],'nmap_ports':[80,443]})

class FakeRouter:
    def __init__(self,answer='**Evidence review**\n\n```python\nprint("safe")\n```'):
        self.answer=answer;self.calls=[]
    def complete(self,messages,kind,event,cancel,tools=None):
        self.calls.append((messages,kind,tools))
        return {'role':'assistant','content':self.answer},'test-fixture'

class WebTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.settings=settings(self.temp.name)
        self.router=FakeRouter();self.app=create_app(self.settings,self.router);self.client=self.app.test_client()
        self.client.get('/')
        with self.client.session_transaction() as session:self.csrf=session['csrf']
        self.headers={'X-CSRF-Token':self.csrf}
        self.chat=self.post('/api/chats',{}).json['id']
    def tearDown(self):self.app.extensions['engine'].close();self.temp.cleanup()
    def post(self,url,payload):return self.client.post(url,json=payload,headers=self.headers)
    def wait(self,key):
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            result=self.client.get('/api/jobs/'+key).json
            if result['status'] not in ('queued','running'):return result
            time.sleep(.01)
        self.fail('Job did not finish')
    def image(self):
        b=BytesIO();Image.new('RGB',(30,20),'red').save(b,format='PNG');b.seek(0)
        return self.client.post('/api/images',data={'image':(b,'spoof.exe')},headers=self.headers)
    def test_markdown_chat_history_and_refs(self):
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'Explain SSRF'});self.assertEqual(response.status_code,202)
        result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'completed')
        self.assertTrue(result['result']['refs']);self.assertIn('```python',result['result']['text'])
        history=self.client.get('/api/chats/'+self.chat).json['messages'];self.assertEqual([m['role'] for m in history],['user','assistant'])
        messages,kind,tools=self.router.calls[0];self.assertIn('[KB:',messages[0]['content']);self.assertEqual(kind,'text');self.assertIsNone(tools)
    def test_image_validation_and_vision_routing(self):
        upload=self.image();self.assertEqual(upload.status_code,201);key=upload.json['id']
        with self.client.get('/api/images/'+key) as preview:self.assertEqual(preview.mimetype,'image/jpeg')
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'Describe this','image_ids':[key],'allow_tools':True})
        self.assertEqual(self.wait(response.json['job_id'])['status'],'completed')
        messages,kind,tools=self.router.calls[0];self.assertEqual(kind,'vision');self.assertIsNone(tools)
        self.assertTrue(messages[-1]['content'][1]['image_url']['url'].startswith('data:image/jpeg;base64,'))
    def test_svg_and_invalid_image_rejected(self):
        result=self.client.post('/api/images',data={'image':(BytesIO(b'<svg onload="alert(1)"></svg>'),'test.png')},headers=self.headers)
        self.assertEqual(result.status_code,400)
    def test_csrf_origin_and_host_rejected(self):
        self.assertEqual(self.client.post('/api/chats',json={}).status_code,403)
        self.assertEqual(self.client.post('/api/chats',json={},headers={**self.headers,'Origin':'https://evil.example'}).status_code,403)
        self.assertEqual(self.client.get('/api/status',headers={'Host':'evil.example'}).status_code,400)
    def test_local_mode_rejects_remote_client(self):
        self.assertEqual(self.client.get('/api/status',environ_base={'REMOTE_ADDR':'8.8.8.8'}).status_code,403)
    def test_typed_tools_require_confirmation_and_scope(self):
        payload={'chat_id':self.chat,'tool':'dns_lookup','arguments':{'origin':'https://outside.example'}}
        self.assertEqual(self.post('/api/tools',payload).status_code,403)
        payload['confirmed']=True;self.assertEqual(self.post('/api/tools',payload).status_code,400)
        payload.update(tool='nmap_scan',arguments={'target':'127.0.0.1;id','ports':[80]})
        self.assertEqual(self.post('/api/tools',payload).status_code,400)
        payload.update(tool='web_headers',arguments={'origin':'https://example.com','shell':'id'})
        self.assertEqual(self.post('/api/tools',payload).status_code,400)
    def test_knowledge_tool_without_api_keys_saves_evidence(self):
        response=self.post('/api/tools',{'chat_id':self.chat,'tool':'knowledge_search','arguments':{'query':'SSRF'},'confirmed':True})
        result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'completed')
        record=result['evidence'][0];file=self.client.get('/api/evidence/'+record['id']);self.addCleanup(file.close);self.assertEqual(file.status_code,200)
        import hashlib
        self.assertEqual(record['sha256'],hashlib.sha256(file.data).hexdigest())
        self.assertEqual(len(self.client.get('/api/chats/'+self.chat).json['evidence']),1)
        self.assertEqual(len(self.client.get('/api/chats/'+self.chat+'/export').json['evidence']),1)
    def test_unknown_image_and_traversal(self):
        self.assertEqual(self.client.get('/api/images/'+'0'*32).status_code,400)
        self.assertEqual(self.client.get('/api/evidence/invalid').status_code,400)
        self.assertEqual(self.post('/api/chat',{'chat_id':self.chat,'message':'hello','image_ids':['../../secret']}).status_code,400)
    def test_parameter_validation(self):
        self.assertEqual(self.post('/api/chat',{'chat_id':self.chat,'message':'x','allow_tools':'true'}).status_code,400)
        self.assertEqual(self.post('/api/chat',{'chat_id':self.chat,'message':'x'*12001}).status_code,400)
        self.assertEqual(self.post('/api/chat',{'chat_id':self.chat,'message':'x','image_ids':[None]}).status_code,400)
    def test_model_tool_execution_and_evidence(self):
        class AgentRouter:
            calls=0
            def complete(inner,messages,kind,event,cancel,tools=None):
                inner.calls+=1
                if inner.calls==1:return {'role':'assistant','content':None,'tool_calls':[{'id':'fixture1','type':'function','function':{'name':'knowledge_search','arguments':'{"query":"SSRF"}'}}]},'agent-fixture'
                self.assertEqual(messages[-1]['role'],'tool');self.assertIn('SSRF',messages[-1]['content'])
                return {'role':'assistant','content':'Retrieved relevant evidence.'},'agent-fixture'
        self.app.extensions['engine'].router=AgentRouter()
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'Find SSRF evidence','allow_tools':True})
        result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'completed');self.assertEqual(len(result['evidence']),1)
    def test_model_cannot_expand_scope(self):
        class AgentRouter:
            calls=0
            def complete(inner,messages,kind,event,cancel,tools=None):
                inner.calls+=1
                if inner.calls==1:return {'role':'assistant','content':None,'tool_calls':[{'id':'fixture1','type':'function','function':{'name':'web_headers','arguments':'{"origin":"https://outside.example"}'}}]},'fixture'
                self.assertIn('outside',messages[-1]['content']);return {'role':'assistant','content':'The target was outside scope.'},'fixture'
        self.app.extensions['engine'].router=AgentRouter()
        with patch('app.tools.PinnedHTTPS') as connection:
            response=self.post('/api/chat',{'chat_id':self.chat,'message':'Check outside scope','allow_tools':True})
            result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'completed');connection.assert_not_called();self.assertEqual(result['evidence'],[])
    def test_tools_disabled_cannot_execute(self):
        class RogueRouter:
            def complete(inner,*args,**kw):return {'role':'assistant','tool_calls':[{'id':'x','function':{'name':'knowledge_search','arguments':'{"query":"SSRF"}'}}]},'fixture'
        self.app.extensions['engine'].router=RogueRouter()
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'hello'})
        result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'failed');self.assertEqual(result['evidence'],[])
    def test_cancellation_and_busy_conversation(self):
        started=threading.Event()
        class SlowRouter:
            def complete(inner,messages,kind,event,cancel,tools=None):
                started.set();cancel.wait(2)
                return {'role':'assistant','content':'This must not be saved after cancellation.'},'fixture'
        self.app.extensions['engine'].router=SlowRouter()
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'hello'});key=response.json['job_id'];self.assertTrue(started.wait(1))
        self.assertEqual(self.post('/api/chat',{'chat_id':self.chat,'message':'second'}).status_code,400)
        self.assertTrue(self.post('/api/jobs/'+key+'/cancel',{}).json['requested'])
        result=self.wait(key);self.assertEqual(result['status'],'cancelled');self.assertEqual(len(self.client.get('/api/chats/'+self.chat).json['messages']),1)
    def test_no_provider_reports_failure_honestly(self):
        self.app.extensions['engine'].router=ModelRouter(self.settings)
        response=self.post('/api/chat',{'chat_id':self.chat,'message':'hello'})
        result=self.wait(response.json['job_id']);self.assertEqual(result['status'],'failed');self.assertIn('No configured text',result['error'])
    def test_login_owner_token(self):
        self.app.extensions['engine'].close()
        self.settings.access_token='test-token-'+('x'*32)
        self.app=create_app(self.settings,self.router);self.client=self.app.test_client();self.client.get('/')
        with self.client.session_transaction() as session:self.headers={'X-CSRF-Token':session['csrf']}
        self.assertEqual(self.client.get('/api/chats').status_code,401)
        self.assertEqual(self.post('/api/login',{'token':'wrong'}).status_code,401)
        self.assertEqual(self.post('/api/login',{'token':self.settings.access_token}).status_code,200)
        self.assertEqual(self.client.get('/api/chats').status_code,200)
        self.post('/api/logout',{});self.assertEqual(self.client.get('/api/chats').status_code,401)
    def test_security_headers(self):
        response=self.client.get('/')
        self.assertIn("script-src 'self'",response.headers['Content-Security-Policy'])
        self.assertEqual(response.headers['X-Content-Type-Options'],'nosniff')
        self.assertIn('no-store',response.headers['Cache-Control'])

class ScopeTests(unittest.TestCase):
    def setUp(self):self.scope=Scope({'web_origins':['https://example.com'],'nmap_targets':['127.0.0.1'],'nmap_ports':[80,443]})
    def test_origin_credentials_queries_redirect_paths_and_suffixes(self):
        for bad in ['https://example.com.evil.test','https://example.com@evil.test','https://example.com/private','https://example.com?x=1','http://example.com','https://example.com:8443']:
            with self.subTest(bad=bad),self.assertRaises(ScopeError):self.scope.origin(bad)
    def test_scan_ip_and_ports(self):
        self.assertEqual(self.scope.scan('127.0.0.1',[443,80]),('127.0.0.1',[80,443]))
        for target,ports in [('example.com',[80]),('8.8.8.8',[80]),('127.0.0.1',[True]),('127.0.0.1',[22]),('169.254.169.254',[80])]:
            with self.subTest(target=target,ports=ports),self.assertRaises(ScopeError):self.scope.scan(target,ports)
    def test_mixed_dns_answers_blocked(self):
        with patch('app.tools.socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]):
            with self.assertRaises(ScopeError):public_addresses('example.com')
    def test_tls_connection_uses_pinned_ip_and_original_sni(self):
        raw=Mock();wrapped=Mock();context=Mock();context.wrap_socket.return_value=wrapped
        with patch('app.tools.ssl.create_default_context',return_value=context),patch('app.tools.socket.create_connection',return_value=raw) as connect:
            c=PinnedHTTPS('example.com','8.8.8.8');c.connect();connect.assert_called_once_with(('8.8.8.8',443),timeout=8)
            context.wrap_socket.assert_called_once_with(raw,server_hostname='example.com')

class FakeResponse:
    def __init__(self,message):self.message=message
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,count):return json.dumps({'choices':[{'message':self.message}]}).encode()

class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.s=settings(self.temp.name)
        chain=[Provider('primary','https://primary.example','private-key-1','a',True),Provider('fallback','https://fallback.example','private-key-2','b',True)]
        self.s.providers={'text':chain,'vision':chain};self.router=ModelRouter(self.s);self.events=[]
    def tearDown(self):self.temp.cleanup()
    def test_text_and_vision_fallbacks(self):
        for kind in ['text','vision']:
            opener=Mock();opener.open.side_effect=[urllib.error.HTTPError('x',429,'quota',{},None),FakeResponse({'role':'assistant','content':'fallback worked'})];self.router.opener=opener
            message,model=self.router.complete([{'role':'user','content':'hello'}],kind,self.events.append,threading.Event())
            self.assertEqual(model,'fallback/b');self.assertEqual(message['content'],'fallback worked');self.assertEqual(opener.open.call_count,2)
        self.assertNotIn('private-key',str(self.events))
    def test_refusal_does_not_trigger_fallback(self):
        opener=Mock();opener.open.return_value=FakeResponse({'role':'assistant','content':None,'refusal':'Cannot fulfill this request.'});self.router.opener=opener
        result,_=self.router.complete([], 'text',self.events.append,threading.Event());self.assertIn('Cannot fulfill',result['content']);self.assertEqual(opener.open.call_count,1)
    def test_all_provider_failure(self):
        opener=Mock();opener.open.side_effect=TimeoutError();self.router.opener=opener
        with self.assertRaises(ProviderError):self.router.complete([], 'vision',self.events.append,threading.Event())
    def test_json_tool_response(self):
        response={'role':'assistant','content':None,'tool_calls':[{'id':'call1','type':'function','function':{'name':'knowledge_search','arguments':'{"query":"SSRF"}'}}]}
        opener=Mock();opener.open.return_value=FakeResponse(response);self.router.opener=opener
        result,_=self.router.complete([], 'text',self.events.append,threading.Event(),[{'type':'function'}]);self.assertEqual(result['tool_calls'][0]['id'],'call1')


class AdapterTests(unittest.TestCase):
    def setUp(self):
        from app.store import Store
        from app.tools import ToolRunner
        self.temp=tempfile.TemporaryDirectory();self.s=settings(self.temp.name);self.store=Store(self.s.data_dir);self.runner=ToolRunner(self.s,self.store)
    def tearDown(self):self.temp.cleanup()
    def test_http_headers_no_redirects_or_cookie_capture(self):
        response=Mock();response.status=302;response.getheaders.return_value=[('Server','test'),('Set-Cookie','secret=value'),('Location','https://outside.example'),('Content-Type','text/html')];response.read.return_value=b'content'
        connection=Mock();connection.getresponse.return_value=response;connection.peer_cert={'notAfter':'Jan 1 2030'}
        with patch('app.tools.public_addresses',return_value=['8.8.8.8']),patch('app.tools.PinnedHTTPS',return_value=connection) as make:
            result=self.runner.web_headers('https://example.com')
        make.assert_called_once_with('example.com','8.8.8.8');connection.request.assert_called_once();self.assertEqual(result['http_status'],302)
        self.assertNotIn('secret',json.dumps(result));self.assertNotIn('location',result['selected_headers']);self.assertEqual(result['certificate_expires'],'Jan 1 2030')
        self.assertTrue(all(o['confidence']=='informational' for o in result['observations']))
    def test_nmap_command_and_xml_parsing(self):
        xml=b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="fixture"><host><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>'
        process=Mock();process.poll.return_value=0;process.returncode=0
        def start(command,**kw):kw['stdout'].write(xml);return process
        with patch('app.tools.shutil.which',return_value='/approved/nmap'),patch('app.tools.subprocess.Popen',side_effect=start) as popen:
            result=self.runner.nmap('127.0.0.1',[80],threading.Event())
        self.assertEqual(result['ports'][0]['state'],'open');self.assertEqual(result['nmap_version'],'fixture')
        command=popen.call_args.args[0];self.assertEqual(command[-1],'127.0.0.1');self.assertIn('-sT',command);self.assertNotIn('--script',command);self.assertFalse(popen.call_args.kwargs['shell'])
    def test_nmap_absent_is_explicit(self):
        with patch('app.tools.shutil.which',return_value=None):
            with self.assertRaisesRegex(ScopeError,'not installed'):self.runner.nmap('127.0.0.1',[80],threading.Event())
    def test_nmap_malicious_xml_rejected(self):
        process=Mock();process.poll.return_value=0;process.returncode=0
        def start(command,**kw):kw['stdout'].write(b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///etc/passwd">]><x/>');return process
        with patch('app.tools.shutil.which',return_value='/approved/nmap'),patch('app.tools.subprocess.Popen',side_effect=start):
            with self.assertRaisesRegex(ScopeError,'XML'):self.runner.nmap('127.0.0.1',[80],threading.Event())
    def test_nmap_cancellation_terminates_process(self):
        from app.providers import Cancelled
        cancel=threading.Event();cancel.set();process=Mock();process.poll.return_value=None
        with patch('app.tools.shutil.which',return_value='/approved/nmap'),patch('app.tools.subprocess.Popen',return_value=process):
            with self.assertRaises(Cancelled):self.runner.nmap('127.0.0.1',[80],cancel)
        process.terminate.assert_called_once();process.wait.assert_called()

if __name__=='__main__':unittest.main()
