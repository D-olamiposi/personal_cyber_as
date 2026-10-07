"""Typed, bounded assessment adapters. No model-generated shell commands."""
import hashlib
import http.client
import ipaddress
import json
import os
import re
import threading
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from .providers import Cancelled
from .retrieval import Retriever
from .store import now,identifier

class ScopeError(ValueError):pass

def canonical_origin(value):
    if not isinstance(value,str) or len(value)>500:raise ScopeError('Expected an HTTPS origin')
    u=urlsplit(value)
    if u.scheme!='https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path not in ('','/'):
        raise ScopeError('Use an exact HTTPS origin without path, query, credentials or fragment')
    if u.port not in (None,443):raise ScopeError('Web adapter supports HTTPS port 443 only')
    host=u.hostname.encode('idna').decode('ascii').lower()
    if host.endswith('.') or any(c.isspace() for c in host):raise ScopeError('Invalid hostname')
    try:
        address=ipaddress.ip_address(host)
        if not address.is_global:raise ScopeError('Web origins must use public destinations')
    except ValueError as exc:
        if isinstance(exc,ScopeError):raise
        labels=host.split('.')
        if len(host)>253 or len(labels)<2 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) for label in labels):
            raise ScopeError('Use an exact public hostname; wildcards are not supported')
    return 'https://'+('['+host+']' if ':' in host else host)

class Scope:
    def __init__(self,config):
        self.origins={canonical_origin(x) for x in config.get('web_origins',[])}
        self.targets=set()
        for value in config.get('nmap_targets',[]):
            self.targets.add(self.valid_scan_ip(value))
        ports=config.get('nmap_ports',[80,443])
        if not isinstance(ports,list) or not 1<=len(ports)<=16 or any(type(p)!=int or not 1<=p<=65535 for p in ports):
            raise ScopeError('Configure 1..16 integer Nmap ports')
        self.ports=set(ports)
    @staticmethod
    def valid_scan_ip(value):
        if not isinstance(value,str) or len(value)>64:raise ScopeError('Expected a literal IP string')
        try:ip=ipaddress.ip_address(value)
        except ValueError:raise ScopeError('Nmap requires a literal approved IP address') from None
        if ip.is_link_local or ip.is_multicast or ip.is_unspecified or '%' in str(value):
            raise ScopeError('Link-local, multicast and unspecified targets are blocked')
        return str(ip)
    def origin(self,value):
        origin=canonical_origin(value)
        if origin not in self.origins:raise ScopeError('HTTPS origin is outside the configured scope')
        return origin
    def scan(self,value,ports):
        target=self.valid_scan_ip(value)
        if target not in self.targets:raise ScopeError('IP is outside the separately approved Nmap scope')
        if not isinstance(ports,list) or not ports or len(ports)>16 or any(type(p)!=int or p not in self.ports for p in ports):
            raise ScopeError('Ports must be selected from the configured Nmap port list')
        return target,sorted(set(ports))

def public_addresses(host):
    answers=socket.getaddrinfo(host,443,type=socket.SOCK_STREAM)
    addresses=sorted({item[4][0] for item in answers})
    if not addresses:raise ScopeError('No DNS addresses returned')
    # Check every answer; fail closed on mixed public/private DNS responses.
    if any(not ipaddress.ip_address(address).is_global for address in addresses):
        raise ScopeError('Web checks refuse private, loopback, reserved or link-local destinations')
    return addresses

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,address):
        super().__init__(host,443,timeout=8,context=ssl.create_default_context())
        self.address=address
    def connect(self):
        raw=socket.create_connection((self.address,443),timeout=self.timeout)
        try:
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
            self.peer_cert=self.sock.getpeercert()
        except Exception:raw.close();raise

def schema(name,description,properties,required):
    return {'type':'function','function':{'name':name,'description':description,'parameters':{'type':'object','properties':properties,'required':required,'additionalProperties':False}}}

SCHEMAS=[
 schema('knowledge_search','Retrieve local knowledge passages with provenance; does not contact targets.',{'query':{'type':'string'}},['query']),
 schema('web_headers','One HTTPS GET of the root page of an approved exact origin. Reports selected headers and TLS; cannot establish absence of application vulnerabilities.',{'origin':{'type':'string'}},['origin']),
 schema('dns_lookup','Resolve the hostname of an approved exact HTTPS origin without scanning its infrastructure.',{'origin':{'type':'string'}},['origin']),
 schema('nmap_scan','Bounded TCP connect scan of a separately approved literal IP, using 1..16 approved ports. No scripts, brute force, exploitation or OS probing.',{'target':{'type':'string'},'ports':{'type':'array','items':{'type':'integer'},'minItems':1,'maxItems':16}},['target','ports']),
 schema('image_metadata','Read dimensions, type and hashes of an image attached to this request. Original metadata is not interpreted as proof of location.',{'image_id':{'type':'string'}},['image_id'])]

class ToolRunner:
    def __init__(self,settings,store):
        self.settings=settings;self.store=store
        self.scope_lock=threading.Lock()
        self.scope_file=settings.data_dir/'managed-scopes.json'
        saved=json.loads(self.scope_file.read_text()) if self.scope_file.exists() else settings.scopes
        self.scope=Scope(saved)
        self.evidence_dir=settings.data_dir/'evidence';self.evidence_dir.mkdir(exist_ok=True)
    def manage_target(self,action,kind,value,confirmed=False):
        if action not in ('add','remove') or kind not in ('web','nmap'):
            raise ScopeError('Choose add/remove and web/nmap')
        if action=='add' and confirmed is not True:
            raise ScopeError('Confirm that this target is within your authorized assessment scope')
        target=canonical_origin(value) if kind=='web' else Scope.valid_scan_ip(value)
        with self.scope_lock:
            config={'web_origins':sorted(self.scope.origins),'nmap_targets':sorted(self.scope.targets),'nmap_ports':sorted(self.scope.ports)}
            field='web_origins' if kind=='web' else 'nmap_targets'
            values=set(config[field])
            if action=='add':values.add(target)
            else:values.discard(target)
            if len(values)>100:raise ScopeError('Save at most 100 targets of each type')
            config[field]=sorted(values)
            updated=Scope(config)
            # Persist first; only publish the new scope after a successful atomic write.
            descriptor,path=tempfile.mkstemp(prefix='.scopes-',dir=self.settings.data_dir)
            try:
                with os.fdopen(descriptor,'w',encoding='utf-8') as file:
                    json.dump(config,file,indent=2);file.write('\n');file.flush();os.fsync(file.fileno())
                os.replace(path,self.scope_file)
            finally:
                if os.path.exists(path):os.unlink(path)
            self.scope=updated
            self.settings.scopes=config
        return self.capabilities()
    def capabilities(self):
        return {'tools':[{'name':s['function']['name'],'available':s['function']['name']!='nmap_scan' or (self.settings.enable_nmap and bool(shutil.which('nmap')))} for s in SCHEMAS],
                'web_origins':sorted(self.scope.origins),'nmap_targets':sorted(self.scope.targets),'nmap_ports':sorted(self.scope.ports)}
    def schemas(self):
        available={x['name'] for x in self.capabilities()['tools'] if x['available']}
        return [s for s in SCHEMAS if s['function']['name'] in available]
    def validate(self,name,args,image_ids):
        expected={'knowledge_search':{'query'},'web_headers':{'origin'},'dns_lookup':{'origin'},'nmap_scan':{'target','ports'},'image_metadata':{'image_id'}}
        if not isinstance(name,str) or name not in expected or not isinstance(args,dict) or set(args)!=expected[name]:raise ScopeError('Unknown tool or invalid argument fields')
        if name=='knowledge_search' and (not isinstance(args['query'],str) or not 1<=len(args['query'])<=2000):raise ScopeError('Query must contain 1..2000 characters')
        if name in ('web_headers','dns_lookup'):self.scope.origin(args['origin'])
        if name=='nmap_scan':
            if not self.settings.enable_nmap:raise ScopeError('Nmap execution is disabled in this interface')
            self.scope.scan(args['target'],args['ports'])
        if name=='image_metadata' and args['image_id'] not in image_ids:raise ScopeError('Image must be attached to this request')
    def run(self,name,args,cancel,event,image_ids=None,record=None):
        self.validate(name,args,image_ids or [])
        if cancel.is_set():raise Cancelled()
        started=now();event(f'Running {name} within configured scope')
        if name=='knowledge_search':result={'passages':Retriever(self.settings.kb_root).search(args['query'])}
        elif name=='web_headers':result=self.web_headers(args['origin'])
        elif name=='dns_lookup':
            origin=self.scope.origin(args['origin']);host=urlsplit(origin).hostname
            result={'origin':origin,'addresses':public_addresses(host),'interpretation':'DNS mapping only; these addresses are not automatically approved scan targets.'}
        elif name=='nmap_scan':result=self.nmap(args['target'],args['ports'],cancel)
        else:result=self.store.get_upload(args['image_id'])['metadata']
        evidence={'id':identifier(),'tool':name,'arguments':args,'started':started,'finished':now(),'result':result}
        encoded=json.dumps(evidence,ensure_ascii=False,indent=2).encode()
        evidence['sha256']=hashlib.sha256(encoded).hexdigest()
        (self.evidence_dir/(evidence['id']+'.json')).write_bytes(encoded)
        if record:record(evidence)
        event(f'{name} finished; evidence saved')
        if cancel.is_set():raise Cancelled()
        return evidence
    def web_headers(self,value):
        origin=self.scope.origin(value);host=urlsplit(origin).hostname
        addresses=public_addresses(host)
        # Pin the validated address at socket connect time to prevent DNS rebinding.
        connection=PinnedHTTPS(host,addresses[0])
        try:
            connection.request('GET','/',headers={'User-Agent':'PersonalCyberAssistant/1.0 (owner-authorized assessment)','Accept':'text/html','Connection':'close'})
            response=connection.getresponse()
            headers={k.lower():v[:4000] for k,v in response.getheaders() if k.lower() in {'content-security-policy','strict-transport-security','x-content-type-options','x-frame-options','referrer-policy','permissions-policy','server','content-type'}}
            cert=getattr(connection,'peer_cert',{})
            # Consume only a bounded body and never send page content to the planner.
            body=response.read(65536)
            observations=[]
            for key in ['content-security-policy','strict-transport-security','x-content-type-options','referrer-policy']:
                if key not in headers:observations.append({'name':key,'status':'not_observed','confidence':'informational','note':'Absence on one response does not establish exploitability.'})
            return {'origin':origin,'resolved_addresses':addresses,'connected_address':addresses[0],'http_status':response.status,'selected_headers':headers,'tls_verified':True,'certificate_expires':cert.get('notAfter'),'body_sample_bytes':len(body),'observations':observations,'limitations':['One root-page response only','Redirects are not followed','No authentication, source review, injection testing or SSRF verification']}
        finally:connection.close()
    def nmap(self,target,ports,cancel):
        target,ports=self.scope.scan(target,ports)
        executable=shutil.which('nmap')
        if not executable:raise ScopeError('Nmap is not installed. Install it separately in the execution environment.')
        command=[executable,'-sT','-Pn','-n','--max-retries','1','--max-rate','5','--host-timeout','25s','-p',','.join(map(str,ports)),'-oX','-']
        if ':' in target:command.append('-6')
        command.append(target)
        with tempfile.TemporaryFile() as out,tempfile.TemporaryFile() as err:
            process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,shell=False)
            deadline=time.monotonic()+30
            try:
                while process.poll() is None:
                    if cancel.is_set():raise Cancelled()
                    if time.monotonic()>deadline:raise ScopeError('Nmap exceeded the local 30-second timeout')
                    if out.tell()>200000 or err.tell()>20000:raise ScopeError('Nmap output exceeded local limits')
                    cancel.wait(0.1)
                out.seek(0);err.seek(0)
                xml=out.read(200001);error=err.read(20001)
                if len(xml)>200000 or len(error)>20000:raise ScopeError('Nmap output exceeded local limits')
                if process.returncode:raise ScopeError('Nmap failed; inspect local installation and scan privileges')
                if b'<!ENTITY' in xml or b'<!DOCTYPE' in xml.replace(b'<!DOCTYPE nmaprun>',b''):raise ScopeError('Unexpected XML declaration')
                tree=ET.fromstring(xml)
                found=[]
                for host in tree.findall('host'):
                    for port in host.findall('ports/port'):
                        state=port.find('state');service=port.find('service')
                        found.append({'port':int(port.get('portid')),'protocol':port.get('protocol'),'state':state.get('state') if state is not None else 'unknown','service':service.get('name') if service is not None else None})
                return {'target':target,'ports_requested':ports,'arguments':command[1:],'nmap_version':tree.get('version'),'ports':found,'raw_xml':xml.decode('utf-8',errors='replace'),'limitations':['No version detection or vulnerability scripts','Open ports are not by themselves vulnerabilities','A timed-out or filtered port does not prove a service is absent']}
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:process.wait(timeout=2)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=2)
