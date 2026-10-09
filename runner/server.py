"""Single-owner container execution service. Never execute commands on the host."""
import hmac
import json
import os
import selectors
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOCK = threading.Lock()
TOKEN = os.environ.get('RUNNER_TOKEN', '')
IMAGE = 'sentinel-tools:local'

def command(mode, code, name):
    if mode not in ('python', 'shell') or not isinstance(code, str) or not 1 <= len(code) <= 12000:
        raise ValueError('Choose python/shell and supply 1..12000 characters')
    program = ['python', '-I', '-u', '-c', code] if mode == 'python' else ['/bin/bash', '-lc', code]
    return ['docker', 'run', '--rm', '--pull=never', '--name', name,
            '--network=none', '--read-only', '--user=65534:65534',
            '--memory=128m', '--memory-swap=128m', '--cpus=0.5', '--pids-limit=64',
            '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--tmpfs=/tmp:rw,noexec,nosuid,size=16m', '--workdir=/tmp',
            '--log-driver=none', IMAGE] + program

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        self.connection.settimeout(5)
        if not TOKEN or not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + TOKEN):
            self.send_error(401); return
        if self.path != '/health': self.send_error(404); return
        available = False
        try:
            available = subprocess.run(['docker', 'image', 'inspect', IMAGE], stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, timeout=3).returncode == 0
        except (OSError, subprocess.TimeoutExpired): pass
        body = json.dumps({'service':'sentinel-runner', 'image':IMAGE, 'image_ready':available,
                           'execution':'offline disposable container', 'network_enabled':False,
                           'tools_in_image':['python','bash','nmap','curl','dig','jq'],
                           'limits':{'seconds':15,'output_bytes':65536,'memory_mb':128},
                           'burp':'Separate remote desktop; not a runner API tool'}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        self.connection.settimeout(5)
        if not TOKEN or not hmac.compare_digest(self.headers.get('Authorization', ''), 'Bearer ' + TOKEN):
            self.send_error(401); return
        if self.path != '/execute': self.send_error(404); return
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 60000: raise ValueError()
            data = json.loads(self.rfile.read(length))
            if set(data) != {'mode', 'code'}: raise ValueError()
            name = 'sentinel-' + uuid.uuid4().hex
            args = command(data['mode'], data['code'], name)
        except (ValueError, KeyError, TypeError): self.send_error(400); return
        if not LOCK.acquire(blocking=False): self.send_error(429); return
        process = None
        try:
            process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env={'PATH': os.environ.get('PATH', '')})
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-ndjson')
            self.send_header('Connection', 'close'); self.end_headers()
            self.close_connection = True
            def emit(value):
                self.wfile.write((json.dumps(value) + '\n').encode()); self.wfile.flush()
            deadline = time.monotonic() + 15
            total = 0; reason = 'completed'
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    if time.monotonic() >= deadline: reason = 'timeout'; break
                    ready = selector.select(0.25)
                    if ready:
                        chunk = os.read(process.stdout.fileno(), 4096)
                        if not chunk: break
                        total += len(chunk)
                        if total > 65536: reason = 'output_limit'; break
                        emit({'output': chunk.decode('utf-8', errors='replace')})
                    else: emit({'heartbeat': True})
            if reason == 'completed':
                try: process.wait(timeout=1)
                except subprocess.TimeoutExpired: reason = 'timeout'
            emit({'done': True, 'reason': reason, 'exit_code': process.poll()})
        except (BrokenPipeError, ConnectionError, OSError): pass
        finally:
            try: subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            except (OSError, subprocess.TimeoutExpired): pass
            if process is not None and process.poll() is None:
                process.kill(); process.wait(timeout=2)
            LOCK.release()

if __name__ == '__main__':
    if len(TOKEN) < 32: raise SystemExit('Set RUNNER_TOKEN to at least 32 random characters')
    ThreadingHTTPServer(('127.0.0.1', 8765), Handler).serve_forever()
