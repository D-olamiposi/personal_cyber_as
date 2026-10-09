"""Owner-only workbench client; never runs shell code in the web process."""
import json
import os
import urllib.request
from urllib.parse import urlsplit

def execute(mode, code):
    url = os.environ.get('RUNNER_URL', '').rstrip('/')
    token = os.environ.get('RUNNER_TOKEN', '')
    parsed = urlsplit(url)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('RUNNER_URL must be a server origin')
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
        raise ValueError('Use HTTPS for a remote runner or HTTP localhost for local use')
    if len(token) < 32: raise ValueError('Configure RUNNER_TOKEN with at least 32 characters')
    request = urllib.request.Request(url + '/execute', data=json.dumps({'mode':mode, 'code':code}).encode(),
        headers={'Authorization':'Bearer '+token, 'Content-Type':'application/json'}, method='POST')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args): return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=20) as response:
        size = 0
        while True:
            line = response.readline(30000)
            if not line: break
            size += len(line)
            if size > 500000: raise ValueError('Runner response exceeded local limit')
            item = json.loads(line)
            yield item
            if item.get('done'): return
    raise ValueError('Runner disconnected before completion')
