"""Small, manual availability sample. This does not establish DDoS resilience."""
import time
from datetime import datetime, timezone
import threading
from urllib.parse import urlsplit
from .tools import canonical_origin, public_addresses, PinnedHTTPS
LOCK = threading.Lock()
LAST = {}

def sample(origin, approved, event=lambda value: None):
    origin = canonical_origin(origin)
    if origin not in approved: raise ValueError('Origin needs separate lab/staging load-check approval')
    if not LOCK.acquire(False): raise ValueError('An availability sample is already running')
    try:
        if time.monotonic() - LAST.get(origin, -1000) < 300:
            raise ValueError('Wait five minutes between samples of this origin')
        LAST[origin] = time.monotonic()
        host = urlsplit(origin).hostname
        rows = []
        for number in range(5):
            start = time.monotonic()
            addresses = public_addresses(host)
            connection = PinnedHTTPS(host, addresses[0])
            try:
                connection.request('GET', '/', headers={'User-Agent':'Sentinel-authorized-availability-sample','Connection':'close'})
                response = connection.getresponse()
                response.read1(65536)
                row = {'request':number+1, 'status':response.status,'seconds':round(time.monotonic()-start,3)}
                rows.append(row); event(row)
                if response.status >= 400 or row['seconds'] > 3: break
            finally: connection.close()
            if number < 4: time.sleep(max(0, 1-(time.monotonic()-start)))
        return {'origin':origin,'collected_at':datetime.now(timezone.utc).isoformat(),'samples':rows,'limits':'Five root GETs maximum, concurrency one, at most one request/second; five-minute cooldown in this runtime. No redirects. Stops on HTTP errors or response over three seconds. Not a DDoS test or capacity measurement.'}
    finally: LOCK.release()
