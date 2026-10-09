import importlib.util
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'chatbot'))
spec = importlib.util.spec_from_file_location('runner_server', ROOT/'runner/server.py')
server = importlib.util.module_from_spec(spec); spec.loader.exec_module(server)
from app.workbench import execute
from app import readiness

class WorkbenchTests(unittest.TestCase):
    def test_container_boundaries(self):
        args=server.command('shell','echo hello','test-name')
        for value in ('--network=none','--read-only','--user=65534:65534','--memory=128m','--pids-limit=64','--cap-drop=ALL','--security-opt=no-new-privileges','--pull=never'):
            self.assertIn(value,args)
        self.assertNotIn('--privileged',args)
        self.assertEqual(args[-3:],['/bin/bash','-lc','echo hello'])
        with self.assertRaises(ValueError): server.command('unknown','x','test')
        with self.assertRaises(ValueError): server.command('python','x'*12001,'test')
    def test_remote_http_rejected(self):
        with patch.dict(os.environ,{'RUNNER_URL':'http://remote.example','RUNNER_TOKEN':'x'*32}):
            with self.assertRaises(ValueError): list(execute('python','print(1)'))
    def test_approval_before_network(self):
        with patch.object(readiness,'public_addresses') as dns:
            with self.assertRaises(ValueError): readiness.sample('https://lab.example',[])
            dns.assert_not_called()
    def test_sample_stops_on_http_error_and_cooldown(self):
        origin='https://lab.example'; readiness.LAST.clear()
        with patch.object(readiness,'public_addresses',return_value=['8.8.8.8']), patch.object(readiness,'PinnedHTTPS') as cls:
            cls.return_value.getresponse.return_value.status=429
            result=readiness.sample(origin,[origin])
            self.assertEqual(len(result['samples']),1)
            with self.assertRaises(ValueError): readiness.sample(origin,[origin])
            self.assertEqual(cls.return_value.request.call_count,1)

if __name__=='__main__':unittest.main()
