import time
import unittest
from unittest.mock import patch

try:
    from fastapi.testclient import TestClient
    from ...api import app as api_app
    from ...api.config import app, auth_secret_key, in_memory_jobs, prune_in_memory_jobs
    from ...api import jobs as api_jobs
    from ...api.schema import CreateScanSchema

    HAVE_API = True
except ImportError:  # api extras / httpx not installed
    HAVE_API = False


@unittest.skipUnless(HAVE_API, 'api extras (fastapi, httpx) not installed')
class TestApiAuth(unittest.TestCase):
    payload = {'mode': 'api', 'openapi': 'https://example.com/openapi.json'}

    def remote(self):
        return TestClient(app, client=('203.0.113.9', 50000))

    def test_remote_without_key_is_401_not_500(self):
        res = self.remote().post('/api/v1/scan', json=self.payload)
        self.assertEqual(res.status_code, 401)

    def test_remote_with_wrong_key_is_401(self):
        for key in ('nope', 'x' * 500):
            res = self.remote().post(
                '/api/v1/scan', json=self.payload, headers={'SECRET-KEY': key}
            )
            self.assertEqual(res.status_code, 401)

    def test_remote_with_valid_key_creates_job(self):
        with patch.object(api_app, 'scan_api', return_value=[]):
            res = self.remote().post(
                '/api/v1/scan',
                json=self.payload,
                headers={'SECRET-KEY': auth_secret_key},
            )
        self.assertEqual(res.status_code, 201)
        self.assertIn('job_id', res.json())

    def test_local_cross_site_origin_is_rejected(self):
        res = TestClient(app).post(
            '/api/v1/scan', json=self.payload, headers={'Origin': 'https://evil.example'}
        )
        self.assertEqual(res.status_code, 401)

    def test_local_foreign_host_header_is_rejected(self):
        res = TestClient(app).post(
            '/api/v1/scan', json=self.payload, headers={'Host': 'evil.example'}
        )
        self.assertEqual(res.status_code, 401)

    def test_local_proxy_headers_are_rejected(self):
        res = TestClient(app).post(
            '/api/v1/scan', json=self.payload, headers={'X-Forwarded-For': '1.2.3.4'}
        )
        self.assertEqual(res.status_code, 401)

    def test_invalid_mode_is_422(self):
        res = TestClient(app).post('/api/v1/scan', json={'mode': 'bogus'})
        self.assertEqual(res.status_code, 422)

    def test_job_runs_and_failure_is_reported(self):
        client = TestClient(app)
        with patch.object(api_app, 'scan_api', side_effect=ValueError('boom')):
            job_id = client.post('/api/v1/scan', json=self.payload).json()['job_id']
            for _ in range(50):
                body = client.get(f'/api/v1/scan/{job_id}/result').json()
                if 'Failed' in body['msg']:
                    break
                time.sleep(0.1)
        self.assertIn('boom', body['msg'])


@unittest.skipUnless(HAVE_API, 'api extras (fastapi, httpx) not installed')
class TestJobs(unittest.TestCase):
    def test_local_file_paths_are_rejected(self):
        for value in ('/etc/passwd', 'C:\\Windows\\win.ini', '../secret.yaml'):
            with self.assertRaises(ValueError):
                api_jobs._load_spec(value)

    def test_inline_spec_is_accepted(self):
        url, spec = api_jobs._load_spec('{"openapi": "3.0.0", "paths": {}}')
        self.assertIsNone(url)
        self.assertEqual(spec['openapi'], '3.0.0')

    def test_metadata_url_is_blocked(self):
        with self.assertRaises(ValueError):
            api_jobs._load_spec('http://169.254.169.254/latest/meta-data/')

    def test_llm_key_goes_to_matching_env_var(self):
        self.assertEqual(api_jobs._llm_env('openai', 'k'), {'OPENAI_API_KEY': 'k'})
        self.assertEqual(api_jobs._llm_env('gemini', 'k'), {'GEMINI_API_KEY': 'k'})
        self.assertEqual(api_jobs._llm_env('openai', None), {})
        with self.assertRaises(ValueError):
            api_jobs._llm_env('unknown-provider', 'k')

    def test_llm_scan_passes_env_overrides(self):
        body = CreateScanSchema(
            mode='llm', llm_model_type='openai', llm_probes='dan', llm_api_key='k'
        )
        with patch('sentinelprobe.llm.handler.run_llm_scan', return_value={'ok': 1}) as m:
            self.assertEqual(api_jobs.scan_api(body), {'ok': 1})
        self.assertEqual(m.call_args.kwargs['env_overrides'], {'OPENAI_API_KEY': 'k'})
        self.assertFalse(m.call_args.kwargs['emit_report'])

    def test_api_scan_requires_openapi(self):
        with self.assertRaises(ValueError):
            api_jobs.scan_api(CreateScanSchema(mode='api'))

    def test_prune_removes_expired_finished_jobs(self):
        in_memory_jobs.clear()
        in_memory_jobs['old'] = {'status': 'finished', 'updated': 0}
        in_memory_jobs['running'] = {'status': 'in_progress', 'updated': 0}
        prune_in_memory_jobs(now=10**9)
        self.assertNotIn('old', in_memory_jobs)
        self.assertIn('running', in_memory_jobs)
        in_memory_jobs.clear()
