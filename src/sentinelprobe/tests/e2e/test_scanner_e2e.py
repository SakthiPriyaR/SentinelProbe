"""
End-to-end: run the real scanner against a local server that is deliberately
vulnerable, and against a hardened one, and check what gets flagged.

Everything runs on 127.0.0.1 with a throw-away stdlib HTTP server.
"""
import json
import threading
import unittest
from html import escape
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

try:
    import aiohttp  # noqa: F401
    from ...parsers.openapi import OpenAPIv3Parser
    from ...tester.handler import generate_and_run_tests

    HAVE_DEPS = True
except ImportError:
    HAVE_DEPS = False


class _Base(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep test output quiet
        pass

    def send(self, status, body, ctype='application/json'):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def query(self):
        return parse_qs(urlparse(self.path).query).get('q', [''])[0]


class VulnerableHandler(_Base):
    """Reflects input, errors on quotes, leaks files/emails, accepts every verb."""

    def respond(self):
        path = urlparse(self.path).path
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        if path.startswith('/users/'):
            # BOLA (any id works) + data exposure (email)
            return self.send(200, json.dumps({'id': path.rsplit('/', 1)[-1], 'email': 'victim@example.com'}))
        if path == '/search':
            q = self.query()
            if "'" in q:
                return self.send(500, 'SQL syntax error near ' + q, 'text/plain')
            if 'etc/passwd' in q:
                return self.send(200, 'root:x:0:0:root:/root:/bin/bash', 'text/plain')
            return self.send(200, '<html>results for ' + q + '</html>', 'text/html')  # reflected XSS
        if path == '/users':
            return self.send(201, '{}')
        self.send(404, '{}')

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = respond


class SecureHandler(_Base):
    """Escapes output, only supports documented verbs, never leaks."""

    def do_GET(self):
        path = urlparse(self.path).path
        if path == '/search':
            return self.send(200, '<html>' + escape(self.query()) + '</html>', 'text/html')
        self.send(404, '{}')

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length:
            self.rfile.read(length)
        self.send(400 if urlparse(self.path).path == '/users' else 404, '{}')

    def _no(self):
        self.send(405, '{}')

    do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _no


def make_spec(port):
    return {
        'openapi': '3.0.0',
        'info': {'title': 'demo', 'version': '1'},
        'servers': [{'url': f'http://127.0.0.1:{port}'}],
        'paths': {
            '/users/{id}': {'get': {
                'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}],
                'responses': {'200': {'description': 'ok'}}}},
            '/users': {'post': {
                'requestBody': {'content': {'application/json': {'schema': {
                    'type': 'object', 'properties': {'name': {'type': 'string'}}}}}},
                'responses': {'201': {'description': 'ok'}}}},
            '/search': {'get': {
                'parameters': [{'name': 'q', 'in': 'query', 'schema': {'type': 'string'}}],
                'responses': {'200': {'description': 'ok'}}}},
        },
    }


def scan(handler_cls):
    server = ThreadingHTTPServer(('127.0.0.1', 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        parser = OpenAPIv3Parser(file_or_url=None, spec=make_spec(server.server_port))
        return generate_and_run_tests(api_parser=parser, rate_limit=1000, ssl_verify=False)
    finally:
        server.shutdown()
        server.server_close()


def vulnerable_tests(results):
    return {r['test_name'] for r in results if r.get('vulnerable')}


@unittest.skipUnless(HAVE_DEPS, 'scanner dependencies (aiohttp, ...) not installed')
class TestScannerEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vuln = scan(VulnerableHandler)
        cls.secure = scan(SecureHandler)

    def test_finds_the_planted_vulnerabilities(self):
        found = vulnerable_tests(self.vuln)
        for expected in (
            'SQLi Test',
            'XSS/HTML Injection Test',
            'OS Command Injection Test',
            'UnSupported HTTP Method Check',
            'BOLA Path Test with Fuzzed Params',
        ):
            self.assertIn(expected, found, f'missed: {expected}; found: {sorted(found)}')

    def test_reports_the_leaked_email(self):
        leaks = [r for r in self.vuln if 'email' in (r.get('data_leak') or {})]
        self.assertTrue(leaks, 'data exposure (email) was not detected')

    def test_hardened_server_has_no_injection_findings(self):
        found = vulnerable_tests(self.secure)
        for name in (
            'SQLi Test',
            'XSS/HTML Injection Test',
            'OS Command Injection Test',
            'UnSupported HTTP Method Check',
        ):
            self.assertNotIn(name, found, f'false positive on hardened server: {name}')

    def test_results_have_reproducible_curl(self):
        self.assertTrue(all(r.get('curl_command', '').startswith('curl -X') for r in self.vuln))
