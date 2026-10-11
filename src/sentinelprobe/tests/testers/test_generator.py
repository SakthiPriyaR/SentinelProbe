import unittest

from ...parsers.openapi import OpenAPIv3Parser
from ...tester.generator import TestGenerator

SPEC = {
    'openapi': '3.0.0',
    'info': {'title': 'test', 'version': '1'},
    'servers': [{'url': 'http://127.0.0.1:9999'}],
    'paths': {
        '/users/{id}': {
            'get': {
                'parameters': [
                    {'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}
                ],
                'responses': {'200': {'description': 'ok'}},
            }
        },
        '/users': {
            'post': {
                'requestBody': {
                    'content': {
                        'application/json': {
                            'schema': {
                                'type': 'object',
                                'properties': {
                                    'name': {'type': 'string'},
                                    'email': {'type': 'string'},
                                },
                            }
                        }
                    }
                },
                'responses': {'201': {'description': 'created'}},
            }
        },
        '/search': {
            'get': {
                'parameters': [{'name': 'q', 'in': 'query', 'schema': {'type': 'string'}}],
                'responses': {'200': {'description': 'ok'}},
            }
        },
    },
}


def parser():
    return OpenAPIv3Parser(file_or_url=None, spec=SPEC)


def all_values(task):
    """every param value in a generated task"""
    values = []
    for key in ('body_params', 'query_params', 'path_params'):
        values += [p.get('value') for p in task.get(key, []) if isinstance(p, dict)]
    return values


class TestGenerators(unittest.TestCase):
    def setUp(self):
        self.gen = TestGenerator()
        self.parser = parser()

    def test_parser_reads_host(self):
        self.assertEqual(self.parser.base_url, 'http://127.0.0.1:9999')

    def test_unsupported_methods_skip_documented_ones(self):
        tasks = self.gen.check_unsupported_http_methods(self.parser)
        search = [t for t in tasks if t['endpoint'].endswith('/search')]
        methods = {t['method'] for t in search}
        self.assertNotIn('GET', methods)
        self.assertTrue({'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'} <= methods)
        users = [t for t in tasks if t['endpoint'].endswith('/users')]
        self.assertNotIn('POST', {t['method'] for t in users})
        for t in tasks:
            self.assertEqual(t['response_filter'], 'STATUS_CODE_FILTER')
            self.assertTrue(t['vuln_details'][True])

    def test_sqli_injects_payload_in_string_params_only(self):
        tasks = self.gen.sqli_fuzz_params_test(self.parser)
        self.assertTrue(tasks)
        for t in tasks:
            self.assertEqual(t['success_codes'], [500])
        post = [t for t in tasks if t['method'] == 'POST']
        self.assertTrue(any(t['malicious_payload'] in all_values(t) for t in post))
        # integer path ids are never replaced with the payload
        gets = [t for t in tasks if t['endpoint'].startswith('/users/') and t['method'] == 'GET']
        for t in gets:
            self.assertNotIn(t['malicious_payload'], t['url'])

    def test_sqli_in_uri_path(self):
        tasks = self.gen.sqli_in_uri_path_fuzz_test(self.parser)
        self.assertTrue(tasks)
        for t in tasks:
            self.assertEqual(t['method'], 'GET')
            self.assertIn(t['malicious_payload'], t['url'])

    def test_body_matching_tests_carry_a_regex(self):
        for name in (
            'os_command_injection_fuzz_params_test',
            'xss_html_injection_fuzz_params_test',
            'ssti_fuzz_params_test',
        ):
            tasks = getattr(self.gen, name)(self.parser)
            self.assertTrue(tasks, name)
            for t in tasks:
                self.assertEqual(t['response_filter'], 'BODY_REGEX_FILTER', name)
                self.assertTrue(t['response_match_regex'], name)

    def test_ssti_payload_and_expected_result_agree(self):
        tasks = self.gen.ssti_fuzz_params_test(self.parser)
        for t in tasks:
            if t['malicious_payload'] == '${7777+99999}':
                self.assertEqual(t['response_match_regex'], str(7777 + 99999))

    def test_bola_only_targets_paths_with_path_params(self):
        tasks = self.gen.bola_fuzz_path_test(self.parser, success_codes=[200])
        self.assertTrue(tasks)
        for t in tasks:
            self.assertEqual(t['method'], 'GET')
            self.assertIn('/users/', t['url'])
            self.assertEqual(t['success_codes'], [200])

    def test_missing_auth_needs_security_in_spec(self):
        self.assertEqual(self.gen.missing_auth_fuzz_test(self.parser), [])

    def test_every_task_has_what_the_runner_needs(self):
        tasks = (
            self.gen.sqli_fuzz_params_test(self.parser)
            + self.gen.xss_html_injection_fuzz_params_test(self.parser)
            + self.gen.bopla_fuzz_test(self.parser, success_codes=[200])
        )
        for t in tasks:
            for key in ('url', 'endpoint', 'method', 'test_name', 'vuln_details'):
                self.assertIn(key, t)
            self.assertTrue(t['url'].startswith('http://127.0.0.1:9999'))
