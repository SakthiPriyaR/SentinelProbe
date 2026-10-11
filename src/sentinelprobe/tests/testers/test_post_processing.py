import unittest

from ...config_data_handler import populate_user_data, validate_config_file_data
from ...tester.post_test_processor import PostRunTests


class TestStatusFilter(unittest.TestCase):
    def test_vulnerable_when_status_in_success_codes(self):
        res = PostRunTests.filter_status_code_based_results(
            [
                {'response_status_code': 500, 'success_codes': [500]},
                {'response_status_code': 200, 'success_codes': [500]},
                {'response_status_code': 200},  # no success codes: dropped
            ]
        )
        self.assertEqual([r['vulnerable'] for r in res], [True, False])


class TestMatcher(unittest.TestCase):
    def test_body_regex(self):
        res = PostRunTests.matcher(
            [
                {'response_filter': 'BODY_REGEX_FILTER', 'response_match_regex': 'root:.*',
                 'response_body': 'root:x:0:0'},
                {'response_filter': 'BODY_REGEX_FILTER', 'response_match_regex': 'root:.*',
                 'response_body': 'nothing'},
                {'response_filter': 'BODY_REGEX_FILTER', 'response_body': 'x'},  # no regex
            ]
        )
        self.assertEqual([r['vulnerable'] for r in res], [True, False])

    def test_status_code_filter(self):
        res = PostRunTests.matcher(
            [{'response_filter': 'STATUS_CODE_FILTER', 'response_match_regex': '^5',
              'response_status_code': 503}]
        )
        self.assertTrue(res[0]['vulnerable'])


class TestDetailsAndExposure(unittest.TestCase):
    def test_update_result_details_picks_text_by_verdict(self):
        res = PostRunTests.update_result_details(
            [{'vulnerable': True, 'vuln_details': {True: 'bad', False: 'ok'}},
             {'vulnerable': False, 'vuln_details': {True: 'bad', False: 'ok'}}]
        )
        self.assertEqual([r['vuln_details'] for r in res], ['bad', 'ok'])

    def test_detects_common_secrets_and_pii(self):
        body = 'mail a@b.com ssn 123-45-6789 key AKIAABCDEFGHIJKLMNOP'
        leak = PostRunTests.detect_data_exposure([{'response_body': body}])[0]['data_leak']
        for kind in ('email', 'ssn', 'AWSAccessKey'):
            self.assertIn(kind, leak)

    def test_clean_body_has_no_leak(self):
        leak = PostRunTests.detect_data_exposure([{'response_body': 'hello world'}])[0]['data_leak']
        self.assertEqual(leak, {})


class TestBrokenAccessControl(unittest.TestCase):
    config = {
        'actors': [
            {'actor1': {'unauthorized_endpoints': []}},
            {'actor2': {'unauthorized_endpoints': ['^/admin']}},
        ]
    }

    def result(self, actor, endpoint, status):
        return {'test_actor_name': actor, 'endpoint': endpoint,
                'response_status_code': status, 'success_codes': [200]}

    def test_flags_restricted_endpoint_reachable_by_actor(self):
        res = PostRunTests.run_broken_access_control_tests(
            [self.result('actor2', '/admin/users', 200),
             self.result('actor2', '/public', 200),
             self.result('actor1', '/admin/users', 200)],
            self.config,
        )
        self.assertEqual(len(res), 1)
        self.assertTrue(res[0]['vulnerable'])
        self.assertEqual(res[0]['test_name'], 'Broken Access Control')

    def test_blocked_request_is_not_vulnerable(self):
        res = PostRunTests.run_broken_access_control_tests(
            [self.result('actor2', '/admin/users', 403)], self.config
        )
        self.assertFalse(res[0]['vulnerable'])


class TestUserConfig(unittest.TestCase):
    def test_validate(self):
        self.assertFalse(validate_config_file_data('nope'))
        self.assertFalse(validate_config_file_data({'error': 'File Not Found'}))
        self.assertFalse(validate_config_file_data({'actors': []}))
        ok = {'actors': [{'actor1': {'request_headers': []}}]}
        self.assertEqual(validate_config_file_data(ok), ok)

    def test_populate_user_data_overrides_without_mutating_input(self):
        tests = [{'body_params': [{'name': 'a', 'value': 1}], 'query_params': [],
                  'path_params': [{'name': 'id', 'value': 5}], 'kwargs': {}}]
        actor = {'request_headers': [{'name': 'Authorization', 'value': 'Bearer x'}],
                 'body': [{'name': 'a', 'value': 9}], 'path': [{'name': 'id', 'value': 42}]}
        out = populate_user_data(actor, 'actor1', tests)[0]
        self.assertEqual(out['body_params'][0]['value'], 9)
        self.assertEqual(out['path_params'][0]['value'], 42)
        self.assertEqual(out['kwargs']['headers']['Authorization'], 'Bearer x')
        self.assertEqual(out['test_actor_name'], 'actor1')
        self.assertEqual(tests[0]['body_params'][0]['value'], 1)  # input untouched
