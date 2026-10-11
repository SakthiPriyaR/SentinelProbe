import unittest

from ...report.generator import ReportGenerator
from ...utils import headers_list_to_dict, join_uri_path, result_to_curl, str_to_dict, update_values


class TestUtils(unittest.TestCase):
    def test_headers_list_to_dict(self):
        self.assertEqual(
            headers_list_to_dict([['A: b', 'C:d'], ['not-a-header']]), {'A': 'b', 'C': 'd'}
        )
        self.assertEqual(headers_list_to_dict(None), {})

    def test_str_to_dict_keeps_colons_in_values(self):
        self.assertEqual(str_to_dict('a:b,c:d:e,bad'), {'a': 'b', 'c': 'd:e'})

    def test_join_uri_path(self):
        self.assertEqual(
            join_uri_path('https://example.com:443', '/v2/', '/pet/findByStatus/'),
            'https://example.com:443/v2/pet/findByStatus/',
        )
        self.assertEqual(join_uri_path('http://h:1', '', '/users/5'), 'http://h:1/users/5')

    def test_update_values(self):
        self.assertEqual(
            update_values([{'name': 'a', 'value': 1}], [{'name': 'a', 'value': 2}]),
            [{'name': 'a', 'value': 2}],
        )

    def test_result_to_curl_quotes_body_and_url(self):
        curl = result_to_curl(
            {'url': 'https://x.test/a', 'method': 'POST',
             'request_headers': {'Accept': '*/*'},
             'body_params': [{'name': 'a', 'value': "it's"}],
             'query_params': [{'name': 'q', 'value': 'a b'}]}
        )
        self.assertIn("curl -X POST 'https://x.test/a?q=a+b'", curl)
        self.assertIn('-H "Accept: */*"', curl)
        self.assertIn('-d', curl)


class TestHtmlReportEscaping(unittest.TestCase):
    def test_script_breakout_and_markup_are_neutralised(self):
        evil = '</script><img src=x onerror=alert(1)>'
        html = ReportGenerator.generate_html_report(
            [{'response_body': evil, 'url': evil, 'endpoint': evil, 'test_name': evil}]
        )
        self.assertNotIn(evil, html)
        self.assertNotIn('</script><img', html)
