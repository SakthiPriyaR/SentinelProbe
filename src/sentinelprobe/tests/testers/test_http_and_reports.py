import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from ...http import AsyncRequests
from ...report.generator import ReportGenerator
from ...tester import handler as tester_handler
import inspect


class TestRetries(unittest.TestCase):
    def run_request(self, method):
        client = AsyncRequests()
        mock = AsyncMock(side_effect=OSError('connection reset'))
        with patch.object(client, '_request_once', mock), patch(
            'asyncio.sleep', new=AsyncMock()
        ):
            with self.assertRaises(OSError):
                asyncio.run(client.request('http://x.test/', method=method))
        return mock.await_count

    def test_safe_methods_are_retried(self):
        self.assertEqual(self.run_request('GET'), 3)

    def test_state_changing_methods_are_sent_once(self):
        for method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            self.assertEqual(self.run_request(method), 1, method)


class TestReportOutput(unittest.TestCase):
    results = [{'error': False, 'test_name': 't', 'vulnerable': True}]

    def test_file_is_written_by_extension_even_when_format_is_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'out.JSON')
            ReportGenerator.generate_report(self.results, 'table', path)
            with open(path) as f:
                self.assertEqual(json.load(f)['results'][0]['test_name'], 't')

    def test_unknown_extension_falls_back_to_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'report')
            ReportGenerator.generate_report(self.results, 'table', path)
            with open(path) as f:
                json.load(f)

    def test_yaml_is_safe_dump(self):
        out = ReportGenerator.handle_report_format([{'a': object()}], 'yaml')
        self.assertNotIn('!!python', out)


class TestHandlerSignature(unittest.TestCase):
    def test_http_methods_is_optional(self):
        sig = inspect.signature(tester_handler.generate_and_run_tests)
        self.assertIsNone(sig.parameters['http_methods'].default)

    def test_unreachable_host_raises(self):
        with patch.object(tester_handler, 'is_host_up', return_value=False):
            with self.assertRaises(tester_handler.HostUnavailableError):
                tester_handler.generate_and_run_tests(
                    api_parser=type('P', (), {'host': 'x'})()
                )
