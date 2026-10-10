import json
import os
import tempfile
import unittest
from unittest.mock import patch

from sentinelprobe.llm import handler
from sentinelprobe.llm.garak_parser import parse_report
from sentinelprobe.llm.report import (
    derive_output_path,
    format_report,
    resolve_format,
    to_html,
)
from sentinelprobe.tests.llm.sample_reports import make_report


def sample_result(tmpdir):
    path = os.path.join(tmpdir, 'x.report.jsonl')
    make_report(path)
    parsed = parse_report(path)
    return {
        'mode': 'llm',
        'target': {'model_type': 'openai', 'model_name': 'gpt-4o-mini'},
        'summary': parsed['summary'],
        'results': parsed['results'],
        'garak_report': path,
    }


class TestReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.result = sample_result(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_html_escapes_untrusted_text(self):
        html = to_html(self.result)
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', html)
        self.assertIn('VULNERABLE', html)

    def test_json_roundtrip(self):
        self.assertEqual(
            json.loads(format_report(self.result, 'json'))['summary']['vulnerable_probes'],
            1,
        )

    def test_yaml(self):
        self.assertIn('vulnerable_probes: 1', format_report(self.result, 'yaml'))

    def test_table_if_rich_available(self):
        try:
            import rich  # noqa: F401
        except ImportError:
            self.skipTest('rich not installed')
        self.assertEqual(len(format_report(self.result, 'table').rows), 2)

    def test_resolve_format(self):
        self.assertEqual(resolve_format('out.html', 'json'), 'html')
        self.assertEqual(resolve_format('out.txt', 'table'), 'json')
        self.assertEqual(resolve_format(None, None), 'table')

    def test_derive_output_path(self):
        self.assertEqual(derive_output_path('r/out.json', 'all'), 'r/out.llm.json')
        self.assertEqual(derive_output_path('r/out.json', 'llm'), 'r/out.json')
        self.assertIsNone(derive_output_path(None, 'all'))


class TestHandler(unittest.TestCase):
    def test_end_to_end_with_mocked_garak(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, 'x.report.jsonl')
            make_report(report)
            out = os.path.join(tmp, 'out', 'scan.json')
            with patch.object(handler, 'run_garak', return_value=(report, '')):
                result = handler.run_llm_scan(
                    model_type='openai',
                    model_name='gpt-4o-mini',
                    probes='dan',
                    output_file=out,
                )
            self.assertEqual(result['summary']['vulnerable_probes'], 1)
            with open(out) as f:
                self.assertEqual(json.load(f)['target']['model_name'], 'gpt-4o-mini')


if __name__ == '__main__':
    unittest.main()
