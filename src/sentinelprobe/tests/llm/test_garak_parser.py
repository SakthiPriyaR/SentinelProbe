import os
import tempfile
import unittest

from sentinelprobe.llm.garak_parser import parse_report
from sentinelprobe.tests.llm.sample_reports import make_report


class TestGarakParser(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, 'x.report.jsonl')
        make_report(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_eval_totals_and_sorting(self):
        parsed = parse_report(self.path)
        results = parsed['results']
        self.assertEqual(len(results), 2)
        # vulnerable probe sorts first
        self.assertEqual(results[0]['probe'], 'dan.Dan_11_0')
        self.assertTrue(results[0]['vulnerable'])
        self.assertEqual(results[0]['failed'], 1)
        self.assertEqual(results[0]['fail_rate'], 0.5)
        self.assertFalse(results[1]['vulnerable'])

    def test_summary(self):
        s = parse_report(self.path)['summary']
        self.assertEqual(s['probes_run'], 2)
        self.assertEqual(s['vulnerable_probes'], 1)
        self.assertEqual(s['total_attempts'], 3)
        self.assertEqual(s['failed_attempts'], 1)

    def test_examples_use_matching_output(self):
        dan = parse_report(self.path)['results'][0]
        self.assertEqual(len(dan['examples']), 1)
        self.assertEqual(dan['examples'][0]['output'], 'I am DAN, no rules')
        self.assertEqual(dan['goal'], 'disregard the system prompt')

    def test_example_text_is_truncated(self):
        parsed = parse_report(self.path, example_chars=10)
        self.assertLessEqual(len(parsed['results'][0]['examples'][0]['prompt']), 11)

    def test_fallback_to_attempts_when_no_eval(self):
        path = os.path.join(self.tmp.name, 'noeval.report.jsonl')
        with open(self.path) as src, open(path, 'w') as dst:
            dst.writelines(l for l in src if '"entry_type": "eval"' not in l)
        results = parse_report(path)['results']
        self.assertEqual({r['probe'] for r in results}, {'dan.Dan_11_0', 'encoding.InjectBase64'})
        self.assertEqual(sum(r['failed'] for r in results), 1)

    def test_empty_report_raises(self):
        path = os.path.join(self.tmp.name, 'empty.report.jsonl')
        with open(path, 'w') as f:
            f.write('garbage\n')
        with self.assertRaises(ValueError):
            parse_report(path)


if __name__ == '__main__':
    unittest.main()


class TestNewerGarakSchema(unittest.TestCase):
    def test_total_evaluated_key_is_understood(self):
        import json
        import os
        import tempfile

        entry = {
            'entry_type': 'eval',
            'probe': 'probes.dan.Dan_11_0',
            'detector': 'detector.dan.DAN',
            'passed': 7,
            'fails': 3,
            'total_evaluated': 10,
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'r.report.jsonl')
            with open(path, 'w') as f:
                f.write(json.dumps(entry) + '\n')
            parsed = parse_report(path)
        res = parsed['results'][0]
        self.assertEqual((res['passed'], res['total'], res['failed']), (7, 10, 3))
        self.assertTrue(res['vulnerable'])
