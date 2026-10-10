import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from sentinelprobe.llm import garak_runner as gr
from sentinelprobe.tests.llm.sample_reports import make_report


def cfg(**kw):
    base = dict(model_type='openai', probes='dan,encoding.InjectBase64')
    base.update(kw)
    return gr.GarakConfig(**base)


class TestValidation(unittest.TestCase):
    def test_valid_config(self):
        c = gr.validate_config(cfg(model_name='meta/llama-3:8b'))
        self.assertEqual(c.probes, 'dan,encoding.InjectBase64')

    def test_rejects_injection_attempts(self):
        for bad in ('--evil', '-x', 'a;b', '$(id)', 'a b', '', 'a\nb', 'openai\n'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gr.validate_config(cfg(model_type=bad))
            if bad:
                with self.assertRaises(ValueError, msg=repr(bad)):
                    gr.validate_config(cfg(model_name=bad))
        for bad in ('--evil', '-x', 'a;b', '$(id)', 'a b', 'a\nb'):
            with self.assertRaises(ValueError, msg=repr(bad)):
                gr.normalize_probes(f'dan,{bad}')

    def test_requires_probe(self):
        with self.assertRaises(ValueError):
            gr.normalize_probes(' , ')

    def test_numeric_and_file_checks(self):
        with self.assertRaises(ValueError):
            gr.validate_config(cfg(generations=0))
        with self.assertRaises(ValueError):
            gr.validate_config(cfg(generator_options_file='/no/such/file.json'))


class TestBuildCommand(unittest.TestCase):
    def test_command_is_argument_list(self):
        cmd = gr.build_command(
            cfg(model_name='gpt-4o-mini', generations=2, parallel_attempts=4, seed=7),
            '/tmp/p',
        )
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[1:3], ['-m', 'garak'])
        for flag, value in [
            ('--model_type', 'openai'),
            ('--model_name', 'gpt-4o-mini'),
            ('--probes', 'dan,encoding.InjectBase64'),
            ('--generations', '2'),
            ('--parallel_attempts', '4'),
            ('--seed', '7'),
            ('--report_prefix', '/tmp/p'),
        ]:
            self.assertEqual(cmd[cmd.index(flag) + 1], value)

    def test_optional_flags_omitted(self):
        cmd = gr.build_command(cfg(), '/tmp/p')
        self.assertNotIn('--model_name', cmd)
        self.assertNotIn('--generations', cmd)


class TestRunGarak(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.report = os.path.join(self.tmp.name, 'run.report.jsonl')
        make_report(self.report)

    def tearDown(self):
        self.tmp.cleanup()

    def test_not_installed(self):
        with patch.object(gr, 'is_garak_installed', return_value=False):
            with self.assertRaises(gr.GarakNotInstalledError):
                gr.run_garak(cfg(report_dir=self.tmp.name))

    def test_success_uses_path_from_stdout(self):
        fake = SimpleNamespace(returncode=0, stdout=f'report closed :) {self.report}\n')
        with patch.object(gr, 'is_garak_installed', return_value=True), patch.object(
            gr.subprocess, 'run', return_value=fake
        ) as run:
            path, _ = gr.run_garak(cfg(report_dir=self.tmp.name))
        self.assertEqual(str(path), self.report)
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_nonzero_exit(self):
        fake = SimpleNamespace(returncode=2, stdout='boom')
        with patch.object(gr, 'is_garak_installed', return_value=True), patch.object(
            gr.subprocess, 'run', return_value=fake
        ):
            with self.assertRaises(gr.GarakRunError):
                gr.run_garak(cfg(report_dir=self.tmp.name))

    def test_timeout(self):
        with patch.object(gr, 'is_garak_installed', return_value=True), patch.object(
            gr.subprocess, 'run', side_effect=subprocess.TimeoutExpired('garak', 1)
        ):
            with self.assertRaises(gr.GarakRunError):
                gr.run_garak(cfg(report_dir=self.tmp.name, timeout=1))

    def test_find_report_by_prefix_when_stdout_has_no_path(self):
        prefix = os.path.join(self.tmp.name, 'sentinelprobe_x')
        target = prefix + '_abc.report.jsonl'
        os.rename(self.report, target)
        self.assertEqual(str(gr.find_report_file('no path here', prefix)), target)

    def test_report_not_found(self):
        with self.assertRaises(gr.GarakReportNotFoundError):
            gr.find_report_file('', os.path.join(self.tmp.name, 'missing_prefix'))


if __name__ == '__main__':
    unittest.main()
