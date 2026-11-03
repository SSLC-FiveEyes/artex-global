"""Verify custom-tool templates with mocked process execution; makes no requests."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent


class ScanTemplateChecks(unittest.TestCase):
    def template(self, name):
        return json.loads((ROOT / (name + '.example.json')).read_text())

    def run_code(self, template, params, approved=False, returncode=0, timeout=False):
        code = template['exec']['code']
        if approved:
            code = code.replace('APPROVED_IPV4 = []', "APPROVED_IPV4 = ['192.0.2.20']")
            code = code.replace('APPROVED_PORTS = []', 'APPROVED_PORTS = [80, 443]')
            code = code.replace('APPROVED_URLS = []', "APPROVED_URLS = ['http://192.0.2.20/search.php?q=normal']")
            code = code.replace('APPROVED_PARAMETER = ""', 'APPROVED_PARAMETER = "q"')
        output = io.StringIO()
        exitcode = 0
        with patch('sys.stdin', io.StringIO(json.dumps(params))), contextlib.redirect_stdout(output), patch('shutil.which', side_effect=lambda name: '/offline/' + name), patch('subprocess.run') as runner:
            runner.return_value = subprocess.CompletedProcess([], returncode, 'offline fixture', '')
            if timeout:
                runner.side_effect = subprocess.TimeoutExpired('offline fixture', 1)
            try:
                exec(compile(code, '<scan-template>', 'exec'), {'__name__': '__main__'})
            except SystemExit as ex:
                exitcode = ex.code
            return json.loads(output.getvalue()), exitcode, runner.call_args_list

    def params(self, name):
        field = {'target': '192.0.2.20'} if 'nmap' in name else {'url': 'http://192.0.2.20/search.php?q=normal'}
        return dict(field, run_id='offline_check')

    def test_templates_disabled_and_scope_required(self):
        for name in ('fiveeyes_nmap_scan', 'fiveeyes_sqlmap_check'):
            with self.subTest(name=name):
                template = self.template(name)
                self.assertFalse(template['enabled'])
                self.assertEqual(template['agents'], [])
                result, code, calls = self.run_code(template, self.params(name))
                self.assertEqual((result['status'], code, len(calls)), ('not_run', 2, 0))

    def test_only_fixed_process_arguments(self):
        for name in ('fiveeyes_nmap_scan', 'fiveeyes_sqlmap_check'):
            with self.subTest(name=name):
                result, code, calls = self.run_code(self.template(name), self.params(name), approved=True)
                self.assertEqual((result['status'], result['exit_code'], code), ('executed', 0, 0))
                self.assertEqual(len(calls), 1)
                self.assertNotIn('shell', calls[0].kwargs)
                argv = calls[0].args[0]
                if 'nmap' in name:
                    self.assertEqual(argv[-1], '192.0.2.20')
                    self.assertIn('80,443', argv)
                    self.assertNotIn('-sV', argv)
                else:
                    self.assertIn('--ignore-redirects', argv)
                    self.assertIn('--technique=B', argv)
                    for flag in ('--dump', '--dbs', '--os-shell', '--crawl'):
                        self.assertNotIn(flag, argv)

    def test_native_failure_is_process_failure(self):
        for name in ('fiveeyes_nmap_scan', 'fiveeyes_sqlmap_check'):
            with self.subTest(name=name):
                result, code, calls = self.run_code(self.template(name), self.params(name), approved=True, returncode=7)
                self.assertEqual((result['exit_code'], code, len(calls)), (7, 1, 1))

    def test_timeout_is_incomplete(self):
        for name in ('fiveeyes_nmap_scan', 'fiveeyes_sqlmap_check'):
            with self.subTest(name=name):
                result, code, calls = self.run_code(self.template(name), self.params(name), approved=True, timeout=True)
                self.assertEqual((result['status'], code, len(calls)), ('incomplete', 2, 1))

    def test_nmap_rejects_different_target_and_injection(self):
        for target in ('192.0.2.21', '192.0.2.20; echo injected', '192.0.2.0/24', 'example.test', '-oN'):
            with self.subTest(target=target):
                params = dict(self.params('fiveeyes_nmap_scan'), target=target)
                result, code, calls = self.run_code(self.template('fiveeyes_nmap_scan'), params, approved=True)
                self.assertEqual((result['status'], code, len(calls)), ('not_run', 2, 0))

    def test_sqlmap_rejects_different_url_and_parameter_scope(self):
        for url in ('http://192.0.2.21/search.php?q=normal', 'http://192.0.2.20/search.php?other=normal', 'http://example.test/search.php?q=normal', 'http://192.0.2.20/search.php?q=normal#fragment'):
            with self.subTest(url=url):
                params = dict(self.params('fiveeyes_sqlmap_check'), url=url)
                result, code, calls = self.run_code(self.template('fiveeyes_sqlmap_check'), params, approved=True)
                self.assertEqual((result['status'], code, len(calls)), ('not_run', 2, 0))

    def test_invalid_run_id_never_starts_process(self):
        for name in ('fiveeyes_nmap_scan', 'fiveeyes_sqlmap_check'):
            with self.subTest(name=name):
                params = dict(self.params(name), run_id='bad value; injected')
                result, code, calls = self.run_code(self.template(name), params, approved=True)
                self.assertEqual((result['status'], code, len(calls)), ('not_run', 2, 0))


if __name__ == '__main__':
    unittest.main()
