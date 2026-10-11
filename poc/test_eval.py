"""Regression guard for the synthetic evaluation. Standard library only.

    python3 -m unittest -v test_eval     (run from poc/)
"""
import contextlib
import io
import sys
import tempfile
from unittest.mock import patch
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'eval'))
import run_eval as ev  # noqa: E402


class TestEvaluation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.inst = ev.evaluate()
        cls.summary = ev.summarize(cls.rows, cls.inst)

    def test_deterministic(self):
        rows2, inst2 = ev.evaluate()
        self.assertEqual(rows2, self.rows)
        self.assertEqual(inst2, self.inst)

    def test_known_misses_and_false_positive_are_stable(self):
        missed = sorted(r['case'] for r in self.rows if r['expected'] != ev.STD and not r['flagged'])
        false_pos = sorted(r['case'] for r in self.rows if r['expected'] == ev.STD and r['flagged'])
        self.assertEqual(missed, ['phone_bare_digits', 'secret_opaque_random'])
        self.assertEqual(false_pos, ['neg_version_ipv4_shaped'])

    def test_format_based_detectors_do_not_regress(self):
        must_catch = {'email', 'phone_e164_spaced', 'phone_us_parens', 'ipv4', 'secret_stripe_like', 'secret_github',
                      'secret_aws', 'secret_slack', 'secret_jwt', 'secret_pem_header', 'freetext_embedded_email',
                      'freetext_embedded_phone', 'freetext_embedded_secret'}
        got = {r['case'] for r in self.rows if r['exact']}
        self.assertLessEqual(must_catch, got)

    def test_no_benign_instruction_false_alarms(self):
        self.assertEqual(self.summary['instruction_false_alarms'], 0)

    def test_committed_docs_are_in_sync(self):
        committed = (HERE.parent / 'docs' / 'EVALUATION.md').read_text(encoding='utf-8')
        self.assertEqual(committed, ev.render_markdown(self.rows, self.inst, self.summary) + '\n')

    def test_golden_fixtures_are_in_sync(self):
        import build_golden as bg
        for name, text in bg.build().items():
            self.assertEqual((bg.OUT / name).read_bytes(), text.encode('utf-8'), name)

    def test_eval_source_has_no_key_shaped_literals(self):
        import re
        src = (HERE / 'eval' / 'run_eval.py').read_text(encoding='utf-8')
        self.assertIsNone(re.search(r'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk_live_[A-Za-z0-9]{10,}|xoxb-\d{6,}', src))


class TestGoldenVerification(unittest.TestCase):
    def invoke(self, output, check=True):
        import build_golden as bg
        stream = io.StringIO()
        args = ['build_golden.py'] + (['--check'] if check else [])
        with patch.object(bg, 'OUT', output), patch.object(sys, 'argv', args), contextlib.redirect_stdout(stream):
            try:
                bg.main()
            except SystemExit as exc:
                return exc.code, stream.getvalue()
        return 0, stream.getvalue()

    def snapshot(self, output):
        return {p.name: (p.read_bytes(), p.stat().st_mtime_ns) for p in output.iterdir()}

    def seed(self, output):
        import build_golden as bg
        for name, text in bg.build().items():
            (output / name).write_bytes(text.encode('utf-8'))

    def test_build_does_not_create_output_directory(self):
        import build_golden as bg
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'absent'
            with patch.object(bg, 'OUT', output):
                self.assertTrue(bg.build())
            self.assertFalse(output.exists())

    def test_check_detects_stale_csv_and_report_without_repair(self):
        for name in ['numbers.csv', 'numbers.golden.json']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)
                self.seed(output)
                (output / name).write_bytes(b'edited fixture')
                before = self.snapshot(output)
                code, message = self.invoke(output)
                self.assertEqual(code, 1)
                self.assertIn(name, message)
                self.assertEqual(self.snapshot(output), before)

    def test_check_missing_directory_does_not_create_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'absent'
            code, message = self.invoke(output)
            self.assertEqual(code, 1)
            self.assertIn('numbers.csv', message)
            self.assertFalse(output.exists())

    def test_check_missing_csv_does_not_recreate_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            self.seed(output)
            (output / 'numbers.csv').unlink()
            before = self.snapshot(output)
            code, message = self.invoke(output)
            self.assertEqual(code, 1)
            self.assertIn('numbers.csv', message)
            self.assertEqual(self.snapshot(output), before)

    def test_explicit_generation_then_check_preserves_bytes_and_mtimes(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'generated'
            self.assertEqual(self.invoke(output, check=False)[0], 0)
            before = self.snapshot(output)
            self.assertIn('numbers.csv', before)
            self.assertIn('numbers.golden.json', before)
            self.assertEqual(self.invoke(output)[0], 0)
            self.assertEqual(self.snapshot(output), before)

    def test_failed_scan_never_writes_output_and_cleans_temporary_csv(self):
        import build_golden as bg
        scanned = []
        def fail(path):
            scanned.append(path)
            raise RuntimeError('synthetic scanner failure')
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            (output / 'quotes_and_shapes.csv').write_bytes(b'keep this fixture')
            before = self.snapshot(output)
            with patch.object(bg, 'OUT', output), patch.object(bg.sc, 'scan_csv', side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, 'synthetic scanner failure'):
                    bg.build()
            self.assertEqual(self.snapshot(output), before)
            self.assertTrue(scanned)
            self.assertFalse(scanned[0].exists())


if __name__ == '__main__':
    unittest.main()
