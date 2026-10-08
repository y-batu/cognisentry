"""Regression guard for the synthetic evaluation. Standard library only.

    python3 -m unittest -v test_eval     (run from poc/)
"""
import sys
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


if __name__ == '__main__':
    unittest.main()
