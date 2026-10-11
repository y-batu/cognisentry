"""Run with: python3 -m unittest discover -s scripts -p 'test_*.py'."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('artifact_audit', Path(__file__).with_name('audit-artifacts.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
# Synthetic fixture assembled at runtime; no key-shaped literal in source control.
SECRET = ('sk-' + 'ant-' + 'Z' * 32).encode()


class ArtifactAuditTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git('init', '-q')
        self.write('.gitignore', b'dist/\n')
        self.write('tracked.txt', b'clean\n')
        self.git('add', '.')
        self.git('-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'Initial fixture')
        self.write('dist/index.html', b'<html></html>')
        self.write('dist/assets/app.js', b'export const clean = true')

    def git(self, *args):
        subprocess.run(['git', *args], cwd=self.root, check=True, capture_output=True)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def audit(self):
        result = module.audit(self.root)
        self.assertNotIn(SECRET.decode(), json.dumps(result), 'Audit output must not echo secrets')
        return result

    def test_clean_build_and_tree(self):
        result = self.audit()
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['known_secret_format_findings'], [])
        self.assertEqual(result['files_inspected']['build'], 2)

    def test_staged_secret_cannot_hide_behind_clean_working_copy(self):
        self.write('tracked.txt', SECRET)
        self.git('add', 'tracked.txt')
        self.write('tracked.txt', b'clean\n')
        findings = self.audit()['known_secret_format_findings']
        self.assertEqual([finding['source'] for finding in findings], ['staged'])

    def test_unstaged_secret(self):
        self.write('tracked.txt', SECRET)
        self.assertEqual(self.audit()['known_secret_format_findings'][0]['source'], 'unstaged')

    def test_binary_untracked_file_with_newline_name(self):
        self.write('new\nfile.bin', b'\x00\xff' + SECRET)
        result = self.audit()
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['known_secret_format_findings'][0]['source'], 'untracked')

    def test_staged_binary_file(self):
        self.write('binary.bin', b'\x00\xff' + SECRET)
        self.git('add', 'binary.bin')
        self.assertEqual(self.audit()['known_secret_format_findings'][0]['source'], 'staged')

    def test_empty_or_partial_build_is_an_error(self):
        (self.root / 'dist/assets/app.js').unlink()
        self.assertEqual(self.audit()['errors'][0]['error'], 'missing_build')
        (self.root / 'dist/index.html').unlink()
        self.assertEqual(self.audit()['errors'][0]['error'], 'missing_build')

    def test_secret_or_active_gateway_in_build(self):
        self.write('dist/assets/app.js', SECRET + b'; fetch("/api/analyze")')
        categories = {item['category'] for item in self.audit()['known_secret_format_findings']}
        self.assertEqual(categories, {'provider_token', 'gateway marker'})

    def test_cli_still_fails_with_python_optimization_enabled(self):
        self.write('scripts/audit-artifacts.py', Path(module.__file__).read_bytes())
        self.write('tracked.txt', SECRET)
        self.git('add', 'tracked.txt')
        self.write('tracked.txt', b'clean\n')
        result = subprocess.run(
            [sys.executable, '-O', 'scripts/audit-artifacts.py'],
            cwd=self.root, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)['known_secret_format_findings'][0]['source'], 'staged')

    def test_untracked_symlink_is_reported_without_following_it(self):
        (self.root / 'link').symlink_to('tracked.txt')
        self.assertEqual(self.audit()['errors'][0]['error'], 'symlink_not_inspected')


if __name__ == '__main__':
    unittest.main()
