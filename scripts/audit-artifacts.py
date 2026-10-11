"""Inspect build artifacts and pending Git contents without printing matched secrets."""
from pathlib import Path
import json
import re
import subprocess
import sys

PATTERNS = {
    'provider_token': rb'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{36,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}',
    'private_key': rb'-----BEGIN [A-Z ]*PRIVATE KEY-----',
    'jwt': rb'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',
}


def git(root, *args):
    return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL)


def paths(output):
    return [name.decode('utf-8', errors='surrogateescape') for name in output.split(b'\0') if name]


def audit(root):
    findings, errors = [], []
    inspected = {'staged': 0, 'unstaged': 0, 'untracked': 0, 'build': 0}

    def inspect(name, content, source):
        inspected[source] += 1
        for category, pattern in PATTERNS.items():
            if re.search(pattern, content):
                findings.append({'file': name, 'source': source, 'category': category})
        if source == 'build' and name.endswith('.js'):
            if any(marker in content for marker in [b'/api/analyze', b'ANTHROPIC_API_KEY', b'x-api-key']):
                findings.append({'file': name, 'source': source, 'category': 'gateway marker'})

    def inspect_file(name, source):
        path = root / name
        if path.is_symlink():
            errors.append({'file': name, 'source': source, 'error': 'symlink_not_inspected'})
            return
        try:
            inspect(name, path.read_bytes(), source)
        except OSError:
            errors.append({'file': name, 'source': source, 'error': 'file_not_readable'})

    build = sorted(path for path in (root / 'dist').rglob('*') if path.is_file() or path.is_symlink())
    if not (root / 'dist/index.html').is_file() or not any(path.suffix == '.js' for path in build):
        errors.append({'source': 'build', 'error': 'missing_build', 'message': 'Run npm run build before auditing.'})
    for path in build:
        inspect_file(str(path.relative_to(root)), 'build')

    # Inspect index blobs separately: a clean working copy can hide a staged secret.
    try:
        for name in paths(git(root, 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z')):
            inspect(name, git(root, 'show', ':' + name), 'staged')
        for name in paths(git(root, 'diff', '--name-only', '--diff-filter=ACMR', '-z')):
            inspect_file(name, 'unstaged')
        for name in paths(git(root, 'ls-files', '--others', '--exclude-standard', '-z')):
            inspect_file(name, 'untracked')
    except subprocess.CalledProcessError:
        errors.append({'source': 'git', 'error': 'git_inspection_failed'})

    return {
        'known_secret_format_findings': findings,
        'errors': errors,
        'files_inspected': inspected,
        'limitations': 'Pattern scanning is not proof of absence of arbitrary secrets. Existing demo data is synthetic. This audit does not check Git history or build freshness.',
    }


if __name__ == '__main__':
    result = audit(Path(__file__).resolve().parents[1])
    print(json.dumps(result, indent=2))
    sys.exit(1 if result['known_secret_format_findings'] or result['errors'] else 0)
