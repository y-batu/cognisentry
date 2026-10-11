from pathlib import Path
import re, subprocess, json
root=Path(__file__).resolve().parents[1]
patterns={
 'provider_token':r'\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|\bgh[pousr]_[A-Za-z0-9]{36,}|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}',
 'private_key':r'-----BEGIN [A-Z ]*PRIVATE KEY-----',
 'jwt':r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}',
}
build=list((root/'dist').rglob('*'))
build=[p for p in build if p.is_file()]
diff=subprocess.check_output(['git','diff','--no-ext-diff','--unified=0'],cwd=root,text=True)
added='\n'.join(l[1:] for l in diff.splitlines() if l.startswith('+') and not l.startswith('+++'))
new=subprocess.check_output(['git','ls-files','--others','--exclude-standard'],cwd=root,text=True).splitlines()
added+='\n'+'\n'.join((root/p).read_text() for p in new)
findings=[]
for label,content in [('added diff / new files',added)]+[(str(p.relative_to(root)),p.read_text()) for p in build]:
 for category,pattern in patterns.items():
  if re.search(pattern,content): findings.append({'file':label,'category':category})
# No active analysis endpoint or SDK credentials in the browser bundle.
for p in build:
 if p.suffix=='.js':
  content=p.read_text()
  for marker in ['/api/analyze','ANTHROPIC_API_KEY','x-api-key']:
   if marker in content: findings.append({'file':str(p.relative_to(root)),'category':'gateway marker'})
unchanged=['poc/cognisentry_local_scanner.py','poc/sample_scan_report.json','poc/test_scanner_hardening.py','src/scanner/scanner.ts','src/scanner/csv.ts','src/scanner/quality.ts','src/app/app.css','index.html']
assert not subprocess.check_output(['git','diff','--',*unchanged],cwd=root,text=True)
result={'known_secret_format_findings':findings,'build_files_inspected':len(build),'unchanged_scanner_style_and_page_shell':unchanged,'limitations':'Pattern scan is not proof of absence of arbitrary secrets. Existing bundled demo CSV is synthetic.'}
print(json.dumps(result,indent=2))
assert not findings
