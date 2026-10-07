#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, ipaddress, json, math, re
from collections import Counter
from pathlib import Path
from statistics import mean

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
URL_RE = re.compile(r'^https?://', re.I)

# --- Column-name hints -------------------------------------------------------
# Matched against whole name tokens (camelCase and separators are split first),
# never as substrings. Hint keys are underscore-joined token sequences.
SENSITIVE_NAME_HINTS = {
    # PII
    'email': 'PII', 'e_mail': 'PII',
    'phone': 'PII', 'phone_number': 'PII', 'mobile_phone': 'PII', 'mobile_number': 'PII',
    'contact_phone': 'PII', 'telephone': 'PII',
    'first_name': 'PII', 'last_name': 'PII', 'full_name': 'PII',
    'date_of_birth': 'PII', 'birth_date': 'PII', 'birthdate': 'PII', 'dob': 'PII',
    'street_address': 'PII', 'home_address': 'PII', 'billing_address': 'PII',
    'shipping_address': 'PII', 'mailing_address': 'PII',
    # Potentially sensitive
    'ip': 'Potentially Sensitive', 'ip_address': 'Potentially Sensitive',
    # Sensitive identifiers
    'customer_id': 'Sensitive', 'user_id': 'Sensitive', 'national_id': 'Sensitive', 'ssn': 'Sensitive',
    'credit_card': 'Sensitive', 'card_number': 'Sensitive', 'cvv': 'Sensitive', 'cvc': 'Sensitive',
    'iban': 'Sensitive', 'passport': 'Sensitive', 'passport_number': 'Sensitive', 'tax_id': 'Sensitive',
    # Secrets
    'password': 'Secret / High Risk', 'passwd': 'Secret / High Risk', 'pwd': 'Secret / High Risk',
    'passphrase': 'Secret / High Risk', 'api_key': 'Secret / High Risk', 'apikey': 'Secret / High Risk',
    'token': 'Secret / High Risk', 'secret': 'Secret / High Risk',
    'private_key': 'Secret / High Risk', 'access_key': 'Secret / High Risk',
}
RISK_ORDER = {'Standard': 0, 'Potentially Sensitive': 1, 'PII': 2, 'Sensitive': 2, 'Secret / High Risk': 3}
# A name that starts/ends with one of these is usually a flag or metric (is_mobile, token_count), not data.
SAFE_FIRST_TOKENS = {'is', 'has', 'num'}
SAFE_LAST_TOKENS = {'count', 'flag', 'enabled', 'status', 'type', 'rate', 'ratio', 'total', 'in'}

# --- Phone values ------------------------------------------------------------
# Deliberately conservative: no dots (so IPv4 and decimals never match), no bare digit runs
# (epoch/IDs), no dates. Bare unformatted numbers rely on the column-name hint instead.
PHONE_CANDIDATE_RE = re.compile(r'^(?:\+\d|\(\d|\d)[\d\s()-]*\d$')
DATE_LIKE_RE = re.compile(r'^(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})$')

# --- Known secret formats (no generic "long string" rule) --------------------
SECRET_PATTERNS = [
    re.compile(r'\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}'),                       # Stripe-like
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}'),                                     # GitHub
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),                                             # AWS access key ID
    re.compile(r'\bxox[abprs]-[A-Za-z0-9-]{10,}'),                                   # Slack
    re.compile(r'\bAIza[0-9A-Za-z_-]{35}'),                                          # Google API key
    re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}'),                                 # sk- / sk-ant- style
    re.compile(r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}'),     # JWT
    re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'),                               # PEM private key header
]

# --- Free-text inspection ----------------------------------------------------
FREE_TEXT_MAX_CELLS = 1000
EMBEDDED_EMAIL_RE = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
EMBEDDED_PHONE_RES = [
    re.compile(r'(?<!\w)\+\d[\d\s()-]{7,}\d'),
    re.compile(r'\(\d{3}\)\s?\d{3}[-\s]?\d{4}'),
]
# Warning signal only. This is NOT a security boundary and will miss most real attacks.
INSTRUCTION_PATTERNS = [re.compile(p, re.I) for p in (
    r'\b(?:ignore|disregard)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)',
    r'\b(?:reveal|print|show|repeat)\s+(?:the\s+|your\s+)?(?:system|developer)\s+(?:prompt|message)',
    r'\bnew\s+instructions\s*:',
    r'<\s*/?\s*(?:system|instructions?)\s*>',
)]


def name_tokens(name):
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', name.strip())
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s)
    return [t for t in re.split(r'[^a-z0-9]+', s.lower()) if t]

def name_matches(tokens, hint):
    if not tokens or tokens[0] in SAFE_FIRST_TOKENS or tokens[-1] in SAFE_LAST_TOKENS:
        return False
    h = hint.split('_')
    n = len(h)
    return any(tokens[i:i + n] == h for i in range(len(tokens) - n + 1))

def is_ipv4(value):
    try:
        return isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False

def looks_like_phone(value):
    v = value.strip()
    if not PHONE_CANDIDATE_RE.match(v) or DATE_LIKE_RE.match(v):
        return False
    if not 8 <= sum(c.isdigit() for c in v) <= 15:
        return False
    return v.startswith(('+', '(')) or bool(re.search(r'[\s-]', v))

def contains_secret_format(value):
    return any(rx.search(value) for rx in SECRET_PATTERNS)

def maybe_number(value):
    value = value.strip()
    if not value: return None
    try: n = float(value.replace(',', ''))
    except ValueError: return None
    return n if math.isfinite(n) else None

def infer_type(values):
    present = [v.strip() for v in values if v.strip()]
    if not present: return 'empty'
    if all(maybe_number(v) is not None for v in present): return 'number'
    if all(v.lower() in {'true','false','yes','no','0','1'} for v in present): return 'boolean'
    return 'text'

def _raise(classification, level):
    return max(classification, level, key=lambda x: RISK_ORDER[x])

def _add(reasons, msg):
    if msg not in reasons: reasons.append(msg)

def classify_column(name, values):
    tokens = name_tokens(name)
    classification, reasons = 'Standard', []
    for hint, risk in SENSITIVE_NAME_HINTS.items():
        if name_matches(tokens, hint):
            classification = _raise(classification, risk)
            _add(reasons, f'column name suggests {risk.lower()}')
    present = [v.strip() for v in values if v.strip()]
    if not present: return classification, reasons
    sample = present[:200]
    counts = Counter()
    for value in sample:
        if EMAIL_RE.match(value): counts['email'] += 1
        if looks_like_phone(value): counts['phone'] += 1
        if is_ipv4(value): counts['ipv4'] += 1
        if URL_RE.match(value): counts['url'] += 1
        if contains_secret_format(value): counts['secret_format'] += 1
    threshold = max(1, math.ceil(len(sample) * 0.2))
    if counts['email'] >= threshold:
        classification = _raise(classification, 'PII'); _add(reasons, 'values resemble email addresses')
    if counts['phone'] >= threshold:
        classification = _raise(classification, 'PII'); _add(reasons, 'values resemble phone numbers')
    if counts['ipv4'] >= threshold:
        classification = _raise(classification, 'Potentially Sensitive'); _add(reasons, 'values resemble IPv4 addresses')
    if counts['secret_format'] >= 1:  # one hit is enough: known formats are specific
        classification = _raise(classification, 'Secret / High Risk'); _add(reasons, 'values contain known secret/token formats')
    if counts['url'] >= threshold and classification == 'Standard': _add(reasons, 'values resemble URLs')
    return classification, reasons

def scan_free_text(values):
    """Return None for non-prose columns, else counts only (never matched text)."""
    present = [v.strip() for v in values if v.strip()]
    if not present: return None
    sample = present[:200]
    if sum(1 for v in sample if re.search(r'\s', v)) < max(1, math.ceil(len(sample) * 0.2)):
        return None
    cells = present[:FREE_TEXT_MAX_CELLS]
    findings = {'email': 0, 'phone': 0, 'secret': 0, 'instruction_like': 0}
    for cell in cells:
        if EMBEDDED_EMAIL_RE.search(cell): findings['email'] += 1
        if any(rx.search(cell) for rx in EMBEDDED_PHONE_RES): findings['phone'] += 1
        if contains_secret_format(cell): findings['secret'] += 1
        if any(rx.search(cell) for rx in INSTRUCTION_PATTERNS): findings['instruction_like'] += 1
    return {'cells_inspected': len(cells), 'findings': findings}

def apply_free_text_findings(classification, reasons, ft):
    f = ft['findings']
    if f['secret']:
        classification = _raise(classification, 'Secret / High Risk')
        if 'values contain known secret/token formats' not in reasons:
            _add(reasons, f"free text contains secret-like strings in {f['secret']} cell(s)")
    if f['email']:
        classification = _raise(classification, 'PII')
        _add(reasons, f"free text contains email addresses in {f['email']} cell(s)")
    if f['phone']:
        classification = _raise(classification, 'PII')
        _add(reasons, f"free text contains phone numbers in {f['phone']} cell(s)")
    if f['instruction_like']:  # warning only: never changes classification
        _add(reasons, f"instruction-like text in {f['instruction_like']} cell(s) (warning only)")
    return classification, reasons

def scan_csv(path):
    with path.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames: raise ValueError('CSV has no header row.')
        rows, fields = list(reader), reader.fieldnames
    fingerprints = [tuple((r.get(field) or '') for field in fields) for r in rows]
    duplicate_rows = len(fingerprints) - len(set(fingerprints))
    columns, highest = [], 0
    for field in fields:
        values = [(r.get(field) or '') for r in rows]
        missing = sum(1 for v in values if not v.strip())
        inferred = infer_type(values)
        classification, reasons = classify_column(field, values)
        ft = scan_free_text(values) if inferred == 'text' else None
        if ft: classification, reasons = apply_free_text_findings(classification, reasons, ft)
        highest = max(highest, RISK_ORDER[classification])
        profile = {
            'name': field, 'type': inferred, 'missing_count': missing,
            'missing_percent': round((missing/len(rows)*100), 2) if rows else 0.0,
            'unique_count': len(set(v for v in values if v.strip())),
            'classification': classification, 'reasons': reasons
        }
        if ft:
            profile['free_text'] = True
            profile['free_text_inspection'] = ft
            if any(ft['findings'].values()): profile['review_recommended'] = True
        if inferred == 'number':
            if classification != 'Standard':
                profile['stats_withheld'] = f'column classified as {classification}'
            else:
                nums = [n for n in (maybe_number(v) for v in values) if n is not None]
                if nums: profile['numeric'] = {'min':min(nums), 'max':max(nums), 'average':round(mean(nums),4)}
        columns.append(profile)
    any_review = any(c.get('review_recommended') for c in columns)
    if highest >= 3: readiness = 'Sensitive data detected'
    elif highest >= 1 or any_review: readiness = 'Review recommended'
    else: readiness = 'No findings (heuristic)'
    return {
        'product':'Cognisentry AI',
        'scanner':'Local CSV Security & Data Quality Scanner PoC',
        'privacy':{'processing':'local','uploaded':False,'note':'This script reads the CSV locally and does not send it to any external service.'},
        'dataset':{'filename':path.name,'rows':len(rows),'columns':len(fields),'duplicate_rows':duplicate_rows},
        'ai_analysis_readiness':readiness,
        'flagged_fields':[{'name':c['name'],'classification':c['classification'],'reasons':c['reasons']} for c in columns if c['classification']!='Standard' or c.get('review_recommended')],
        'column_profiles':columns,
        'limitations':['Heuristic detection can produce false positives and false negatives.','This PoC does not provide compliance certification or a security guarantee.','No Claude API call is made by this scanner.','Free-text inspection covers at most the first 1000 non-empty values per column.','Instruction-like text detection is a warning signal only, not a security boundary.']
    }

def main():
    p = argparse.ArgumentParser(description='Cognisentry AI local CSV scanner PoC')
    p.add_argument('csv_file', type=Path); p.add_argument('--out', type=Path)
    a = p.parse_args(); report = scan_csv(a.csv_file); rendered = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False)
    if a.out: a.out.write_text(rendered+'\n', encoding='utf-8'); print(f'Report written to {a.out}')
    else: print(rendered)

if __name__ == '__main__': main()
