#!/usr/bin/env python3
from __future__ import annotations
import argparse, csv, ipaddress, json, math, re
from collections import Counter
from pathlib import Path
from statistics import mean

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PHONE_RE = re.compile(r'^\+?[0-9][0-9\s().-]{7,}$')
URL_RE = re.compile(r'^https?://', re.I)
TOKEN_RE = re.compile(r'^[A-Za-z0-9_\-]{24,}$')
SENSITIVE_NAME_HINTS = {
    'email': 'PII', 'e_mail': 'PII', 'phone': 'PII', 'mobile': 'PII',
    'ip': 'Potentially Sensitive', 'ip_address': 'Potentially Sensitive',
    'customer_id': 'Sensitive', 'user_id': 'Sensitive', 'national_id': 'Sensitive',
    'ssn': 'Sensitive', 'password': 'Secret / High Risk', 'passwd': 'Secret / High Risk',
    'api_key': 'Secret / High Risk', 'apikey': 'Secret / High Risk', 'token': 'Secret / High Risk',
    'secret': 'Secret / High Risk'
}
RISK_ORDER = {'Standard':0, 'Potentially Sensitive':1, 'PII':2, 'Sensitive':2, 'Secret / High Risk':3}

def normalize_name(name):
    return re.sub(r'[^a-z0-9]+', '_', name.strip().lower()).strip('_')

def is_ipv4(value):
    try:
        return isinstance(ipaddress.ip_address(value.strip()), ipaddress.IPv4Address)
    except ValueError:
        return False

def maybe_number(value):
    value = value.strip()
    if not value: return None
    try: return float(value.replace(',', ''))
    except ValueError: return None

def infer_type(values):
    present = [v.strip() for v in values if v.strip()]
    if not present: return 'empty'
    if all(maybe_number(v) is not None for v in present): return 'number'
    if all(v.lower() in {'true','false','yes','no','0','1'} for v in present): return 'boolean'
    return 'text'

def classify_column(name, values):
    norm = normalize_name(name)
    classification, reasons = 'Standard', []
    for hint, risk in SENSITIVE_NAME_HINTS.items():
        if hint == norm or hint in norm:
            classification = max(classification, risk, key=lambda x: RISK_ORDER[x])
            reasons.append(f'column name suggests {risk.lower()}')
    present = [v.strip() for v in values if v.strip()]
    if not present: return classification, reasons
    sample = present[:200]
    counts = Counter()
    for value in sample:
        if EMAIL_RE.match(value): counts['email'] += 1
        if PHONE_RE.match(value): counts['phone'] += 1
        if is_ipv4(value): counts['ipv4'] += 1
        if URL_RE.match(value): counts['url'] += 1
        if TOKEN_RE.match(value) and not EMAIL_RE.match(value): counts['token_like'] += 1
    threshold = max(1, math.ceil(len(sample)*0.2))
    if counts['email'] >= threshold:
        classification = max(classification, 'Sensitive', key=lambda x: RISK_ORDER[x]); reasons.append('values resemble email addresses')
    if counts['phone'] >= threshold:
        classification = max(classification, 'Sensitive', key=lambda x: RISK_ORDER[x]); reasons.append('values resemble phone numbers')
    if counts['ipv4'] >= threshold:
        classification = max(classification, 'Potentially Sensitive', key=lambda x: RISK_ORDER[x]); reasons.append('values resemble IPv4 addresses')
    if counts['token_like'] >= threshold:
        classification = max(classification, 'Secret / High Risk', key=lambda x: RISK_ORDER[x]); reasons.append('values resemble long token/secret strings')
    if counts['url'] >= threshold and classification == 'Standard': reasons.append('values resemble URLs')
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
        highest = max(highest, RISK_ORDER[classification])
        profile = {
            'name': field, 'type': inferred, 'missing_count': missing,
            'missing_percent': round((missing/len(rows)*100), 2) if rows else 0.0,
            'unique_count': len(set(v for v in values if v.strip())),
            'classification': classification, 'reasons': reasons
        }
        if inferred == 'number':
            nums = [n for n in (maybe_number(v) for v in values) if n is not None]
            if nums: profile['numeric'] = {'min':min(nums), 'max':max(nums), 'average':round(mean(nums),4)}
        columns.append(profile)
    readiness = 'Sensitive data detected' if highest >= 3 else ('Review recommended' if highest >= 1 else 'Ready for analysis')
    return {
        'product':'Cognisentry AI',
        'scanner':'Local CSV Security & Data Quality Scanner PoC',
        'privacy':{'processing':'local','uploaded':False,'note':'This script reads the CSV locally and does not send it to any external service.'},
        'dataset':{'filename':path.name,'rows':len(rows),'columns':len(fields),'duplicate_rows':duplicate_rows},
        'ai_analysis_readiness':readiness,
        'flagged_fields':[{'name':c['name'],'classification':c['classification'],'reasons':c['reasons']} for c in columns if c['classification']!='Standard'],
        'column_profiles':columns,
        'limitations':['Heuristic detection can produce false positives and false negatives.','This PoC does not provide compliance certification or a security guarantee.','No Claude API call is made by this scanner.']
    }

def main():
    p = argparse.ArgumentParser(description='Cognisentry AI local CSV scanner PoC')
    p.add_argument('csv_file', type=Path); p.add_argument('--out', type=Path)
    a = p.parse_args(); report = scan_csv(a.csv_file); rendered = json.dumps(report, indent=2, ensure_ascii=False)
    if a.out: a.out.write_text(rendered+'\n', encoding='utf-8'); print(f'Report written to {a.out}')
    else: print(rendered)

if __name__ == '__main__': main()
