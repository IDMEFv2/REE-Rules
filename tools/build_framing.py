#!/usr/bin/env python3
"""For samples whose syslog header is not recognised by 00-my_collected.conf (NOT_COLLECTED),
find a syslog framing that lets the line reach its own rule, offline.
Rulesets used: logstash/rulesets overlaid with tools/pattern_fixes/*.yml.
Writes tools/framing.json  {"<source>/<id>": "<framed line>"} , read by inject_parsing_tests.py --frame.
The sample text itself is never modified; only a header is added (or the vendor prefix replaced by one)."""
import json, os, re, shutil, tempfile, glob
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
tmp = tempfile.mkdtemp()
for f in glob.glob(os.path.join(ROOT, 'logstash', 'rulesets', '*.yml')):
    shutil.copy(f, tmp)
for f in glob.glob(os.path.join(HERE, 'pattern_fixes', '*.yml')):
    shutil.copy(f, tmp)
os.environ['RULESETS'] = tmp
import sys; sys.path.insert(0, HERE)
import offline_grok_check as og

TS = 'Sep 21 10:00:00'
sets = og.load_sets(tmp)

def prog_of(pred):
    """program name satisfying a process.name predicate, if any"""
    if not isinstance(pred, dict):
        return None
    ops = pred.get('operands')
    if pred.get('operator') in ('in', 'equal') and isinstance(ops, list) and len(ops) == 2:
        v, c = ops
        if v.get('operands') == '[Attachment][RawLog][Content][process][name]' and isinstance(c.get('operands'), str):
            return c['operands']
    if pred.get('operator') in ('or', 'and') and isinstance(ops, list):
        for o in ops:
            p = prog_of(o)
            if p:
                return p
    return None

out, report = {}, []
for rs in sets:
    prog = prog_of(rs['pred']) or 'concerto-test'
    for r in rs['rules']:
        if not r['samples']:
            continue
        s = r['samples'][0].strip()
        base = s if s.startswith('<') else '<38>' + s
        stage, _, _ = og.classify(rs, r, base, sets)
        if stage != 'HEADER_FAIL':
            continue
        body = re.sub(r'^<\d+>', '', s)
        rest = body.split(': ', 1)[1] if ': ' in body else body
        candidates = [
            f'<38>{TS} testhost {prog}: {body}',
            f'<38>{TS} testhost {prog}: {rest}',
            f'<38>{TS} {body}',
            f'<38>{TS} testhost {body}',
        ]
        chosen, why = None, 'no framing reaches the rule'
        for c in candidates:
            st, det, _ = og.classify(rs, r, c, sets)
            if st == 'OK':
                chosen = c; break
            why = why if why.startswith('PRED') or why.startswith('PATTERN') else f'{st} {det}'[:100]
        key = f"{rs['file']}/{r['id']}"
        if chosen:
            out[key] = chosen
        report.append((key, 'FRAMED' if chosen else 'NOT_FRAMABLE', chosen or why))

json.dump(out, open(os.path.join(HERE, 'framing.json'), 'w', encoding='utf-8'), indent=1)
for k, v, d in report:
    print(f'{v:13} {k:28} {d[:150]}')
print(f'\nframed: {len(out)} / {len(report)} header failures -> tools/framing.json')
shutil.rmtree(tmp)
