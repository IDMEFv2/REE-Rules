#!/usr/bin/env python3
"""Offline replay of the Concerto collection + rule matching on each rule's sample.

Replays, without Logstash:
  1. the syslog header grok of pipeline/00-my_collected.conf (message, process.name, host.*)
  2. each ruleset predicate (scripts/match.rb semantics) and its grok patterns (break_on_match)
and tells, for every rule with a sample, where it stops:
  HEADER_FAIL  - no header pattern matches (log would go to the _ERR topic)
  PRED_FAIL    - the rule's own ruleset predicate is false (value of the predicate variable shown)
  PATTERN_FAIL - predicate OK but the rule's pattern does not match its own sample
  SHADOWED     - an earlier pattern of the same ruleset matches first
  OK           - the rule matches its own sample
Read-only: touches nothing, writes tools/offline_grok_report.csv.
Note: Python 'regex' is used instead of Joni/Oniguruma; rare syntax differences are flagged as REGEX_ERROR.
"""
import csv, glob, os, re, sys
import regex, yaml, pygrok

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LS = os.path.join(ROOT, 'logstash')
RULESETS = os.environ.get('RULESETS', os.path.join(LS, 'rulesets'))

# ---------- grok library ----------
PAT = {}
pdir = os.path.join(os.path.dirname(pygrok.__file__), 'patterns')
for f in os.listdir(pdir):
    for ln in open(os.path.join(pdir, f), encoding='utf-8', errors='replace'):
        ln = ln.rstrip('\n')
        if ln and not ln.startswith('#') and ' ' in ln:
            k, v = ln.split(' ', 1)
            PAT[k] = v.strip()

GROUPS = {}
def gname(field):
    n = 'g%d' % len(GROUPS)
    GROUPS[n] = field
    return n

def expand(p, extra, depth=0):
    if depth > 30:
        raise ValueError('recursion')
    def rep(m):
        name, field = m.group(1), m.group(2)
        body = extra.get(name, PAT.get(name))
        if body is None:
            raise KeyError(name)
        body = expand(body, extra, depth + 1)
        return f'(?P<{gname(field)}>{body})' if field else f'(?:{body})'
    p = re.sub(r'%\{(\w+)(?::([^:}]+))?(?::\w+)?\}', rep, p)
    # Oniguruma named groups with non-identifier names -> sanitized
    def ng(m):
        return f'(?P<{gname(m.group(1))}>'
    p = re.sub(r'\(\?<([^>=!]+)>', ng, p)
    return p

def compile_grok(p, extra=None):
    return regex.compile(expand(p, extra or {}))

def fields_of(m):
    out = {}
    for k, v in m.groupdict().items():
        if v is not None and k in GROUPS:
            out.setdefault(GROUPS[k], v)
    return out

# ---------- header patterns from the pipeline ----------
conf = open(os.path.join(LS, 'pipeline', '00-my_collected.conf'), encoding='utf-8').read()
HEADERS = [s.replace("\\\\", "\\") for s in re.findall(r"^\s*'(\^.*?)',?\s*$", conf, re.M)]
SYSLOGTS = re.search(r"'SYSLOGTIMESTAMP' => '(.*)'", conf).group(1)
HDR_EXTRA = {'SYSLOGTIMESTAMP': SYSLOGTS}
HDR = []
for h in HEADERS:
    try:
        HDR.append(compile_grok(h, HDR_EXTRA))
    except Exception as e:
        # the pipeline's own SYSLOGTIMESTAMP contains '%{TIME)'; fall back to the standard one
        HDR.append(compile_grok(h))

def parse_header(line):
    for r in HDR:
        m = r.search(line)
        if m:
            f = fields_of(m)
            ev = {k: v for k, v in f.items() if k.startswith('[Attachment]')}
            ev['[Attachment][RawLog][Content][event][original]'] = line
            ev.setdefault('[Attachment][RawLog][Content][process][name]', '-')
            return ev
    return None

# ---------- predicate (match.rb) ----------
def ev_pred(p, ev):
    op, o = p['operator'], p.get('operands')
    if op == 'variable':  return ev.get(o)
    if op == 'constant':  return o
    if op == 'not':       return not ev.get(o[0]) if isinstance(o[0], str) else not ev_pred(o[0], ev)
    a = ev_pred(o[0], ev)
    if op == 'and':  return bool(a) and bool(ev_pred(o[1], ev))
    if op == 'or':   return bool(a) or bool(ev_pred(o[1], ev))
    if op == 'nand': return (not a) and not ev_pred(o[1], ev)
    b = ev_pred(o[1], ev)
    try:
        if op == 'equal':     return a == b
        if op == 'not_equal': return a != b
        if op == 'in':        return b in a      # Ruby: opd1.include?(opd2)
        if op == 'not_in':    return b not in a
        if op in ('match', 'not_match'):
            r = bool(regex.search(b, a))
            return r if op == 'match' else not r
        if op == 'xor': return bool(a) ^ bool(b)
    except Exception:
        return False
    return False

def pred_vars(p, acc):
    if isinstance(p, dict):
        if p.get('operator') == 'variable':
            acc.append(p['operands'])
        for x in (p.get('operands') if isinstance(p.get('operands'), list) else []):
            pred_vars(x, acc)
    return acc

# ---------- load rulesets ----------
def load_sets(path):
    sets = []
    for fn in sorted(glob.glob(os.path.join(path, '*.yml'))):
        for doc in yaml.safe_load_all(open(fn, encoding='utf-8')):
            if not doc or 'ruleset' not in doc:
                continue
            rs = doc['ruleset']
            rules = []
            for r in rs.get('rules') or []:
                try:
                    rx, err = compile_grok(r.get('pattern', '')), ''
                except Exception as e:
                    rx, err = None, f'{type(e).__name__}: {e}'
                rules.append(dict(id=r.get('id'), rx=rx, err=err, samples=r.get('samples') or []))
            sets.append(dict(file=os.path.basename(fn)[:-4], name=rs.get('name'),
                             field=rs.get('field'), pred=rs.get('predicate'), rules=rules))
    return sets


def classify(rs, r, line, sets):
    """Stage reached by one line for rule r of ruleset rs."""
    ev = parse_header(line)
    if r['err']:
        return 'REGEX_ERROR', r['err'][:120], ev
    if ev is None:
        return 'HEADER_FAIL', '', ev
    pv = pred_vars(rs['pred'], [])
    if rs['pred'] and not ev_pred(rs['pred'], ev):
        return 'PRED_FAIL', '; '.join(f"{v.split('][')[-1].rstrip(']')}={ev.get(v)!r}" for v in pv)[:160], ev
    val = ev.get(rs['field'])
    if val is None or not r['rx'].search(val):
        return 'PATTERN_FAIL', f"field {rs['field'].split('][')[-1].rstrip(']')} = {str(val)[:140]!r}", ev
    fm = first_match(rs, ev)
    if fm != r['id']:
        return 'SHADOWED', f'rule {fm} matches first', ev
    return 'OK', '', ev


def first_match(rs, ev):
    val = ev.get(rs['field'])
    if val is None:
        return None
    for r in rs['rules']:
        if r['rx'] is not None and r['rx'].search(val):
            return r['id']
    return None

# ---------- run ----------
def main():
    sets = load_sets(RULESETS)
    rows = []
    for rs in sets:
        for r in rs['rules']:
            if not r['samples']:
                continue
            line = r['samples'][0].strip()
            if not line.startswith('<'):
                line = '<38>' + line
            stage, detail, ev = classify(rs, r, line, sets)
            other = ''
            if ev is not None:
                for s2 in sets:
                    if (not s2['pred'] or ev_pred(s2['pred'], ev)):
                        fm = first_match(s2, ev)
                        if fm is not None:
                            other = f"{s2['file']}/{fm}"
                            break
            rows.append(dict(source=rs['file'], rule=r['id'], stage=stage, detail=detail,
                             pipeline_first_match=other,
                             process_name=(ev or {}).get('[Attachment][RawLog][Content][process][name]', ''),
                             message=((ev or {}).get('[Attachment][RawLog][Content][message]') or '')[:200],
                             sample=line[:250]))
    out = os.path.join(ROOT, 'tools', 'offline_grok_report.csv')
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    from collections import Counter
    print('rules with sample:', len(rows))
    print(Counter(r['stage'] for r in rows))
    print('report:', out)


if __name__ == '__main__':
    main()
