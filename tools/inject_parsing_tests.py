#!/usr/bin/env python3
"""End-to-end test of the parsing and mapping rules - v2.

Every sample line is sent VERBATIM over syslog TCP (only a <38> priority is
prepended, as on the wire). Nothing in the line is rewritten, so the ruleset
predicates see exactly what the rule author tested.

The stored alert is identified by:
  - it did not exist in the index before the run (CreateTime = log timestamp, unusable);
  - its raw line (event.original), equal to the line sent;
  - its Ref "urn:rule:<id>", which names the rule that actually fired.

Verdicts: PASS, NO_ALERT, WRONG_RULE (another rule fired on that sample),
WRONG_CATEGORY, WRONG_PRIORITY.

  python3 tools/inject_parsing_tests.py --dry-run
  python3 tools/inject_parsing_tests.py --only ssh
  python3 tools/inject_parsing_tests.py --wait 60

Environment: SYSLOG_HOST (localhost) SYSLOG_PORT (6514)
             ES_URL (http://localhost:9200) ES_USER ES_PASS ES_INDEX (alerts)
"""
import os, re, sys, ssl, json, time, socket, base64, argparse, collections
import urllib.request
from datetime import datetime, timezone, timedelta
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LS   = os.path.join(ROOT, 'logstash')

SYSLOG_HOST = os.environ.get('SYSLOG_HOST', 'localhost')
SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', '6514'))
ES_URL   = os.environ.get('ES_URL', 'http://localhost:9200').rstrip('/')
ES_USER  = os.environ.get('ES_USER', 'elastic')
ES_PASS  = os.environ.get('ES_PASS', 'elastic')
ES_INDEX = os.environ.get('ES_INDEX', 'alerts')
ES_LOGS  = os.environ.get('ES_LOGS', 'logs')


def load(path):
    with open(path, encoding='utf-8') as fh:
        return yaml.safe_load(fh) or {}


def rules_of(d):
    return (d.get('ruleset') or {}).get('rules') or []


def overlay(base, extra):
    out = {}
    for d in (base, extra):
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith('.yml'):
                    out[f] = os.path.join(d, f)
    return out


def expectation(mrule):
    f = mrule.get('fields') or {}
    cat = f.get('[Category][0]') or f.get('[Category]')
    if isinstance(cat, list):
        cat = cat[0] if cat else None
    pri = f.get('[Priority]')
    for t in mrule.get('translate') or []:
        if t.get('target') == '[Priority]':
            pri = None          # computed at runtime, not asserted
    return cat, (pri if isinstance(pri, str) else None)


def es(path, body):
    req = urllib.request.Request(
        f'{ES_URL}{path}', data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json',
                 'Authorization': 'Basic ' + base64.b64encode(
                     f'{ES_USER}:{ES_PASS}'.encode()).decode()},
        method='POST')
    ctx = ssl._create_unverified_context() if ES_URL.startswith('https') else None
    with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
        return json.load(r)


def all_hits(source):
    """Every document of the index (paged with search_after)."""
    out, after = [], None
    while True:
        body = {'size': 5000, '_source': source, 'sort': ['_doc'], 'query': {'match_all': {}}}
        if after is not None:
            body['search_after'] = after
        hits = es(f'/{ES_INDEX}/_search', body)['hits']['hits']
        if not hits:
            return out
        out.extend(hits)
        after = hits[-1]['sort']


def original_of(src):
    """Raw line as received, from the RawLog attachment."""
    for att in src.get('Attachment') or []:
        if att.get('Name') == 'RawLog':
            try:
                c = json.loads(att.get('Content') or '{}')
                return ((c.get('event') or {}).get('original') or '').strip()
            except Exception:
                return ''
    return ''


def fired_rules(src):
    out = []
    for ref in src.get('Ref') or []:
        m = re.match(r'urn:rule:(\d+)$', str(ref))
        if m:
            out.append(int(m.group(1)))
    return out


def diagnose(line, rid):
    """Where did a line stop? Looks it up in the logs index (every collected log)."""
    try:
        hits = es(f'/{ES_LOGS}/_search', {'size': 50, 'query': {'match_phrase': {'event.original': line}}})['hits']['hits']
    except Exception as exc:
        return 'LOGS_QUERY_ERROR', str(exc)[:80]
    docs = [h['_source'] for h in hits if ((h['_source'].get('event') or {}).get('original') or '').strip() == line]
    if not docs:
        return 'NOT_COLLECTED', 'syslog header not parsed (see _ERR topic / /tmp/logstash_errors)'
    d = docs[0]
    ids = {str((x.get('rule') or {}).get('id')) for x in docs if (x.get('rule') or {}).get('id') is not None}
    hip = (d.get('host') or {}).get('ip')
    extra = ' ; host.ip has 2 values -> Sensor.IP rejected by ES' if isinstance(hip, list) and len(hip) > 1 else ''
    if not ids:
        return 'NO_RULE_MATCH', 'collected, no ruleset/pattern matched' + extra
    if str(rid) not in ids:
        return 'OTHER_RULE_MATCH', f'matched rule(s) {sorted(ids)}' + extra
    return 'MATCHED_NOT_STORED', 'rule matched, alert not indexed' + extra


def first(v):
    return v[0] if isinstance(v, list) and v else v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--only')
    ap.add_argument('--limit', type=int)
    ap.add_argument('--dry-run', action='store_true')
    ap.add_argument('--wait', type=int, default=60)
    ap.add_argument('--frame', action='store_true',
                    help='use tools/framing.json: syslog header added to raw samples (built offline by build_framing.py)')
    a = ap.parse_args()

    rs_files = overlay(os.path.join(LS, 'rulesets'), os.path.join(LS, 'rulesets_fixed'))
    id_files = overlay(os.path.join(LS, 'idmef'), os.path.join(LS, 'idmef_proposed'))

    framing = {}
    if a.frame:
        fp = os.path.join(ROOT, 'tools', 'framing.json')
        framing = json.load(open(fp, encoding='utf-8'))
        print(f'framing          : {len(framing)} raw samples get a syslog header ({fp})')

    cases = []
    for fname in sorted(rs_files):
        src = fname[:-4]
        if a.only and src != a.only:
            continue
        maps = {}
        if fname in id_files:
            maps = {r.get('id'): r for r in rules_of(load(id_files[fname]))}
        for r in rules_of(load(rs_files[fname])):
            rid = r.get('id')
            samples = r.get('samples') or []
            if not samples or rid not in maps:
                continue
            cat, pri = expectation(maps[rid])
            line = samples[0].strip()
            if not line.startswith('<'):
                line = '<38>' + line
            line = framing.get(f'{src}/{rid}', line)
            cases.append(dict(source=src, rid=int(rid), line=line, cat=cat, pri=pri))
    if a.limit:
        cases = cases[:a.limit]

    dup = collections.Counter(c['line'] for c in cases)
    print(f'testable rules   : {len(cases)}')
    print(f'shared samples   : {sum(1 for c in cases if dup[c["line"]] > 1)} rules share their sample with another rule')
    print(f'syslog target    : {SYSLOG_HOST}:{SYSLOG_PORT} (TCP)')
    print(f'elasticsearch    : {ES_URL}/{ES_INDEX}')
    if a.dry_run:
        for c in cases[:12]:
            print(f'  [{c["source"]}/{c["rid"]}] {c["line"][:140]}')
        print(f'  ... ({len(cases)} lines, nothing sent)')
        return

    # CreateTime is the timestamp written in the log line (often years old),
    # so new alerts are identified as documents absent before the run.
    try:
        before = {h['_id'] for h in all_hits(False)}
    except Exception as exc:
        print(f'ERROR querying Elasticsearch: {exc}')
        return
    start = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
    print(f'alerts already stored: {len(before)}')
    sock = socket.create_connection((SYSLOG_HOST, SYSLOG_PORT), timeout=20)
    for c in cases:
        sock.sendall((c['line'] + '\n').encode('utf-8', 'replace'))
        time.sleep(0.02)
    sock.close()
    print(f'run started      : {start}Z')
    print(f'injected         : {len(cases)} lines')
    print(f'waiting {a.wait}s for the pipeline...')
    time.sleep(a.wait)

    try:
        hits = all_hits(['Category', 'Priority', 'Ref', 'Attachment'])
    except Exception as exc:
        print(f'ERROR querying Elasticsearch: {exc}')
        return

    by_line = collections.defaultdict(list)
    recent = 0
    for h in hits:
        s = h['_source']
        if h['_id'] in before:
            continue
        recent += 1
        by_line[original_of(s)].append(s)
    print(f'alerts of this run: {recent}')

    stats = collections.Counter()
    rows = []
    for c in cases:
        got = by_line.get(c['line'], [])
        mine = [s for s in got if c['rid'] in fired_rules(s)]
        if not got:
            v = 'NO_ALERT'
            stage, why = diagnose(c['line'], c['rid'])
            d = f'{stage}: {why}'
            stats['  ' + stage] += 1
        elif not mine:
            others = sorted({r for s in got for r in fired_rules(s)})
            v, d = 'WRONG_RULE', f'sample fired rule(s) {others}'
        else:
            s = mine[0]
            gcat, gpri = first(s.get('Category')), s.get('Priority')
            if c['cat'] and gcat != c['cat']:
                v, d = 'WRONG_CATEGORY', f'expected {c["cat"]}, got {gcat}'
            elif c['pri'] and gpri != c['pri']:
                v, d = 'WRONG_PRIORITY', f'expected {c["pri"]}, got {gpri}'
            else:
                v, d = 'PASS', f'{gcat} / {gpri}'
        stats[v] += 1
        rows.append((c['source'], c['rid'], v, d))

    print()
    for k in ('PASS', 'NO_ALERT', 'WRONG_RULE', 'WRONG_CATEGORY', 'WRONG_PRIORITY'):
        print(f'  {k:<16} {stats[k]}')
    for k in sorted(x for x in stats if x.startswith('  ')):
        print(f'    {k.strip():<22} {stats[k]}')
    print()
    for s, rid, v, d in rows:
        if v != 'PASS':
            print(f'  {v:<16} {s}/{rid}  {d}')

    tag = datetime.now().strftime('%Y%m%d_%H%M%S')
    out = os.path.join(ROOT, 'tools', f'injection_report_{tag}.json')
    json.dump([dict(source=s, rule=rid, verdict=v, detail=d) for s, rid, v, d in rows],
              open(out, 'w', encoding='utf-8'), indent=1)
    print(f'\nreport: {out}')
    print('Also check: docker logs proto-logstash-1 2>&1 | grep -c "Could not index event"')


if __name__ == '__main__':
    main()
