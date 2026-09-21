#!/usr/bin/env python3
"""Rewrite the capture targets of the parsing rules that write outside
[Attachment][RawLog][Content].

Nothing in logstash/rulesets/ is modified. Corrected copies are written to
logstash/rulesets_fixed/ together with a diff report, so the change can be
reviewed and proposed as an explicit contribution.
"""
import os, re, sys, yaml, difflib, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC  = os.path.join(ROOT, 'logstash', 'rulesets')
IDM  = os.path.join(ROOT, 'logstash', 'idmef')
DST  = os.path.join(ROOT, 'logstash', 'rulesets_fixed')
REPORT = os.path.join(ROOT, 'tools', 'namespace_fix_report.txt')
P = '[Attachment][RawLog][Content]'

# bare capture name -> path under [Attachment][RawLog][Content]
NAME_MAP = {
    # network entities - these become IDMEFv2 Source/Target
    'src':             '[source][address]',
    'srcAddr':         '[source][address]',
    'dst':             '[destination][address]',
    'target':          '[destination][address]',
    'server':          '[server][address]',
    'port':            '[destination][port]',
    'macAddr':         '[source][mac]',
    'domain':          '[destination][domain]',
    # identities
    'user':            '[user][name]',
    'userName':        '[user][name]',
    'usrName':         '[user][name]',
    'UserName':        '[user][name]',
    # host and service
    'nodename':        '[host][hostname]',
    'service':         '[service][name]',
    'vipname':         '[service][name]',
    'interface':       '[interface]',
    'interface_name':  '[interface]',
    'interfaceport':   '[interface]',
    'process_name':    '[process][name]',
    'process_id':      '[process][pid]',
    'pid':             '[process][pid]',
    # files
    'filePath':        '[file][path]',
    'tableName':       '[file][name]',
    # environment
    'degreTemp':       '[temperature]',
    # event context (not mappable to an IDMEFv2 entity, kept for the raw log)
    'id':              '[event][id]',
    'Id':              '[event][id]',
    'Num':             '[event][id]',
    'Number':          '[event][id]',
    'indexId':         '[event][id]',
    'totalId':         '[event][id]',
    'trap':            '[event][id]',
    'numPlugin':       '[event][id]',
    'signalId':        '[event][id]',
    'signal_id':       '[event][id]',
    'signal_number':   '[event][id]',
    'classification':  '[event][category]',
    'status':          '[event][outcome]',
    'level':           '[log][level]',
    'desc':            '[event][reason]',
    'data':            '[event][reason]',
    'type':            '[rule][name]',
    'name':            '[event][action]',
    'package':         '[package][name]',
    'pkg_version':     '[package][version]',
    'version':         '[service][version]',
    'distribution':    '[service][type]',
}

# per-rule overrides where the generic name would be wrong in context
OVERRIDE = {
    ('clamav', 3200):      {'type': '[rule][name]', 'filePath': '[file][path]'},
    ('trendmicro', 24301): {'name': '[file][name]'},
    ('cisco-ace', 5104):   {'name': '[event][action]'},
    ('nortel-switch', 16043): {'port': '[server][port]'},
    ('mysql', 23603):      {'tableName': '[file][name]'},
    ('sendmail', 3706):    {'user': '[destination][user][name]', 'domain': '[destination][domain]'},
}


def rules_of(path):
    with open(path, encoding='utf-8') as fh:
        d = yaml.safe_load(fh) or {}
    return (d.get('ruleset') or {}).get('rules') or []


def caps(pat):
    return re.findall(r'%\{[A-Z0-9_]+:([^}]+?)(?::\w+)?\}', pat or '')


def main():
    mapped = {f: {r.get('id') for r in rules_of(os.path.join(IDM, f))} for f in os.listdir(IDM)}
    os.makedirs(DST, exist_ok=True)
    report, touched, unknown = [], collections.Counter(), collections.Counter()
    files_written = 0

    for f in sorted(os.listdir(SRC)):
        done = mapped.get(f, set())
        src_path = os.path.join(SRC, f)

        # which rule ids need fixing, and which names inside each
        targets = {}
        for r in rules_of(src_path):
            rid = r.get('id')
            if rid in done:
                continue
            c = caps(r.get('pattern') or '')
            if not c or any(x.startswith(P) for x in c):
                continue
            ov = OVERRIDE.get((f[:-4], rid), {})
            names = {}
            for name in c:
                tgt = ov.get(name) or NAME_MAP.get(name)
                if tgt:
                    names[name] = tgt
                else:
                    unknown[name] += 1
            if names:
                targets[rid] = names
        if not targets:
            continue

        # rewrite the raw text, block by block
        lines = open(src_path, encoding='utf-8').read().split('\n')
        cur = None
        changed = []
        id_re = re.compile(r'^\s*-\s*id:\s*(\S+)')
        for i, line in enumerate(lines):
            m = id_re.match(line)
            if m:
                raw = m.group(1).strip().strip('"\'')
                try:
                    cur = int(raw)
                except ValueError:
                    cur = raw
            if cur in targets and '%{' in line:
                before = line
                for name, tgt in targets[cur].items():
                    line, n = re.subn(
                        r'(%\{[A-Z0-9_]+:)' + re.escape(name) + r'((?::\w+)?\})',
                        lambda mm: mm.group(1) + P + tgt + mm.group(2), line)
                    if n:
                        touched[name] += n
                if line != before:
                    lines[i] = line
                    changed.append((cur, before.strip(), line.strip()))

        if changed:
            open(os.path.join(DST, f), 'w', encoding='utf-8').write('\n'.join(lines))
            files_written += 1
            report.append(f'=== {f}  ({len(changed)} rules)')
            for rid, old, new in changed:
                report.append(f'  id {rid}')
                report.append(f'    -  {old}')
                report.append(f'    +  {new}')
            report.append('')

    with open(REPORT, 'w', encoding='utf-8') as fh:
        fh.write('Capture-namespace corrections for the Concerto parsing rules\n')
        fh.write('Source: logstash/rulesets/   Corrected copies: logstash/rulesets_fixed/\n')
        fh.write('No file under logstash/rulesets/ has been modified.\n\n')
        fh.write('\n'.join(report))

    print(f'files written   : {files_written} -> logstash/rulesets_fixed/')
    print(f'captures renamed: {sum(touched.values())}')
    if unknown:
        print('UNMAPPED NAMES  :', dict(unknown))
    print(f'report          : {REPORT}')


if __name__ == '__main__':
    main()
