#!/usr/bin/env python3
"""Propose IDMEFv2 mappings for the Concerto parsing rules that have none.

Writes a review sheet (tools/mapping_review.xlsx) and, with --emit, staging
YAML under logstash/idmef_proposed/. It never writes into logstash/idmef/.

Category and Priority are PROPOSALS. The review sheet pre-fills the FINAL
columns with them so the reviewer only edits what he disagrees with; the
DECISION column stays "TO CONFIRM" until a human sets it.
"""
import os, re, sys, yaml, collections
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULESETS = os.path.join(ROOT, 'logstash', 'rulesets')
IDMEF    = os.path.join(ROOT, 'logstash', 'idmef')
PROPOSED = os.path.join(ROOT, 'logstash', 'idmef_proposed')
OUT      = os.path.join(ROOT, 'tools', 'mapping_review.xlsx')
P = '[Attachment][RawLog][Content]'
ILLEGAL = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f]')

FIELD_MAP = [
    ('[source][address]',         None,                    'meta_source'),
    ('[source][hostname]',        None,                    'meta_source'),
    ('[source][ip]',              None,                    'meta_source'),
    ('[source][port]',            None,                    'meta_source'),
    ('[source][user][name]',      '[Source][0][User]',     None),
    ('[destination][address]',    '[Target][0][IP]',       None),
    ('[destination][ip]',         '[Target][0][IP]',       None),
    ('[destination][hostname]',   '[Target][0][Hostname]', None),
    ('[destination][port]',       '[Target][0][Port][0]',  None),
    ('[destination][user][name]', '[Target][0][User]',     None),
    ('[user][target][name]',      '[Target][0][User]',     None),
    ('[user][name]',              '[Target][0][User]',     None),
    ('[related][user]',           '[Target][0][User]',     None),
    ('[network][transport]',      '[Source][0][Protocol]', None),
    ('[network][protocol]',       '[Source][0][Protocol]', None),
    ('[service][name]',           '[Target][0][Service]',  None),
    ('[process][name]',           '[Target][0][Service]',  None),
]

# ordered, most specific first: (regex, Category, Priority, Analyzer.Data, confidence)
RULES = [
 (r'virus|malware|trojan|worm\b|ransom|spyware|rootkit|infected|quarantine',
  'Malware.Virus', 'High', 'Content', 'high'),
 (r'brute.?force|too many (failed|authentication|login)|repeated (failures|login)',
  'Access.Forced', 'High', 'Authentication', 'high'),
 (r'(accepted|success\w*)\s+(password|publickey|keyboard|login|auth)|session opened|logged in'
  r'|authentication succeeded|login succeeded|successful connection|new session login|user .{0,20}login\b',
  'Access.Authorized', 'Info', 'Authentication', 'high'),
 (r'(fail\w*|invalid|illegal|incorrect|bad|wrong|unknown|no such)\s+(password|auth\w*|login|user|credential)'
  r'|authentication fail|password authentication.{0,20}fail|user unknown|login refused|login denied'
  r'|(login|auth\w*|password|authentication)\s*failure|failed login',
  'Access.Unauthorized', 'Medium', 'Authentication', 'high'),
 (r'\bdenied\b|\bdeny\b|reject|refused|blocked|forbidden|not allowed|unauthori[sz]ed|permission denied'
  r'|disallow\w*|invalid authorization|unknown community|unauthorized ssh key',
  'Access.Unauthorized', 'Medium', 'Authentication', 'high'),
 (r'\bsudo\b|\bsu\b|setuid|privilege|escalat|root access|became root|enable password',
  'Access.Escalation', 'Medium', 'Authentication', 'high'),
 (r'new (user|group)|delete[d]? user|user removed|group removed|change (user|gid|uid)'
  r'|add .{0,12} to group|useradd|userdel|groupadd|account (created|deleted|locked|unlocked)',
  'Operational.Other', 'Medium', 'Authentication', 'high'),
 (r'logout|log out|session closed|disconnected by user|connection closed by user',
  'Access.Other', 'Info', 'Authentication', 'medium'),
 (r'\bscan\b|probe|sweep|\bVRFY\b|\bEXPN\b|closed port|unknown connection|killing (attempted|unknown)'
  r'|did not receive identification|port ?scan|enumerat',
  'Recon.Network', 'Medium', 'Network', 'high'),
 (r'spoof|masquerad|impersonat|forged|set sender to',
  'Fraud.Masquerade', 'High', 'Network', 'high'),
 (r'phishing|spam\b|unsolicited',
  'Fraud.Phishing', 'Medium', 'Content', 'high'),
 (r'flood|denial of service|\bdos\b|\bddos\b|syn attack|smurf',
  'Availability.DoS', 'High', 'Network', 'high'),
 (r'exceed(ed|s)?|utilization|usage (exceed|high)|capacity|disk space critical'
  r'|overload|too many connections|queue (is )?full|exhaust|out of memory|limit reached'
  r'|no space left|disk full|threshold exceeded',
  'Availability.Overload', 'Medium', 'Log', 'high'),
 (r'(died|crash|panic|core dump|exited due to signal|segfault|abnormal\w*|assertion failed)',
  'Operational.Process Failure', 'Medium', 'Log', 'high'),
 (r'(down|lost|unreachable|no route|timed? ?out|link ?down|not responding|failover|failed over)',
  'Availability.Failure', 'Medium', 'Log', 'high'),
 (r'fail(ure|ed|s)?\b|cannot\b|unable to|not successful|handshake failure|\bcrash\w*|\bproblem\b',
  'Availability.Failure', 'Medium', 'Log', 'high'),
 (r'expired|certificate|clock drift|out of sync|synchroni[sz]ation failed',
  'Availability.Misconfiguration', 'Medium', 'Log', 'medium'),
 (r'(link ?up|is now up|changed state to up|back in service|online|alive|heartbeat|keepalive|unit ?up|\bup\b)',
  'Availability.HeartBeat', 'Info', 'Log', 'medium'),
 (r'misconfig|invalid config|bad config|configuration error|parse error in config',
  'Availability.Misconfiguration', 'Medium', 'Log', 'high'),
 (r'shutdown|startup|start(ing|ed)?\b|stop(ping|ped)?\b|restart|reload|reboot|boot\b'
  r'|listening on|accepting|enabled|disabled|switching to',
  'Operational.Other', 'Info', 'Log', 'medium'),
 (r'temperature|humidity|thermal|fan\b|power supply|voltage|battery',
  'Operational.Other', 'Info', 'Temperature', 'medium'),
 (r'severe|critical|fatal|emergency|alarm',
  'Availability.Failure', 'High', 'Log', 'medium'),
 (r'error|warning|exception|fault|malformed|corrupt|invalid',
  'Availability.Failure', 'Medium', 'Log', 'low'),
]

# per-source profile: (regex on filename, extra Analyzer.Data, fallback Category, fallback Priority)
PROFILES = [
 (r'clamav|symantec|trendmicro|sophos|mcafee', 'Content', 'Malware.Other',      'High'),
 (r'honeyd|kojoney|rishi',                     'Network', 'Recon.Network',      'Medium'),
 (r'selinux|tripwire|suhosin',                 'Host',    'Access.Unauthorized','Medium'),
 (r'shadow-utils|openldap|ldap|radius|ras-securid|pam', 'Authentication', 'Operational.Other', 'Medium'),
 (r'sendmail|vpopmail|imapd|spamassassin|ironport', 'Relay', 'Operational.Other', 'Info'),
 (r'mysql|postgres|oracle|ms-sql',             'Data',    'Operational.Other',  'Info'),
 (r'cisco|juniper|paloalto|sonicwall|checkpoint|f5|netscaler|nortel|extreme|linksys|radware'
  r'|switch|router|vpn|ipchains|ipfw|squid|bluecoat|vigor|arpwatch|bonding|keepalived',
  'Network', 'Operational.Other', 'Info'),
]


def clean(v):
    return ILLEGAL.sub(' ', v)[:2000] if isinstance(v, str) else v


def load(path):
    with open(path, encoding='utf-8') as fh:
        d = yaml.safe_load(fh) or {}
    return (d.get('ruleset') or {}).get('rules') or []


def all_caps(pat):
    return re.findall(r'%\{[A-Z0-9_]+:([^}]+?)(?::\w+)?\}', pat or '')


def raw_caps(pat):
    return [c[len(P):] for c in all_caps(pat) if c.startswith(P)]


def off_namespace(pat):
    c = all_caps(pat)
    return bool(c) and not any(x.startswith(P) for x in c)


def literal(pat):
    """The human-readable text of a pattern: placeholders and regex noise removed."""
    t = re.sub(r'%\{[^}]*\}', ' ', pat or '')
    t = re.sub(r'\(\?P?<[^>]*>', ' ', t)
    t = re.sub(r'\\[sdwSDWb]', ' ', t)
    t = re.sub(r'[\\^$*+?()\[\]{}|]', ' ', t)
    return re.sub(r'\s+', ' ', t).strip()


def family(pat):
    return ' '.join(literal(pat).split()[:6]).lower() or '(no literal text)'


def profile(fname):
    for rx, ad, cat, pri in PROFILES:
        if re.search(rx, fname, re.I):
            return ad, cat, pri
    return None, 'Other.Undetermined', 'Low'


def propose(pat, fname):
    text = literal(pat)
    p_ad, p_cat, p_pri = profile(fname)
    for rx, cat, pri, ad, conf in RULES:
        if re.search(rx, text, re.I):
            return cat, pri, ad, conf
    return p_cat, p_pri, p_ad or 'Log', ('low' if p_cat != 'Other.Undetermined' else 'none')


def sheet_path():
    if '--sheet' in sys.argv:
        return sys.argv[sys.argv.index('--sheet') + 1]
    return OUT


def read_sheet():
    """Read back the reviewer's decisions: {(source, id): (category, priority, ok)}."""
    path = sheet_path()
    if not os.path.exists(path):
        return {}
    import openpyxl
    print(f'reading decisions from: {os.path.basename(path)}')
    ws = openpyxl.load_workbook(path, data_only=True).active
    head = [c.value for c in ws[1]]
    ix = {h: i for i, h in enumerate(head) if h}
    need = ('Source', 'Rule id', 'DECISION', 'FINAL Category', 'FINAL Priority')
    if any(k not in ix for k in need):
        return {}
    out = {}
    for row in ws.iter_rows(min_row=2, values_only=True):
        src, rid = row[ix['Source']], row[ix['Rule id']]
        if src is None or rid is None:
            continue
        dec = str(row[ix['DECISION']] or '').strip().upper()
        note = row[ix['Reviewer note']] if 'Reviewer note' in ix else None
        out[(str(src), rid)] = (row[ix['FINAL Category']], row[ix['FINAL Priority']],
                                dec in ('OK', 'VALIDATED', 'YES', 'OUI'), note)
    return out


def build():
    mapped = {f: {r.get('id') for r in load(os.path.join(IDMEF, f))} for f in os.listdir(IDMEF)}
    rows = []
    for f in sorted(os.listdir(RULESETS)):
        done = mapped.get(f, set())
        p_ad, _, _ = profile(f)
        for r in load(os.path.join(RULESETS, f)):
            if r.get('id') in done:
                continue
            pat = r.get('pattern') or ''
            caps = raw_caps(pat)
            cat, pri, ad, conf = propose(pat, f)
            fields, meta_src = {}, False
            for suffix, target, flag in FIELD_MAP:
                if any(c.endswith(suffix) for c in caps):
                    if flag == 'meta_source':
                        meta_src = True
                    elif target and target not in fields:
                        fields[target] = suffix
            analyzer = list(dict.fromkeys(['Log'] + ([ad] if ad else []) + ([p_ad] if p_ad else [])))
            env = literal(pat).lower()
            for word, tag in (('temperature', 'Temperature'), ('thermal', 'Temperature'),
                              ('humidity', 'Humidity'), ('snmp', 'SNMP'), ('trap', 'SNMP')):
                if word in env and tag not in analyzer:
                    analyzer.append(tag)
            rows.append(dict(
                source=f[:-4], rid=r.get('id'), family=family(pat), literal=literal(pat),
                pattern=pat, sample=(r.get('samples') or [''])[0],
                caps=', '.join(caps) or '(none)', no_entity=not caps,
                meta_src=meta_src, category=cat, priority=pri, analyzer=analyzer,
                fieldmap=fields, confidence=conf, off_ns=off_namespace(pat)))
    rows.sort(key=lambda r: (r['source'], r['family'], r['rid']))

    if '--from-sheet' in sys.argv:
        dec = read_sheet()
        applied = 0
        for r in rows:
            got = dec.get((r['source'], r['rid']))
            if got and got[2]:
                if got[0]:
                    r['category'] = str(got[0]).strip()
                if got[1]:
                    r['priority'] = str(got[1]).strip()
                r['validated'] = True
                r['note'] = got[3] or ''
                applied += 1
            else:
                r['validated'] = False
                r['note'] = (got[3] if got else '') or ''
        print(f'decisions applied : {applied} of {len(rows)} rows marked OK in the review sheet')
    else:
        for r in rows:
            r['validated'] = False
            r['note'] = ''
    return rows


def sheet(rows):
    wb = Workbook(); ws = wb.active; ws.title = 'Mapping review'
    head = ['Source', 'Rule id', 'Family', 'Literal text of the pattern', 'Sample',
            'Captured fields', 'No entity', 'Confidence', 'Proposed Category',
            'Proposed Priority', 'Analyzer.Data', 'Proposed IDMEFv2 fields',
            'meta source', 'meta target', 'DECISION', 'FINAL Category', 'FINAL Priority',
            'Reviewer note', 'Off-namespace', 'Pattern']
    thin = Side(style='thin'); bd = Border(thin, thin, thin, thin)
    hdr = PatternFill('solid', fgColor='D6DCE8')
    yel = PatternFill('solid', fgColor='FFF2CC')
    red = PatternFill('solid', fgColor='FCE4E4')
    gry = PatternFill('solid', fgColor='EDEDED')
    top = Alignment(wrap_text=True, vertical='top')
    for i, h in enumerate(head, 1):
        c = ws.cell(row=1, column=i, value=h)
        c.font = Font(bold=True); c.fill = hdr; c.border = bd; c.alignment = top
    for n, r in enumerate(rows, start=2):
        vals = [r['source'], r['rid'], r['family'], r['literal'], r['sample'], r['caps'],
                'YES' if r['no_entity'] else '', r['confidence'], r['category'], r['priority'],
                ' + '.join(r['analyzer']),
                '\n'.join(f'{k} <- {v}' for k, v in r['fieldmap'].items()) or '(none)',
                'source' if r['meta_src'] else '', 'host',
                'OK' if r.get('validated') else 'TO CONFIRM',
                r['category'], r['priority'], r.get('note', ''),
                'YES' if r['off_ns'] else '', r['pattern']]
        for i, v in enumerate(vals, 1):
            c = ws.cell(row=n, column=i, value=clean(v)); c.border = bd; c.alignment = top
        for col in (15, 16, 17, 18):
            ws.cell(row=n, column=col).fill = yel
        if r['confidence'] in ('none', 'low'):
            ws.cell(row=n, column=8).fill = red
        if r['off_ns']:
            for col in range(1, len(head) + 1):
                ws.cell(row=n, column=col).fill = gry
    for i, w in enumerate([15, 8, 28, 46, 44, 34, 8, 11, 22, 11, 22, 30, 11, 11,
                           13, 22, 13, 24, 12, 58], 1):
        ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w
    ws.freeze_panes = 'C2'
    try:
        wb.save(OUT)
    except PermissionError:
        print(f'WARNING: {os.path.basename(OUT)} is locked (open in Excel?) - sheet not rewritten')


def emit(rows):
    os.makedirs(PROPOSED, exist_ok=True)
    skipped = [r for r in rows if r['off_ns']]
    with open(os.path.join(ROOT, 'tools', 'rules_nonconforming_namespace.txt'), 'w',
              encoding='utf-8') as fh:
        fh.write('Parsing rules capturing outside [Attachment][RawLog][Content].\n'
                 'Left out of the mapping pass: the parsing rule must be fixed first.\n\n')
        for r in sorted(skipped, key=lambda x: (x['source'], x['rid'])):
            fh.write(f"{r['source']:24} id={r['rid']:<10} {r['pattern'][:120]}\n")
    only = None
    if '--only' in sys.argv:
        only = sys.argv[sys.argv.index('--only') + 1]
    bysrc = collections.OrderedDict()
    for r in rows:
        if r['off_ns'] or (only and r['source'] != only):
            continue
        bysrc.setdefault(r['source'], []).append(r)
    written = 0
    for src, rs in bysrc.items():
        n_ok = sum(1 for x in rs if x.get('validated'))
        state = (f'# {n_ok}/{len(rs)} rules validated by the reviewer.'
                 if n_ok else '# Category and Priority are PROPOSALS pending human validation.')
        out = ['# IDMEFv2 mapping - generated by tools/gen_mappings.py',
               state,
               'ruleset:', f'  name: {src}', '  rules:']
        for r in sorted(rs, key=lambda x: x['rid']):
            out += [f"    - id: {r['rid']}"
                    + ('' if r.get('validated') else '   # PROPOSAL - not yet validated'),
                    '      fields:']
            if r['meta_src']:
                out.append('        "[@metadata][IDMEFv2][source]": "source"')
            out.append('        "[@metadata][IDMEFv2][target]": "host"')
            out.append(f'        "[Category][0]": "{r["category"]}"')
            out.append('        "[Analyzer][Data]":')
            out += [f'          - "{a}"' for a in r['analyzer']]
            out.append('        "[Type]": "Cyber"')
            out.append(f'        "[Priority]": "{r["priority"]}"')
            for tgt, suf in r['fieldmap'].items():
                out.append(f'        "{tgt}": "%{{{P}{suf}}}"')
            out.append(f'        "[Description]": "%{{{P}[message]}}"')
            written += 1
        with open(os.path.join(PROPOSED, f'{src}.yml'), 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(out) + '\n')
    return written, len(bysrc), len(skipped)


def main():
    rows = build()
    sheet(rows)
    conf = collections.Counter(r['confidence'] for r in rows)
    cat = collections.Counter(r['category'] for r in rows if not r['off_ns'])
    print(f'rules to map      : {len(rows)}   sources: {len({r["source"] for r in rows})}')
    print(f'no-entity rules   : {sum(1 for r in rows if r["no_entity"])}')
    print('confidence        : ' + ', '.join(f'{k}={v}' for k, v in conf.most_common()))
    print('proposed categories:')
    for k, v in cat.most_common():
        print(f'   {v:4}  {k}')
    if '--emit' in sys.argv:
        w, n, s = emit(rows)
        print(f'emitted           : {w} rules in {n} files -> logstash/idmef_proposed/')
        print(f'left out (off-ns) : {s} rules -> tools/rules_nonconforming_namespace.txt')
    print(f'review sheet      : {OUT}')


if __name__ == '__main__':
    main()
