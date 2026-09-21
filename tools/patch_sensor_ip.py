#!/usr/bin/env python3
"""Sensor.IP fix for pipeline/00-my_collected.conf (test only, run on the VM copy).
host.ip receives the TCP source IP only when the syslog header gave none,
so it never becomes a 2-value array (ES rejects Sensor.IP = "a,b").
Usage: python3 patch_sensor_ip.py <path to 00-my_collected.conf>"""
import sys, re
p = sys.argv[1]
s = open(p, newline='').read()
nl = '\r\n' if '\r\n' in s else '\n'
line_re = re.compile(r"[ \t]*'\[Attachment\]\[RawLog\]\[Content\]\[host\]\[ip\]'\s*=>\s*'%\{\[@metadata\]\[input\]\[tcp\]\[source\]\[ip\]\}'\r?\n")
if 'S4S-FIX sensor-ip' in s:
    sys.exit('already patched')
m = line_re.search(s)
if not m:
    sys.exit('line not found - nothing changed')
s = s[:m.start()] + s[m.end():]
block = nl.join([
    "  # S4S-FIX sensor-ip: only when the header carried no IP",
    "  if ![Attachment][RawLog][Content][host][ip] {",
    "    mutate {",
    "      add_field => {",
    "        '[Attachment][RawLog][Content][host][ip]' => '%{[@metadata][input][tcp][source][ip]}'",
    "      }",
    "    }",
    "  }", ""])
i = s.index('  mutate {', s.index("timeout_scope"))
s = s[:i] + block + nl + s[i:]
open(p, 'w', newline='').write(s)
print('patched', p)
