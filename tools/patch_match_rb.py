#!/usr/bin/env python3
"""match.rb fix (test only): `match`/`not_match` predicates always evaluated to false
(Regex instead of Regexp, and 'match' missing from the operations table). Returns the regex result directly.
Usage: python3 patch_match_rb.py <path to scripts/match.rb>"""
import sys, re
p = sys.argv[1]
s = open(p, newline='').read()
if 'S4S-FIX match' in s:
    sys.exit('already patched')
m = re.search(r"opd2 = opd1\s*\n\s*opd1 = Regexp?\.new\(eval_predicate\(predicate\['operands'\]\[1\], event\)\)\.match\(opd1\)", s)
if not m:
    sys.exit('not found - nothing changed')
new = ("m = Regexp.new(eval_predicate(predicate['operands'][1], event)).match(opd1.to_s) # S4S-FIX match\n"
       "      return op == 'match' ? !m.nil? : m.nil?")
s = s[:m.start()] + new + s[m.end():]
open(p, 'w', newline='').write(s)
print('patched', p)
