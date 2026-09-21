# Fixes to shipped Concerto-SIEM files — for review with the maintainers

These files **replace** files shipped by Concerto-SIEM, so they are kept apart from the rules (the repository rule is
"additions only"). They were validated end to end in the ReelIT lab (see [../../docs/GATE2_FIXES.md](../../docs/GATE2_FIXES.md)).
To apply them on a deployment, copy the tree over `<concerto>/logstash/` and restart Logstash; the full change set is
in `concerto-siem-gate2.diff`.

| File | Change |
|---|---|
| `logstash/rulesets/` (10 files, 34 rules) | patterns/predicates that could not match their own sample: bluecoat-system, apc-emu, sophos, cisco-asa, cisco-router, imapd, ipchains, tripwire, ironport, pam |
| `logstash/scripts/match.rb` | `match`/`not_match` predicates were always false (`Regex` instead of `Regexp`, `match` missing from the operator table, both errors silently rescued) |
| `logstash/pipeline/00-my_collected.conf` | TCP source IP added to `host.ip` only when the syslog header has none (otherwise `Sensor.IP = "a,b"`, rejected by Elasticsearch) |

The 49 rules capturing outside `[Attachment][RawLog][Content]` are **not** touched here (fix prepared, not yet
validated end to end).
