# tools – audit, mapping and test tooling for Concerto-SIEM rules

Everything needed to reproduce the method described in [README-RULES.md](../README-RULES.md): static audit, mapping
proposals and human review, offline replay, and end-to-end injection on a running Concerto-SIEM.

```bash
pip install -r tools/requirements.txt      # pyyaml, openpyxl, regex, pygrok
```

All scripts locate the repository from their own path (`tools/..`) and read `logstash/rulesets` and `logstash/idmef`.
None of them commits or pushes anything.

## Recommended order

| Step | Tool | Output |
|---|---|---|
| 1. Static audit | `concerto_audit.py` | Excel report: coverage, off-schema fields, off-enum values, samples vs patterns |
| 2. Mapping proposals | `gen_mappings.py` | `mapping_review.xlsx` (review sheet), then `logstash/idmef_proposed/` with `--emit` |
| 3. Human review | `mapping_review.xlsx` | DECISION / FINAL Category / FINAL Priority set by a human for every row |
| 4. Offline replay | `offline_grok_check.py` | `offline_grok_report.csv`: where each sample stops (header, predicate, pattern) |
| 5. Syslog framing | `build_framing.py` | `framing.json`: header for raw samples so that they reach their own rule |
| 6. End-to-end test | `inject_parsing_tests.py` | verdict per rule + JSON report, on a running instance |
| (fix) | `patch_match_rb.py`, `patch_sensor_ip.py` | apply the two pipeline fixes to another deployment |
| (fix) | `fix_namespaces.py` | `logstash/rulesets_fixed/` for rules capturing outside `[Attachment][RawLog][Content]` (not validated yet) |

## gen_mappings.py – mapping proposals

```bash
python3 tools/gen_mappings.py                 # write/refresh tools/mapping_review.xlsx (decisions already taken are kept)
python3 tools/gen_mappings.py --only pam      # one source
python3 tools/gen_mappings.py --emit          # write logstash/idmef_proposed/<source>.yml from the reviewed sheet
```
Category and Priority are **proposals** built from the pattern text, the draft-08 enumeration (128 categories) and
per-source profiles. They are never final until a human sets DECISION in the sheet. `logstash/idmef/` is never written.

## offline_grok_check.py – offline replay

```bash
python3 tools/offline_grok_check.py
RULESETS=/path/to/rulesets python3 tools/offline_grok_check.py
```
Replays the syslog header grok of `pipeline/00-my_collected.conf`, each ruleset predicate (`scripts/match.rb`
semantics) and each rule pattern on the rule's own sample. Stages: `HEADER_FAIL`, `PRED_FAIL`, `PATTERN_FAIL`,
`SHADOWED`, `OK`. Uses Python `regex`, not Joni: confirm any result on Logstash (one rule, pam 1, differed).

## build_framing.py – syslog framing of raw samples

```bash
python3 tools/build_framing.py
```
For samples without a usable syslog header, finds offline a header (program name taken from the ruleset predicate)
that lets the line reach its own rule. The sample text is never modified. Writes `framing.json`.

## inject_parsing_tests.py – end-to-end test

```bash
python3 tools/inject_parsing_tests.py --dry-run
python3 tools/inject_parsing_tests.py --only ssh
python3 tools/inject_parsing_tests.py --frame --wait 90
```
Environment: `SYSLOG_HOST` (localhost), `SYSLOG_PORT` (6514), `ES_URL` (http://localhost:9200), `ES_USER`,
`ES_PASS`, `ES_INDEX` (alerts), `ES_LOGS` (logs). Sends each sample over syslog TCP, identifies the new alert by its
raw line and `Ref urn:rule:<id>`, and checks rule, Category and Priority against the mapping. Each failure is located
with the `logs` index: `NOT_COLLECTED`, `NO_RULE_MATCH`, `OTHER_RULE_MATCH`, `MATCHED_NOT_STORED`.
Also count `docker logs <logstash> 2>&1 | grep -c "Could not index event"` before and after: Elasticsearch
rejections are only logged as WARN.

## patch_match_rb.py / patch_sensor_ip.py

```bash
python3 tools/patch_match_rb.py   <concerto>/logstash/scripts/match.rb
python3 tools/patch_sensor_ip.py  <concerto>/logstash/pipeline/00-my_collected.conf
```
Idempotent (markers `S4S-FIX match`, `S4S-FIX sensor-ip`). Restart Logstash afterwards.

## fix_namespaces.py

```bash
python3 tools/fix_namespaces.py
```
Writes corrected copies to `logstash/rulesets_fixed/` and a report; `logstash/rulesets/` is not modified.
**Not validated end to end yet.**

## concerto_audit.py – IDMEFv2 conformance audit

`concerto_audit.py` checks the parsing rules and the IDMEFv2 mappings of a
Concerto-SIEM installation against the IDMEFv2 draft-08 schema, and writes an
Excel report.

### What it checks

- parsing rules that have no IDMEFv2 mapping, and mappings whose id matches no
  parsing rule
- mappings that set no `Category`
- target fields that do not exist in the IDMEFv2 schema
- values that are not part of the enumeration declared by the schema
  (`Category`, `Priority`, …), including the values of `translate` dictionaries
  and their `fallback`
- every `samples:` line replayed against its own pattern, using a built-in GROK
  engine — no Logstash, no container needed
- fields captured by a pattern but never used by the mapping
- id uniqueness across the whole installation

The IDMEFv2 data model is **read from the schema at runtime**: swapping
`IDMEFv2.schema` is all it takes to validate against another draft version.

### Usage

```bash
pip install pyyaml openpyxl regex
python3 concerto_audit.py <path-to-logstash-folder> [report.xlsx] [IDMEFv2.schema]
```

Example, from a Concerto-SIEM checkout:

```bash
python3 tools/concerto_audit.py ./logstash report.xlsx tools/IDMEFv2.schema
```

On Windows, `run_audit.bat` does the same: double-click it, or drag the
`logstash` folder onto it.

### Report

Three sheets: a summary, one line per source with the counters, and the detailed
anomaly list (source, rule id, anomaly type, detail).

### Known false-positive sources, handled

Two pipeline behaviours would otherwise be reported as lost data, and are
accounted for:

- `scripts/fill_alert.rb` fills `Hostname`, `Location`, `IP`, `Port` and
  `GeoLocation` on its own from the `[@metadata][IDMEFv2][source|target]`
  directive;
- a grok in `pipeline/00-my_processed.conf` derives `.ip` / `.hostname` from the
  ECS `address` field.

A pattern capturing one of these is consumed by the pipeline even though no
mapping line mentions it.
