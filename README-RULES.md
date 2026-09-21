# Concerto rules work – method, AI usage and results (DRAFT)

*ReelIT – Abdou Mestari – 21 September 2026 – draft for the consortium, to be completed*

Detailed fixes and gate-2 test results: [docs/GATE2_FIXES.md](docs/GATE2_FIXES.md).

## Scope

Concerto-SIEM parsing rules (`logstash/rulesets`, grok) and their IDMEFv2 draft-08 mappings (`logstash/idmef`).
Starting point: 116 mapped rules (17 sources). In this branch: 425 of 474 rules mapped (74/75 sources), 169 of them
tested end to end. The 49 remaining rules capture fields outside the `[Attachment][RawLog][Content]` namespace; their
fix is prepared locally but not pushed until tested end to end. Correlation (ElastAlert2/Sigma) is not covered yet.

## The gap with a few-hours AI run

Generating rules with AI **is** fast. The difference is not in generation; it is in what is checked afterwards. A rule that loads in Logstash is not
yet a rule that produces a conformant, stored alert:

- **The reference example is not draft-08.** The example in `docs/DetectionRules.md` (the natural context to give an
  AI) uses `Attempt.Login` (not one of the 128 draft-08 categories), `Analyzer.Data: Auth` (not in the enumeration)
  and `[Analyzer][Type]` (not an Analyzer attribute in draft-08, which forbids additional properties). An AI fed with it
  reproduces these values; the rules load and look right, but are not conformant.
- **The alert can be lost without any error.** In this work, an indexed form (`"[Type][0]"`, present in our own first mappings) that looked correct made
  Elasticsearch reject every alert with a single WARN line; `match` predicates are always false in the shipped
  `match.rb`; `Sensor.IP` gets two values when the syslog header carries an IP. None of this is visible without
  reading the alert back from Elasticsearch.
- **Samples do not always match their own rule** (raw lines, masked IPs, truncated lines): a rule "with samples" is not
  a tested rule.

We suggest measuring rather than comparing impressions: running `tools/concerto_audit.py` (static) and
`tools/inject_parsing_tests.py` (end to end) on Maxime's rules would give the same figures as below for both results,
and show exactly where they differ. We agree with the remark that AI makes no difference between 10 and 75 sources
for **generation**; validation, however, still scales with the number of sources (samples, human review of
categories).

## Why it took this long

The mapping work itself is fast once the ground is solid. Most of the time went into making the ground solid:

1. **Two references for IDMEFv2.** The shipped mappings were written against the old SECEF schema (rev. 0.3, 58
   categories). Draft-08 (2.D.V08, 128 categories) removed or renamed many values (e.g. `Recon.Scanning`,
   `Intrusion.UserCompromise`), so the existing mappings had to be audited and partly rewritten before extending them.
2. **No way to test existed.** Rules came with samples, but nothing executed them end to end. We had to build a
   static audit first, then an offline replay, then an injection harness against a running instance.
3. **Failures are silent.** A mapping that looks correct can still produce no alert: Elasticsearch rejects it with a
   single WARN line (`[Type][0]`, `Sensor.IP`), a predicate is always false without any error (`match.rb`), or the
   mapping directory is simply not mounted by the default `docker-compose.yml`. Each case had to be found on the
   running stack, one by one.
4. **Samples are not test data.** Many are raw lines without syslog header, masked (`x.y`), truncated or with fields
   swapped; each failure had to be classified as rule defect or sample defect before touching anything.
5. **Human review on purpose.** Every category and priority (358 proposed rows) was decided by a human, not by the AI.
6. **AI wrong leads.** Several causes proposed by the AI were wrong and cost iterations; the rule became "no fix
   without evidence from the logs or the index".

## AI used and how

- **Tools**: **Gemini Pro** (Google) as the main AI, then **Claude** (Anthropic) as a second, contradictory AI to
  challenge the results, the proposals and the explanations of failures. Both worked on a local copy of the
  repositories; **nothing was pushed** by an AI.
- **Real environment**: **every command was run by a human on a real environment, the ReelIT lab** (a full
  Concerto-SIEM stack: Logstash, Kafka, Elasticsearch), not on a simulation.
- **Prompting style**: task + hard constraints, e.g. *"map every unmapped rule to IDMEFv2 draft-08 (schema 2.D.V08,
  128 categories), propose only, the category decision is mine; keep shipped files untouched; local only"*. Then short
  iterative prompts on evidence: *"here is the log output, find the cause, prove it before fixing"*.
- **Division of work**: AI = extraction, heuristics, bulk editing, test tooling, log triage. Human = every category
  and priority decision (review sheet), execution on the VM, acceptance of each fix.

## Prompts you can reuse

Reconstructed from the working sessions (the exchanges were iterative; these are the reusable core, not verbatim logs).
Always start with the constraints block.

**Constraints (first message)**
```
You work on my local copy of Concerto-SIEM only. Never commit, never push. When a command must run on the test
instance, list it clearly: I run it myself and paste the output. Reference: IDMEFv2 draft-08, schema 2.D.V08
(logstash/IDMEFv2.schema). Do not change a shipped file without telling me why and showing the diff.
```

**1. Static audit**
```
For every ruleset in logstash/rulesets and every mapping in logstash/idmef, report: rules without mapping, mapping
fields not in the draft-08 schema, values not in its enumerations (Category, Priority, Analyzer.Data...), captures
outside [Attachment][RawLog][Content], and whether each sample matches its own pattern. Report only, fix nothing.
```

**2. Mapping proposals**
```
For each parsing rule without mapping, propose an IDMEFv2 mapping: Category from the 128 draft-08 values only,
Priority, Analyzer.Data, and Source/Target fields built only from captured fields. Give a confidence and the reason.
Write a review sheet with an empty DECISION column: I decide every row, you never decide a category.
```

**3. End-to-end test**
```
Write a script that sends each rule sample over syslog TCP to Logstash, finds the resulting alert in Elasticsearch
(Ref urn:rule:<id>), and checks rule id, Category and Priority against the mapping. For every failure, locate where
the line stopped (not collected / no rule matched / matched but not indexed) using the logs index.
```

**4. Triage**
```
Here are the harness output and the Logstash log. Explain the failures. For each cause, show the evidence (log line,
indexed document, code line). Classify as rule defect, mapping defect, pipeline defect or sample defect.
Propose a fix only when the cause is proven, and wait for my go.
```

## Method (four gates)

| Gate | What | Tool |
|---|---|---|
| 1. Static conformance | schema, enums, required fields, field namespaces | `concerto_audit.py` |
| 2. Proposal + human review | mapping proposals from the pattern text, reviewed row by row (358 rows, 36 corrected) | `gen_mappings.py` + review sheet |
| 3. Offline replay | syslog header grok + ruleset predicates + rule patterns replayed on each sample | `offline_grok_check.py` |
| 4. End-to-end injection | each sample sent over syslog to a running Concerto; alert read back from Elasticsearch; verdict per rule; failures located (not collected / no rule match / matched but not indexed) using the `logs` index | `inject_parsing_tests.py` |

## Results

| Step (169 rules with sample + mapping) | PASS |
|---|---|
| Baseline, samples sent verbatim | 63 |
| + pattern/predicate fixes (10 rulesets), predicate engine fix, Sensor.IP fix, syslog framing of raw samples | 145 |
| + ras-securid mapping fix | 147 |

0 wrong category, 0 wrong priority. The remaining failures come from the shipped samples (masked IPs, truncated
lines, non-syslog formats, swapped fields), not from rules or mappings.

**Product defects found** (silent – no error, the alert or the rule is simply lost):
1. `"[Type][0]": "Cyber"` in mappings creates an object `{0: Cyber}`; Elasticsearch rejects the alert (only a WARN).
   Present in most mappings, including the ones already in Concerto-Rules. Fix: `"[Type]": "Cyber"`.
2. `scripts/match.rb`: `Regex.new` instead of `Regexp.new`, and `match` missing from the operator table → every
   `match` predicate is always false (4 rulesets never fire).
3. `00-my_collected.conf`: when the syslog header carries an IP, `host.ip` gets two values → `Sensor.IP` rejected.
4. Conversion artefacts in patterns (`\.` instead of `\d` or `\(`), prefixes already consumed by the header, a
   malformed capture, a field name with an extra `]`.
5. Unresolved references (`%{[...]}`) are kept literally when an optional capture is missing; hostnames can reach
   IP-typed fields (`IPORHOST` → `[Target][0][IP]`).

## Pitfalls met

- ** The AI proposed several wrong explanations (schema, timestamps, its own harness).
  Rule adopted: no fix without evidence from the logs or the index.
- **Silent failures** in the pipeline hide defects; counting `Could not index event` is mandatory in any test.
- **Samples are not test data**: many are not syslog-framed, masked or truncated.
- **Regex engines differ** (Python vs Joni/Oniguruma): offline replay must be confirmed on Logstash.
- **Taxonomy gaps**: no spam category in draft-08 (nearest fit used, reported to WP3); some vendor semantics uncertain.

## Confidence

- **High**: syntax and schema conformance (all 425 mapped rules), extraction and alert production for the 147 rules passing gate 4.
- **Medium**: category/priority semantics – human-reviewed, a few flagged "vendor semantics to confirm".
- **Low / not measured**: mapped rules not tested end to end (256 of 425) – static validation only; behaviour on real
  traffic.

## Limits of AI usage

It cannot validate on real traffic, cannot decide vendor semantics reliably, may state wrong causes confidently, and
depends on the quality of samples. It accelerated the bulk work (extraction, proposals, tooling, triage) by a large
factor, but every decision and every test run stayed human.

## Proposals

1. **CI for rules**: every rule must carry ≥1 realistic, syslog-framed sample (documentation IPs 192.0.2.0/24 instead of
   masks) that must match *its own* rule; run the injection harness in CI.
2. **Load-time validation of mappings**: forbid `[...][0]` on array fields, check enum values and field types (IP vs
   hostname) before deployment.
3. **No silent rescue**: log predicate/grok errors; count and expose Elasticsearch rejections (dead-letter queue).
4. **Drop unresolved `%{...}`** values in the pipeline instead of storing them.
5. **Syntax**: a grok/field-name linter; one namespace (`[Attachment][RawLog][Content]…`) enforced.
6. **Taxonomy**: add a spam category (WP3).
7. **Documentation used as AI context**: align the example of `docs/DetectionRules.md` with draft-08 (`Attempt.Login`,
   `Analyzer.Data: Auth`, `[Analyzer][Type]`) and fix its path (`logstash/to_idmef/` → `logstash/idmef/`) before giving
   it to an AI.

## Validation still needed

Real logs from the pilots (WP8); correlation tests (TESTPLAN.md, flat fields prerequisite); deployment test of the
namespace-fixed rulesets (49 rules); consortium review of categories; review of the product fixes above by the
Concerto-SIEM maintainers.
