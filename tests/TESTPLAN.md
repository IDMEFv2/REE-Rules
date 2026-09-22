# Test plan — correlation rules

How to load the rules of this repository on a Concerto-SIEM deployment, inject
controlled alerts, and prove which rules fire and which do not.

Nothing here modifies a shipped rule. Every step is reversible.

---

## 1. Prerequisite — the flat fields must exist

The correlation rules select and group on flat fields (`Source_IP`,
`Source_User`, `Target_User`, `Target_Service`). A stock Concerto-SIEM
deployment does **not** produce them: `logstash/pipeline/00-my_stored.conf`
carries no flattening filter, `IDMEFv2.mapping` declares no such property.

Without this section, every rule reads its events and matches **zero**, silently.
That includes the two rules already published here.

Three synchronised changes are required. Miss one and the field disappears with
no error.

**1.1 — Ruby filter**, in `logstash/pipeline/00-my_stored.conf`, before the
`prune` block:

```ruby
ruby {
  code => "
    source = event.get('[Source]')
    if source.is_a?(Array) && source[0]
      event.set('[Source_IP]',   source[0]['IP'])   if source[0]['IP']
      event.set('[Source_User]', source[0]['User']) if source[0]['User']
    end
    target = event.get('[Target]')
    if target.is_a?(Array) && target[0]
      event.set('[Target_User]',    target[0]['User'])    if target[0]['User']
      event.set('[Target_Service]', target[0]['Service']) if target[0]['Service']
      event.set('[Target_IP]',      target[0]['IP'])      if target[0]['IP']
    end
  "
}
```

`Target_IP` is not used by the current rules. It is added here because 49 of the
122 mappings populate `Target[0][IP]`, and without a flat copy the whole
availability family (`Availability.DoS`, `DDoS`, `Overload`) cannot be
correlated on anything.

**1.2 — prune whitelist**, same file, add to `whitelist_names`:

```
'Source_IP', 'Source_User', 'Target_User', 'Target_Service', 'Target_IP',
```

**1.3 — index mapping**, in `logstash/IDMEFv2.mapping`, under
`mappings.properties` (the index sets `dynamic: false`, so an undeclared field is
stored but never indexed, therefore never aggregatable):

```json
"Source_IP":      { "type": "keyword", "norms": false },
"Source_User":    { "type": "keyword", "norms": false },
"Target_User":    { "type": "keyword", "norms": false },
"Target_Service": { "type": "keyword", "norms": false },
"Target_IP":      { "type": "keyword", "norms": false }
```

On an **existing** index the file is not enough — it only applies at index
creation. Declare the fields on the live index, a non-destructive operation:

```bash
curl -u elastic:elastic -H 'Content-Type: application/json' \
  -X PUT "http://localhost:9200/alerts/_mapping" -d '{"properties":{
    "Source_IP":{"type":"keyword","norms":false},
    "Source_User":{"type":"keyword","norms":false},
    "Target_User":{"type":"keyword","norms":false},
    "Target_Service":{"type":"keyword","norms":false},
    "Target_IP":{"type":"keyword","norms":false}}}'
```

**Verify before going further** — inject one alert, then:

```bash
curl -s -u elastic:elastic \
  'http://localhost:9200/alerts/_search?size=0' -H 'Content-Type: application/json' \
  -d '{"aggs":{"by_ip":{"terms":{"field":"Source_IP"}}}}' | python3 -m json.tool
```

Non-empty buckets: the chain works. Empty buckets: one of the three changes is
missing — do not continue, every result below would be a false negative.

---

## 2. Load the rules

```bash
cp correlator/rules/*.yml <concerto>/correlator/rules/
docker compose -p proto restart correlator
```

`docker-compose.yml` mounts `./correlator/rules` on `/opt/sigma_rules`.

**2.1 — Which rules compiled?** This is the first result of the test, and the
only one that matters for `value_count` and `temporal_ordered`, whose support by
the Sigma to ElastAlert backend is not established:

```bash
docker compose -p proto logs correlator | grep -iE 'error|traceback|unsupported|cannot'
docker compose -p proto exec correlator ls -1 /opt/elastalert/rules/
```

A rule absent from `/opt/elastalert/rules/` did not compile. Record which ones,
with the exact error: that is a reportable finding, not a failure of the test.

> After wiping Elasticsearch, the correlator keeps failing with
> `no such index [elastalert_status]` until it is restarted. Restart it before
> concluding anything.

---

## 3. Inject and observe

```bash
./tests/inject_correlation_tests.sh          # every scenario
./tests/inject_correlation_tests.sh 3        # one scenario
```

| # | Scenario | Injected | Expected result |
|---|----------|----------|-----------------|
| 1 | `firewall_scan` | 60 × `Access.Unauthorized` / `Network`, one source IP, < 1 min | 1 alert `Recon.Network` / High |
| 2 | `account_bruteforce` | 12 × `Access.Unauthorized` / `Authentication` on `victim1`, 12 distinct sources | 1 alert `Access.Forced` / High |
| 3 | `sudo_failures` | 6 × `Access.Other`, `Target_Service: sudo`, `victim2` | 1 alert `Access.Escalation` / High |
| 4 | `masquerade_burst` | 6 × `Fraud.Masquerade`, one source IP | 1 alert `Fraud.Masquerade` / High |
| 5 | `password_spraying` | 10 accounts from a single source IP | 1 alert `Access.Forced` / High — **`value_count`, to validate** |
| 6 | `bruteforce_success` | 5 denials then 1 grant on `victim3` | 1 alert `Access.Forced` / High — **`temporal_ordered`, to validate** |
| 7 | negative control | 3 denials on `nobody` | **nothing** must fire |

Scenario 2 is the one that proves the design: twelve different source IPs, a
single targeted account. A rule grouped on `Source_IP` would never see it.

### Checks

**Correlator, per rule — hits read and matches produced:**

```bash
curl -s -u elastic:elastic \
  'http://localhost:9200/elastalert_status_status/_search?size=50&sort=@timestamp:desc' \
  -H 'Content-Type: application/json' \
  -d '{"_source":["rule_name","hits","matches","@timestamp"]}' | python3 -m json.tool
```

`hits > 0, matches = 0` is the nested-field signature: the rule reads the events
but the grouping returns nothing. Go back to section 1.

**Alerts actually generated:**

```bash
curl -s -u elastic:elastic \
  'http://localhost:9200/alerts/_count?q=Category:Access.Forced'
curl -s -u elastic:elastic \
  'http://localhost:9200/alerts/_search?q=Priority:High&size=20' \
  -H 'Content-Type: application/json' \
  -d '{"_source":["CreateTime","Category","Description","CorrelID"]}' | python3 -m json.tool
```

A correlated alert carries a `CorrelID`. That is what distinguishes it from the
base alerts that produced it.

**Schema rejections — the step people skip:**

```bash
docker compose -p proto logs logstash | grep -c _schemacheckfailure
```

The count must not increase. A rejected alert is still stored and displayed, so
neither Elasticsearch nor the GUI will tell you anything is wrong.

---

## 4. Recording the result

For each rule, record: compiled yes/no, hits read, matches, alert generated,
`CorrelID` present. A rule that does not compile and a rule that compiles but
never matches are two different findings, and only the second one is about the
nested fields.
