#!/usr/bin/env bash
#
# inject_correlation_tests.sh — exercise the correlation rules of this repository
# by injecting IDMEFv2 alerts directly into the Concerto HTTP input.
#
# Usage:
#   ./inject_correlation_tests.sh            # run every scenario
#   ./inject_correlation_tests.sh 3          # run scenario 3 only
#
# Prerequisites: the flat fields Source_IP, Source_User, Target_User,
# Target_Service must exist (Ruby filter + prune whitelist + index mapping).
# See TESTPLAN.md, section 1.

set -euo pipefail

HOST="${CONCERTO_HOST:-localhost}"
PORT="${CONCERTO_HTTP_PORT:-4690}"
URL="http://${HOST}:${PORT}"
ONLY="${1:-all}"

uuid() { cat /proc/sys/kernel/random/uuid 2>/dev/null || python3 -c 'import uuid;print(uuid.uuid4())'; }
now()  { date -u +%Y-%m-%dT%H:%M:%SZ; }

# send <category> <analyzer-data> <source-ip> <target-user> <target-service> <description>
send() {
  local cat="$1" data="$2" sip="$3" tuser="$4" tsvc="$5" desc="$6"
  local src="" tgt=""
  [ -n "$sip" ]   && src="\"Source\": [{\"IP\": \"${sip}\"}],"
  if [ -n "$tuser" ] || [ -n "$tsvc" ]; then
    tgt="\"Target\": [{"
    [ -n "$tuser" ] && tgt="${tgt}\"User\": \"${tuser}\""
    [ -n "$tuser" ] && [ -n "$tsvc" ] && tgt="${tgt}, "
    [ -n "$tsvc" ]  && tgt="${tgt}\"Service\": \"${tsvc}\""
    tgt="${tgt}}],"
  fi
  curl -sS -o /dev/null -w "%{http_code} " -X POST "$URL" \
    -H 'Content-Type: application/json' \
    -d "{
      \"Version\": \"2.D.V08\",
      \"ID\": \"$(uuid)\",
      \"CreateTime\": \"$(now)\",
      \"Analyzer\": {
        \"IP\": \"192.0.2.10\",
        \"Name\": \"reelit-correlation-test\",
        \"Model\": \"test-injector\",
        \"Category\": [\"LOG\"],
        \"Data\": [${data}],
        \"Method\": [\"Monitor\"],
        \"Type\": \"Cyber\"
      },
      \"Category\": [\"${cat}\"],
      \"Priority\": \"Medium\",
      \"Type\": \"Cyber\",
      \"Description\": \"${desc}\",
      ${src}
      ${tgt}
      \"Status\": \"Incident\"
    }"
}

run() { [ "$ONLY" = "all" ] || [ "$ONLY" = "$1" ]; }

if run 1; then
echo; echo "### 1. firewall_scan — expect 1 Recon.Network / High"
for i in $(seq 1 60); do
  send "Access.Unauthorized" '"Log","Network"' "198.51.100.7" "" "" "ASA dropped packet #$i"
done; echo
fi

if run 2; then
echo; echo "### 2. account_bruteforce — expect 1 Access.Forced / High on victim1"
for i in $(seq 1 12); do
  send "Access.Unauthorized" '"Log","Authentication"' "198.51.100.$((10+i))" "victim1" "" "VPN login denied #$i"
done; echo
fi

if run 3; then
echo; echo "### 3. sudo_failures — expect 1 Access.Escalation / High on victim2"
for i in $(seq 1 6); do
  send "Access.Other" '"Log","Authentication"' "" "victim2" "sudo" "3 incorrect sudo password attempts #$i"
done; echo
fi

if run 4; then
echo; echo "### 4. masquerade_burst — expect 1 Fraud.Masquerade / High"
for i in $(seq 1 6); do
  send "Fraud.Masquerade" '"Log","Network"' "198.51.100.9" "" "" "Spoofed address detected #$i"
done; echo
fi

if run 5; then
echo; echo "### 5. password_spraying — expect 1 Access.Forced / High (value_count, to validate)"
for u in alice bob carol dave erin frank grace heidi ivan judy; do
  send "Access.Unauthorized" '"Log","Authentication"' "198.51.100.30" "$u" "" "Login denied for $u"
done; echo
fi

if run 6; then
echo; echo "### 6. bruteforce_success — expect 1 Access.Forced / High (temporal_ordered, to validate)"
for i in $(seq 1 5); do
  send "Access.Unauthorized" '"Log","Authentication"' "198.51.100.40" "victim3" "" "Login denied #$i"
done
sleep 2
send "Access.Authorized" '"Log","Authentication"' "198.51.100.40" "victim3" "" "Login accepted"
echo
fi

if run 7; then
echo; echo "### 7. NEGATIVE CONTROL — below every threshold, nothing must fire"
for i in $(seq 1 3); do
  send "Access.Unauthorized" '"Log","Authentication"' "203.0.113.99" "nobody" "" "Login denied #$i (control)"
done; echo
fi

echo; echo "Injection done. Wait for one correlator cycle, then run the checks in TESTPLAN.md section 3."
