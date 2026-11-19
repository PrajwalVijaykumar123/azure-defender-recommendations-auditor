#!/bin/sh
# Runs the real scanner.py against a compliant pair and a noncompliant
# pair of Defender for Cloud exports, asserting specific check_ids fire.
set -e
cd "$(dirname "$0")/.."

OUT=/tmp/azd_test_$$
mkdir -p "$OUT"

run() {
  label="$1"
  python3 scanner.py \
    --assessments "test_fixtures/${label}_assessments.json" \
    --secure-score-controls "test_fixtures/${label}_secure_score_controls.json" \
    --json "$OUT/$label.json" --fail-on any > "$OUT/$label.txt" 2>&1
  echo $? > "$OUT/$label.exit"
}

assert_exit() {
  label="$1"; expected="$2"
  actual=$(cat "$OUT/$label.exit")
  [ "$actual" = "$expected" ] && echo "PASS: $label exit code $actual" \
    || { echo "FAIL: $label expected exit $expected, got $actual"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

assert_fires() {
  label="$1"; check_id="$2"
  python3 -c "
import json, sys
findings = json.load(open('$OUT/$label.json'))
sys.exit(0 if any(f['check_id'] == '$check_id' for f in findings) else 1)
" && echo "PASS: $label -> $check_id fired" \
  || { echo "FAIL: $label -> $check_id did not fire"; cat "$OUT/$label.txt"; rm -rf "$OUT"; exit 1; }
}

echo "== Compliant =="
set +e; run compliant; set -e
cat "$OUT/compliant.txt"
assert_exit compliant 0
python3 -c "
import json, sys
findings = json.load(open('$OUT/compliant.json'))
sys.exit(0 if len(findings) == 0 else 1)
" && echo "PASS: compliant produced zero findings" \
  || { echo "FAIL: compliant unexpectedly produced findings"; rm -rf "$OUT"; exit 1; }

echo
echo "== Noncompliant =="
set +e; run noncompliant; set -e
cat "$OUT/noncompliant.txt"
assert_exit noncompliant 1
for cid in AZD-1 AZD-2 AZD-3 AZD-4 AZD-5; do
  assert_fires noncompliant "$cid"
done

# AZD-4 must fire for BOTH categories, not just one.
python3 -c "
import json
findings = json.load(open('$OUT/noncompliant.json'))
azd4 = [f for f in findings if f['check_id'] == 'AZD-4']
assert len(azd4) == 2, f'expected 2 AZD-4 findings (one per category), got {len(azd4)}'
print('PASS: AZD-4 fires once per affected category (Networking and Identity and access)')
"

rm -rf "$OUT"
echo
echo "All tests passed."
