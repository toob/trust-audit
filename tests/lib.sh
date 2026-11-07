# shellcheck shell=bash
# tests/lib.sh - pure shell assertions, sourced by the tests.
# Usage in a test:  . "$(dirname "$0")/lib.sh"
PASS=0; FAIL=0
# FAILFAST=1 stops at the first failed assertion.
nok() { FAIL=$((FAIL+1)); echo "  NOK - $1"; [ "${FAILFAST:-0}" = 1 ] && { echo "PASS=$PASS FAIL=$FAIL"; exit 1; }; return 0; }

assert_eq() { # desc expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok  - $1"
  else nok "$1 (expected='$2' actual='$3')"; fi
}

assert_contains() { # desc file substring
  if grep -qF -- "$3" "$2" 2>/dev/null; then PASS=$((PASS+1)); echo "  ok  - $1"
  else nok "$1 ('$3' not found in $2)"; fi
}

assert_rc() { # desc expected_rc actual_rc
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  ok  - $1"
  else nok "$1 (expected rc=$2 actual=$3)"; fi
}

finish() { echo "PASS=$PASS FAIL=$FAIL"; [ "$FAIL" -eq 0 ]; }

# Isolated temporary directory, cleaned up on exit.
new_tmp() { mktemp -d "${TMPDIR:-/tmp}/trust-audit-test.XXXXXX"; }
