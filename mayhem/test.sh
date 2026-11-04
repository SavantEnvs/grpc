#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the known-answer self-test (mayhem/selftest.cc, built by mayhem/build.sh) for gRPC core.
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# grpc_selftest checks fixed known answers (RFC 7541 Huffman vectors, URI/percent-encoding/JSON/HTTP/sockaddr parse
# results, gzip decode, service-config validation, chaotic-good header bytes) against a normal-flags libgrpc and
# prints one `PASS name` / `FAIL name` line per check. A missing binary, missing output or a short count is a failure.
EXPECTED=59
BIN="$SRC/grpc_selftest"
[ -x "$BIN" ] || { echo "missing $BIN — mayhem/build.sh should have built it" >&2; emit_ctrf grpc-selftest 0 1 0; exit 1; }

OUT="$(timeout 600 "$BIN" 2>&1)"; rc=$?
printf '%s\n' "$OUT" | grep -E '^(FAIL|SUMMARY)' >&2 || true
passed=$(printf '%s\n' "$OUT" | grep -c '^PASS ' || true)
failed=$(printf '%s\n' "$OUT" | grep -c '^FAIL ' || true)
summary=$(printf '%s\n' "$OUT" | grep -c "^SUMMARY pass=$passed fail=$failed\$" || true)
if [ "$rc" -ne 0 ] || [ "$summary" -ne 1 ] || [ "$passed" -ne "$EXPECTED" ]; then
  failed=$(( failed > 0 ? failed : 1 ))
  echo "selftest rc=$rc passed=$passed (want $EXPECTED) summary-line-matches=$summary" >&2
fi
emit_ctrf grpc-selftest "$passed" "$failed" 0
