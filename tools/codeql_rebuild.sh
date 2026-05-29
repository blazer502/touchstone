#!/usr/bin/env bash
# Rebuild the kernel CodeQL DB with prepare ISOLATED from the traced build
# (the first build under-extracted net/ — prepare chained inside the traced
# command raced the extractor). Verify net/ extraction before swapping in.
set -u
REPO=/home/chanyoung/veri-agent
SRC=$REPO/eval/kernelctf-latest/linux/source
DB=$REPO/run-logs/codeql-db/kernel-netfs3
CODEQL=$REPO/tools/codeql/codeql

cd "$SRC" || exit 1
echo "=== make clean ==="; make clean >/dev/null 2>&1
echo "=== make prepare (UNTRACED, isolated) ==="; make -j32 prepare >/dev/null 2>&1; echo "prepare rc=$?"
echo "=== codeql database create (traced: make net/ fs/ only) ==="
"$CODEQL" database create "$DB" \
  --language=cpp --source-root="$SRC" \
  --command="bash -c 'make -j1 net/ && make -j16 fs/'" --overwrite
echo "create rc=$?"
echo "=== verify net/ extraction ==="
"$CODEQL" query run --database="$DB" --additional-packs="$REPO/tools/codeql" \
  --output="$REPO/run-logs/diag-coverage2.bqrs" \
  "$REPO/tools/codeql-queries/diag_coverage.ql" >/dev/null 2>&1
"$CODEQL" bqrs decode --format=csv "$REPO/run-logs/diag-coverage2.bqrs"
