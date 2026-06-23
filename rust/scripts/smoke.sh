#!/usr/bin/env bash
#
# End-to-end smoke test for s3gateway-rs (plaintext mode), driven by the AWS CLI.
#
# Builds the binary, starts the server on a throwaway data dir + port, then
# exercises the full S3 surface and reports PASS/FAIL per operation. Kills the
# server on exit.
#
# Usage:  rust/scripts/smoke.sh
#   Optional env: PORT (default 8444), AWS (path to aws cli, default `aws` on PATH).
#
# Requires: cargo, aws-cli, md5sum.

set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # the rust/ crate dir
PORT="${PORT:-8444}"
AWS="${AWS:-aws}"
DATA_DIR="$(mktemp -d /tmp/s3rs-smoke-data.XXXXXX)"
WORK="$(mktemp -d /tmp/s3rs-smoke-work.XXXXXX)"
CREDS="$WORK/creds.json"
EP="--endpoint-url http://localhost:${PORT}"

export AWS_ACCESS_KEY_ID=test-access-key
export AWS_SECRET_ACCESS_KEY=test-secret-key
export AWS_DEFAULT_REGION=us-east-1
# Force the AWS CLI to use small multipart chunks so a ~20MB object uploads as
# a real multipart (exercises the multipart path end-to-end via `s3 cp`).
export AWS_S3_MULTIPART_THRESHOLD=8MB
export AWS_S3_MULTIPART_CHUNKSIZE=8MB

PASS=0
FAIL=0
SERVER_PID=""

cleanup() {
  [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
  rm -rf "$DATA_DIR" "$WORK"
}
trap cleanup EXIT

ok()   { echo "PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL: $1"; FAIL=$((FAIL+1)); }
check(){ if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (expected [$2] got [$1])"; fi; }

echo "== building =="
( cd "$HERE" && cargo build 2>&1 | tail -1 ) || { echo "build failed"; exit 1; }

cat > "$CREDS" <<EOF
{"credentials":[{"accessKeyId":"test-access-key","secretAccessKey":"test-secret-key"}]}
EOF

echo "== starting server (plaintext) on :$PORT =="
"$HERE/target/debug/s3gateway-rs" --data-dir "$DATA_DIR" --credentials "$CREDS" \
  --port "$PORT" --workers 2 > "$WORK/server.log" 2>&1 &
SERVER_PID=$!

# Wait for health.
for _ in $(seq 1 50); do
  if curl -sf "http://localhost:${PORT}/healthz" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

B=smoke-bucket

echo "== health check =="
H=$(curl -s "http://localhost:${PORT}/healthz")
check "$H" '{"status":"ok"}' "healthz"

echo "== create-bucket =="
$AWS $EP s3 mb "s3://$B" >/dev/null 2>&1 && ok "create-bucket" || bad "create-bucket"

echo "== put-object (small) =="
echo "small-object-content-12345" > "$WORK/small.txt"
$AWS $EP s3 cp "$WORK/small.txt" "s3://$B/small.txt" --no-progress >/dev/null 2>&1 \
  && ok "put-object small" || bad "put-object small"

echo "== get-object (small) + md5 =="
$AWS $EP s3 cp "s3://$B/small.txt" "$WORK/small-dl.txt" --no-progress >/dev/null 2>&1
check "$(md5sum < "$WORK/small.txt")" "$(md5sum < "$WORK/small-dl.txt")" "get-object small md5"

echo "== head-object =="
LEN=$($AWS $EP s3api head-object --bucket "$B" --key small.txt --query 'ContentLength' --output text 2>/dev/null)
check "$LEN" "$(wc -c < "$WORK/small.txt" | tr -d ' ')" "head-object content-length"

echo "== put/get 20MB (auto-multipart via s3 cp) + md5 =="
head -c 20971520 /dev/urandom > "$WORK/big.bin"
$AWS $EP s3 cp "$WORK/big.bin" "s3://$B/big.bin" --no-progress >/dev/null 2>&1 \
  && ok "put-object 20MB" || bad "put-object 20MB"
$AWS $EP s3 cp "s3://$B/big.bin" "$WORK/big-dl.bin" --no-progress >/dev/null 2>&1
check "$(md5sum < "$WORK/big.bin")" "$(md5sum < "$WORK/big-dl.bin")" "get-object 20MB md5"

echo "== range GET (bytes 0-4) =="
$AWS $EP s3api get-object --bucket "$B" --key small.txt --range "bytes=0-4" "$WORK/range.txt" >/dev/null 2>&1
check "$(cat "$WORK/range.txt")" "small" "range GET first 5 bytes"

echo "== explicit multipart (create -> 3 parts -> complete -> get) =="
UPID=$($AWS $EP s3api create-multipart-upload --bucket "$B" --key mp.bin --query 'UploadId' --output text 2>/dev/null)
if [ -n "$UPID" ]; then ok "create-multipart-upload"; else bad "create-multipart-upload"; fi
head -c 5242880 /dev/urandom > "$WORK/p1"
head -c 5242880 /dev/urandom > "$WORK/p2"
head -c 1048576 /dev/urandom > "$WORK/p3"
cat "$WORK/p1" "$WORK/p2" "$WORK/p3" > "$WORK/mp-expected.bin"
# Note: --output text returns ETags WITH embedded quotes; strip them so we can
# re-quote cleanly when building the completion JSON.
strip_q() { echo "$1" | tr -d '"'; }
E1=$(strip_q "$($AWS $EP s3api upload-part --bucket "$B" --key mp.bin --part-number 1 --upload-id "$UPID" --body "$WORK/p1" --query 'ETag' --output text 2>/dev/null)")
E2=$(strip_q "$($AWS $EP s3api upload-part --bucket "$B" --key mp.bin --part-number 2 --upload-id "$UPID" --body "$WORK/p2" --query 'ETag' --output text 2>/dev/null)")
E3=$(strip_q "$($AWS $EP s3api upload-part --bucket "$B" --key mp.bin --part-number 3 --upload-id "$UPID" --body "$WORK/p3" --query 'ETag' --output text 2>/dev/null)")
if [ -n "$E1" ] && [ -n "$E2" ] && [ -n "$E3" ]; then ok "upload-part x3"; else bad "upload-part x3"; fi
NPARTS=$($AWS $EP s3api list-parts --bucket "$B" --key mp.bin --upload-id "$UPID" --query 'length(Parts)' --output text 2>/dev/null)
check "$NPARTS" "3" "list-parts count"
cat > "$WORK/parts.json" <<EOF
{"Parts":[{"PartNumber":1,"ETag":"\"$E1\""},{"PartNumber":2,"ETag":"\"$E2\""},{"PartNumber":3,"ETag":"\"$E3\""}]}
EOF
CETAG=$($AWS $EP s3api complete-multipart-upload --bucket "$B" --key mp.bin --upload-id "$UPID" --multipart-upload "file://$WORK/parts.json" --query 'ETag' --output text 2>/dev/null)
case "$CETAG" in
  *-3|*-3\") ok "complete-multipart composite ETag (-3)";;
  *)         bad "complete-multipart composite ETag (got [$CETAG])";;
esac
$AWS $EP s3api get-object --bucket "$B" --key mp.bin "$WORK/mp-dl.bin" >/dev/null 2>&1
check "$(md5sum < "$WORK/mp-expected.bin")" "$(md5sum < "$WORK/mp-dl.bin")" "multipart reassembled md5"

echo "== list-objects-v2 =="
# Count via length(Contents): the awscli `--query KeyCount` path returns None in
# this botocore build even for AWS S3 itself, so count the parsed objects array.
KC=$($AWS $EP s3api list-objects-v2 --bucket "$B" --query 'length(Contents)' --output text 2>/dev/null)
check "$KC" "3" "list-objects-v2 object count (big.bin, mp.bin, small.txt)"

echo "== unicode key round-trip =="
echo "unicode-body" > "$WORK/u.txt"
$AWS $EP s3 cp "$WORK/u.txt" "s3://$B/日本語/ファイル.txt" --no-progress >/dev/null 2>&1
$AWS $EP s3 cp "s3://$B/日本語/ファイル.txt" "$WORK/u-dl.txt" --no-progress >/dev/null 2>&1
check "$(md5sum < "$WORK/u.txt")" "$(md5sum < "$WORK/u-dl.txt")" "unicode key round-trip"

echo "== error: NoSuchKey =="
ERR=$($AWS $EP s3api get-object --bucket "$B" --key does-not-exist "$WORK/none" 2>&1 | grep -o 'NoSuchKey' | head -1)
check "$ERR" "NoSuchKey" "NoSuchKey error"

echo "== error: SignatureDoesNotMatch =="
ERR=$(AWS_SECRET_ACCESS_KEY=wrong-secret $AWS $EP s3api list-objects-v2 --bucket "$B" 2>&1 | grep -o 'SignatureDoesNotMatch' | head -1)
check "$ERR" "SignatureDoesNotMatch" "SignatureDoesNotMatch error"

echo "== delete objects =="
$AWS $EP s3 rm "s3://$B/small.txt" >/dev/null 2>&1
$AWS $EP s3 rm "s3://$B/big.bin" >/dev/null 2>&1
$AWS $EP s3 rm "s3://$B/mp.bin" >/dev/null 2>&1
$AWS $EP s3 rm "s3://$B/日本語/ファイル.txt" >/dev/null 2>&1
# After deleting everything, `Contents` is absent; count remaining lines from s3 ls.
REMAIN=$($AWS $EP s3 ls "s3://$B/" --recursive 2>/dev/null | wc -l | tr -d ' ')
check "$REMAIN" "0" "delete objects (bucket empty)"

echo "== delete-bucket =="
$AWS $EP s3 rb "s3://$B" >/dev/null 2>&1 && ok "delete-bucket" || bad "delete-bucket"

echo
echo "================ SMOKE SUMMARY ================"
echo "PASS=$PASS  FAIL=$FAIL"
echo "=============================================="
[ "$FAIL" -eq 0 ]
