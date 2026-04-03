#!/bin/bash
# S3 Gateway integration tests using aws-cli

ENDPOINT="http://localhost:8333"
BUCKET="test-cli-bucket"
LARGE_BUCKET="test-cli-large"

export AWS_ACCESS_KEY_ID="test-access-key"
export AWS_SECRET_ACCESS_KEY="test-secret-key"
export AWS_DEFAULT_REGION="us-east-1"

AWS="aws --endpoint-url $ENDPOINT"

pass=0
fail=0

check() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc"
        fail=$((fail + 1))
    fi
}

check_output() {
    local desc="$1"
    local expected="$2"
    shift 2
    local output
    output=$("$@" 2>&1)
    if echo "$output" | grep -q "$expected"; then
        echo "PASS: $desc"
        pass=$((pass + 1))
    else
        echo "FAIL: $desc (expected '$expected', got: $output)"
        fail=$((fail + 1))
    fi
}

check_fail() {
    local desc="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "FAIL: $desc (should have failed)"
        fail=$((fail + 1))
    else
        echo "PASS: $desc"
        pass=$((pass + 1))
    fi
}

echo "=== S3 Gateway AWS CLI Integration Tests ==="

# Bucket CRUD
check "Create bucket" $AWS s3 mb s3://$BUCKET
check "Head bucket" $AWS s3api head-bucket --bucket $BUCKET
check "List buckets" $AWS s3 ls

# Object CRUD - small file
echo "hello from aws-cli" > /tmp/test-upload.txt
check "Upload small file" $AWS s3 cp /tmp/test-upload.txt s3://$BUCKET/hello.txt
check "Download small file" $AWS s3 cp s3://$BUCKET/hello.txt /tmp/test-download.txt
check_output "Verify content" "hello from aws-cli" cat /tmp/test-download.txt

# HEAD object
check "Head object" $AWS s3api head-object --bucket $BUCKET --key hello.txt

# List objects
check "List objects" $AWS s3 ls s3://$BUCKET/

# Unicode key
echo "unicode content" > /tmp/test-unicode.txt
check "Upload unicode key" $AWS s3 cp /tmp/test-unicode.txt "s3://$BUCKET/日本語/ファイル.txt"
check "Download unicode key" $AWS s3 cp "s3://$BUCKET/日本語/ファイル.txt" /tmp/test-unicode-dl.txt

# Nested keys with delimiter
echo "nested" > /tmp/test-nested.txt
check "Upload nested key 1" $AWS s3 cp /tmp/test-nested.txt s3://$BUCKET/a/b/c/deep.txt
check "Upload nested key 2" $AWS s3 cp /tmp/test-nested.txt s3://$BUCKET/a/b/other.txt
check "Upload root key" $AWS s3 cp /tmp/test-nested.txt s3://$BUCKET/root.txt

# List with delimiter
check_output "List with delimiter" "PRE a/" $AWS s3 ls s3://$BUCKET/

# User metadata
check "Upload with metadata" $AWS s3api put-object --bucket $BUCKET --key meta.txt --body /tmp/test-upload.txt --metadata '{"color":"blue","size":"large"}'
META_OUT=$($AWS s3api head-object --bucket $BUCKET --key meta.txt 2>&1)
if echo "$META_OUT" | grep -iq "color"; then
    echo "PASS: Metadata round-trip"
    pass=$((pass + 1))
else
    echo "FAIL: Metadata round-trip (output: $META_OUT)"
    fail=$((fail + 1))
fi

# Delete object
check "Delete object" $AWS s3 rm s3://$BUCKET/hello.txt
check_fail "Get deleted object" $AWS s3api head-object --bucket $BUCKET --key hello.txt

# Error conditions
check_fail "Get from non-existent bucket" $AWS s3api head-object --bucket nonexistent-bucket --key anything
check_fail "Get non-existent key" $AWS s3api head-object --bucket $BUCKET --key nonexistent-key

# Large file multipart upload
check "Create large bucket" $AWS s3 mb s3://$LARGE_BUCKET

# Generate 10MB test file
dd if=/dev/urandom of=/tmp/test-large.bin bs=1M count=10 2>/dev/null
check "Upload large file (multipart)" $AWS s3 cp /tmp/test-large.bin s3://$LARGE_BUCKET/large.bin
check "Download large file" $AWS s3 cp s3://$LARGE_BUCKET/large.bin /tmp/test-large-dl.bin

# Verify large file integrity
ORIG_MD5=$(md5sum /tmp/test-large.bin | awk '{print $1}')
DL_MD5=$(md5sum /tmp/test-large-dl.bin | awk '{print $1}')
if [ "$ORIG_MD5" = "$DL_MD5" ]; then
    echo "PASS: Large file integrity check"
    pass=$((pass + 1))
else
    echo "FAIL: Large file integrity check (orig=$ORIG_MD5, dl=$DL_MD5)"
    fail=$((fail + 1))
fi

# Cleanup
$AWS s3 rm s3://$BUCKET --recursive >/dev/null 2>&1 || true
$AWS s3 rb s3://$BUCKET >/dev/null 2>&1 || true
$AWS s3 rm s3://$LARGE_BUCKET --recursive >/dev/null 2>&1 || true
$AWS s3 rb s3://$LARGE_BUCKET >/dev/null 2>&1 || true
rm -f /tmp/test-upload.txt /tmp/test-download.txt /tmp/test-unicode.txt /tmp/test-unicode-dl.txt /tmp/test-nested.txt /tmp/test-large.bin /tmp/test-large-dl.bin

echo ""
echo "=== Results: $pass passed, $fail failed ==="
[ $fail -eq 0 ] || exit 1
