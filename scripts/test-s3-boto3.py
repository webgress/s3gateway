#!/usr/bin/env python3
"""S3 Gateway integration tests using boto3."""

import boto3
import hashlib
import os
import sys
import tempfile
from botocore.config import Config

ENDPOINT = "http://localhost:8333"
BUCKET = "test-boto3-bucket"

s3 = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id="test-access-key",
    aws_secret_access_key="test-secret-key",
    region_name="us-east-1",
    config=Config(s3={"addressing_style": "path"}),
)

passed = 0
failed = 0


def check(desc, fn):
    global passed, failed
    try:
        fn()
        print(f"PASS: {desc}")
        passed += 1
    except Exception as e:
        print(f"FAIL: {desc} ({e})")
        failed += 1


def check_raises(desc, fn, expected_code=None):
    global passed, failed
    try:
        fn()
        print(f"FAIL: {desc} (should have raised)")
        failed += 1
    except Exception as e:
        if expected_code and hasattr(e, "response"):
            code = e.response.get("Error", {}).get("Code", "")
            if code == expected_code:
                print(f"PASS: {desc}")
                passed += 1
            else:
                print(f"FAIL: {desc} (expected {expected_code}, got {code})")
                failed += 1
        else:
            print(f"PASS: {desc}")
            passed += 1


print("=== S3 Gateway boto3 Integration Tests ===")

# Bucket CRUD
check("Create bucket", lambda: s3.create_bucket(Bucket=BUCKET))
check("Head bucket", lambda: s3.head_bucket(Bucket=BUCKET))
def test_list_buckets():
    resp = s3.list_buckets()
    assert any(b["Name"] == BUCKET for b in resp["Buckets"])

check("List buckets", test_list_buckets)

# Object CRUD
content = b"hello from boto3"
check(
    "Put object",
    lambda: s3.put_object(
        Bucket=BUCKET, Key="hello.txt", Body=content, ContentType="text/plain"
    ),
)

# Get and verify
def test_get():
    resp = s3.get_object(Bucket=BUCKET, Key="hello.txt")
    body = resp["Body"].read()
    assert body == content, f"content mismatch: {body}"
    assert resp["ContentType"] == "text/plain"

check("Get object", test_get)

# Head object
def test_head():
    resp = s3.head_object(Bucket=BUCKET, Key="hello.txt")
    assert resp["ContentLength"] == len(content)
    assert "ETag" in resp

check("Head object", test_head)

# User metadata
check(
    "Put with metadata",
    lambda: s3.put_object(
        Bucket=BUCKET,
        Key="meta.txt",
        Body=b"metadata test",
        Metadata={"color": "red", "year": "2024"},
    ),
)

def test_metadata():
    resp = s3.head_object(Bucket=BUCKET, Key="meta.txt")
    meta = resp.get("Metadata", {})
    # Keys may be capitalized due to Go HTTP header canonicalization
    meta_lower = {k.lower(): v for k, v in meta.items()}
    assert meta_lower.get("color") == "red", f"metadata: {meta}"
    assert meta_lower.get("year") == "2024", f"metadata: {meta}"

check("Metadata round-trip", test_metadata)

# Unicode key
check(
    "Put unicode key",
    lambda: s3.put_object(Bucket=BUCKET, Key="日本語/テスト.txt", Body=b"unicode"),
)
def test_get_unicode():
    resp = s3.get_object(Bucket=BUCKET, Key="日本語/テスト.txt")
    assert resp["Body"].read() == b"unicode"

check("Get unicode key", test_get_unicode)

# List objects
for i in range(5):
    s3.put_object(Bucket=BUCKET, Key=f"list/item{i:02d}", Body=b"x")

def test_list():
    resp = s3.list_objects_v2(Bucket=BUCKET, Prefix="list/")
    assert resp["KeyCount"] >= 5, f"KeyCount={resp['KeyCount']}"

check("List objects with prefix", test_list)

# List with delimiter
def test_delimiter():
    resp = s3.list_objects_v2(Bucket=BUCKET, Delimiter="/")
    prefixes = [p["Prefix"] for p in resp.get("CommonPrefixes", [])]
    assert len(prefixes) > 0, f"no common prefixes"

check("List with delimiter", test_delimiter)

# Delete object
check("Delete object", lambda: s3.delete_object(Bucket=BUCKET, Key="hello.txt"))
check_raises(
    "Get deleted object",
    lambda: s3.head_object(Bucket=BUCKET, Key="hello.txt"),
)

# Error conditions
check_raises(
    "NoSuchBucket",
    lambda: s3.head_object(Bucket="nonexistent-bucket-xyz", Key="anything"),
)
check_raises(
    "NoSuchKey",
    lambda: s3.head_object(Bucket=BUCKET, Key="nonexistent-key-xyz"),
)

# Multipart upload (15MB)
mp_key = "multipart-test.bin"
size = 15 * 1024 * 1024  # 15MB

with tempfile.NamedTemporaryFile(delete=False) as f:
    data = os.urandom(size)
    f.write(data)
    upload_path = f.name

orig_md5 = hashlib.md5(data).hexdigest()

def test_multipart_upload():
    s3.upload_file(upload_path, BUCKET, mp_key)

check("Multipart upload (15MB)", test_multipart_upload)

with tempfile.NamedTemporaryFile(delete=False) as f:
    download_path = f.name

def test_multipart_download():
    s3.download_file(BUCKET, mp_key, download_path)
    with open(download_path, "rb") as f:
        dl_data = f.read()
    dl_md5 = hashlib.md5(dl_data).hexdigest()
    assert dl_md5 == orig_md5, f"MD5 mismatch: {orig_md5} vs {dl_md5}"

check("Download multipart file", test_multipart_download)

# Cleanup
os.unlink(upload_path)
os.unlink(download_path)

# Delete all objects in bucket
resp = s3.list_objects_v2(Bucket=BUCKET)
for obj in resp.get("Contents", []):
    s3.delete_object(Bucket=BUCKET, Key=obj["Key"])
# Handle pagination
while resp.get("IsTruncated"):
    resp = s3.list_objects_v2(
        Bucket=BUCKET, ContinuationToken=resp["NextContinuationToken"]
    )
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=BUCKET, Key=obj["Key"])

s3.delete_bucket(Bucket=BUCKET)

print(f"\n=== Results: {passed} passed, {failed} failed ===")
sys.exit(1 if failed > 0 else 0)
