//! S3 XML response structs and serialization.
//!
//! Ported from the Go `internal/s3response/xml.go`. Success responses carry the
//! `http://s3.amazonaws.com/doc/2006-03-01/` namespace on their root element.
//!
//! We hand-roll serialization for the success types so the namespace attribute
//! and field ordering are byte-exact (quick-xml's serde path does not emit a
//! root-element xmlns cleanly, and AWS clients are picky about ordering). The
//! request-body parse types (CompleteMultipartUpload) use serde for ergonomic
//! deserialization via quick-xml.

use serde::Deserialize;

use super::errors::xml_escape_into;

/// S3 success-response XML namespace.
pub const S3_NS: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

const XML_DECL: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

fn open_root(out: &mut String, name: &str) {
    out.push('<');
    out.push_str(name);
    out.push_str(" xmlns=\"");
    out.push_str(S3_NS);
    out.push_str("\">");
}

fn tag(out: &mut String, name: &str, value: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
    xml_escape_into(value, out);
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

/// Format a time as S3 ISO-8601 (`RFC3339`, second precision, `Z`).
/// `secs` is seconds since the Unix epoch (UTC).
pub fn format_time(secs: i64) -> String {
    // Minimal civil-time formatter (no chrono dep). Valid for all dates we
    // care about (post-1970). Algorithm: days->y/m/d via Howard Hinnant's
    // civil_from_days.
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, m, d, hh, mm, ss
    )
}

// ---- ListAllMyBucketsResult (GET /) ----

pub struct Owner {
    pub id: String,
    pub display_name: String,
}

pub struct BucketEntry {
    pub name: String,
    /// ISO-8601 creation date string.
    pub creation_date: String,
}

pub struct ListAllMyBucketsResult {
    pub owner: Owner,
    pub buckets: Vec<BucketEntry>,
}

impl ListAllMyBucketsResult {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(XML_DECL);
        open_root(&mut out, "ListAllMyBucketsResult");
        out.push_str("<Owner>");
        tag(&mut out, "ID", &self.owner.id);
        tag(&mut out, "DisplayName", &self.owner.display_name);
        out.push_str("</Owner>");
        out.push_str("<Buckets>");
        for b in &self.buckets {
            out.push_str("<Bucket>");
            tag(&mut out, "Name", &b.name);
            tag(&mut out, "CreationDate", &b.creation_date);
            out.push_str("</Bucket>");
        }
        out.push_str("</Buckets>");
        out.push_str("</ListAllMyBucketsResult>");
        out
    }
}

// ---- ListBucketResult (ListObjectsV2) ----

pub struct ObjectEntry {
    pub key: String,
    pub last_modified: String,
    pub etag: String,
    pub size: i64,
    pub storage_class: String,
}

pub struct ListBucketResultV2 {
    pub name: String,
    pub prefix: String,
    pub delimiter: String,
    pub max_keys: i32,
    pub is_truncated: bool,
    pub key_count: i32,
    pub start_after: String,
    pub continuation_token: String,
    pub next_continuation_token: String,
    pub contents: Vec<ObjectEntry>,
    pub common_prefixes: Vec<String>,
}

impl ListBucketResultV2 {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(1024);
        out.push_str(XML_DECL);
        open_root(&mut out, "ListBucketResult");
        tag(&mut out, "Name", &self.name);
        tag(&mut out, "Prefix", &self.prefix);
        if !self.delimiter.is_empty() {
            tag(&mut out, "Delimiter", &self.delimiter);
        }
        tag(&mut out, "MaxKeys", &self.max_keys.to_string());
        tag(&mut out, "KeyCount", &self.key_count.to_string());
        tag(&mut out, "IsTruncated", if self.is_truncated { "true" } else { "false" });
        if !self.start_after.is_empty() {
            tag(&mut out, "StartAfter", &self.start_after);
        }
        if !self.continuation_token.is_empty() {
            tag(&mut out, "ContinuationToken", &self.continuation_token);
        }
        if !self.next_continuation_token.is_empty() {
            tag(&mut out, "NextContinuationToken", &self.next_continuation_token);
        }
        for o in &self.contents {
            out.push_str("<Contents>");
            tag(&mut out, "Key", &o.key);
            tag(&mut out, "LastModified", &o.last_modified);
            tag(&mut out, "ETag", &o.etag);
            tag(&mut out, "Size", &o.size.to_string());
            tag(&mut out, "StorageClass", &o.storage_class);
            out.push_str("</Contents>");
        }
        for p in &self.common_prefixes {
            out.push_str("<CommonPrefixes>");
            tag(&mut out, "Prefix", p);
            out.push_str("</CommonPrefixes>");
        }
        out.push_str("</ListBucketResult>");
        out
    }
}

// ---- Multipart results ----

pub struct InitiateMultipartUploadResult {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
}

impl InitiateMultipartUploadResult {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str(XML_DECL);
        open_root(&mut out, "InitiateMultipartUploadResult");
        tag(&mut out, "Bucket", &self.bucket);
        tag(&mut out, "Key", &self.key);
        tag(&mut out, "UploadId", &self.upload_id);
        out.push_str("</InitiateMultipartUploadResult>");
        out
    }
}

pub struct CompleteMultipartUploadResult {
    pub location: String,
    pub bucket: String,
    pub key: String,
    pub etag: String,
}

impl CompleteMultipartUploadResult {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str(XML_DECL);
        open_root(&mut out, "CompleteMultipartUploadResult");
        tag(&mut out, "Location", &self.location);
        tag(&mut out, "Bucket", &self.bucket);
        tag(&mut out, "Key", &self.key);
        tag(&mut out, "ETag", &self.etag);
        out.push_str("</CompleteMultipartUploadResult>");
        out
    }
}

pub struct UploadEntry {
    pub key: String,
    pub upload_id: String,
    pub initiated: String,
}

pub struct ListMultipartUploadsResult {
    pub bucket: String,
    pub key_marker: String,
    pub max_uploads: i32,
    pub is_truncated: bool,
    pub uploads: Vec<UploadEntry>,
}

impl ListMultipartUploadsResult {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(XML_DECL);
        open_root(&mut out, "ListMultipartUploadsResult");
        tag(&mut out, "Bucket", &self.bucket);
        tag(&mut out, "KeyMarker", &self.key_marker);
        tag(&mut out, "MaxUploads", &self.max_uploads.to_string());
        tag(&mut out, "IsTruncated", if self.is_truncated { "true" } else { "false" });
        for u in &self.uploads {
            out.push_str("<Upload>");
            tag(&mut out, "Key", &u.key);
            tag(&mut out, "UploadId", &u.upload_id);
            tag(&mut out, "Initiated", &u.initiated);
            out.push_str("</Upload>");
        }
        out.push_str("</ListMultipartUploadsResult>");
        out
    }
}

pub struct PartEntry {
    pub part_number: i32,
    pub last_modified: String,
    pub etag: String,
    pub size: i64,
}

pub struct ListPartsResult {
    pub bucket: String,
    pub key: String,
    pub upload_id: String,
    pub parts: Vec<PartEntry>,
}

impl ListPartsResult {
    pub fn to_xml(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(XML_DECL);
        open_root(&mut out, "ListPartsResult");
        tag(&mut out, "Bucket", &self.bucket);
        tag(&mut out, "Key", &self.key);
        tag(&mut out, "UploadId", &self.upload_id);
        for p in &self.parts {
            out.push_str("<Part>");
            tag(&mut out, "PartNumber", &p.part_number.to_string());
            tag(&mut out, "LastModified", &p.last_modified);
            tag(&mut out, "ETag", &p.etag);
            tag(&mut out, "Size", &p.size.to_string());
            out.push_str("</Part>");
        }
        out.push_str("</ListPartsResult>");
        out
    }
}

// ---- Request body parse types (deserialize via quick-xml + serde) ----

/// Parsed `<CompleteMultipartUpload>` request body.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename = "CompleteMultipartUpload")]
pub struct CompleteMultipartUpload {
    #[serde(rename = "Part", default)]
    pub parts: Vec<CompleteUploadPart>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub struct CompleteUploadPart {
    #[serde(rename = "PartNumber")]
    pub part_number: i32,
    #[serde(rename = "ETag", default)]
    pub etag: String,
}

impl CompleteMultipartUpload {
    /// Parse a `<CompleteMultipartUpload>` request body.
    pub fn from_xml(body: &str) -> Result<Self, quick_xml::DeError> {
        quick_xml::de::from_str(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_buckets_has_namespace() {
        let r = ListAllMyBucketsResult {
            owner: Owner {
                id: "id".into(),
                display_name: "name".into(),
            },
            buckets: vec![BucketEntry {
                name: "b1".into(),
                creation_date: "2024-01-01T00:00:00Z".into(),
            }],
        };
        let xml = r.to_xml();
        assert!(xml.contains(&format!("xmlns=\"{}\"", S3_NS)));
        assert!(xml.contains("<ListAllMyBucketsResult"));
        assert!(xml.contains("<Name>b1</Name>"));
        assert!(xml.contains("<CreationDate>2024-01-01T00:00:00Z</CreationDate>"));
    }

    #[test]
    fn list_objects_v2_serializes() {
        let r = ListBucketResultV2 {
            name: "bucket".into(),
            prefix: "p/".into(),
            delimiter: "/".into(),
            max_keys: 1000,
            is_truncated: true,
            key_count: 1,
            start_after: String::new(),
            continuation_token: String::new(),
            next_continuation_token: "tok".into(),
            contents: vec![ObjectEntry {
                key: "p/a".into(),
                last_modified: "2024-01-01T00:00:00Z".into(),
                etag: "\"abc\"".into(),
                size: 42,
                storage_class: "STANDARD".into(),
            }],
            common_prefixes: vec!["p/sub/".into()],
        };
        let xml = r.to_xml();
        assert!(xml.contains(&format!("xmlns=\"{}\"", S3_NS)));
        assert!(xml.contains("<ListBucketResult"));
        assert!(xml.contains("<KeyCount>1</KeyCount>"));
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<NextContinuationToken>tok</NextContinuationToken>"));
        assert!(xml.contains("<Key>p/a</Key>"));
        assert!(xml.contains("<Size>42</Size>"));
        assert!(xml.contains("<CommonPrefixes><Prefix>p/sub/</Prefix></CommonPrefixes>"));
        assert!(xml.contains("<Delimiter>/</Delimiter>"));
    }

    #[test]
    fn initiate_multipart_serializes() {
        let r = InitiateMultipartUploadResult {
            bucket: "b".into(),
            key: "k".into(),
            upload_id: "u".into(),
        };
        let xml = r.to_xml();
        assert!(xml.contains(&format!("xmlns=\"{}\"", S3_NS)));
        assert!(xml.contains("<UploadId>u</UploadId>"));
    }

    #[test]
    fn complete_multipart_result_serializes() {
        let r = CompleteMultipartUploadResult {
            location: "http://x/b/k".into(),
            bucket: "b".into(),
            key: "k".into(),
            etag: "\"abc-3\"".into(),
        };
        let xml = r.to_xml();
        assert!(xml.contains("<ETag>\"abc-3\"</ETag>"));
        assert!(xml.contains(&format!("xmlns=\"{}\"", S3_NS)));
    }

    #[test]
    fn parse_complete_multipart_body() {
        let body = r#"<CompleteMultipartUpload>
            <Part><PartNumber>1</PartNumber><ETag>"aaa"</ETag></Part>
            <Part><PartNumber>2</PartNumber><ETag>"bbb"</ETag></Part>
        </CompleteMultipartUpload>"#;
        let parsed = CompleteMultipartUpload::from_xml(body).unwrap();
        assert_eq!(parsed.parts.len(), 2);
        assert_eq!(parsed.parts[0].part_number, 1);
        assert_eq!(parsed.parts[0].etag, "\"aaa\"");
        assert_eq!(parsed.parts[1].part_number, 2);
    }

    #[test]
    fn format_time_epoch() {
        assert_eq!(format_time(0), "1970-01-01T00:00:00Z");
        // 2021-01-01T00:00:00Z = 1609459200
        assert_eq!(format_time(1_609_459_200), "2021-01-01T00:00:00Z");
        // 2024-02-29T12:34:56Z (leap day) = 1709209  -> compute: use known value
        // 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(format_time(1_709_164_800), "2024-02-29T00:00:00Z");
    }
}
