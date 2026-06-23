//! Minimal date/time parsing+formatting for SigV4, without a chrono dependency.
//!
//! Handles only what SigV4 needs:
//!
//! - ISO8601 basic format `YYYYMMDDThhmmssZ` (the `X-Amz-Date` format)
//! - `YYYYMMDD` credential-scope date
//! - RFC1123 HTTP `Date` header (subset)
//!
//! All times are UTC. Returns seconds since the Unix epoch.

const DAYS_IN_MONTH: [i64; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Convert a y/m/d h:m:s (UTC) into Unix seconds. Returns None on out-of-range.
fn to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    if !(1..=12).contains(&mo) || !(0..=23).contains(&h) || !(0..=59).contains(&mi) {
        return None;
    }
    if !(0..=60).contains(&s) {
        return None; // allow leap second 60
    }
    let mut dim = DAYS_IN_MONTH[(mo - 1) as usize];
    if mo == 2 && is_leap(y) {
        dim = 29;
    }
    if !(1..=dim).contains(&d) {
        return None;
    }
    // Days from epoch using civil_to_days (Howard Hinnant).
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let mp = if mo > 2 { mo - 3 } else { mo + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// Parse `YYYYMMDDThhmmssZ` (SigV4 `X-Amz-Date`). Returns Unix seconds.
pub fn parse_iso8601(s: &str) -> Option<i64> {
    // Expect exactly 16 chars: 8 date, 'T', 6 time, 'Z'.
    let b = s.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return None;
    }
    let y = parse_n(&s[0..4])?;
    let mo = parse_n(&s[4..6])?;
    let d = parse_n(&s[6..8])?;
    let h = parse_n(&s[9..11])?;
    let mi = parse_n(&s[11..13])?;
    let se = parse_n(&s[13..15])?;
    to_unix(y, mo, d, h, mi, se)
}

/// Parse `YYYYMMDD`. Returns Unix seconds at 00:00:00Z (validity check only
/// needs the date to be well-formed).
pub fn parse_yyyymmdd(s: &str) -> Option<i64> {
    if s.len() != 8 {
        return None;
    }
    let y = parse_n(&s[0..4])?;
    let mo = parse_n(&s[4..6])?;
    let d = parse_n(&s[6..8])?;
    to_unix(y, mo, d, 0, 0, 0)
}

/// Parse a (subset of) RFC1123 HTTP date, e.g.
/// `Fri, 24 May 2013 00:00:00 GMT`. Returns Unix seconds.
pub fn parse_http_date(s: &str) -> Option<i64> {
    // Split off the weekday prefix if present.
    let s = s.trim();
    let rest = match s.find(", ") {
        Some(i) => &s[i + 2..],
        None => s,
    };
    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 5 {
        return None;
    }
    let d = parse_n(parts[0])?;
    let mo = month_from_abbrev(parts[1])?;
    let y = parse_n(parts[2])?;
    let tparts: Vec<&str> = parts[3].split(':').collect();
    if tparts.len() != 3 {
        return None;
    }
    let h = parse_n(tparts[0])?;
    let mi = parse_n(tparts[1])?;
    let se = parse_n(tparts[2])?;
    to_unix(y, mo, d, h, mi, se)
}

fn month_from_abbrev(m: &str) -> Option<i64> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

fn parse_n(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Format Unix seconds as `YYYYMMDDThhmmssZ` (SigV4 `X-Amz-Date`).
pub fn iso8601_from_unix(secs: i64) -> String {
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
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        year, m, d, hh, mm, ss
    )
}

/// Current wall-clock time as Unix seconds (UTC).
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_roundtrip() {
        // 2013-05-24T00:00:00Z
        let s = "20130524T000000Z";
        let u = parse_iso8601(s).unwrap();
        assert_eq!(iso8601_from_unix(u), s);
    }

    #[test]
    fn iso8601_known_epoch() {
        assert_eq!(parse_iso8601("19700101T000000Z").unwrap(), 0);
        assert_eq!(parse_iso8601("20210101T000000Z").unwrap(), 1_609_459_200);
    }

    #[test]
    fn iso8601_malformed() {
        assert!(parse_iso8601("2013-05-24").is_none());
        assert!(parse_iso8601("20130524T000000").is_none());
        assert!(parse_iso8601("").is_none());
        assert!(parse_iso8601("20131324T000000Z").is_none()); // month 13
    }

    #[test]
    fn yyyymmdd_ok() {
        assert!(parse_yyyymmdd("20240229").is_some()); // leap day
        assert!(parse_yyyymmdd("20230229").is_none()); // not leap
        assert!(parse_yyyymmdd("2024029").is_none());
    }

    #[test]
    fn http_date_parses() {
        let u = parse_http_date("Fri, 24 May 2013 00:00:00 GMT").unwrap();
        assert_eq!(u, parse_iso8601("20130524T000000Z").unwrap());
    }
}
