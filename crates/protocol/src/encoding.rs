//! Wire encodings shared by the PAM module, the helper and the pages
//! (docs/design/exchange-format.md, 共通).

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (RFC 4648 §5), the form used for every binary value.
pub fn base64url(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let value = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..=chunk.len() {
            out.push(char::from(
                BASE64URL[(value >> (18 - 6 * index) & 63) as usize],
            ));
        }
    }
    out
}

/// Formats Unix seconds as RFC 3339 UTC with second precision (`2026-11-03T12:00:00Z`).
pub fn format_utc(unix_seconds: i64) -> String {
    let days = unix_seconds.div_euclid(86_400);
    let seconds = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}

/// Parses exactly the form [`format_utc`] writes. Other RFC 3339 forms are rejected so that
/// both sides of the protocol agree on one deadline value.
pub fn parse_utc(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let digits = text.get(range)?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())?
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    // Reject day overflow (e.g. 02-30) by round-tripping the calendar date.
    if civil_from_days(days) != (year, month, day) {
        return None;
    }
    Some(days * 86_400 + hour * 3600 + minute * 60 + second)
}

// Proleptic Gregorian conversions (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4648 §10 test vectors, with padding removed and the URL-safe alphabet.
    #[test]
    fn base64url_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), expected);
        }
        // The two alphabet positions that differ from standard base64.
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        // A 16-byte request ID is 22 characters.
        assert_eq!(base64url(&[0u8; 16]).len(), 22);
    }

    // The epoch, a leap day and a far date fix the calendar conversion against known values.
    #[test]
    fn formats_known_instants() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_793_707_200), "2026-11-03T12:00:00Z");
        assert_eq!(format_utc(253_402_300_799), "9999-12-31T23:59:59Z");
    }

    // The helper parses what the PAM module wrote and must arrive at the same instant.
    #[test]
    fn parse_inverts_format() {
        for seconds in [
            0,
            951_782_400,
            1_793_707_200,
            1_793_707_289,
            253_402_300_799,
        ] {
            assert_eq!(parse_utc(&format_utc(seconds)), Some(seconds));
        }
    }

    // Any other spelling of a time is not a deadline the two sides agreed on.
    #[test]
    fn parse_rejects_other_forms() {
        for text in [
            "2026-11-03T12:00:00+00:00",
            "2026-11-03T12:00:00.5Z",
            "2026-11-03 12:00:00Z",
            "2026-13-03T12:00:00Z",
            "2026-02-30T12:00:00Z",
            "2026-11-03T24:00:00Z",
            "2026-11-03T12:60:00Z",
            "+026-11-03T12:00:00Z",
            "",
        ] {
            assert_eq!(parse_utc(text), None, "{text}");
        }
    }
}
