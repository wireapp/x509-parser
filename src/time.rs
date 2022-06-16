use asn1_rs::FromDer;
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Utc};
use der_parser::ber::{ber_read_element_header, BerObjectContent, Tag, MAX_OBJECT_SIZE};
use der_parser::der::{parse_der_generalizedtime, parse_der_utctime, DerObject};
use der_parser::error::{BerError, DerResult};
use nom::branch::alt;
use nom::combinator::{complete, map_res, opt};
use std::fmt;
use std::ops::{Add, Sub};

use crate::error::{X509Error, X509Result};

/// An ASN.1 timestamp.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time(pub DateTime<Utc>);

impl ASN1Time {
    pub(crate) fn from_der_opt(i: &[u8]) -> X509Result<Option<Self>> {
        opt(map_res(parse_choice_of_time, der_to_utctime))(i)
            .map_err(|_| X509Error::InvalidDate.into())
    }

    #[inline]
    pub const fn to_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// Makes a new `ASN1Time` from the number of non-leap seconds since Epoch
    pub fn from_timestamp(secs: i64) -> Self {
        let dt = NaiveDateTime::from_timestamp(secs, 0);
        Self(DateTime::from_utc(dt, Utc))
    }

    /// Returns the number of non-leap seconds since January 1, 1970 0:00:00 UTC (aka "UNIX timestamp").
    #[inline]
    pub fn timestamp(&self) -> i64 {
        self.0.timestamp()
    }

    /// Returns a `ASN1Time` which corresponds to the current date.
    #[inline]
    pub fn now() -> Self {
        Self(Utc::now())
    }

    /// Returns an RFC 2822 date and time string such as `Tue, 1 Jul 2003 10:52:37 +0200`.
    ///
    /// Conversion to RFC2822 date can fail if date cannot be represented in this format,
    /// for example if year < 1900.
    ///
    /// For an infallible conversion to string, use `.to_string()`.
    #[inline]
    pub fn to_rfc2822(self) -> Result<String, String> {
        if self.0.year() >= 1900 {
            Ok(self.0.to_rfc2822())
        } else {
            Err("Year was below 1900 which is not allowed by RFC 2822".to_string())
        }
    }
}

impl<'a> FromDer<'a, X509Error> for ASN1Time {
    fn from_der(i: &[u8]) -> X509Result<Self> {
        map_res(parse_choice_of_time, der_to_utctime)(i).map_err(|_| X509Error::InvalidDate.into())
    }
}

fn parse_choice_of_time(i: &[u8]) -> DerResult {
    alt((
        complete(parse_der_utctime),
        complete(parse_der_generalizedtime),
        complete(parse_malformed_date),
    ))(i)
}

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(i: &[u8]) -> DerResult {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    // fn check_char(b: &u8) -> bool {
    //     (0x20 <= *b && *b <= 0x7f) || (*b == b'+')
    // }
    let (_rem, hdr) = ber_read_element_header(i)?;
    let len = hdr.length().definite()?;
    if len > MAX_OBJECT_SIZE {
        return Err(nom::Err::Error(BerError::InvalidLength));
    }
    match hdr.tag() {
        Tag::UtcTime => {
            // // if we are in this function, the PrintableString could not be validated.
            // // Accept it without validating charset, because some tools do not respect the charset
            // // restrictions (for ex. they use '*' while explicingly disallowed)
            // let (rem, data) = take(len as usize)(rem)?;
            // if !data.iter().all(check_char) {
            //     return Err(nom::Err::Error(BerError::BerValueError));
            // }
            // let s = std::str::from_utf8(data).map_err(|_| BerError::BerValueError)?;
            // let content = BerObjectContent::UTCTime(s);
            // let obj = DerObject::from_header_and_content(hdr, content);
            // Ok((rem, obj))
            Err(nom::Err::Error(BerError::BerValueError))
        }
        _ => Err(nom::Err::Error(BerError::unexpected_tag(None, hdr.tag()))),
    }
}

impl fmt::Display for ASN1Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format = "%b  %-d %H:%M:%S %-Y %:z";
        let s = self.0.format(format).to_string();
        f.write_str(&s)
    }
}

pub(crate) fn der_to_utctime(obj: DerObject) -> Result<ASN1Time, X509Error> {
    match obj.content {
        BerObjectContent::UTCTime(s) => {
            let dt = s.to_datetime().map_err(|_| X509Error::InvalidDate)?;
            let dt = NaiveDateTime::from_timestamp(dt.unix_timestamp(), 0);
            let dt = DateTime::from_utc(dt, Utc);
            let year = dt.year();
            // RFC 5280 rules for interpreting the year
            let year = if year >= 50 { year + 1900 } else { year + 2000 };
            let dt = dt.with_year(year).ok_or(X509Error::InvalidDate)?;
            Ok(ASN1Time(dt))
        }
        BerObjectContent::GeneralizedTime(s) => {
            let dt = s.to_datetime().map_err(|_| X509Error::InvalidDate)?;
            let dt = NaiveDateTime::from_timestamp(dt.unix_timestamp(), 0);
            let dt = DateTime::from_utc(dt, Utc);
            Ok(ASN1Time(dt))
        }
        _ => Err(X509Error::InvalidDate),
    }
}

impl Add<Duration> for ASN1Time {
    type Output = Option<ASN1Time>;

    #[inline]
    fn add(self, rhs: Duration) -> Self::Output {
        Some(Self(self.0.add(rhs)))
    }
}

impl Sub<ASN1Time> for ASN1Time {
    type Output = Option<Duration>;

    #[inline]
    fn sub(self, rhs: ASN1Time) -> Self::Output {
        if self.0 > rhs.0 {
            let this = self.0.signed_duration_since(chrono::MIN_DATETIME);
            let rhs = rhs.0.signed_duration_since(chrono::MIN_DATETIME);
            Some(this - rhs)
        } else {
            None
        }
    }
}

impl From<DateTime<Utc>> for ASN1Time {
    fn from(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use wasm_bindgen_test::*;
    wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test]
    fn test_time_to_string() {
        let d = Utc.ymd(1, 1, 1).and_hms(12, 34, 56);
        let t = ASN1Time::from(d);
        assert_eq!(t.to_string(), "Jan  1 12:34:56 1 +00:00".to_string());
    }

    #[test]
    #[wasm_bindgen_test]
    fn test_nonrfc2822_date() {
        // test year < 1900
        let d = Utc.ymd(1, 1, 1).and_hms(0, 0, 0);
        let t = ASN1Time::from(d);
        assert!(t.to_rfc2822().is_err());
    }
}
