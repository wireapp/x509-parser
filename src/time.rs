use asn1_rs::nom::Err;
use asn1_rs::{Error, FromDer, GeneralizedTime, Header, ParseResult, UtcTime};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, Utc};
use der_parser::ber::{Tag, MAX_OBJECT_SIZE};
use std::fmt;
use std::ops::{Add, Sub};

use crate::error::{X509Error, X509Result};

/// An ASN.1 timestamp.
#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ASN1Time(pub DateTime<Utc>);

impl ASN1Time {
    pub(crate) fn from_der_opt(i: &[u8]) -> X509Result<Option<Self>> {
        if i.is_empty() {
            return Ok((i, None));
        }
        match parse_choice_of_time(i) {
            Ok((rem, dt)) => Ok((rem, Some(ASN1Time(dt)))),
            Err(Err::Error(Error::InvalidTag)) | Err(Err::Error(Error::UnexpectedTag { .. })) => {
                Ok((i, None))
            }
            Err(_) => Err(Err::Error(X509Error::InvalidDate)),
        }
    }

    #[inline]
    pub const fn new(dt: DateTime<Utc>) -> Self {
        Self(dt)
    }

    #[inline]
    pub const fn to_datetime(&self) -> DateTime<Utc> {
        self.0
    }

    /// Makes a new `ASN1Time` from the number of non-leap seconds since Epoch
    pub fn from_timestamp(secs: i64) -> Result<Self, X509Error> {
        let dt = NaiveDateTime::from_timestamp_opt(secs, 0).ok_or(X509Error::InvalidDate)?;
        Ok(ASN1Time(DateTime::from_utc(dt, Utc)))
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
        let (rem, dt) = parse_choice_of_time(i).map_err(|_| X509Error::InvalidDate)?;
        Ok((rem, ASN1Time(dt)))
    }
}

pub(crate) fn parse_choice_of_time(i: &[u8]) -> ParseResult<DateTime<Utc>> {
    if let Ok((rem, t)) = UtcTime::from_der(i) {
        let dt = t.utc_adjusted_datetime()?;
        let dt = DateTime::from_utc(NaiveDateTime::from_timestamp(dt.unix_timestamp(), 0), Utc);
        return Ok((rem, dt));
    }
    if let Ok((rem, t)) = GeneralizedTime::from_der(i) {
        let dt = t.utc_datetime()?;
        let dt = DateTime::from_utc(NaiveDateTime::from_timestamp(dt.unix_timestamp(), 0), Utc);
        return Ok((rem, dt));
    }
    parse_malformed_date(i)
}

// allow relaxed parsing of UTCTime (ex: 370116130016+0000)
fn parse_malformed_date(i: &[u8]) -> ParseResult<DateTime<Utc>> {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    // fn check_char(b: &u8) -> bool {
    //     (0x20 <= *b && *b <= 0x7f) || (*b == b'+')
    // }
    let (_rem, hdr) = Header::from_der(i)?;
    let len = hdr.length().definite()?;
    if len > MAX_OBJECT_SIZE {
        return Err(nom::Err::Error(Error::InvalidLength));
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
            Err(nom::Err::Error(Error::BerValueError))
        }
        _ => Err(nom::Err::Error(Error::unexpected_tag(None, hdr.tag()))),
    }
}

impl fmt::Display for ASN1Time {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let format = "%b  %-d %H:%M:%S %-Y %:z";
        let s = self.0.format(format).to_string();
        f.write_str(&s)
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
            let this = self.0.signed_duration_since(DateTime::<Utc>::MIN_UTC);
            let rhs = rhs.0.signed_duration_since(DateTime::<Utc>::MIN_UTC);
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
