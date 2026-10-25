//! TOTP codes (RFC 6238) from the formats KeePass clients store:
//!
//! * KeePassXC: `otp` = `otpauth://totp/...?secret=...&period=30&digits=6&algorithm=SHA1`
//!   (`encoder=steam` for Steam Guard), or the legacy `key=...&step=30&size=6`.
//! * KeePass 2.47+: `TimeOtp-Secret-Base32` / `-Hex` / `-Base64` / `TimeOtp-Secret` with
//!   `TimeOtp-Length`, `TimeOtp-Period`, `TimeOtp-Algorithm`.
//! * KeeOtp / old KeePassXC: `TOTP Seed` + `TOTP Settings` (`30;6`, `30;S` for Steam).

use base64::Engine;
use hmac::{Hmac, Mac};
use keepass::db::Entry;
use zeroize::Zeroizing;

const STEAM_ALPHABET: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug)]
pub struct Spec {
    secret: Zeroizing<Vec<u8>>,
    period: u64,
    digits: u32,
    algorithm: Algorithm,
    steam: bool,
}

fn field<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    entry.get(name).map(str::trim).filter(|v| !v.is_empty())
}

pub fn has_totp(entry: &Entry) -> bool {
    [
        "otp",
        "TimeOtp-Secret-Base32",
        "TimeOtp-Secret-Hex",
        "TimeOtp-Secret-Base64",
        "TimeOtp-Secret",
        "TOTP Seed",
    ]
    .iter()
    .any(|name| field(entry, name).is_some())
}

/// The current code and the seconds it stays valid.
pub fn current_code(entry: &Entry) -> Result<(Zeroizing<String>, u64), String> {
    let spec = spec(entry)?.ok_or_else(|| "This entry has no TOTP".to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    Ok((code_at(&spec, now), spec.period - now % spec.period))
}

pub fn spec(entry: &Entry) -> Result<Option<Spec>, String> {
    if let Some(otp) = field(entry, "otp") {
        return parse_otp_field(otp).map(Some);
    }
    let keepass2 = [
        ("TimeOtp-Secret-Base32", Encoding::Base32),
        ("TimeOtp-Secret-Hex", Encoding::Hex),
        ("TimeOtp-Secret-Base64", Encoding::Base64),
        ("TimeOtp-Secret", Encoding::Utf8),
    ];
    for (name, encoding) in keepass2 {
        if let Some(value) = field(entry, name) {
            let algorithm = match field(entry, "TimeOtp-Algorithm") {
                None | Some("HMAC-SHA-1") => Algorithm::Sha1,
                Some("HMAC-SHA-256") => Algorithm::Sha256,
                Some("HMAC-SHA-512") => Algorithm::Sha512,
                Some(other) => return Err(format!("Unsupported TOTP algorithm {other}")),
            };
            return Ok(Some(
                Spec {
                    secret: decode(value, encoding)?,
                    period: parse_num(field(entry, "TimeOtp-Period"), 30)?,
                    digits: parse_num(field(entry, "TimeOtp-Length"), 6)?,
                    algorithm,
                    steam: false,
                }
                .checked()?,
            ));
        }
    }
    if let Some(seed) = field(entry, "TOTP Seed") {
        let settings = field(entry, "TOTP Settings").unwrap_or("30;6");
        let (period, size) = settings.split_once(';').unwrap_or((settings, "6"));
        let steam = size.eq_ignore_ascii_case("S");
        return Ok(Some(
            Spec {
                secret: decode(seed, Encoding::Base32)?,
                period: parse_num(Some(period), 30)?,
                digits: if steam { 5 } else { parse_num(Some(size), 6)? },
                algorithm: Algorithm::Sha1,
                steam,
            }
            .checked()?,
        ));
    }
    Ok(None)
}

impl Spec {
    fn checked(self) -> Result<Self, String> {
        if self.secret.is_empty() {
            return Err("The TOTP secret is empty".into());
        }
        if self.period == 0 || self.period > 3600 {
            return Err("Invalid TOTP period".into());
        }
        if !(1..=10).contains(&self.digits) {
            return Err("Invalid number of TOTP digits".into());
        }
        Ok(self)
    }
}

fn parse_num<T: std::str::FromStr>(value: Option<&str>, default: T) -> Result<T, String> {
    match value {
        None => Ok(default),
        Some(v) => v.trim().parse().map_err(|_| format!("Invalid TOTP setting '{v}'")),
    }
}

fn parse_otp_field(value: &str) -> Result<Spec, String> {
    let query = match value.split_once("://") {
        Some((scheme, rest)) => {
            if !scheme.eq_ignore_ascii_case("otpauth") {
                return Err(format!("Unsupported OTP URI scheme {scheme}"));
            }
            if !rest.get(..5).is_some_and(|kind| kind.eq_ignore_ascii_case("totp/")) {
                return Err("Only time-based OTP (totp) is supported".into());
            }
            rest.split_once('?').map_or("", |(_, q)| q)
        }
        // Legacy KeePassXC / KeeOtp format: key=...&step=...&size=...
        None => value,
    };
    let mut spec = Spec {
        secret: Zeroizing::new(Vec::new()),
        period: 30,
        digits: 6,
        algorithm: Algorithm::Sha1,
        steam: false,
    };
    for pair in query.split('&') {
        let (key, raw) = pair.split_once('=').unwrap_or((pair, ""));
        let val = Zeroizing::new(percent_decode(raw));
        match key.to_ascii_lowercase().as_str() {
            "secret" | "key" => spec.secret = decode(&val, Encoding::Base32)?,
            "period" | "step" => spec.period = parse_num(Some(&val), 30)?,
            "digits" | "size" => spec.digits = parse_num(Some(&val), 6)?,
            "algorithm" | "otphashmode" => {
                spec.algorithm = match val.to_ascii_uppercase().replace('-', "").as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => return Err(format!("Unsupported TOTP algorithm {other}")),
                }
            }
            "encoder" => spec.steam = val.eq_ignore_ascii_case("steam"),
            _ => {}
        }
    }
    if spec.steam {
        spec.digits = 5;
    }
    spec.checked()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
            if let Some(b) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Clone, Copy)]
enum Encoding {
    Base32,
    Hex,
    Base64,
    Utf8,
}

fn decode(value: &str, encoding: Encoding) -> Result<Zeroizing<Vec<u8>>, String> {
    let compact: Zeroizing<String> = Zeroizing::new(value.chars().filter(|c| !c.is_whitespace()).collect());
    let bytes = match encoding {
        Encoding::Base32 => base32_decode(&compact),
        Encoding::Hex => (0..compact.len())
            .step_by(2)
            .map(|i| compact.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
            .collect::<Option<Vec<u8>>>(),
        Encoding::Base64 => base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()).ok(),
        Encoding::Utf8 => Some(value.as_bytes().to_vec()),
    };
    bytes.map(Zeroizing::new).ok_or_else(|| "The TOTP secret is not valid".to_string())
}

/// RFC 4648 base32, case-insensitive, padding optional.
fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in input.trim_end_matches('=').bytes() {
        let value = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn hmac<M: Mac + hmac::digest::KeyInit>(secret: &[u8], counter: u64) -> Vec<u8> {
    let mut mac = <M as hmac::digest::KeyInit>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn code_at(spec: &Spec, unix_secs: u64) -> Zeroizing<String> {
    let counter = unix_secs / spec.period;
    let digest = Zeroizing::new(match spec.algorithm {
        Algorithm::Sha1 => hmac::<Hmac<sha1::Sha1>>(&spec.secret, counter),
        Algorithm::Sha256 => hmac::<Hmac<sha2::Sha256>>(&spec.secret, counter),
        Algorithm::Sha512 => hmac::<Hmac<sha2::Sha512>>(&spec.secret, counter),
    });
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let mut value = u32::from_be_bytes(digest[offset..offset + 4].try_into().expect("4 bytes")) & 0x7fff_ffff;
    let mut code = Zeroizing::new(String::with_capacity(spec.digits as usize));
    if spec.steam {
        for _ in 0..spec.digits {
            code.push(STEAM_ALPHABET[(value % STEAM_ALPHABET.len() as u32) as usize] as char);
            value /= STEAM_ALPHABET.len() as u32;
        }
    } else {
        let modulus = 10u64.pow(spec.digits);
        code.push_str(&format!("{:0width$}", u64::from(value) % modulus, width = spec.digits as usize));
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(secret: &[u8], digits: u32, algorithm: Algorithm) -> Spec {
        Spec { secret: Zeroizing::new(secret.to_vec()), period: 30, digits, algorithm, steam: false }
    }

    #[test]
    fn rfc6238_vectors() {
        let sha1 = spec(b"12345678901234567890", 8, Algorithm::Sha1);
        let sha256 = spec(b"12345678901234567890123456789012", 8, Algorithm::Sha256);
        let sha512 =
            spec(b"1234567890123456789012345678901234567890123456789012345678901234", 8, Algorithm::Sha512);
        assert_eq!(*code_at(&sha1, 59), "94287082");
        assert_eq!(*code_at(&sha1, 1111111109), "07081804");
        assert_eq!(*code_at(&sha1, 20000000000), "65353130");
        assert_eq!(*code_at(&sha256, 59), "46119246");
        assert_eq!(*code_at(&sha512, 59), "90693936");
        assert_eq!(*code_at(&sha512, 2000000000), "38618901");
    }

    #[test]
    fn parses_otpauth_uri() {
        let s = parse_otp_field(
            "otpauth://totp/ACME:jane?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&algorithm=sha1&period=30",
        )
        .unwrap();
        assert_eq!(s.digits, 8);
        assert_eq!(*code_at(&s, 59), "94287082");
    }

    #[test]
    fn parses_legacy_and_steam() {
        let legacy = parse_otp_field("key=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&step=30&size=8").unwrap();
        assert_eq!(*code_at(&legacy, 59), "94287082");
        let steam =
            parse_otp_field("otpauth://totp/Steam:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&encoder=steam")
                .unwrap();
        let code = code_at(&steam, 59);
        assert_eq!(code.len(), 5);
        assert!(code.bytes().all(|b| STEAM_ALPHABET.contains(&b)));
    }

    #[test]
    fn rejects_hotp_and_garbage() {
        assert!(parse_otp_field("otpauth://hotp/x?secret=GEZDGNBV&counter=1").is_err());
        assert!(parse_otp_field("otpauth://totp/x?secret=not*base32").is_err());
        assert!(parse_otp_field("otpauth://totp/x?period=30").is_err());
    }

    #[test]
    fn base32_and_percent_decoding() {
        assert_eq!(base32_decode("jbswy3dpehpk3pxp").unwrap(), b"Hello!\xde\xad\xbe\xef");
        assert_eq!(base32_decode("MZXW6===").unwrap(), b"foo");
        assert_eq!(percent_decode("a%20b%3D+c%"), "a b= c%");
    }
}
