//! Hex and base64url, written out rather than depended on.
//!
//! This crate is meant to be embedded in a wire proxy, a CI runner and a Vault
//! plugin, and to be ported to Go and TypeScript early. Every dependency it
//! carries is one the people doing that have to accept too, so the two ~40-line
//! codecs it needs are here instead.

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Decode lowercase or uppercase hex. Odd length or a non-hex byte is an error.
pub fn hex_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    if s.len() % 2 != 0 {
        return Err(EncodingError::BadHex);
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in b.chunks_exact(2) {
        let hi = nibble(pair[0]).ok_or(EncodingError::BadHex)?;
        let lo = nibble(pair[1]).ok_or(EncodingError::BadHex)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url, **unpadded** — the encoding the spec names for `nonce` and
/// `signature`.
pub fn b64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

/// Decode unpadded base64url.
///
/// Padding (`=`) is rejected rather than tolerated: the spec says unpadded, and
/// accepting both spellings means the same bytes have two encodings, which in a
/// protocol that hashes its own fields is how you end up with two digests for
/// one request.
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    let b = s.as_bytes();
    if b.len() % 4 == 1 {
        return Err(EncodingError::BadBase64);
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for chunk in b.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = b64_value(c).ok_or(EncodingError::BadBase64)?;
            n |= (v as u32) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// A malformed hex or base64url field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    BadHex,
    BadBase64,
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodingError::BadHex => f.write_str("not valid hex"),
            EncodingError::BadBase64 => f.write_str("not valid unpadded base64url"),
        }
    }
}

impl std::error::Error for EncodingError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&bytes)).unwrap(), bytes);
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa9, 0xff]), "000fa9ff");
        assert_eq!(
            hex_decode("000FA9FF").unwrap(),
            vec![0x00, 0x0f, 0xa9, 0xff]
        );
    }

    #[test]
    fn hex_rejects_junk() {
        assert!(hex_decode("abc").is_err(), "odd length");
        assert!(hex_decode("zz").is_err(), "non-hex");
    }

    #[test]
    fn base64url_round_trips_at_every_remainder() {
        for len in 0..64usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let enc = b64url_encode(&bytes);
            assert!(!enc.contains('='), "must be unpadded: {enc}");
            assert!(
                !enc.contains('+') && !enc.contains('/'),
                "must be url-safe: {enc}"
            );
            assert_eq!(b64url_decode(&enc).unwrap(), bytes, "len {len}");
        }
    }

    #[test]
    fn base64url_matches_known_vectors() {
        // RFC 4648 test vectors, url alphabet, padding stripped.
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        // The two bytes that separate the url alphabet from the standard one.
        assert_eq!(b64url_encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn base64url_rejects_padding_and_the_standard_alphabet() {
        assert!(b64url_decode("Zm8=").is_err(), "padding is not tolerated");
        assert!(
            b64url_decode("+_8").is_err(),
            "standard alphabet is not tolerated"
        );
        assert!(
            b64url_decode("Z").is_err(),
            "a 1-byte remainder is impossible"
        );
    }
}
