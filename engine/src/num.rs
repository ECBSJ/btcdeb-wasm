//! CScriptNum: the sign-magnitude little-endian integers script arithmetic uses.

pub const MAX_NUM_SIZE: usize = 4;

#[derive(Debug)]
pub struct NumError(pub String);

/// Decode a stack element as a number.
///
/// `max_size` is 4 for ordinary arithmetic and 5 for the locktime opcodes,
/// which need to represent times past 2038. `require_minimal` enforces
/// SCRIPT_VERIFY_MINIMALDATA's canonical encoding rule.
pub fn decode(bytes: &[u8], require_minimal: bool, max_size: usize) -> Result<i64, NumError> {
    if bytes.len() > max_size {
        return Err(NumError(format!(
            "script number overflow (got {} bytes, max {})",
            bytes.len(),
            max_size
        )));
    }
    if require_minimal && !bytes.is_empty() {
        // The high bit of the top byte is the sign bit, so a top byte of 0x00
        // or 0x80 is only canonical when the next byte down needs the sign bit.
        if bytes[bytes.len() - 1] & 0x7f == 0 {
            if bytes.len() <= 1 || bytes[bytes.len() - 2] & 0x80 == 0 {
                return Err(NumError("non-minimally encoded script number".into()));
            }
        }
    }
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    if bytes[bytes.len() - 1] & 0x80 != 0 {
        let mask = !(0x80i64 << (8 * (bytes.len() - 1)));
        return Ok(-(result & mask));
    }
    Ok(result)
}

/// Encode a number back into its canonical stack representation.
pub fn encode(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    let neg = value < 0;
    let mut abs = value.unsigned_abs();
    while abs > 0 {
        result.push((abs & 0xff) as u8);
        abs >>= 8;
    }
    // If the top byte already uses its high bit we need an extra byte to hold
    // the sign, otherwise the sign rides along in the existing top byte.
    if result[result.len() - 1] & 0x80 != 0 {
        result.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = result.len() - 1;
        result[last] |= 0x80;
    }
    result
}

/// Script's notion of truthiness: any non-zero byte, where a lone sign bit in
/// the top byte still counts as zero (negative zero is false).
pub fn cast_to_bool(bytes: &[u8]) -> bool {
    for (i, &b) in bytes.iter().enumerate() {
        if b != 0 {
            if i == bytes.len() - 1 && b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for v in [0i64, 1, -1, 127, 128, -128, 255, 256, -256, 2147483647, -2147483647] {
            let e = encode(v);
            assert_eq!(decode(&e, true, 5).unwrap(), v, "value {}", v);
        }
    }

    #[test]
    fn known_encodings() {
        assert_eq!(encode(0), Vec::<u8>::new());
        assert_eq!(encode(1), vec![0x01]);
        assert_eq!(encode(-1), vec![0x81]);
        assert_eq!(encode(127), vec![0x7f]);
        assert_eq!(encode(128), vec![0x80, 0x00]);
        assert_eq!(encode(-128), vec![0x80, 0x80]);
        assert_eq!(encode(256), vec![0x00, 0x01]);
    }

    #[test]
    fn minimal_encoding_enforced() {
        assert!(decode(&[0x01, 0x00], true, 4).is_err());
        assert_eq!(decode(&[0x01, 0x00], false, 4).unwrap(), 1);
        assert!(decode(&[0x00, 0x81], true, 4).is_ok()); // -256, needs the pad
    }

    #[test]
    fn truthiness() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x80]));
        assert!(!cast_to_bool(&[0x00, 0x00, 0x80]));
        assert!(cast_to_bool(&[0x01]));
        assert!(cast_to_bool(&[0x00, 0x01]));
    }
}
