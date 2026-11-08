//! The part of CBOR (RFC 8949) that a WebAuthn registration carries: the attestation object
//! and the COSE public key inside its authenticatorData. Definite lengths only (CTAP2 encodes
//! nothing else), no tags, no floats; a map with a repeated key is not accepted.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i128),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    /// The value under `key` if this is a map.
    pub fn get(&self, key: &Value) -> Option<&Value> {
        let Self::Map(entries) = self else {
            return None;
        };
        entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value)
    }

    pub fn integer(&self) -> Option<i128> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(value) => Some(value),
            _ => None,
        }
    }
}

/// Nesting deeper than this is not a registration object.
const MAX_DEPTH: usize = 8;

/// One item from the start of `input`, and the bytes after it.
pub fn decode(input: &[u8]) -> Option<(Value, &[u8])> {
    item(input, 0)
}

fn item(input: &[u8], depth: usize) -> Option<(Value, &[u8])> {
    if depth > MAX_DEPTH {
        return None;
    }
    let (&initial, rest) = input.split_first()?;
    let (major, info) = (initial >> 5, initial & 0x1f);
    if major == 7 {
        let simple = match info {
            20 => Value::Bool(false),
            21 => Value::Bool(true),
            22 => Value::Null,
            _ => return None,
        };
        return Some((simple, rest));
    }
    let (argument, rest) = argument(info, rest)?;
    match major {
        0 => Some((Value::Integer(i128::from(argument)), rest)),
        1 => Some((Value::Integer(-1 - i128::from(argument)), rest)),
        2 | 3 => {
            let length = usize::try_from(argument).ok()?;
            if rest.len() < length {
                return None;
            }
            let (content, rest) = rest.split_at(length);
            let value = if major == 2 {
                Value::Bytes(content.to_vec())
            } else {
                Value::Text(String::from_utf8(content.to_vec()).ok()?)
            };
            Some((value, rest))
        }
        4 | 5 => {
            // Every item takes at least one byte, which bounds the count before allocating.
            let count = usize::try_from(argument).ok()?;
            if count > rest.len() {
                return None;
            }
            let mut rest = rest;
            if major == 4 {
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    let (value, after) = item(rest, depth + 1)?;
                    values.push(value);
                    rest = after;
                }
                return Some((Value::Array(values), rest));
            }
            let mut entries: Vec<(Value, Value)> = Vec::with_capacity(count);
            for _ in 0..count {
                let (key, after) = item(rest, depth + 1)?;
                let (value, after) = item(after, depth + 1)?;
                if entries.iter().any(|(known, _)| *known == key) {
                    return None;
                }
                entries.push((key, value));
                rest = after;
            }
            Some((Value::Map(entries), rest))
        }
        _ => None,
    }
}

/// The argument of the initial byte: inline, or 1 / 2 / 4 / 8 following bytes.
fn argument(info: u8, rest: &[u8]) -> Option<(u64, &[u8])> {
    let width = match info {
        0..=23 => return Some((u64::from(info), rest)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    if rest.len() < width {
        return None;
    }
    let (bytes, rest) = rest.split_at(width);
    let value = bytes
        .iter()
        .fold(0u64, |value, byte| value << 8 | u64::from(*byte));
    Some((value, rest))
}

#[cfg(test)]
pub mod encode {
    //! The encoder the test authenticator builds its attestation objects with.

    use super::Value;

    fn head(major: u8, argument: u64, out: &mut Vec<u8>) {
        let major = major << 5;
        match argument {
            0..=23 => out.push(major | argument as u8),
            24..=0xff => out.extend([major | 24, argument as u8]),
            0x100..=0xffff => {
                out.push(major | 25);
                out.extend((argument as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                out.push(major | 26);
                out.extend((argument as u32).to_be_bytes());
            }
            _ => {
                out.push(major | 27);
                out.extend(argument.to_be_bytes());
            }
        }
    }

    pub fn to_vec(value: &Value) -> Vec<u8> {
        let mut out = Vec::new();
        write(value, &mut out);
        out
    }

    fn write(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Integer(number) if *number >= 0 => head(0, *number as u64, out),
            Value::Integer(number) => head(1, (-1 - *number) as u64, out),
            Value::Bytes(bytes) => {
                head(2, bytes.len() as u64, out);
                out.extend(bytes);
            }
            Value::Text(text) => {
                head(3, text.len() as u64, out);
                out.extend(text.as_bytes());
            }
            Value::Array(values) => {
                head(4, values.len() as u64, out);
                values.iter().for_each(|value| write(value, out));
            }
            Value::Map(entries) => {
                head(5, entries.len() as u64, out);
                for (key, value) in entries {
                    write(key, out);
                    write(value, out);
                }
            }
            Value::Bool(false) => out.push(0xf4),
            Value::Bool(true) => out.push(0xf5),
            Value::Null => out.push(0xf6),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8949 Appendix A examples for each supported major type.
    #[test]
    fn decodes_rfc8949_examples() {
        let cases: [(&[u8], Value); 9] = [
            (&[0x00], Value::Integer(0)),
            (&[0x18, 0x64], Value::Integer(100)),
            (
                &[0x1b, 0, 0, 0, 0xe8, 0xd4, 0xa5, 0x10, 0x00],
                Value::Integer(1_000_000_000_000),
            ),
            (&[0x26], Value::Integer(-7)),
            (&[0x39, 0x03, 0xe7], Value::Integer(-1000)),
            (&[0x44, 1, 2, 3, 4], Value::Bytes(vec![1, 2, 3, 4])),
            (&[0x64, 0x49, 0x45, 0x54, 0x46], Value::Text("IETF".into())),
            (
                &[0x83, 0x01, 0x82, 0x02, 0x03, 0xf6],
                Value::Array(vec![
                    Value::Integer(1),
                    Value::Array(vec![Value::Integer(2), Value::Integer(3)]),
                    Value::Null,
                ]),
            ),
            (
                &[0xa2, 0x01, 0x02, 0x03, 0xf5],
                Value::Map(vec![
                    (Value::Integer(1), Value::Integer(2)),
                    (Value::Integer(3), Value::Bool(true)),
                ]),
            ),
        ];
        for (bytes, expected) in cases {
            let (value, rest) = decode(bytes).unwrap();
            assert_eq!(value, expected, "{bytes:02x?}");
            assert!(rest.is_empty());
            assert_eq!(encode::to_vec(&value), bytes);
        }
        // The bytes after the first item are handed back untouched.
        assert_eq!(decode(&[0x01, 0xff]).unwrap().1, [0xff]);
    }

    // Truncated items, indefinite lengths, tags, floats, repeated map keys and runaway nesting
    // are not registration objects.
    #[test]
    fn rejects_what_ctap2_does_not_encode() {
        for bytes in [
            &[][..],
            &[0x18],                                                 // argument byte missing
            &[0x44, 1, 2],                   // byte string shorter than its length
            &[0x5f, 0x41, 0x00, 0xff],       // indefinite-length byte string
            &[0xc0, 0x00],                   // tag
            &[0xf9, 0x3c, 0x00],             // half float
            &[0x62, 0xff, 0xfe],             // text that is not UTF-8
            &[0xa2, 0x01, 0x02, 0x01, 0x03], // key 1 twice
            &[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // count beyond the input
        ] {
            assert_eq!(decode(bytes), None, "{bytes:02x?}");
        }
        let deep = [vec![0x81; MAX_DEPTH + 1], vec![0x00]].concat();
        assert_eq!(decode(&deep), None);
        let shallow = [vec![0x81; MAX_DEPTH], vec![0x00]].concat();
        assert!(decode(&shallow).is_some());
    }
}
