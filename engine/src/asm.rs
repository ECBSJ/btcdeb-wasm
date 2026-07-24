//! Script decoding, disassembly, and assembly (the `btcc` half of btcdeb).

use crate::num;
use crate::opnames::{op_code, op_name};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::ScriptBuf;

#[derive(Clone)]
pub struct Ins {
    /// Byte offset of the opcode within the script.
    pub offset: usize,
    /// Total encoded length, including the push prefix and data.
    pub len: usize,
    pub opcode: u8,
    pub data: Option<Vec<u8>>,
    /// Display text: the opcode name, or the hex payload for data pushes.
    pub text: String,
    pub minimal_push: bool,
    pub error: Option<String>,
}

/// Decode a script into instructions. A truncated push is reported on the
/// instruction where it happens rather than aborting the whole decode, so
/// malformed scripts remain inspectable.
pub fn decode_script(bytes: &[u8]) -> (Vec<Ins>, Option<String>) {
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut err = None;

    while i < bytes.len() {
        let start = i;
        let op = bytes[i];
        i += 1;

        if op == 0 || op > 0x4e {
            out.push(Ins {
                offset: start,
                len: 1,
                opcode: op,
                data: if op == 0 { Some(Vec::new()) } else { None },
                text: op_name(op),
                minimal_push: true,
                error: None,
            });
            continue;
        }

        // A data push: figure out how many bytes of length prefix it uses.
        let (nsize, prefix_len) = match op {
            0x4c => {
                if i >= bytes.len() {
                    err = Some("truncated OP_PUSHDATA1 length".into());
                    out.push(bad_ins(start, op, "truncated OP_PUSHDATA1 length"));
                    break;
                }
                let n = bytes[i] as usize;
                i += 1;
                (n, 2)
            }
            0x4d => {
                if i + 1 >= bytes.len() {
                    err = Some("truncated OP_PUSHDATA2 length".into());
                    out.push(bad_ins(start, op, "truncated OP_PUSHDATA2 length"));
                    break;
                }
                let n = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                i += 2;
                (n, 3)
            }
            0x4e => {
                if i + 3 >= bytes.len() {
                    err = Some("truncated OP_PUSHDATA4 length".into());
                    out.push(bad_ins(start, op, "truncated OP_PUSHDATA4 length"));
                    break;
                }
                let n =
                    u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
                i += 4;
                (n, 5)
            }
            _ => (op as usize, 1),
        };

        if i + nsize > bytes.len() {
            let msg = format!(
                "push of {} bytes runs past the end of the script ({} available)",
                nsize,
                bytes.len() - i
            );
            err = Some(msg.clone());
            out.push(bad_ins(start, op, &msg));
            break;
        }
        let data = bytes[i..i + nsize].to_vec();
        i += nsize;
        out.push(Ins {
            offset: start,
            len: prefix_len + nsize,
            opcode: op,
            minimal_push: is_minimal_push(op, &data),
            text: if data.is_empty() {
                op_name(op)
            } else {
                hex::encode(&data)
            },
            data: Some(data),
            error: None,
        });
    }
    (out, err)
}

fn bad_ins(offset: usize, op: u8, msg: &str) -> Ins {
    Ins {
        offset,
        len: 1,
        opcode: op,
        data: None,
        text: op_name(op),
        minimal_push: false,
        error: Some(msg.to_string()),
    }
}

/// Would a minimal encoder have used this opcode for this payload?
pub fn is_minimal_push(op: u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return op == 0x00;
    }
    if data.len() == 1 {
        if data[0] >= 1 && data[0] <= 16 {
            return op == 0x50 + data[0];
        }
        if data[0] == 0x81 {
            return op == 0x4f;
        }
    }
    if data.len() <= 75 {
        return op as usize == data.len();
    }
    if data.len() <= 255 {
        return op == 0x4c;
    }
    if data.len() <= 65535 {
        return op == 0x4d;
    }
    op == 0x4e
}

/// Disassemble to btcdeb-style text, one instruction per line.
pub fn disassemble(bytes: &[u8]) -> Vec<String> {
    let (ins, err) = decode_script(bytes);
    let mut lines: Vec<String> = ins.iter().map(|i| i.text.clone()).collect();
    if let Some(e) = err {
        lines.push(format!("<error: {}>", e));
    }
    lines
}

/// Assemble human-readable script into bytes — the `btcc` tool.
///
/// Accepts opcode names (`OP_DUP`, or bare `DUP`), hex payloads to push,
/// decimal numbers, and `'quoted strings'` pushed as UTF-8. Square and angle
/// brackets are ignored so pasted btcdeb snippets work as-is.
pub fn assemble(input: &str) -> Result<ScriptBuf, String> {
    let mut builder = Builder::new();
    for token in tokenize(input) {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }

        // Quoted string: push its bytes.
        if (t.starts_with('\'') && t.ends_with('\'') && t.len() >= 2)
            || (t.starts_with('"') && t.ends_with('"') && t.len() >= 2)
        {
            let inner = &t[1..t.len() - 1];
            builder = push_bytes(builder, inner.as_bytes())?;
            continue;
        }

        // Opcode name.
        let looks_like_op = t.to_ascii_uppercase().starts_with("OP_")
            || op_code(t).is_some() && !is_hexish(t) && t.parse::<i64>().is_err();
        if looks_like_op {
            let Some(code) = op_code(t) else {
                return Err(format!("unknown opcode: {}", t));
            };
            builder = builder.push_opcode(bitcoin::opcodes::Opcode::from(code));
            continue;
        }

        // Decimal number.
        if let Ok(n) = t.parse::<i64>() {
            if !(t.len() > 1 && (t.starts_with('0') || t.starts_with("-0"))) {
                builder = match n {
                    -1 => builder.push_opcode(bitcoin::opcodes::Opcode::from(0x4f)),
                    0 => builder.push_opcode(bitcoin::opcodes::Opcode::from(0x00)),
                    1..=16 => builder.push_opcode(bitcoin::opcodes::Opcode::from(0x50 + n as u8)),
                    _ => push_bytes(builder, &num::encode(n))?,
                };
                continue;
            }
        }

        // Otherwise: hex data to push.
        let hexstr = t.strip_prefix("0x").unwrap_or(t);
        if hexstr.is_empty() {
            continue;
        }
        if hexstr.len() % 2 != 0 {
            return Err(format!(
                "'{}' is not an opcode, a number, or an even-length hex string",
                t
            ));
        }
        let bytes = hex::decode(hexstr)
            .map_err(|_| format!("'{}' is not an opcode, a number, or valid hex", t))?;
        builder = push_bytes(builder, &bytes)?;
    }
    Ok(builder.into_script())
}

fn push_bytes(builder: Builder, data: &[u8]) -> Result<Builder, String> {
    let buf = PushBytesBuf::try_from(data.to_vec())
        .map_err(|_| format!("cannot push {} bytes", data.len()))?;
    Ok(builder.push_slice(buf))
}

fn is_hexish(t: &str) -> bool {
    let s = t.strip_prefix("0x").unwrap_or(t);
    !s.is_empty() && s.len() % 2 == 0 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Split on whitespace and commas, dropping the brackets btcdeb prints.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in input.chars() {
        match quote {
            Some(q) => {
                cur.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    cur.push(c);
                }
                '[' | ']' | '<' | '>' | ',' => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c if c.is_whitespace() => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            },
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_p2pkh() {
        let s = assemble(
            "OP_DUP OP_HASH160 897c81ac37ae36f7bc5b91356cfb0138bfacb3c1 OP_EQUALVERIFY OP_CHECKSIG",
        )
        .unwrap();
        assert_eq!(
            hex::encode(s.as_bytes()),
            "76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac"
        );
    }

    #[test]
    fn brackets_are_ignored() {
        let a = assemble("[OP_DUP OP_HASH160]").unwrap();
        let b = assemble("OP_DUP OP_HASH160").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn numbers_use_small_opcodes() {
        assert_eq!(hex::encode(assemble("1 2 OP_ADD").unwrap().as_bytes()), "515293");
        assert_eq!(hex::encode(assemble("17").unwrap().as_bytes()), "0111");
    }

    #[test]
    fn decodes_offsets() {
        let script = hex::decode("76a914897c81ac37ae36f7bc5b91356cfb0138bfacb3c188ac").unwrap();
        let (ins, err) = decode_script(&script);
        assert!(err.is_none());
        assert_eq!(ins.len(), 5);
        assert_eq!(ins[0].text, "OP_DUP");
        assert_eq!(ins[2].offset, 2);
        assert_eq!(ins[2].len, 21);
        assert!(ins[2].minimal_push);
    }

    #[test]
    fn truncated_push_is_reported() {
        let (_ins, err) = decode_script(&hex::decode("4c05aabb").unwrap());
        assert!(err.is_some());
    }
}
