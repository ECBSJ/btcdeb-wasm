//! Opcode names, matching Bitcoin Core's `GetOpName` so output reads the same
//! way btcdeb's does.

pub fn op_name(op: u8) -> String {
    match op {
        0x00 => "OP_0".into(),
        0x01..=0x4b => format!("OP_PUSHBYTES_{}", op),
        0x4c => "OP_PUSHDATA1".into(),
        0x4d => "OP_PUSHDATA2".into(),
        0x4e => "OP_PUSHDATA4".into(),
        0x4f => "OP_1NEGATE".into(),
        0x50 => "OP_RESERVED".into(),
        0x51 => "OP_1".into(),
        0x52..=0x60 => format!("OP_{}", op - 0x50),
        0x61 => "OP_NOP".into(),
        0x62 => "OP_VER".into(),
        0x63 => "OP_IF".into(),
        0x64 => "OP_NOTIF".into(),
        0x65 => "OP_VERIF".into(),
        0x66 => "OP_VERNOTIF".into(),
        0x67 => "OP_ELSE".into(),
        0x68 => "OP_ENDIF".into(),
        0x69 => "OP_VERIFY".into(),
        0x6a => "OP_RETURN".into(),
        0x6b => "OP_TOALTSTACK".into(),
        0x6c => "OP_FROMALTSTACK".into(),
        0x6d => "OP_2DROP".into(),
        0x6e => "OP_2DUP".into(),
        0x6f => "OP_3DUP".into(),
        0x70 => "OP_2OVER".into(),
        0x71 => "OP_2ROT".into(),
        0x72 => "OP_2SWAP".into(),
        0x73 => "OP_IFDUP".into(),
        0x74 => "OP_DEPTH".into(),
        0x75 => "OP_DROP".into(),
        0x76 => "OP_DUP".into(),
        0x77 => "OP_NIP".into(),
        0x78 => "OP_OVER".into(),
        0x79 => "OP_PICK".into(),
        0x7a => "OP_ROLL".into(),
        0x7b => "OP_ROT".into(),
        0x7c => "OP_SWAP".into(),
        0x7d => "OP_TUCK".into(),
        0x7e => "OP_CAT".into(),
        0x7f => "OP_SUBSTR".into(),
        0x80 => "OP_LEFT".into(),
        0x81 => "OP_RIGHT".into(),
        0x82 => "OP_SIZE".into(),
        0x83 => "OP_INVERT".into(),
        0x84 => "OP_AND".into(),
        0x85 => "OP_OR".into(),
        0x86 => "OP_XOR".into(),
        0x87 => "OP_EQUAL".into(),
        0x88 => "OP_EQUALVERIFY".into(),
        0x89 => "OP_RESERVED1".into(),
        0x8a => "OP_RESERVED2".into(),
        0x8b => "OP_1ADD".into(),
        0x8c => "OP_1SUB".into(),
        0x8d => "OP_2MUL".into(),
        0x8e => "OP_2DIV".into(),
        0x8f => "OP_NEGATE".into(),
        0x90 => "OP_ABS".into(),
        0x91 => "OP_NOT".into(),
        0x92 => "OP_0NOTEQUAL".into(),
        0x93 => "OP_ADD".into(),
        0x94 => "OP_SUB".into(),
        0x95 => "OP_MUL".into(),
        0x96 => "OP_DIV".into(),
        0x97 => "OP_MOD".into(),
        0x98 => "OP_LSHIFT".into(),
        0x99 => "OP_RSHIFT".into(),
        0x9a => "OP_BOOLAND".into(),
        0x9b => "OP_BOOLOR".into(),
        0x9c => "OP_NUMEQUAL".into(),
        0x9d => "OP_NUMEQUALVERIFY".into(),
        0x9e => "OP_NUMNOTEQUAL".into(),
        0x9f => "OP_LESSTHAN".into(),
        0xa0 => "OP_GREATERTHAN".into(),
        0xa1 => "OP_LESSTHANOREQUAL".into(),
        0xa2 => "OP_GREATERTHANOREQUAL".into(),
        0xa3 => "OP_MIN".into(),
        0xa4 => "OP_MAX".into(),
        0xa5 => "OP_WITHIN".into(),
        0xa6 => "OP_RIPEMD160".into(),
        0xa7 => "OP_SHA1".into(),
        0xa8 => "OP_SHA256".into(),
        0xa9 => "OP_HASH160".into(),
        0xaa => "OP_HASH256".into(),
        0xab => "OP_CODESEPARATOR".into(),
        0xac => "OP_CHECKSIG".into(),
        0xad => "OP_CHECKSIGVERIFY".into(),
        0xae => "OP_CHECKMULTISIG".into(),
        0xaf => "OP_CHECKMULTISIGVERIFY".into(),
        0xb0 => "OP_NOP1".into(),
        0xb1 => "OP_CHECKLOCKTIMEVERIFY".into(),
        0xb2 => "OP_CHECKSEQUENCEVERIFY".into(),
        0xb3..=0xb9 => format!("OP_NOP{}", op - 0xb0),
        0xba => "OP_CHECKSIGADD".into(),
        _ => format!("OP_UNKNOWN_{:#04x}", op),
    }
}

/// Reverse lookup used by the assembler. Accepts the canonical name plus the
/// aliases btcdeb/Core tolerate (`OP_TRUE`, `OP_FALSE`, `OP_CLTV`, ...).
pub fn op_code(name: &str) -> Option<u8> {
    let up = name.to_ascii_uppercase();
    let n = if up.starts_with("OP_") { up.clone() } else { format!("OP_{}", up) };
    match n.as_str() {
        "OP_FALSE" => return Some(0x00),
        "OP_TRUE" => return Some(0x51),
        "OP_CLTV" => return Some(0xb1),
        "OP_CSV" => return Some(0xb2),
        "OP_NOP2" => return Some(0xb1),
        "OP_NOP3" => return Some(0xb2),
        _ => {}
    }
    (0u8..=0xffu8).find(|&op| op_name(op) == n)
}

/// Opcodes that are unconditionally invalid wherever they appear in a script.
pub fn is_disabled(op: u8) -> bool {
    matches!(
        op,
        0x7e | 0x7f | 0x80 | 0x81 | 0x83 | 0x84 | 0x85 | 0x86 | 0x8d | 0x8e | 0x95 | 0x96
            | 0x97 | 0x98 | 0x99
    )
}

/// BIP342: opcodes reserved for future soft forks inside tapscript.
pub fn is_op_success(op: u8) -> bool {
    op == 80
        || op == 98
        || (op >= 126 && op <= 129)
        || (op >= 131 && op <= 134)
        || (op >= 137 && op <= 138)
        || (op >= 141 && op <= 142)
        || (op >= 149 && op <= 153)
        || (op >= 187 && op <= 254)
}
