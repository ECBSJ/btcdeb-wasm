//! Signature checking: sighash construction (delegated to rust-bitcoin) plus
//! ECDSA / BIP340 Schnorr verification.

use bitcoin::hashes::Hash;
use bitcoin::script::Script;
use bitcoin::secp256k1::{ecdsa, schnorr, Message, Secp256k1, VerifyOnly, XOnlyPublicKey};
use bitcoin::sighash::{Annex, Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};

/// Outcome of a single signature check, verbose enough that the UI can explain
/// *why* something failed rather than just showing a red 0.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SigResult {
    pub valid: bool,
    /// Sighash actually signed, hex, big-endian display order. Empty when the
    /// check never got far enough to build one.
    pub sighash: String,
    pub sighash_type: String,
    pub detail: String,
    pub warnings: Vec<String>,
    /// True when there is no transaction loaded, so verification was skipped
    /// rather than performed.
    pub assumed: bool,
    /// The exact pair this check ran against, hex, as it sat on the stack.
    /// Multisig performs several checks per op, so without these the UI cannot
    /// say *which* signature went with *which* key.
    pub pubkey: String,
    pub signature: String,
}

impl SigResult {
    fn fail(detail: impl Into<String>) -> Self {
        SigResult {
            valid: false,
            sighash: String::new(),
            sighash_type: String::new(),
            detail: detail.into(),
            warnings: vec![],
            ..Default::default()
        }
    }

    /// Record the pair that was checked. Every result leaves `check_ecdsa` /
    /// `check_schnorr` through here, including the early failures.
    fn with_pair(mut self, sig: &[u8], pubkey: &[u8]) -> Self {
        self.signature = hex::encode(sig);
        self.pubkey = hex::encode(pubkey);
        self
    }
}

pub struct SigContext {
    pub tx: Transaction,
    pub input_index: usize,
    pub prevouts: Vec<TxOut>,
}

/// How the sighash for this check should be built.
pub enum SigMode<'a> {
    Legacy { script_code: &'a Script },
    WitnessV0 { script_code: &'a Script },
    Tapscript { leaf_hash: TapLeafHash, codesep_pos: u32, annex: Option<&'a [u8]> },
    TaprootKeyPath { annex: Option<&'a [u8]> },
}

fn describe_ecdsa_hashtype(b: u8) -> String {
    let base = b & 0x1f;
    let name = match base {
        1 => "SIGHASH_ALL",
        2 => "SIGHASH_NONE",
        3 => "SIGHASH_SINGLE",
        _ => "SIGHASH_INVALID",
    };
    if b & 0x80 != 0 {
        format!("{}|SIGHASH_ANYONECANPAY (0x{:02x})", name, b)
    } else {
        format!("{} (0x{:02x})", name, b)
    }
}

impl SigContext {
    fn value(&self) -> Result<Amount, String> {
        self.prevouts
            .get(self.input_index)
            .map(|o| o.value)
            .ok_or_else(|| "missing prevout for this input".to_string())
    }

    /// ECDSA check (`OP_CHECKSIG` family, legacy and segwit v0).
    ///
    /// `sig` is the raw stack element: DER signature with the sighash byte
    /// appended.
    pub fn check_ecdsa(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        sig: &[u8],
        pubkey: &[u8],
        mode: &SigMode,
        require_strict_der: bool,
        require_low_s: bool,
    ) -> SigResult {
        self.check_ecdsa_inner(secp, sig, pubkey, mode, require_strict_der, require_low_s)
            .with_pair(sig, pubkey)
    }

    fn check_ecdsa_inner(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        sig: &[u8],
        pubkey: &[u8],
        mode: &SigMode,
        require_strict_der: bool,
        require_low_s: bool,
    ) -> SigResult {
        if sig.is_empty() {
            return SigResult::fail("empty signature (this is a normal way to fail a check)");
        }
        let mut warnings = Vec::new();
        let hash_type_byte = sig[sig.len() - 1];
        let der = &sig[..sig.len() - 1];

        let base = hash_type_byte & 0x1f;
        if base < 1 || base > 3 {
            warnings.push(format!(
                "sighash type byte 0x{:02x} is not ALL/NONE/SINGLE",
                hash_type_byte
            ));
        }

        // BIP66 strictness is a byte-level test on the signature including its
        // sighash type byte, exactly Core's IsValidSignatureEncoding. libsecp's
        // strict parser cannot stand in for it: some malformed encodings (e.g.
        // a negative-looking R) come back Ok as an all-zero signature.
        if !is_strict_der(sig) {
            if require_strict_der {
                return SigResult {
                    valid: false,
                    sighash: String::new(),
                    sighash_type: describe_ecdsa_hashtype(hash_type_byte),
                    detail: "signature is not strict DER (SCRIPT_VERIFY_DERSIG)".into(),
                    warnings,
                    ..Default::default()
                };
            }
            warnings.push("signature is not strict DER; parsed leniently".into());
        }
        // Core always parses with the lax parser (CPubKey::Verify), whatever
        // the flags say; strictness is only ever the check above.
        let Some(signature) = ecdsa::Signature::from_der_lax(der).ok() else {
            return SigResult {
                valid: false,
                sighash: String::new(),
                sighash_type: describe_ecdsa_hashtype(hash_type_byte),
                detail: "could not parse ECDSA signature".into(),
                warnings,
                ..Default::default()
            };
        };

        let mut normalized = signature;
        normalized.normalize_s();
        if normalized.serialize_compact() != signature.serialize_compact() {
            if require_low_s {
                return SigResult {
                    valid: false,
                    sighash: String::new(),
                    sighash_type: describe_ecdsa_hashtype(hash_type_byte),
                    detail: "signature has high S value (SCRIPT_VERIFY_LOW_S)".into(),
                    warnings,
                    ..Default::default()
                };
            }
            warnings.push("signature has a high S value (non-standard, BIP62)".into());
        }

        let pk = match bitcoin::secp256k1::PublicKey::from_slice(pubkey) {
            Ok(p) => p,
            Err(e) => {
                return SigResult {
                    valid: false,
                    sighash: String::new(),
                    sighash_type: describe_ecdsa_hashtype(hash_type_byte),
                    detail: format!("invalid public key: {}", e),
                    warnings,
                    ..Default::default()
                }
            }
        };
        if pubkey.len() == 65 {
            warnings.push("uncompressed public key (not allowed under segwit)".into());
        }

        let sighash = match self.ecdsa_sighash(mode, hash_type_byte as u32) {
            Ok(h) => h,
            Err(e) => {
                return SigResult {
                    valid: false,
                    sighash: String::new(),
                    sighash_type: describe_ecdsa_hashtype(hash_type_byte),
                    detail: e,
                    warnings,
                    ..Default::default()
                }
            }
        };

        let msg = Message::from_digest(sighash);
        // libsecp only accepts low-S signatures, but high S is consensus-valid
        // (LOW_S is policy); verify the normalized copy, the way Core calls
        // secp256k1_ecdsa_signature_normalize before verifying.
        let valid = secp.verify_ecdsa(&msg, &normalized, &pk).is_ok();
        let mut display = sighash;
        display.reverse(); // sighashes are conventionally shown big-endian
        SigResult {
            valid,
            sighash: hex::encode(display),
            sighash_type: describe_ecdsa_hashtype(hash_type_byte),
            detail: if valid {
                "signature is valid for this pubkey and sighash".into()
            } else {
                "signature does not verify against this pubkey and sighash".into()
            },
            warnings,
            ..Default::default()
        }
    }

    fn ecdsa_sighash(&self, mode: &SigMode, hash_type: u32) -> Result<[u8; 32], String> {
        let cache = SighashCache::new(&self.tx);
        match mode {
            SigMode::Legacy { script_code } => cache
                .legacy_signature_hash(self.input_index, script_code, hash_type)
                .map(|h| h.to_byte_array())
                .map_err(|e| format!("legacy sighash failed: {}", e)),
            SigMode::WitnessV0 { script_code } => self.bip143_sighash(script_code, hash_type),
            _ => Err("taproot sighash requested for an ECDSA check".into()),
        }
    }

    /// BIP143 digest, hand-rolled so the raw hash-type byte is what gets
    /// serialized. Core hashes `vchSig.back()` verbatim; rust-bitcoin's typed
    /// API canonicalizes nonstandard bytes (e.g. 0x65 becomes SIGHASH_ALL)
    /// before serializing, so mined signatures with odd sighash bytes — which
    /// are consensus-valid — would fail to verify.
    fn bip143_sighash(&self, script_code: &Script, hash_type: u32) -> Result<[u8; 32], String> {
        use bitcoin::consensus::Encodable;
        use bitcoin::hashes::{sha256d, Hash};

        let tx = &self.tx;
        let input = tx
            .input
            .get(self.input_index)
            .ok_or_else(|| "input index out of range".to_string())?;
        let base = hash_type & 0x1f;
        let single = base == 3;
        let none = base == 2;
        let anyone_can_pay = hash_type & 0x80 != 0;

        let hash_prevouts = if anyone_can_pay {
            [0u8; 32]
        } else {
            let mut v = Vec::new();
            for i in &tx.input {
                i.previous_output.consensus_encode(&mut v).unwrap();
            }
            sha256d::Hash::hash(&v).to_byte_array()
        };
        let hash_sequence = if anyone_can_pay || single || none {
            [0u8; 32]
        } else {
            let mut v = Vec::new();
            for i in &tx.input {
                i.sequence.consensus_encode(&mut v).unwrap();
            }
            sha256d::Hash::hash(&v).to_byte_array()
        };
        let hash_outputs = if !single && !none {
            let mut v = Vec::new();
            for o in &tx.output {
                o.consensus_encode(&mut v).unwrap();
            }
            sha256d::Hash::hash(&v).to_byte_array()
        } else if single && self.input_index < tx.output.len() {
            let mut v = Vec::new();
            tx.output[self.input_index].consensus_encode(&mut v).unwrap();
            sha256d::Hash::hash(&v).to_byte_array()
        } else {
            [0u8; 32]
        };

        let mut enc = Vec::new();
        tx.version.consensus_encode(&mut enc).unwrap();
        enc.extend_from_slice(&hash_prevouts);
        enc.extend_from_slice(&hash_sequence);
        input.previous_output.consensus_encode(&mut enc).unwrap();
        script_code.consensus_encode(&mut enc).unwrap();
        self.value()?.consensus_encode(&mut enc).unwrap();
        input.sequence.consensus_encode(&mut enc).unwrap();
        enc.extend_from_slice(&hash_outputs);
        tx.lock_time.consensus_encode(&mut enc).unwrap();
        enc.extend_from_slice(&hash_type.to_le_bytes());
        Ok(sha256d::Hash::hash(&enc).to_byte_array())
    }

    /// Schnorr check (`OP_CHECKSIG` in tapscript, and key-path spends).
    ///
    /// `sig` is 64 bytes for implicit SIGHASH_DEFAULT, or 65 with an explicit
    /// sighash type byte.
    pub fn check_schnorr(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        sig: &[u8],
        pubkey: &[u8],
        mode: &SigMode,
    ) -> SigResult {
        self.check_schnorr_inner(secp, sig, pubkey, mode)
            .with_pair(sig, pubkey)
    }

    fn check_schnorr_inner(
        &self,
        secp: &Secp256k1<VerifyOnly>,
        sig: &[u8],
        pubkey: &[u8],
        mode: &SigMode,
    ) -> SigResult {
        if sig.is_empty() {
            return SigResult::fail("empty signature (this is a normal way to fail a check)");
        }
        if sig.len() != 64 && sig.len() != 65 {
            return SigResult::fail(format!(
                "invalid Schnorr signature length {} (must be 64 or 65)",
                sig.len()
            ));
        }
        if pubkey.len() != 32 {
            return SigResult::fail(format!(
                "invalid x-only public key length {} (must be 32)",
                pubkey.len()
            ));
        }

        let mut warnings = Vec::new();
        let (sig_bytes, sighash_type) = if sig.len() == 65 {
            let b = sig[64];
            if b == 0x00 {
                return SigResult::fail(
                    "explicit sighash byte 0x00 is invalid; omit it for SIGHASH_DEFAULT",
                );
            }
            match TapSighashType::from_consensus_u8(b) {
                Ok(t) => (&sig[..64], t),
                Err(_) => {
                    return SigResult::fail(format!("invalid taproot sighash type 0x{:02x}", b))
                }
            }
        } else {
            (&sig[..], TapSighashType::Default)
        };

        let signature = match schnorr::Signature::from_slice(sig_bytes) {
            Ok(s) => s,
            Err(e) => return SigResult::fail(format!("invalid Schnorr signature: {}", e)),
        };
        let xonly = match XOnlyPublicKey::from_slice(pubkey) {
            Ok(p) => p,
            Err(e) => return SigResult::fail(format!("invalid x-only public key: {}", e)),
        };

        let sighash = match self.taproot_sighash(mode, sighash_type) {
            Ok(h) => h,
            Err(e) => return SigResult::fail(e),
        };
        let msg = Message::from_digest(sighash);
        let valid = secp.verify_schnorr(&signature, &msg, &xonly).is_ok();
        if sighash_type != TapSighashType::Default {
            warnings.push(format!("explicit sighash type {:?}", sighash_type));
        }
        let mut display = sighash;
        display.reverse();
        SigResult {
            valid,
            sighash: hex::encode(display),
            sighash_type: format!("{:?}", sighash_type),
            detail: if valid {
                "BIP340 signature is valid".into()
            } else {
                "BIP340 signature does not verify".into()
            },
            warnings,
            ..Default::default()
        }
    }

    fn taproot_sighash(
        &self,
        mode: &SigMode,
        sighash_type: TapSighashType,
    ) -> Result<[u8; 32], String> {
        let mut cache = SighashCache::new(&self.tx);
        let prevouts = Prevouts::All(&self.prevouts);
        let (leaf, raw_annex) = match mode {
            SigMode::Tapscript { leaf_hash, codesep_pos, annex } => {
                (Some((*leaf_hash, *codesep_pos)), *annex)
            }
            SigMode::TaprootKeyPath { annex } => (None, *annex),
            _ => return Err("non-taproot sighash requested for a Schnorr check".into()),
        };
        // BIP341 commits to the annex when one is present; omitting it would
        // silently produce the wrong sighash.
        let annex = match raw_annex {
            Some(bytes) => Some(
                Annex::new(bytes).map_err(|e| format!("invalid annex: {:?}", e))?,
            ),
            None => None,
        };
        cache
            .taproot_signature_hash(self.input_index, &prevouts, annex, leaf, sighash_type)
            .map(|h| h.to_byte_array())
            .map_err(|e| format!("BIP341 sighash failed: {}", e))
    }
}

/// Core's `IsValidSignatureEncoding` (BIP66), byte for byte. `sig` includes
/// the trailing sighash type byte, as Core checks it.
pub fn is_strict_der(sig: &[u8]) -> bool {
    // Minimum and maximum size constraints.
    if sig.len() < 9 || sig.len() > 73 {
        return false;
    }
    // A signature is of type 0x30 (compound), covering everything but the
    // sighash byte.
    if sig[0] != 0x30 || sig[1] as usize != sig.len() - 3 {
        return false;
    }
    let len_r = sig[3] as usize;
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = sig[5 + len_r] as usize;
    if len_r + len_s + 7 != sig.len() {
        return false;
    }
    // R: positive integer, minimally encoded.
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    // S: positive integer, minimally encoded.
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}

/// Legacy `FindAndDelete`: `OP_CHECKSIG` strips any push of the signature from
/// the scriptCode before hashing. Only reachable in pre-segwit scripts.
///
/// Core only matches at opcode boundaries: a signature embedded inside some
/// larger push's data stays put.
pub fn find_and_delete(script: &Script, sig: &[u8]) -> ScriptBuf {
    if sig.is_empty() {
        return script.into();
    }
    let pattern = bitcoin::script::Builder::new()
        .push_slice::<&bitcoin::script::PushBytes>(
            sig.try_into().expect("signature fits a push"),
        )
        .into_script();
    let pat = pattern.as_bytes();
    let hay = script.as_bytes();
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        while hay.len() - i >= pat.len() && &hay[i..i + pat.len()] == pat {
            i += pat.len();
        }
        // Copy one opcode, push data included.
        let start = i;
        let Some(next) = next_opcode(hay, i) else {
            // Truncated push at the tail: Core copies the remainder verbatim.
            out.extend_from_slice(&hay[start..]);
            break;
        };
        i = next;
        out.extend_from_slice(&hay[start..i]);
    }
    ScriptBuf::from_bytes(out)
}

/// Offset just past the opcode at `i`, or `None` if its push data is truncated.
fn next_opcode(hay: &[u8], mut i: usize) -> Option<usize> {
    if i >= hay.len() {
        return None;
    }
    let op = hay[i];
    i += 1;
    let len = match op {
        0x01..=0x4b => op as usize,
        0x4c => {
            let n = *hay.get(i)? as usize;
            i += 1;
            n
        }
        0x4d => {
            let n = u16::from_le_bytes([*hay.get(i)?, *hay.get(i + 1)?]) as usize;
            i += 2;
            n
        }
        0x4e => {
            let n = u32::from_le_bytes([
                *hay.get(i)?,
                *hay.get(i + 1)?,
                *hay.get(i + 2)?,
                *hay.get(i + 3)?,
            ]) as usize;
            i += 4;
            n
        }
        _ => 0,
    };
    if hay.len() - i < len {
        return None;
    }
    Some(i + len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(hex: &str) -> ScriptBuf {
        ScriptBuf::from_bytes(hex::decode(hex).unwrap())
    }

    #[test]
    fn strict_der_matches_core() {
        // Real mined signatures (sighash byte included).
        let strict = hex::decode("3045022100c233c3a8a510e03ad18b0a24694ef00c78101bfd5ac075b8c1e9807b4c7deb8702204124fe2ec6e15f72fe5df8b2ce87f6d65bceb385a9f8cc9dea711cbec9d56aa901").unwrap();
        assert!(is_strict_der(&strict));
        // R has its high bit set with no 0x00 prefix: valid signature on the
        // chain (block 170065), but not strict DER.
        let negative_r = hex::decode("30440220848b4dd5fe1b177a2aa7e5fca089b2633b2e90fbbbc62b41f6d7801902566e600220d911b4138c44b611ff835fd00163ccd2b96b12bd2b126cfa1abc7e78a2bdab9e01").unwrap();
        assert!(!is_strict_der(&negative_r));
        assert!(!is_strict_der(&[0x01])); // hashtype byte alone
        assert!(!is_strict_der(&strict[..strict.len() - 1])); // hashtype missing
    }

    #[test]
    fn find_and_delete_removes_a_pushed_signature() {
        // PUSH(2) aabb / OP_DUP / PUSH(2) aabb
        let s = script("02aabb7602aabb");
        let out = find_and_delete(&s, &[0xaa, 0xbb]);
        assert_eq!(out.as_bytes(), &[0x76]);
    }

    #[test]
    fn find_and_delete_only_matches_at_opcode_boundaries() {
        // PUSH(4) 02aabbcc: the pattern 02aabb sits inside the push data, and
        // Core's FindAndDelete never looks there.
        let s = script("0402aabbcc");
        let out = find_and_delete(&s, &[0xaa, 0xbb]);
        assert_eq!(out.as_bytes(), s.as_bytes());
    }

    #[test]
    fn find_and_delete_removes_back_to_back_matches() {
        // Two adjacent pushes of the signature, then OP_1.
        let s = script("02aabb02aabb51");
        let out = find_and_delete(&s, &[0xaa, 0xbb]);
        assert_eq!(out.as_bytes(), &[0x51]);
    }

    #[test]
    fn find_and_delete_keeps_a_truncated_tail() {
        // OP_1 then a PUSH(4) with only two data bytes: copied through as-is.
        let s = script("5104aabb");
        let out = find_and_delete(&s, &[0xaa, 0xbb]);
        assert_eq!(out.as_bytes(), s.as_bytes());
    }
}
