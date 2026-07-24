//! Spend-type resolution: turn (scriptSig, witness, scriptPubKey) into the
//! ordered list of scripts the interpreter should walk, the way Bitcoin Core's
//! VerifyScript decides what to execute.

use bitcoin::opcodes::all as opcodes;
use bitcoin::script::{Builder, Script};
use bitcoin::secp256k1::{Secp256k1, VerifyOnly, XOnlyPublicKey};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash};
use bitcoin::{ScriptBuf, Witness};

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
pub enum SigVersion {
    Legacy,
    WitnessV0,
    Tapscript,
    TaprootKeyPath,
}

#[derive(Clone, Debug, serde::Serialize)]
pub enum EnterAction {
    /// Continue with the stack as-is.
    Keep,
    /// P2SH: the top element is the serialized redeem script; drop it.
    PopRedeem,
    /// Segwit: execution restarts from the witness stack.
    ResetStack(Vec<String>),
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Frame {
    pub label: String,
    pub script_hex: String,
    pub sigversion: SigVersion,
    pub enter: EnterAction,
    /// Set for tapscript frames; needed for the BIP341 sighash.
    pub leaf_hash: Option<String>,
    /// A key-path spend has no script — it is a single Schnorr check.
    pub key_path: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SpendInfo {
    /// Human-readable spend type, e.g. "P2SH-P2WSH" or "P2TR (script path)".
    pub kind: String,
    pub frames: Vec<Frame>,
    pub initial_stack: Vec<String>,
    pub notes: Vec<String>,
    pub errors: Vec<String>,
    /// x-only output key for taproot spends, hex.
    pub output_key: Option<String>,
    pub annex: Option<String>,
}

fn hexv(items: &[Vec<u8>]) -> Vec<String> {
    items.iter().map(hex::encode).collect()
}

/// Recover the redeem script from a P2SH scriptSig: it is the final push.
fn last_push(script: &Script) -> Option<Vec<u8>> {
    let mut last = None;
    for ins in script.instructions() {
        match ins {
            Ok(bitcoin::script::Instruction::PushBytes(b)) => last = Some(b.as_bytes().to_vec()),
            Ok(bitcoin::script::Instruction::Op(_)) => last = None,
            Err(_) => return None,
        }
    }
    last
}

fn p2wpkh_script(hash: &[u8]) -> ScriptBuf {
    Builder::new()
        .push_opcode(opcodes::OP_DUP)
        .push_opcode(opcodes::OP_HASH160)
        .push_slice::<&bitcoin::script::PushBytes>(hash.try_into().expect("20 bytes"))
        .push_opcode(opcodes::OP_EQUALVERIFY)
        .push_opcode(opcodes::OP_CHECKSIG)
        .into_script()
}

/// Decide what to execute for this input.
pub fn resolve(
    secp: &Secp256k1<VerifyOnly>,
    script_sig: &Script,
    witness: &Witness,
    spk: &Script,
) -> SpendInfo {
    let mut info = SpendInfo {
        kind: "unknown".into(),
        frames: vec![],
        initial_stack: vec![],
        notes: vec![],
        errors: vec![],
        output_key: None,
        annex: None,
    };

    let wit: Vec<Vec<u8>> = witness.iter().map(|w| w.to_vec()).collect();

    // A P2SH scriptPubKey may wrap a witness program, so peel that first.
    let (effective_spk, p2sh_prefix): (ScriptBuf, Option<ScriptBuf>) = if spk.is_p2sh() {
        match last_push(script_sig) {
            Some(redeem) => (ScriptBuf::from_bytes(redeem.clone()), Some(ScriptBuf::from_bytes(redeem))),
            None => {
                info.errors
                    .push("P2SH scriptPubKey but scriptSig has no redeem script push".into());
                (spk.into(), None)
            }
        }
    } else {
        (spk.into(), None)
    };

    let nested = p2sh_prefix.is_some();
    let is_witness = effective_spk.witness_version().is_some() && !wit.is_empty();

    if is_witness {
        let version = effective_spk.witness_version().unwrap();
        let program = &effective_spk.as_bytes()[2..];

        // BIP341: a final element starting with 0x50 is the annex, not a stack item.
        let mut stack = wit.clone();
        if stack.len() >= 2 {
            if let Some(last) = stack.last() {
                if last.first() == Some(&0x50) {
                    info.annex = Some(hex::encode(last));
                    stack.pop();
                }
            }
        }

        if nested {
            info.frames.push(Frame {
                label: "scriptSig".into(),
                script_hex: hex::encode(script_sig.as_bytes()),
                sigversion: SigVersion::Legacy,
                enter: EnterAction::Keep,
                leaf_hash: None,
                key_path: false,
            });
            info.frames.push(Frame {
                label: "scriptPubKey (P2SH)".into(),
                script_hex: hex::encode(spk.as_bytes()),
                sigversion: SigVersion::Legacy,
                enter: EnterAction::Keep,
                leaf_hash: None,
                key_path: false,
            });
        }

        match (version.to_num(), program.len()) {
            (0, 20) => {
                info.kind = if nested { "P2SH-P2WPKH".into() } else { "P2WPKH".into() };
                if stack.len() != 2 {
                    info.errors.push(format!(
                        "P2WPKH requires exactly 2 witness elements, found {}",
                        stack.len()
                    ));
                }
                info.notes
                    .push("scriptPubKey is a v0 witness program; executing the implied P2PKH script".into());
                info.frames.push(Frame {
                    label: "witness (implied P2PKH)".into(),
                    script_hex: hex::encode(p2wpkh_script(program).as_bytes()),
                    sigversion: SigVersion::WitnessV0,
                    enter: EnterAction::ResetStack(hexv(&stack)),
                    leaf_hash: None,
                    key_path: false,
                });
                info.initial_stack = if nested { vec![] } else { hexv(&stack) };
            }
            (0, 32) => {
                info.kind = if nested { "P2SH-P2WSH".into() } else { "P2WSH".into() };
                let Some(script) = stack.last().cloned() else {
                    info.errors.push("P2WSH witness stack is empty".into());
                    return info;
                };
                let expected = bitcoin::hashes::sha256::Hash::hash(&script);
                if expected.as_byte_array() != program {
                    info.errors
                        .push("witness script does not hash to the witness program".into());
                }
                let args = stack[..stack.len() - 1].to_vec();
                info.frames.push(Frame {
                    label: "witnessScript".into(),
                    script_hex: hex::encode(&script),
                    sigversion: SigVersion::WitnessV0,
                    enter: EnterAction::ResetStack(hexv(&args)),
                    leaf_hash: None,
                    key_path: false,
                });
                info.initial_stack = if nested { vec![] } else { hexv(&args) };
            }
            (1, 32) if !nested => {
                info.output_key = Some(hex::encode(program));
                if stack.len() == 1 {
                    info.kind = "P2TR (key path)".into();
                    info.notes.push(
                        "key-path spend: one Schnorr signature checked against the output key"
                            .into(),
                    );
                    info.frames.push(Frame {
                        label: "taproot key path".into(),
                        script_hex: String::new(),
                        sigversion: SigVersion::TaprootKeyPath,
                        enter: EnterAction::ResetStack(hexv(&stack)),
                        leaf_hash: None,
                        key_path: true,
                    });
                    info.initial_stack = hexv(&stack);
                } else if stack.len() >= 2 {
                    info.kind = "P2TR (script path)".into();
                    let control = stack.pop().unwrap();
                    let leaf_script = stack.pop().unwrap();
                    match ControlBlock::decode(&control) {
                        Ok(cb) => {
                            let leaf_version = cb.leaf_version;
                            let script = ScriptBuf::from_bytes(leaf_script.clone());
                            let leaf = TapLeafHash::from_script(&script, leaf_version);
                            info.notes.push(format!(
                                "control block: leaf version 0x{:02x}, {} merkle step(s), internal key {}",
                                leaf_version.to_consensus(),
                                cb.merkle_branch.len(),
                                cb.internal_key
                            ));
                            match XOnlyPublicKey::from_slice(program) {
                                Ok(output_key) => {
                                    if cb.verify_taproot_commitment(secp, output_key, &script) {
                                        info.notes.push(
                                            "taproot commitment verified: this leaf is in the tree"
                                                .into(),
                                        );
                                    } else {
                                        info.errors.push(
                                            "taproot commitment INVALID: leaf/path does not tweak to the output key"
                                                .into(),
                                        );
                                    }
                                }
                                Err(e) => info
                                    .errors
                                    .push(format!("output key is not a valid x-only key: {}", e)),
                            }
                            if leaf_version != LeafVersion::TapScript {
                                info.notes.push(
                                    "unknown leaf version: consensus treats this as anyone-can-spend"
                                        .into(),
                                );
                            }
                            info.frames.push(Frame {
                                label: "tapscript leaf".into(),
                                script_hex: hex::encode(&leaf_script),
                                sigversion: SigVersion::Tapscript,
                                enter: EnterAction::ResetStack(hexv(&stack)),
                                leaf_hash: Some(hex::encode(leaf.to_byte_array())),
                                key_path: false,
                            });
                            info.initial_stack = hexv(&stack);
                        }
                        Err(e) => {
                            info.errors.push(format!("invalid control block: {}", e));
                        }
                    }
                } else {
                    info.errors.push("empty witness for a P2TR input".into());
                }
            }
            (v, l) => {
                info.kind = format!("witness v{} program ({} bytes)", v, l);
                info.notes.push(
                    "unknown witness version: consensus treats this as anyone-can-spend".into(),
                );
                info.initial_stack = hexv(&stack);
            }
        }
        return info;
    }

    // Non-witness paths.
    info.frames.push(Frame {
        label: "scriptSig".into(),
        script_hex: hex::encode(script_sig.as_bytes()),
        sigversion: SigVersion::Legacy,
        enter: EnterAction::Keep,
        leaf_hash: None,
        key_path: false,
    });
    info.frames.push(Frame {
        label: "scriptPubKey".into(),
        script_hex: hex::encode(spk.as_bytes()),
        sigversion: SigVersion::Legacy,
        enter: EnterAction::Keep,
        leaf_hash: None,
        key_path: false,
    });

    if let Some(redeem) = p2sh_prefix {
        info.kind = "P2SH".into();
        info.notes
            .push("P2SH: after scriptPubKey succeeds, the redeem script is deserialized and run".into());
        info.frames.push(Frame {
            label: "redeemScript".into(),
            script_hex: hex::encode(redeem.as_bytes()),
            sigversion: SigVersion::Legacy,
            enter: EnterAction::PopRedeem,
            leaf_hash: None,
            key_path: false,
        });
    } else {
        info.kind = classify_legacy(spk);
    }
    info
}

fn classify_legacy(spk: &Script) -> String {
    if spk.is_p2pkh() {
        "P2PKH".into()
    } else if spk.is_p2pk() {
        "P2PK".into()
    } else if spk.is_multisig() {
        "bare multisig".into()
    } else if spk.is_op_return() {
        "OP_RETURN (unspendable)".into()
    } else {
        "bare script".into()
    }
}

use bitcoin::hashes::Hash as _;
