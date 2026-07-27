//! WASM bindings for a btcdeb-style Bitcoin Script debugger.
//!
//! Script parsing, sighash construction, and signature verification come from
//! rust-bitcoin (and libsecp256k1 compiled to WASM). The stepping evaluator in
//! `interp` is ours, since rust-bitcoin ships no script VM.

pub mod asm;
pub mod interp;
pub mod num;
pub mod opnames;
pub mod sig;
pub mod spend;

use bitcoin::consensus::Decodable;
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut, Witness};
use interp::Machine;
use spend::{SigVersion, SpendInfo};
use wasm_bindgen::prelude::*;

fn js_err(e: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&e.to_string())
}

fn to_js<T: serde::Serialize>(v: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(v).map_err(js_err)
}

#[derive(serde::Deserialize)]
struct PrevoutInput {
    /// Value in satoshis.
    value: u64,
    /// scriptPubKey, hex.
    script_pubkey: String,
}

#[derive(serde::Serialize)]
struct InsView {
    offset: usize,
    text: String,
    opcode: u8,
    op_name: String,
    is_push: bool,
    data: Option<String>,
    minimal: bool,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct FrameView {
    label: String,
    sigversion: SigVersion,
    key_path: bool,
    script_hex: String,
    instructions: Vec<InsView>,
}

fn frame_views(frames: &[spend::Frame]) -> Vec<FrameView> {
    frames
        .iter()
        .map(|f| {
            let bytes = hex::decode(&f.script_hex).unwrap_or_default();
            let (ins, _) = asm::decode_script(&bytes);
            FrameView {
                label: f.label.clone(),
                sigversion: f.sigversion,
                key_path: f.key_path,
                script_hex: f.script_hex.clone(),
                instructions: ins
                    .iter()
                    .map(|i| InsView {
                        offset: i.offset,
                        text: i.text.clone(),
                        opcode: i.opcode,
                        op_name: opnames::op_name(i.opcode),
                        is_push: i.data.is_some(),
                        data: i.data.as_ref().map(hex::encode),
                        minimal: i.minimal_push,
                        error: i.error.clone(),
                    })
                    .collect(),
            }
        })
        .collect()
}

#[wasm_bindgen]
pub struct Debugger {
    machine: Machine,
    info: SpendInfo,
    frames: Vec<spend::Frame>,
}

#[wasm_bindgen]
impl Debugger {
    /// Debug a real spend: a transaction, which input to examine, and the
    /// prevouts being spent (needed for segwit and taproot sighashes).
    #[wasm_bindgen(js_name = fromTx)]
    pub fn from_tx(
        tx_hex: &str,
        input_index: usize,
        prevouts: JsValue,
        flags: u32,
        assume_valid_sigs: bool,
    ) -> Result<Debugger, JsValue> {
        let raw = hex::decode(tx_hex.trim()).map_err(|e| js_err(format!("bad tx hex: {}", e)))?;
        let tx = Transaction::consensus_decode(&mut raw.as_slice())
            .map_err(|e| js_err(format!("could not parse transaction: {}", e)))?;
        if input_index >= tx.input.len() {
            return Err(js_err(format!(
                "input index {} out of range; this tx has {} input(s)",
                input_index,
                tx.input.len()
            )));
        }

        let parsed: Vec<PrevoutInput> = serde_wasm_bindgen::from_value(prevouts)
            .map_err(|e| js_err(format!("bad prevouts: {}", e)))?;
        let mut outs = Vec::new();
        for p in &parsed {
            let spk = hex::decode(&p.script_pubkey)
                .map_err(|e| js_err(format!("bad prevout scriptPubKey hex: {}", e)))?;
            outs.push(TxOut {
                value: Amount::from_sat(p.value),
                script_pubkey: ScriptBuf::from_bytes(spk),
            });
        }
        if outs.len() != tx.input.len() {
            return Err(js_err(format!(
                "got {} prevouts for a tx with {} inputs; taproot sighashes need all of them",
                outs.len(),
                tx.input.len()
            )));
        }

        let secp: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
        let input = &tx.input[input_index];
        let spk = outs[input_index].script_pubkey.clone();
        let info = spend::resolve(&secp, &input.script_sig, &input.witness, &spk);

        let mut initial = Vec::new();
        for item in &info.initial_stack {
            initial.push(hex::decode(item).map_err(js_err)?);
        }
        let witness_size: usize = input.witness.iter().map(|w| w.len() + 1).sum();

        let annex = match &info.annex {
            Some(a) => Some(hex::decode(a).map_err(js_err)?),
            None => None,
        };
        let ctx = sig::SigContext { tx: tx.clone(), input_index, prevouts: outs };
        let machine = Machine::new(
            &info.frames,
            initial,
            flags,
            Some(ctx),
            assume_valid_sigs,
            witness_size,
            annex,
        )
        .map_err(js_err)?;
        let frames = info.frames.clone();
        Ok(Debugger { machine, info, frames })
    }

    /// Debug a bare script with a hand-made initial stack — no transaction, so
    /// signature checks are reported as unverified unless `assume_valid_sigs`.
    ///
    /// `source` accepts hex or assembly. `sigversion` is one of
    /// `legacy`, `witness_v0`, `tapscript`.
    #[wasm_bindgen(js_name = fromScript)]
    pub fn from_script(
        source: &str,
        stack: JsValue,
        sigversion: &str,
        flags: u32,
        assume_valid_sigs: bool,
    ) -> Result<Debugger, JsValue> {
        let script = parse_script_source(source).map_err(js_err)?;
        let sv = match sigversion {
            "witness_v0" => SigVersion::WitnessV0,
            "tapscript" => SigVersion::Tapscript,
            _ => SigVersion::Legacy,
        };

        let items: Vec<String> = if stack.is_null() || stack.is_undefined() {
            vec![]
        } else {
            serde_wasm_bindgen::from_value(stack).map_err(|e| js_err(format!("bad stack: {}", e)))?
        };
        let mut initial = Vec::new();
        for it in &items {
            let t = it.trim();
            if t.is_empty() {
                initial.push(Vec::new());
                continue;
            }
            initial.push(
                hex::decode(t.strip_prefix("0x").unwrap_or(t))
                    .map_err(|e| js_err(format!("stack item '{}' is not hex: {}", t, e)))?,
            );
        }

        let frame = interp::single_frame(script.as_script(), "script", sv);
        let frames = vec![frame];
        let info = SpendInfo {
            kind: "bare script (no transaction)".into(),
            frames: frames.clone(),
            initial_stack: initial.iter().map(hex::encode).collect(),
            notes: vec![
                "no transaction loaded: signature checks cannot compute a real sighash".into(),
            ],
            errors: vec![],
            output_key: None,
            annex: None,
        };
        let machine = Machine::new(&frames, initial, flags, None, assume_valid_sigs, 0, None)
            .map_err(js_err)?;
        Ok(Debugger { machine, info, frames })
    }

    /// Execute one instruction.
    pub fn step(&mut self) -> Result<JsValue, JsValue> {
        let rec = self.machine.step();
        to_js(&rec)
    }

    /// Run up to `max` steps, stopping on completion or error.
    pub fn run(&mut self, max: usize) -> Result<JsValue, JsValue> {
        let mut out = Vec::new();
        for _ in 0..max {
            if self.machine.state().finished {
                break;
            }
            out.push(self.machine.step());
        }
        to_js(&out)
    }

    /// Undo the last step.
    pub fn rewind(&mut self) -> Result<JsValue, JsValue> {
        self.machine.rewind().map_err(js_err)?;
        to_js(&self.machine.state())
    }

    pub fn state(&self) -> Result<JsValue, JsValue> {
        to_js(&self.machine.state())
    }

    /// Everything the UI needs to render the script listing.
    pub fn listing(&self) -> Result<JsValue, JsValue> {
        to_js(&frame_views(&self.frames))
    }

    /// Detected spend type, notes, and any structural errors.
    pub fn info(&self) -> Result<JsValue, JsValue> {
        to_js(&self.info)
    }

    /// All step records so far.
    pub fn records(&self) -> Result<JsValue, JsValue> {
        to_js(&self.machine.records)
    }
}

fn parse_script_source(source: &str) -> Result<ScriptBuf, String> {
    let s = source.trim();
    if s.is_empty() {
        return Err("empty script".into());
    }
    let compact: String = s.split_whitespace().collect();
    let hexish = compact.strip_prefix("0x").unwrap_or(&compact);
    if !hexish.is_empty()
        && hexish.len() % 2 == 0
        && hexish.chars().all(|c| c.is_ascii_hexdigit())
        && !s.to_ascii_uppercase().contains("OP_")
    {
        return Ok(ScriptBuf::from_bytes(hex::decode(hexish).map_err(|e| e.to_string())?));
    }
    asm::assemble(s)
}

/// `btcc`: assemble script assembly into hex.
#[wasm_bindgen]
pub fn btcc(source: &str) -> Result<String, JsValue> {
    let s = asm::assemble(source).map_err(js_err)?;
    Ok(hex::encode(s.as_bytes()))
}

/// Disassemble script hex into one instruction per line.
#[wasm_bindgen]
pub fn disasm(script_hex: &str) -> Result<JsValue, JsValue> {
    let bytes = hex::decode(script_hex.trim()).map_err(|e| js_err(format!("bad hex: {}", e)))?;
    to_js(&asm::disassemble(&bytes))
}

#[derive(serde::Serialize)]
struct TxView {
    txid: String,
    wtxid: String,
    version: i32,
    lock_time: u32,
    size: usize,
    vsize: usize,
    weight: u64,
    is_segwit: bool,
    inputs: Vec<TxInView>,
    outputs: Vec<TxOutView>,
}

#[derive(serde::Serialize)]
struct TxInView {
    index: usize,
    txid: String,
    vout: u32,
    sequence: u32,
    script_sig: String,
    script_sig_asm: Vec<String>,
    witness: Vec<String>,
}

#[derive(serde::Serialize)]
struct TxOutView {
    index: usize,
    value: u64,
    script_pubkey: String,
    script_pubkey_asm: Vec<String>,
    address: Option<String>,
}

/// Parse a raw transaction for display.
#[wasm_bindgen(js_name = parseTx)]
pub fn parse_tx(tx_hex: &str, network: &str) -> Result<JsValue, JsValue> {
    let raw = hex::decode(tx_hex.trim()).map_err(|e| js_err(format!("bad tx hex: {}", e)))?;
    let tx = Transaction::consensus_decode(&mut raw.as_slice())
        .map_err(|e| js_err(format!("could not parse transaction: {}", e)))?;
    let net = network_from_str(network);

    let view = TxView {
        txid: tx.compute_txid().to_string(),
        wtxid: tx.compute_wtxid().to_string(),
        version: tx.version.0,
        lock_time: tx.lock_time.to_consensus_u32(),
        size: raw.len(),
        vsize: tx.vsize(),
        weight: tx.weight().to_wu(),
        is_segwit: tx.input.iter().any(|i| !i.witness.is_empty()),
        inputs: tx
            .input
            .iter()
            .enumerate()
            .map(|(i, inp)| TxInView {
                index: i,
                txid: inp.previous_output.txid.to_string(),
                vout: inp.previous_output.vout,
                sequence: inp.sequence.to_consensus_u32(),
                script_sig: hex::encode(inp.script_sig.as_bytes()),
                script_sig_asm: asm::disassemble(inp.script_sig.as_bytes()),
                witness: inp.witness.iter().map(hex::encode).collect(),
            })
            .collect(),
        outputs: tx
            .output
            .iter()
            .enumerate()
            .map(|(i, o)| TxOutView {
                index: i,
                value: o.value.to_sat(),
                script_pubkey: hex::encode(o.script_pubkey.as_bytes()),
                script_pubkey_asm: asm::disassemble(o.script_pubkey.as_bytes()),
                address: bitcoin::Address::from_script(&o.script_pubkey, net)
                    .ok()
                    .map(|a| a.to_string()),
            })
            .collect(),
    };
    to_js(&view)
}

fn network_from_str(network: &str) -> bitcoin::Network {
    match network {
        "testnet" | "testnet4" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => bitcoin::Network::Bitcoin,
    }
}

/// `tf`: apply a transform to a value, as btcdeb's `tf` command does.
#[wasm_bindgen]
pub fn tf(func: &str, arg: &str) -> Result<String, JsValue> {
    use bitcoin::hashes::{ripemd160, sha1, sha256, sha256d, Hash, HashEngine};
    let trimmed = arg.trim();
    let bytes = || -> Result<Vec<u8>, JsValue> {
        let h = trimmed.strip_prefix("0x").unwrap_or(trimmed);
        hex::decode(h).map_err(|e| js_err(format!("argument must be hex: {}", e)))
    };

    let out = match func {
        "sha256" => hex::encode(sha256::Hash::hash(&bytes()?).to_byte_array()),
        "sha256d" | "hash256" => hex::encode(sha256d::Hash::hash(&bytes()?).to_byte_array()),
        "ripemd160" => hex::encode(ripemd160::Hash::hash(&bytes()?).to_byte_array()),
        "sha1" => hex::encode(sha1::Hash::hash(&bytes()?).to_byte_array()),
        "hash160" => hex::encode(bitcoin::hashes::hash160::Hash::hash(&bytes()?).to_byte_array()),
        "reverse" => {
            let mut b = bytes()?;
            b.reverse();
            hex::encode(b)
        }
        "int" => num::decode(&bytes()?, false, 8)
            .map(|v| v.to_string())
            .map_err(|e| js_err(e.0))?,
        "num" => {
            let v: i64 = trimmed
                .parse()
                .map_err(|_| js_err("argument must be a decimal integer"))?;
            hex::encode(num::encode(v))
        }
        "str" => hex::encode(trimmed.as_bytes()),
        "unstr" => String::from_utf8(bytes()?).map_err(js_err)?,
        "x" => {
            let b = bytes()?;
            match b.len() {
                33 => hex::encode(&b[1..]),
                32 => hex::encode(&b),
                _ => {
                    return Err(js_err(
                        "expected a 33-byte compressed or 32-byte x-only key",
                    ))
                }
            }
        }
        "tagged-hash" => {
            let (tag, rest) = trimmed
                .split_once(':')
                .ok_or_else(|| js_err("usage: tf tagged-hash <tag>:<hex>"))?;
            let msg = hex::decode(rest.trim()).map_err(js_err)?;
            let tag_hash = sha256::Hash::hash(tag.as_bytes());
            let mut eng = sha256::Hash::engine();
            eng.input(&tag_hash.to_byte_array());
            eng.input(&tag_hash.to_byte_array());
            eng.input(&msg);
            hex::encode(sha256::Hash::from_engine(eng).to_byte_array())
        }
        _ => {
            return Err(js_err(format!(
                "unknown transform '{}'; try sha256, sha256d, hash160, ripemd160, sha1, reverse, int, num, str, unstr, x, tagged-hash",
                func
            )))
        }
    };
    Ok(out)
}

/// Derive the address for a scriptPubKey, when it has one.
#[wasm_bindgen(js_name = scriptAddress)]
pub fn script_address(script_hex: &str, network: &str) -> Result<String, JsValue> {
    let bytes = hex::decode(script_hex.trim()).map_err(js_err)?;
    let spk = ScriptBuf::from_bytes(bytes);
    bitcoin::Address::from_script(&spk, network_from_str(network))
        .map(|a| a.to_string())
        .map_err(|e| js_err(format!("no address for this script: {}", e)))
}

/// Resolve a spend without building a debugger, for the "what is this input?"
/// summary line.
#[wasm_bindgen(js_name = describeSpend)]
pub fn describe_spend(
    script_sig_hex: &str,
    witness: JsValue,
    script_pubkey_hex: &str,
) -> Result<JsValue, JsValue> {
    let ss = ScriptBuf::from_bytes(hex::decode(script_sig_hex.trim()).map_err(js_err)?);
    let spk = ScriptBuf::from_bytes(hex::decode(script_pubkey_hex.trim()).map_err(js_err)?);
    let items: Vec<String> = if witness.is_null() || witness.is_undefined() {
        vec![]
    } else {
        serde_wasm_bindgen::from_value(witness).map_err(js_err)?
    };
    let mut w = Witness::new();
    for it in &items {
        w.push(hex::decode(it).map_err(js_err)?);
    }
    let secp: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
    to_js(&spend::resolve(&secp, ss.as_script(), &w, spk.as_script()))
}

#[derive(serde::Serialize)]
struct FlagView {
    name: String,
    bit: u32,
    description: String,
    /// Standardness-only rule: mainnet relay enforces it, mined blocks need not.
    policy: bool,
}

/// Script verification flags, exposed so the UI can build its toggles.
#[wasm_bindgen(js_name = flagInfo)]
pub fn flag_info() -> Result<JsValue, JsValue> {
    let flags = [
        ("P2SH", interp::VERIFY_P2SH, "evaluate P2SH redeem scripts", false),
        ("DERSIG", interp::VERIFY_DERSIG, "require strict DER signatures", false),
        ("LOW_S", interp::VERIFY_LOW_S, "require low S values (policy)", true),
        ("NULLDUMMY", interp::VERIFY_NULLDUMMY, "CHECKMULTISIG dummy must be empty", false),
        ("MINIMALDATA", interp::VERIFY_MINIMALDATA, "require minimal pushes and numbers (policy)", true),
        ("CLEANSTACK", interp::VERIFY_CLEANSTACK, "require exactly one stack element at the end (policy)", true),
        ("CHECKLOCKTIMEVERIFY", interp::VERIFY_CHECKLOCKTIMEVERIFY, "enforce BIP65 CLTV", false),
        ("CHECKSEQUENCEVERIFY", interp::VERIFY_CHECKSEQUENCEVERIFY, "enforce BIP112 CSV", false),
        ("NULLFAIL", interp::VERIFY_NULLFAIL, "failed checks must use an empty signature (policy)", true),
    ];
    let list: Vec<FlagView> = flags
        .into_iter()
        .map(|(name, bit, description, policy)| FlagView {
            name: name.to_string(),
            bit,
            description: description.to_string(),
            policy,
        })
        .collect();
    to_js(&list)
}

#[wasm_bindgen]
pub fn version() -> String {
    concat!("btcdeb-wasm ", env!("CARGO_PKG_VERSION"), " / rust-bitcoin 0.32").to_string()
}
