//! End-to-end checks against real mainnet spends.
//!
//! Every fixture in `real_spends.json` was taken from a mined block, so it is
//! consensus-valid by construction: the interpreter must run each one to
//! completion with a true stack top. A failure here means the VM, the sighash
//! selection, or the spend resolution is wrong.

use bitcoin::consensus::Decodable;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, ScriptBuf, Transaction, TxOut};
use btcdeb_engine::interp::{self, Machine};
use btcdeb_engine::sig::SigContext;
use btcdeb_engine::spend;

const FIXTURES: &str = include_str!("real_spends.json");

/// Consensus + standardness flags a mainnet node would apply today.
fn flags() -> u32 {
    interp::VERIFY_P2SH
        | interp::VERIFY_DERSIG
        | interp::VERIFY_LOW_S
        | interp::VERIFY_NULLDUMMY
        | interp::VERIFY_MINIMALDATA
        | interp::VERIFY_CLEANSTACK
        | interp::VERIFY_CHECKLOCKTIMEVERIFY
        | interp::VERIFY_CHECKSEQUENCEVERIFY
        | interp::VERIFY_NULLFAIL
}

struct Outcome {
    success: bool,
    error: Option<String>,
    kind: String,
    steps: usize,
    sig_checks: usize,
    valid_sigs: usize,
    trace: Vec<String>,
}

fn run_fixture(f: &serde_json::Value) -> Outcome {
    let tx_hex = f["tx_hex"].as_str().unwrap();
    let input_index = f["input_index"].as_u64().unwrap() as usize;
    let raw = hex::decode(tx_hex).expect("fixture tx hex");
    let tx = Transaction::consensus_decode(&mut raw.as_slice()).expect("fixture tx parses");

    let prevouts: Vec<TxOut> = f["prevouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| TxOut {
            value: Amount::from_sat(p["value"].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_bytes(
                hex::decode(p["script_pubkey"].as_str().unwrap()).unwrap(),
            ),
        })
        .collect();

    let secp = Secp256k1::verification_only();
    let input = &tx.input[input_index];
    let spk = prevouts[input_index].script_pubkey.clone();
    let info = spend::resolve(&secp, &input.script_sig, &input.witness, &spk);
    assert!(
        info.errors.is_empty(),
        "spend resolution reported errors for a valid tx: {:?}",
        info.errors
    );

    let initial: Vec<Vec<u8>> = info
        .initial_stack
        .iter()
        .map(|s| hex::decode(s).unwrap())
        .collect();
    let witness_size: usize = input.witness.iter().map(|w| w.len() + 1).sum();
    let ctx = SigContext { tx: tx.clone(), input_index, prevouts };

    let annex = info.annex.as_ref().map(|a| hex::decode(a).unwrap());
    let mut m = Machine::new(
        &info.frames,
        initial,
        flags(),
        Some(ctx),
        false, // never assume: these must verify for real
        witness_size,
        annex,
    )
    .expect("machine builds");

    let mut trace = Vec::new();
    let (mut sig_checks, mut valid_sigs) = (0, 0);
    for _ in 0..10_000 {
        if m.state().finished {
            break;
        }
        let r = m.step();
        for s in &r.sigs {
            sig_checks += 1;
            if s.valid {
                valid_sigs += 1;
            }
            assert!(!s.assumed, "signature check was assumed rather than verified");
        }
        trace.push(format!(
            "#{:03} {:<28} | {}{}",
            r.n,
            truncate(&r.op, 28),
            m.state().stack.join(" "),
            r.error.as_ref().map(|e| format!("  ERROR: {}", e)).unwrap_or_default()
        ));
    }
    let st = m.state();
    Outcome {
        success: st.success,
        error: st.error,
        kind: info.kind,
        steps: st.step_n,
        sig_checks,
        valid_sigs,
        trace,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}

#[test]
fn real_mainnet_spends_all_verify() {
    let fixtures: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
    let obj = fixtures.as_object().expect("fixture map");
    assert!(obj.len() >= 4, "expected several spend types in the fixtures");

    let mut failures = Vec::new();
    for (name, f) in obj {
        let out = run_fixture(f);
        println!(
            "\n=== {} ({}) txid {} vin {} ===",
            name,
            out.kind,
            f["txid"].as_str().unwrap(),
            f["input_index"]
        );
        for line in &out.trace {
            println!("{}", line);
        }
        println!(
            "steps={} sig_checks={} valid={} success={} error={:?}",
            out.steps, out.sig_checks, out.valid_sigs, out.success, out.error
        );

        if !out.success {
            failures.push(format!("{}: {:?}", name, out.error));
        }
        // Every one of these spend types authorises with at least one signature.
        if out.sig_checks == 0 {
            failures.push(format!("{}: no signature was checked", name));
        } else if out.valid_sigs == 0 {
            failures.push(format!("{}: no signature verified", name));
        }
    }
    assert!(failures.is_empty(), "spends that should verify did not:\n{}", failures.join("\n"));
}

/// A valid spend must stop verifying if we corrupt the sighash preimage, which
/// proves the signature check is really bound to the transaction.
#[test]
fn tampering_with_the_tx_breaks_the_signature() {
    let fixtures: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
    let f = fixtures
        .as_object()
        .unwrap()
        .values()
        .find(|f| f["type"] == "v0_p2wpkh")
        .expect("a p2wpkh fixture");

    let mut tampered = f.clone();
    let raw = hex::decode(f["tx_hex"].as_str().unwrap()).unwrap();
    let mut tx = Transaction::consensus_decode(&mut raw.as_slice()).unwrap();
    // Redirect a payment: same script shape, one satoshi less.
    tx.output[0].value = Amount::from_sat(tx.output[0].value.to_sat() - 1);
    tampered["tx_hex"] = serde_json::Value::String(hex::encode(
        bitcoin::consensus::encode::serialize(&tx),
    ));

    let out = run_fixture(&tampered);
    assert!(
        !out.success,
        "changing an output value must invalidate the signature, but the script still passed"
    );
    assert_eq!(out.valid_sigs, 0, "no signature should verify over a tampered tx");
}

/// The rewind command must restore state exactly, so stepping forward again
/// reproduces the same run.
#[test]
fn rewind_restores_state() {
    let fixtures: serde_json::Value = serde_json::from_str(FIXTURES).unwrap();
    let f = fixtures.as_object().unwrap().values().next().unwrap();
    let tx_hex = f["tx_hex"].as_str().unwrap();
    let input_index = f["input_index"].as_u64().unwrap() as usize;
    let raw = hex::decode(tx_hex).unwrap();
    let tx = Transaction::consensus_decode(&mut raw.as_slice()).unwrap();
    let prevouts: Vec<TxOut> = f["prevouts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| TxOut {
            value: Amount::from_sat(p["value"].as_u64().unwrap()),
            script_pubkey: ScriptBuf::from_bytes(
                hex::decode(p["script_pubkey"].as_str().unwrap()).unwrap(),
            ),
        })
        .collect();
    let secp = Secp256k1::verification_only();
    let input = &tx.input[input_index];
    let info = spend::resolve(
        &secp,
        &input.script_sig,
        &input.witness,
        &prevouts[input_index].script_pubkey.clone(),
    );
    let initial: Vec<Vec<u8>> = info.initial_stack.iter().map(|s| hex::decode(s).unwrap()).collect();
    let ctx = SigContext { tx: tx.clone(), input_index, prevouts };
    let mut m = Machine::new(&info.frames, initial, flags(), Some(ctx), false, 0, None).unwrap();

    for _ in 0..4 {
        m.step();
    }
    let before = m.state();
    m.step();
    m.rewind().expect("rewind works");
    let after = m.state();
    assert_eq!(before.stack, after.stack);
    assert_eq!(before.step_n, after.step_n);
    assert_eq!(before.ip, after.ip);
    assert_eq!(before.frame_idx, after.frame_idx);

    m.rewind().unwrap();
    m.rewind().unwrap();
    m.rewind().unwrap();
    m.rewind().unwrap();
    assert!(m.rewind().is_err(), "rewinding past the start must error");
}
