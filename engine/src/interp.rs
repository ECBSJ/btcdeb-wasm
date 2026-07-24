//! The stepping interpreter.
//!
//! rust-bitcoin parses scripts and builds sighashes but has no script VM, so
//! this is a from-scratch evaluator that follows Bitcoin Core's
//! `EvalScript` closely enough to debug real spends. Every step snapshots
//! state so `rewind` can walk backwards.

use bitcoin::script::Script;
use bitcoin::secp256k1::{Secp256k1, VerifyOnly};
use bitcoin::taproot::TapLeafHash;
use bitcoin::{ScriptBuf, Sequence};

use crate::asm::{decode_script, Ins};
use crate::num;
use crate::opnames::{is_disabled, is_op_success, op_name};
use crate::sig::{find_and_delete, SigContext, SigMode, SigResult};
use crate::spend::{EnterAction, Frame, SigVersion};

pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
pub const MAX_STACK_SIZE: usize = 1000;
pub const MAX_OPS_PER_SCRIPT: usize = 201;
pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;
pub const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;
pub const LOCKTIME_THRESHOLD: i64 = 500_000_000;

// Script verification flags, mirrored in the JS UI.
pub const VERIFY_P2SH: u32 = 1 << 0;
pub const VERIFY_DERSIG: u32 = 1 << 2;
pub const VERIFY_LOW_S: u32 = 1 << 3;
pub const VERIFY_NULLDUMMY: u32 = 1 << 4;
pub const VERIFY_MINIMALDATA: u32 = 1 << 6;
pub const VERIFY_CLEANSTACK: u32 = 1 << 8;
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 = 1 << 9;
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 = 1 << 10;
pub const VERIFY_NULLFAIL: u32 = 1 << 14;

#[derive(Clone, serde::Serialize)]
pub struct StepRecord {
    /// Monotonic step number, 1-based, as btcdeb labels ops.
    pub n: usize,
    pub frame: usize,
    pub frame_label: String,
    /// Byte offset of this op within its script.
    pub offset: usize,
    pub op: String,
    /// Data pushed, if this was a push.
    pub data: Option<String>,
    /// True when the op was skipped because we are inside a false branch.
    pub skipped: bool,
    pub notes: Vec<String>,
    pub error: Option<String>,
    /// Every signature check this op performed. Multisig produces several.
    pub sigs: Vec<SigResult>,
    /// Set on the synthetic records emitted when execution moves between scripts.
    pub transition: bool,
}

impl StepRecord {
    fn new(n: usize, frame: usize, label: &str, offset: usize, op: String) -> Self {
        StepRecord {
            n,
            frame,
            frame_label: label.to_string(),
            offset,
            op,
            data: None,
            skipped: false,
            notes: vec![],
            error: None,
            sigs: vec![],
            transition: false,
        }
    }
}

struct CompiledFrame {
    label: String,
    script: ScriptBuf,
    ins: Vec<Ins>,
    decode_error: Option<String>,
    sigversion: SigVersion,
    enter: EnterAction,
    leaf_hash: Option<TapLeafHash>,
    key_path: bool,
}

#[derive(Clone)]
struct Snapshot {
    frame_idx: usize,
    ip: usize,
    stack: Vec<Vec<u8>>,
    altstack: Vec<Vec<u8>>,
    cond: Vec<bool>,
    op_count: usize,
    begin_codehash: usize,
    codesep_pos: u32,
    finished: bool,
    error: Option<String>,
    entered: bool,
    saved_sigstack: Vec<Vec<u8>>,
    budget: i64,
    step_n: usize,
}

#[derive(Clone, serde::Serialize)]
pub struct MachineState {
    pub frame_idx: usize,
    pub frame_label: String,
    pub sigversion: SigVersion,
    pub ip: usize,
    pub stack: Vec<String>,
    pub altstack: Vec<String>,
    pub cond: Vec<bool>,
    pub op_count: usize,
    pub finished: bool,
    pub error: Option<String>,
    pub success: bool,
    pub step_n: usize,
    pub can_rewind: bool,
    pub budget: i64,
}

pub struct Machine {
    frames: Vec<CompiledFrame>,
    frame_idx: usize,
    ip: usize,
    stack: Vec<Vec<u8>>,
    altstack: Vec<Vec<u8>>,
    cond: Vec<bool>,
    op_count: usize,
    begin_codehash: usize,
    codesep_pos: u32,
    finished: bool,
    error: Option<String>,
    /// Whether the current frame's enter action has been applied.
    entered: bool,
    saved_sigstack: Vec<Vec<u8>>,
    budget: i64,
    step_n: usize,
    history: Vec<Snapshot>,
    pub flags: u32,
    pub ctx: Option<SigContext>,
    /// Without a transaction there is nothing to sign, so signature checks are
    /// reported as assumed-valid instead of failing.
    pub assume_valid_sigs: bool,
    /// BIP341 annex for this input, if the witness carried one.
    pub annex: Option<Vec<u8>>,
    secp: Secp256k1<VerifyOnly>,
    pub records: Vec<StepRecord>,
}

impl Machine {
    pub fn new(
        frames: &[Frame],
        initial_stack: Vec<Vec<u8>>,
        flags: u32,
        ctx: Option<SigContext>,
        assume_valid_sigs: bool,
        witness_size: usize,
        annex: Option<Vec<u8>>,
    ) -> Result<Machine, String> {
        let mut compiled = Vec::new();
        for f in frames {
            let bytes = hex::decode(&f.script_hex).map_err(|e| format!("bad script hex: {}", e))?;
            if bytes.len() > MAX_SCRIPT_SIZE {
                return Err(format!(
                    "script {} is {} bytes, over the {} byte limit",
                    f.label,
                    bytes.len(),
                    MAX_SCRIPT_SIZE
                ));
            }
            let (ins, decode_error) = decode_script(&bytes);
            let leaf_hash = match &f.leaf_hash {
                Some(h) => {
                    let raw = hex::decode(h).map_err(|e| format!("bad leaf hash: {}", e))?;
                    let arr: [u8; 32] = raw
                        .try_into()
                        .map_err(|_| "leaf hash must be 32 bytes".to_string())?;
                    Some(
                        <TapLeafHash as bitcoin::hashes::Hash>::from_byte_array(arr),
                    )
                }
                None => None,
            };
            compiled.push(CompiledFrame {
                label: f.label.clone(),
                script: ScriptBuf::from_bytes(bytes),
                ins,
                decode_error,
                sigversion: f.sigversion,
                enter: f.enter.clone(),
                leaf_hash,
                key_path: f.key_path,
            });
        }
        if compiled.is_empty() {
            return Err("nothing to execute".into());
        }
        Ok(Machine {
            frames: compiled,
            frame_idx: 0,
            ip: 0,
            stack: initial_stack,
            altstack: vec![],
            cond: vec![],
            op_count: 0,
            begin_codehash: 0,
            codesep_pos: 0xffff_ffff,
            finished: false,
            error: None,
            entered: false,
            saved_sigstack: vec![],
            budget: 50 + witness_size as i64,
            step_n: 0,
            history: vec![],
            flags,
            ctx,
            assume_valid_sigs,
            annex,
            secp: Secp256k1::verification_only(),
            records: vec![],
        })
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            frame_idx: self.frame_idx,
            ip: self.ip,
            stack: self.stack.clone(),
            altstack: self.altstack.clone(),
            cond: self.cond.clone(),
            op_count: self.op_count,
            begin_codehash: self.begin_codehash,
            codesep_pos: self.codesep_pos,
            finished: self.finished,
            error: self.error.clone(),
            entered: self.entered,
            saved_sigstack: self.saved_sigstack.clone(),
            budget: self.budget,
            step_n: self.step_n,
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.frame_idx = s.frame_idx;
        self.ip = s.ip;
        self.stack = s.stack;
        self.altstack = s.altstack;
        self.cond = s.cond;
        self.op_count = s.op_count;
        self.begin_codehash = s.begin_codehash;
        self.codesep_pos = s.codesep_pos;
        self.finished = s.finished;
        self.error = s.error;
        self.entered = s.entered;
        self.saved_sigstack = s.saved_sigstack;
        self.budget = s.budget;
        self.step_n = s.step_n;
    }

    pub fn rewind(&mut self) -> Result<(), String> {
        let Some(snap) = self.history.pop() else {
            return Err("at the beginning; nothing to rewind".into());
        };
        self.restore(snap);
        self.records.pop();
        Ok(())
    }

    pub fn state(&self) -> MachineState {
        let frame = &self.frames[self.frame_idx.min(self.frames.len() - 1)];
        MachineState {
            frame_idx: self.frame_idx,
            frame_label: frame.label.clone(),
            sigversion: frame.sigversion,
            ip: self.ip,
            stack: self.stack.iter().map(hex::encode).collect(),
            altstack: self.altstack.iter().map(hex::encode).collect(),
            cond: self.cond.clone(),
            op_count: self.op_count,
            finished: self.finished,
            error: self.error.clone(),
            success: self.finished && self.error.is_none(),
            step_n: self.step_n,
            can_rewind: !self.history.is_empty(),
            budget: self.budget,
        }
    }

    fn exec_enabled(&self) -> bool {
        self.cond.iter().all(|c| *c)
    }

    fn require_minimal(&self) -> bool {
        self.flags & VERIFY_MINIMALDATA != 0
    }

    fn pop(&mut self) -> Result<Vec<u8>, String> {
        self.stack.pop().ok_or_else(|| "stack underflow".to_string())
    }

    fn peek(&self, from_top: usize) -> Result<&Vec<u8>, String> {
        if self.stack.len() <= from_top {
            return Err("stack underflow".into());
        }
        Ok(&self.stack[self.stack.len() - 1 - from_top])
    }

    fn pop_num(&mut self, max_size: usize) -> Result<i64, String> {
        let v = self.pop()?;
        num::decode(&v, self.require_minimal(), max_size).map_err(|e| e.0)
    }

    fn push_num(&mut self, v: i64) {
        self.stack.push(num::encode(v));
    }

    fn push_bool(&mut self, b: bool) {
        self.stack.push(if b { vec![1u8] } else { Vec::new() });
    }

    /// Advance one step. Returns the record describing what happened.
    pub fn step(&mut self) -> StepRecord {
        if self.finished {
            let mut r = StepRecord::new(self.step_n, self.frame_idx, "", 0, "(done)".into());
            r.error = Some(
                self.error
                    .clone()
                    .unwrap_or_else(|| "execution already finished".into()),
            );
            return r;
        }

        self.history.push(self.snapshot());
        let rec = self.step_inner();
        if let Some(e) = &rec.error {
            self.error = Some(e.clone());
            self.finished = true;
        }
        self.records.push(rec.clone());
        rec
    }

    fn step_inner(&mut self) -> StepRecord {
        // Apply the pending enter action for this frame first, as its own step
        // so the stack change is visible.
        if !self.entered {
            self.entered = true;
            let frame = &self.frames[self.frame_idx];
            let label = frame.label.clone();
            let enter = frame.enter.clone();
            let decode_error = frame.decode_error.clone();
            self.step_n += 1;
            let mut r = StepRecord::new(
                self.step_n,
                self.frame_idx,
                &label,
                0,
                format!("── {} ──", label),
            );
            r.transition = true;
            self.begin_codehash = 0;

            match enter {
                EnterAction::Keep => {}
                EnterAction::PopRedeem => {
                    // Core restores the stack left by scriptSig and pops the
                    // serialized redeem script off it.
                    self.stack = self.saved_sigstack.clone();
                    match self.stack.pop() {
                        Some(_) => r
                            .notes
                            .push("popped the serialized redeem script off the stack".into()),
                        None => {
                            r.error = Some("no redeem script on the stack".into());
                            return r;
                        }
                    }
                }
                EnterAction::ResetStack(items) => {
                    let mut decoded = Vec::new();
                    for it in &items {
                        match hex::decode(it) {
                            Ok(b) => decoded.push(b),
                            Err(e) => {
                                r.error = Some(format!("bad stack item hex: {}", e));
                                return r;
                            }
                        }
                    }
                    self.stack = decoded;
                    r.notes
                        .push("stack initialised from the witness".into());
                }
            }
            if let Some(e) = decode_error {
                r.notes.push(format!("script decode warning: {}", e));
            }
            if self.frames[self.frame_idx].key_path {
                r.notes
                    .push("no script to execute; the next step performs the key-path check".into());
            }
            return r;
        }

        let frame_idx = self.frame_idx;
        let key_path = self.frames[frame_idx].key_path;

        // Taproot key path: a single Schnorr check, no script.
        if key_path {
            self.step_n += 1;
            let label = self.frames[frame_idx].label.clone();
            let mut r = StepRecord::new(
                self.step_n,
                frame_idx,
                &label,
                0,
                "CHECKSIG (BIP341 key path)".into(),
            );
            let sig = match self.stack.last().cloned() {
                Some(s) => s,
                None => {
                    r.error = Some("no signature on the witness stack".into());
                    return r;
                }
            };
            let output_key = match &self.ctx {
                Some(c) => c
                    .prevouts
                    .get(c.input_index)
                    .and_then(|o| {
                        let b = o.script_pubkey.as_bytes();
                        if b.len() == 34 { Some(b[2..].to_vec()) } else { None }
                    }),
                None => None,
            };
            match (&self.ctx, output_key) {
                (Some(ctx), Some(key)) => {
                    let res = ctx.check_schnorr(
                        &self.secp,
                        &sig,
                        &key,
                        &SigMode::TaprootKeyPath { annex: self.annex.as_deref() },
                    );
                    if !res.valid {
                        r.error = Some(format!("key-path signature check failed: {}", res.detail));
                    } else {
                        r.notes.push("key-path spend is valid".into());
                    }
                    r.sigs.push(res);
                }
                _ => {
                    if self.assume_valid_sigs {
                        r.notes.push(
                            "no transaction context: assuming the key-path signature is valid"
                                .into(),
                        );
                    } else {
                        r.error = Some("no transaction context for the key-path check".into());
                        return r;
                    }
                }
            }
            self.stack.clear();
            self.push_bool(true);
            self.ip = 1; // mark the pseudo-script as consumed
            self.finish_or_advance(&mut r);
            return r;
        }

        // End of the current script?
        if self.ip >= self.frames[frame_idx].ins.len() {
            self.step_n += 1;
            let label = self.frames[frame_idx].label.clone();
            let mut r =
                StepRecord::new(self.step_n, frame_idx, &label, 0, format!("── end of {} ──", label));
            r.transition = true;
            self.finish_or_advance(&mut r);
            return r;
        }

        let ins = self.frames[frame_idx].ins[self.ip].clone();
        let label = self.frames[frame_idx].label.clone();
        self.ip += 1;
        self.step_n += 1;

        let mut r = StepRecord::new(self.step_n, frame_idx, &label, ins.offset, ins.text.clone());
        if let Some(d) = &ins.data {
            r.data = Some(hex::encode(d));
        }
        if let Some(e) = &ins.error {
            r.error = Some(e.clone());
            return r;
        }

        let op = ins.opcode;
        let sigversion = self.frames[frame_idx].sigversion;
        let tapscript = sigversion == SigVersion::Tapscript;

        // BIP342 reserves a range of opcodes; encountering one makes the whole
        // script succeed immediately.
        if tapscript && is_op_success(op) {
            r.notes
                .push("OP_SUCCESSx in tapscript: the script succeeds immediately".into());
            self.stack.clear();
            self.push_bool(true);
            self.ip = self.frames[frame_idx].ins.len();
            self.finish_or_advance(&mut r);
            return r;
        }

        if is_disabled(op) {
            r.error = Some(format!("{} is disabled", op_name(op)));
            return r;
        }

        // Op budget (not applied to tapscript, which uses the sigops budget).
        if !tapscript && op > 0x60 {
            self.op_count += 1;
            if self.op_count > MAX_OPS_PER_SCRIPT {
                r.error = Some(format!("op count exceeded {}", MAX_OPS_PER_SCRIPT));
                return r;
            }
        }

        let exec = self.exec_enabled();
        let is_cond_op = matches!(op, 0x63 | 0x64 | 0x67 | 0x68);
        if !exec && !is_cond_op {
            r.skipped = true;
            r.notes.push("skipped (inside an unexecuted branch)".into());
            return r;
        }

        if let Err(e) = self.execute(op, &ins, &mut r, sigversion, frame_idx) {
            r.error = Some(e);
            return r;
        }

        if self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            r.error = Some(format!("stack size exceeded {} elements", MAX_STACK_SIZE));
            return r;
        }
        if self.ip >= self.frames[frame_idx].ins.len() {
            // Fall through to the frame-end handling on the next step so the
            // user sees this op's result first.
        }
        r
    }

    /// Called when a script runs off the end: either move to the next script or
    /// apply the final result rules.
    fn finish_or_advance(&mut self, r: &mut StepRecord) {
        let is_last = self.frame_idx + 1 >= self.frames.len();
        let label = self.frames[self.frame_idx].label.clone();

        if !self.cond.is_empty() {
            r.error = Some("unbalanced conditional: missing OP_ENDIF".into());
            return;
        }

        if label == "scriptSig" {
            self.saved_sigstack = self.stack.clone();
        }

        if is_last {
            self.finished = true;
            if self.stack.is_empty() {
                r.error = Some("script finished with an empty stack (evaluates to false)".into());
                return;
            }
            let top = self.stack.last().unwrap().clone();
            if !num::cast_to_bool(&top) {
                r.error = Some(format!(
                    "script finished with a false top stack element (0x{})",
                    hex::encode(&top)
                ));
                return;
            }
            if self.flags & VERIFY_CLEANSTACK != 0 && self.stack.len() != 1 {
                r.error = Some(format!(
                    "CLEANSTACK: {} elements left on the stack, expected exactly 1",
                    self.stack.len()
                ));
                return;
            }
            r.notes.push("SCRIPT SUCCEEDED".into());
        } else {
            // Intermediate scripts must leave a true value behind, exactly as
            // VerifyScript requires between scriptSig and scriptPubKey stages.
            if label != "scriptSig" {
                if self.stack.is_empty() {
                    r.error = Some(format!("{} finished with an empty stack", label));
                    return;
                }
                let top = self.stack.last().unwrap().clone();
                if !num::cast_to_bool(&top) {
                    r.error = Some(format!("{} evaluated to false", label));
                    return;
                }
            }
            self.frame_idx += 1;
            self.ip = 0;
            self.entered = false;
            self.op_count = 0;
            r.notes.push(format!(
                "moving on to {}",
                self.frames[self.frame_idx].label
            ));
        }
    }

    /// Legacy/segwit scriptCode: everything from the last OP_CODESEPARATOR on.
    fn script_code(&self, frame_idx: usize) -> ScriptBuf {
        let frame = &self.frames[frame_idx];
        let start = frame
            .ins
            .get(self.begin_codehash)
            .map(|i| i.offset)
            .unwrap_or(0);
        let bytes = frame.script.as_bytes();
        // Strip OP_CODESEPARATOR bytes, as Core's serializer does.
        let mut out = Vec::with_capacity(bytes.len() - start);
        for ins in frame.ins.iter().skip(self.begin_codehash) {
            if ins.opcode == 0xab {
                continue;
            }
            let end = ins.offset + ins.len;
            out.extend_from_slice(&bytes[ins.offset..end.min(bytes.len())]);
        }
        ScriptBuf::from_bytes(out)
    }

    fn check_sig(
        &mut self,
        sig: &[u8],
        pubkey: &[u8],
        sigversion: SigVersion,
        frame_idx: usize,
        r: &mut StepRecord,
    ) -> Result<bool, String> {
        // BIP342: only 32-byte keys are defined; other sizes stay spendable for
        // future upgrades.
        if sigversion == SigVersion::Tapscript && pubkey.len() != 32 {
            if pubkey.is_empty() {
                return Err("empty public key in tapscript".into());
            }
            r.notes.push(
                "unknown public key type in tapscript: the check passes for upgradability".into(),
            );
            return Ok(true);
        }

        let Some(ctx) = &self.ctx else {
            if self.assume_valid_sigs {
                r.notes
                    .push("no transaction context: assuming this signature is valid".into());
                r.sigs.push(SigResult {
                    valid: true,
                    sighash: String::new(),
                    sighash_type: String::new(),
                    detail: "not verified; no transaction loaded".into(),
                    warnings: vec!["load a transaction to verify this for real".into()],
                    assumed: true,
                });
                return Ok(true);
            }
            return Err("no transaction context; cannot compute a sighash".into());
        };

        if sigversion == SigVersion::Tapscript {
            if self.budget < VALIDATION_WEIGHT_PER_SIGOP_PASSED {
                return Err("tapscript validation weight budget exhausted".into());
            }
            let leaf = self.frames[frame_idx]
                .leaf_hash
                .ok_or("tapscript frame is missing its leaf hash")?;
            let res = ctx.check_schnorr(
                &self.secp,
                sig,
                pubkey,
                &SigMode::Tapscript {
                    leaf_hash: leaf,
                    codesep_pos: self.codesep_pos,
                    annex: self.annex.as_deref(),
                },
            );
            let valid = res.valid;
            r.sigs.push(res);
            if valid {
                self.budget -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            }
            return Ok(valid);
        }

        let script_code = match sigversion {
            SigVersion::Legacy => find_and_delete(&self.script_code(frame_idx), sig),
            _ => self.script_code(frame_idx),
        };
        let mode = if sigversion == SigVersion::Legacy {
            SigMode::Legacy { script_code: script_code.as_script() }
        } else {
            SigMode::WitnessV0 { script_code: script_code.as_script() }
        };
        let res = ctx.check_ecdsa(
            &self.secp,
            sig,
            pubkey,
            &mode,
            self.flags & VERIFY_DERSIG != 0,
            self.flags & VERIFY_LOW_S != 0,
        );
        let valid = res.valid;
        r.sigs.push(res);
        Ok(valid)
    }

    fn execute(
        &mut self,
        op: u8,
        ins: &Ins,
        r: &mut StepRecord,
        sigversion: SigVersion,
        frame_idx: usize,
    ) -> Result<(), String> {
        match op {
            // --- pushes ---
            0x00 => self.stack.push(Vec::new()),
            0x01..=0x4e => {
                let data = ins.data.clone().unwrap_or_default();
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(format!(
                        "push of {} bytes exceeds the {} byte element limit",
                        data.len(),
                        MAX_SCRIPT_ELEMENT_SIZE
                    ));
                }
                if self.require_minimal() && !ins.minimal_push {
                    return Err("non-minimal push (SCRIPT_VERIFY_MINIMALDATA)".into());
                }
                self.stack.push(data);
            }
            0x4f => self.push_num(-1),
            0x51..=0x60 => self.push_num((op - 0x50) as i64),

            // --- control flow ---
            0x61 => {} // OP_NOP
            0x63 | 0x64 => {
                // OP_IF / OP_NOTIF
                let mut value = false;
                if self.exec_enabled() {
                    let v = self.pop()?;
                    if sigversion == SigVersion::Tapscript && (v.len() > 1 || (v.len() == 1 && v[0] != 1)) {
                        return Err(
                            "OP_IF argument must be exactly OP_0 or OP_1 in tapscript (BIP342)"
                                .into(),
                        );
                    }
                    value = num::cast_to_bool(&v);
                    if op == 0x64 {
                        value = !value;
                    }
                    r.notes
                        .push(format!("branch taken: {}", if value { "yes" } else { "no" }));
                }
                self.cond.push(value);
            }
            0x67 => {
                // OP_ELSE
                let last = self
                    .cond
                    .last_mut()
                    .ok_or("OP_ELSE without a matching OP_IF")?;
                *last = !*last;
            }
            0x68 => {
                self.cond.pop().ok_or("OP_ENDIF without a matching OP_IF")?;
            }
            0x69 => {
                // OP_VERIFY
                let v = self.pop()?;
                if !num::cast_to_bool(&v) {
                    return Err("OP_VERIFY failed: top of stack was false".into());
                }
            }
            0x6a => return Err("OP_RETURN: script aborted".into()),

            // --- stack ---
            0x6b => {
                let v = self.pop()?;
                self.altstack.push(v);
            }
            0x6c => {
                let v = self
                    .altstack
                    .pop()
                    .ok_or("OP_FROMALTSTACK on an empty altstack")?;
                self.stack.push(v);
            }
            0x6d => {
                self.pop()?;
                self.pop()?;
            }
            0x6e => {
                let a = self.peek(1)?.clone();
                let b = self.peek(0)?.clone();
                self.stack.push(a);
                self.stack.push(b);
            }
            0x6f => {
                let a = self.peek(2)?.clone();
                let b = self.peek(1)?.clone();
                let c = self.peek(0)?.clone();
                self.stack.push(a);
                self.stack.push(b);
                self.stack.push(c);
            }
            0x70 => {
                let a = self.peek(3)?.clone();
                let b = self.peek(2)?.clone();
                self.stack.push(a);
                self.stack.push(b);
            }
            0x71 => {
                if self.stack.len() < 6 {
                    return Err("stack underflow".into());
                }
                let n = self.stack.len();
                let a = self.stack.remove(n - 6);
                let b = self.stack.remove(n - 6);
                self.stack.push(a);
                self.stack.push(b);
            }
            0x72 => {
                if self.stack.len() < 4 {
                    return Err("stack underflow".into());
                }
                let n = self.stack.len();
                self.stack.swap(n - 4, n - 2);
                self.stack.swap(n - 3, n - 1);
            }
            0x73 => {
                let top = self.peek(0)?.clone();
                if num::cast_to_bool(&top) {
                    self.stack.push(top);
                }
            }
            0x74 => {
                let d = self.stack.len() as i64;
                self.push_num(d);
            }
            0x75 => {
                self.pop()?;
            }
            0x76 => {
                let top = self.peek(0)?.clone();
                self.stack.push(top);
            }
            0x77 => {
                if self.stack.len() < 2 {
                    return Err("stack underflow".into());
                }
                let n = self.stack.len();
                self.stack.remove(n - 2);
            }
            0x78 => {
                let v = self.peek(1)?.clone();
                self.stack.push(v);
            }
            0x79 | 0x7a => {
                // OP_PICK / OP_ROLL
                let n = self.pop_num(num::MAX_NUM_SIZE)?;
                if n < 0 || n as usize >= self.stack.len() {
                    return Err(format!("{} index {} out of range", op_name(op), n));
                }
                let idx = self.stack.len() - 1 - n as usize;
                if op == 0x79 {
                    let v = self.stack[idx].clone();
                    self.stack.push(v);
                } else {
                    let v = self.stack.remove(idx);
                    self.stack.push(v);
                }
            }
            0x7b => {
                if self.stack.len() < 3 {
                    return Err("stack underflow".into());
                }
                let n = self.stack.len();
                let v = self.stack.remove(n - 3);
                self.stack.push(v);
            }
            0x7c => {
                if self.stack.len() < 2 {
                    return Err("stack underflow".into());
                }
                let n = self.stack.len();
                self.stack.swap(n - 2, n - 1);
            }
            0x7d => {
                if self.stack.len() < 2 {
                    return Err("stack underflow".into());
                }
                let top = self.peek(0)?.clone();
                let n = self.stack.len();
                self.stack.insert(n - 2, top);
            }

            0x82 => {
                let len = self.peek(0)?.len() as i64;
                self.push_num(len);
            }

            // --- equality ---
            0x87 | 0x88 => {
                let b = self.pop()?;
                let a = self.pop()?;
                let equal = a == b;
                if op == 0x88 {
                    if !equal {
                        return Err(format!(
                            "OP_EQUALVERIFY failed: 0x{} != 0x{}",
                            hex::encode(&a),
                            hex::encode(&b)
                        ));
                    }
                } else {
                    self.push_bool(equal);
                }
            }

            // --- arithmetic ---
            0x8b | 0x8c | 0x8f | 0x90 | 0x91 | 0x92 => {
                let n = self.pop_num(num::MAX_NUM_SIZE)?;
                let res = match op {
                    0x8b => n + 1,
                    0x8c => n - 1,
                    0x8f => -n,
                    0x90 => n.abs(),
                    0x91 => (n == 0) as i64,
                    _ => (n != 0) as i64,
                };
                self.push_num(res);
            }
            0x93 | 0x94 | 0x9a | 0x9b | 0x9c | 0x9d | 0x9e | 0x9f | 0xa0 | 0xa1 | 0xa2 | 0xa3
            | 0xa4 => {
                let b = self.pop_num(num::MAX_NUM_SIZE)?;
                let a = self.pop_num(num::MAX_NUM_SIZE)?;
                let res = match op {
                    0x93 => a + b,
                    0x94 => a - b,
                    0x9a => ((a != 0) && (b != 0)) as i64,
                    0x9b => ((a != 0) || (b != 0)) as i64,
                    0x9c | 0x9d => (a == b) as i64,
                    0x9e => (a != b) as i64,
                    0x9f => (a < b) as i64,
                    0xa0 => (a > b) as i64,
                    0xa1 => (a <= b) as i64,
                    0xa2 => (a >= b) as i64,
                    0xa3 => a.min(b),
                    _ => a.max(b),
                };
                if op == 0x9d {
                    if res == 0 {
                        return Err(format!("OP_NUMEQUALVERIFY failed: {} != {}", a, b));
                    }
                } else {
                    self.push_num(res);
                }
            }
            0xa5 => {
                let max = self.pop_num(num::MAX_NUM_SIZE)?;
                let min = self.pop_num(num::MAX_NUM_SIZE)?;
                let x = self.pop_num(num::MAX_NUM_SIZE)?;
                self.push_bool(x >= min && x < max);
            }

            // --- crypto ---
            0xa6 | 0xa7 | 0xa8 | 0xa9 | 0xaa => {
                use bitcoin::hashes::{ripemd160, sha1, sha256, sha256d, Hash};
                let v = self.pop()?;
                let out: Vec<u8> = match op {
                    0xa6 => ripemd160::Hash::hash(&v).to_byte_array().to_vec(),
                    0xa7 => sha1::Hash::hash(&v).to_byte_array().to_vec(),
                    0xa8 => sha256::Hash::hash(&v).to_byte_array().to_vec(),
                    0xa9 => bitcoin::hashes::hash160::Hash::hash(&v).to_byte_array().to_vec(),
                    _ => sha256d::Hash::hash(&v).to_byte_array().to_vec(),
                };
                r.notes.push(format!("{} → {}", op_name(op), hex::encode(&out)));
                self.stack.push(out);
            }
            0xab => {
                // OP_CODESEPARATOR
                self.begin_codehash = self.ip;
                self.codesep_pos = ins.offset as u32;
                r.notes.push(format!(
                    "scriptCode for later signature checks now starts at byte {}",
                    ins.offset + ins.len
                ));
            }
            0xac | 0xad => {
                // OP_CHECKSIG / OP_CHECKSIGVERIFY
                let pubkey = self.pop()?;
                let sig = self.pop()?;
                let ok = self.check_sig(&sig, &pubkey, sigversion, frame_idx, r)?;
                if !ok && self.flags & VERIFY_NULLFAIL != 0 && !sig.is_empty() {
                    return Err(
                        "NULLFAIL: a failing signature check must have an empty signature".into(),
                    );
                }
                if op == 0xad {
                    if !ok {
                        return Err("OP_CHECKSIGVERIFY failed".into());
                    }
                } else {
                    self.push_bool(ok);
                }
            }
            0xba => {
                // OP_CHECKSIGADD (tapscript only)
                if sigversion != SigVersion::Tapscript {
                    return Err("OP_CHECKSIGADD is only valid in tapscript".into());
                }
                let pubkey = self.pop()?;
                let n = self.pop_num(num::MAX_NUM_SIZE)?;
                let sig = self.pop()?;
                let ok = if sig.is_empty() {
                    r.notes.push("empty signature: counts as a failed check".into());
                    false
                } else {
                    self.check_sig(&sig, &pubkey, sigversion, frame_idx, r)?
                };
                if !ok && !sig.is_empty() {
                    return Err("NULLFAIL: failing tapscript check with a non-empty signature".into());
                }
                self.push_num(n + ok as i64);
            }
            0xae | 0xaf => {
                // OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                if sigversion == SigVersion::Tapscript {
                    return Err(
                        "OP_CHECKMULTISIG is disabled in tapscript; use OP_CHECKSIGADD".into()
                    );
                }
                let nkeys = self.pop_num(num::MAX_NUM_SIZE)?;
                if nkeys < 0 || nkeys > MAX_PUBKEYS_PER_MULTISIG {
                    return Err(format!("invalid public key count {}", nkeys));
                }
                if !self.frames[frame_idx].sigversion.eq(&SigVersion::Tapscript) {
                    self.op_count += nkeys as usize;
                    if self.op_count > MAX_OPS_PER_SCRIPT {
                        return Err(format!("op count exceeded {}", MAX_OPS_PER_SCRIPT));
                    }
                }
                let mut keys = Vec::new();
                for _ in 0..nkeys {
                    keys.push(self.pop()?);
                }
                keys.reverse();
                let nsigs = self.pop_num(num::MAX_NUM_SIZE)?;
                if nsigs < 0 || nsigs > nkeys {
                    return Err(format!(
                        "invalid signature count {} for {} keys",
                        nsigs, nkeys
                    ));
                }
                let mut sigs = Vec::new();
                for _ in 0..nsigs {
                    sigs.push(self.pop()?);
                }
                sigs.reverse();
                let dummy = self.pop()?;
                if self.flags & VERIFY_NULLDUMMY != 0 && !dummy.is_empty() {
                    return Err("NULLDUMMY: the extra CHECKMULTISIG element must be empty".into());
                }
                if !dummy.is_empty() {
                    r.notes.push(
                        "the off-by-one dummy element is non-empty (fine pre-NULLDUMMY)".into(),
                    );
                }

                // Signatures must appear in the same relative order as keys.
                let mut ki = 0usize;
                let mut matched = 0usize;
                let mut details = Vec::new();
                for sig in &sigs {
                    let mut found = false;
                    while ki < keys.len() {
                        let key = keys[ki].clone();
                        ki += 1;
                        let ok = self.check_sig(sig, &key, sigversion, frame_idx, r)?;
                        if ok {
                            details.push(format!("signature {} matched key {}", matched + 1, ki));
                            matched += 1;
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        break;
                    }
                }
                let ok = matched == sigs.len();
                for d in details {
                    r.notes.push(d);
                }
                r.notes
                    .push(format!("{}-of-{} multisig: {}", nsigs, nkeys, if ok { "satisfied" } else { "NOT satisfied" }));
                if !ok && self.flags & VERIFY_NULLFAIL != 0 && sigs.iter().any(|s| !s.is_empty()) {
                    return Err("NULLFAIL: failing multisig with non-empty signatures".into());
                }
                if op == 0xaf {
                    if !ok {
                        return Err("OP_CHECKMULTISIGVERIFY failed".into());
                    }
                } else {
                    self.push_bool(ok);
                }
            }

            // --- locktime ---
            0xb1 => {
                if self.flags & VERIFY_CHECKLOCKTIMEVERIFY == 0 {
                    r.notes.push("CLTV not enforced by the current flags: acts as OP_NOP2".into());
                    return Ok(());
                }
                let want = num::decode(self.peek(0)?, self.require_minimal(), 5).map_err(|e| e.0)?;
                if want < 0 {
                    return Err("CLTV: negative locktime".into());
                }
                let Some(ctx) = &self.ctx else {
                    r.notes
                        .push("no transaction context: CLTV treated as satisfied".into());
                    return Ok(());
                };
                let tx_lock = ctx.tx.lock_time.to_consensus_u32() as i64;
                let same_unit = (want < LOCKTIME_THRESHOLD) == (tx_lock < LOCKTIME_THRESHOLD);
                if !same_unit {
                    return Err(format!(
                        "CLTV: mixed units (script wants {}, tx locktime is {})",
                        want, tx_lock
                    ));
                }
                if want > tx_lock {
                    return Err(format!(
                        "CLTV: locktime requirement {} not met by tx locktime {}",
                        want, tx_lock
                    ));
                }
                if ctx.tx.input[ctx.input_index].sequence == Sequence::MAX {
                    return Err("CLTV: input sequence is final (0xffffffff), which disables locktime".into());
                }
                r.notes.push(format!(
                    "CLTV satisfied: requires {}, tx locktime is {}",
                    want, tx_lock
                ));
            }
            0xb2 => {
                if self.flags & VERIFY_CHECKSEQUENCEVERIFY == 0 {
                    r.notes.push("CSV not enforced by the current flags: acts as OP_NOP3".into());
                    return Ok(());
                }
                let want = num::decode(self.peek(0)?, self.require_minimal(), 5).map_err(|e| e.0)?;
                if want < 0 {
                    return Err("CSV: negative sequence".into());
                }
                const SEQUENCE_LOCKTIME_DISABLE_FLAG: i64 = 1 << 31;
                const SEQUENCE_LOCKTIME_TYPE_FLAG: i64 = 1 << 22;
                const SEQUENCE_LOCKTIME_MASK: i64 = 0x0000_ffff;
                if want & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
                    r.notes.push("CSV: disable flag set, requirement ignored".into());
                    return Ok(());
                }
                let Some(ctx) = &self.ctx else {
                    r.notes
                        .push("no transaction context: CSV treated as satisfied".into());
                    return Ok(());
                };
                let tx_seq = ctx.tx.input[ctx.input_index].sequence.to_consensus_u32() as i64;
                if ctx.tx.version.0 < 2 {
                    return Err(format!(
                        "CSV: requires tx version >= 2, this tx is version {}",
                        ctx.tx.version.0
                    ));
                }
                if tx_seq & SEQUENCE_LOCKTIME_DISABLE_FLAG != 0 {
                    return Err("CSV: the input's sequence disables relative locktime".into());
                }
                if (want & SEQUENCE_LOCKTIME_TYPE_FLAG) != (tx_seq & SEQUENCE_LOCKTIME_TYPE_FLAG) {
                    return Err("CSV: mixed units (blocks vs time)".into());
                }
                if (want & SEQUENCE_LOCKTIME_MASK) > (tx_seq & SEQUENCE_LOCKTIME_MASK) {
                    return Err(format!(
                        "CSV: requires {} but the input's sequence gives {}",
                        want & SEQUENCE_LOCKTIME_MASK,
                        tx_seq & SEQUENCE_LOCKTIME_MASK
                    ));
                }
                let unit = if want & SEQUENCE_LOCKTIME_TYPE_FLAG != 0 { "512s units" } else { "blocks" };
                r.notes.push(format!(
                    "CSV satisfied: requires {} {}",
                    want & SEQUENCE_LOCKTIME_MASK,
                    unit
                ));
            }

            0x50 => return Err("OP_RESERVED in an executed branch".into()),
            0x62 => return Err("OP_VER in an executed branch".into()),
            0x65 | 0x66 => return Err(format!("{} is always invalid", op_name(op))),
            0x89 | 0x8a => return Err(format!("{} in an executed branch", op_name(op))),
            0xb0 | 0xb3..=0xb9 => {
                r.notes.push(format!("{} does nothing", op_name(op)));
            }
            _ => return Err(format!("unimplemented or invalid opcode {}", op_name(op))),
        }
        Ok(())
    }
}

/// Convenience for the "just run a script" mode: no tx, no spend resolution.
pub fn single_frame(script: &Script, label: &str, sigversion: SigVersion) -> Frame {
    Frame {
        label: label.to_string(),
        script_hex: hex::encode(script.as_bytes()),
        sigversion,
        enter: EnterAction::Keep,
        leaf_hash: None,
        key_path: false,
    }
}
