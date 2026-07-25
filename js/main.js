// Session wiring: boot the WASM engine, own the debugger instance, and connect
// it to the panels, the console, and mempool.space.

import init, * as engine from '../pkg/btcdeb_engine.js';
import * as mp from './mempool.js';
import * as ui from './ui.js';
import { runCommand, commandNames } from './commands.js';
import { initLayout } from './layout.js';

const $ = (id) => document.getElementById(id);

/** WASM errors arrive as bare strings, not Error objects. */
const errMsg = (e) => (e && e.message) || (typeof e === 'string' ? e : String(e));

const session = {
  dbg: null,
  frames: [],
  info: null,
  lastRecord: null,
  source: null, // {type:'tx'|'script', ...} — enough to rebuild from scratch
  meta: {},
  network: 'mainnet',
  flags: 0,
  flagList: [],
  assumeSigs: false,
};

// ── debugger lifecycle ────────────────────────────────────────────────────

function instantiate() {
  const src = session.source;
  if (!src) return;

  if (src.type === 'tx') {
    session.dbg = engine.Debugger.fromTx(
      src.txHex,
      src.vin,
      src.prevouts,
      session.flags,
      session.assumeSigs,
    );
  } else {
    session.dbg = engine.Debugger.fromScript(
      src.src,
      src.stack,
      src.sigversion,
      session.flags,
      session.assumeSigs,
    );
  }
  session.frames = session.dbg.listing();
  session.info = session.dbg.info();
  session.lastRecord = null;
  ui.renderSpendInfo(session.info, session.meta);
  refresh();
}

function refresh() {
  if (!session.dbg) return;
  const state = session.dbg.state();
  ui.renderListing(session.frames, state);
  ui.renderStacks(state);
  ui.renderStats(state, session.meta);
  ui.setStatus(state);
  ui.renderStepDetail(session.lastRecord);

  $('btn-step').disabled = state.finished;
  $('btn-run').disabled = state.finished;
  $('btn-rewind').disabled = !state.can_rewind;
  $('btn-reset').disabled = false;
}

/** Log one step the way btcdeb prints it, then surface notes and sig results. */
function logRecord(rec) {
  const label = `#${String(rec.n).padStart(3, '0')} ${rec.op}`;
  ui.log(label, rec.transition ? 'info' : rec.skipped ? 'info' : 'out');
  // A note indented by the engine continues the note above it (multisig spells
  // its matched pairs out over several lines), so it gets no bullet of its own.
  for (const n of rec.notes || []) {
    ui.log(n.startsWith('  ') ? `      ${n}` : `     · ${n}`, 'info');
  }
  for (const s of rec.sigs || []) {
    if (s.assumed) {
      ui.log('     ⚠ signature not verified (no transaction loaded)', 'warn');
    } else {
      ui.log(`     ${s.valid ? '✓' : '✗'} ${s.detail}`, s.valid ? 'trace' : 'err');
    }
    if (s.pubkey) ui.log(`       key       ${s.pubkey}`, 'info');
    if (s.signature) ui.log(`       signature ${s.signature}`, 'info');
    if (s.sighash) ui.log(`       sighash   ${s.sighash} [${s.sighash_type}]`, 'info');
    for (const w of s.warnings || []) ui.log(`     ! ${w}`, 'warn');
  }
  if (rec.error) ui.log(`     ✗ ${rec.error}`, 'err');
}

function step() {
  if (!session.dbg) return false;
  if (session.dbg.state().finished) {
    ui.log('script has finished — `reset` to run it again', 'info');
    return false;
  }
  const rec = session.dbg.step();
  session.lastRecord = rec;
  logRecord(rec);
  refresh();
  announceIfDone();
  return !session.dbg.state().finished;
}

function rewind() {
  if (!session.dbg) return false;
  try {
    session.dbg.rewind();
  } catch (e) {
    ui.log(errMsg(e), 'err');
    return false;
  }
  const records = session.dbg.records();
  session.lastRecord = records[records.length - 1] || null;
  ui.log(`rewound to step ${session.dbg.state().step_n}`, 'info');
  refresh();
  return true;
}

function runAll() {
  if (!session.dbg) return;
  const records = session.dbg.run(100000);
  for (const rec of records) logRecord(rec);
  session.lastRecord = records[records.length - 1] || session.lastRecord;
  refresh();
  announceIfDone();
}

function announceIfDone() {
  const state = session.dbg.state();
  if (!state.finished) return;
  if (state.success) {
    ui.log('══ SCRIPT SUCCEEDED ══', 'cmd');
  } else {
    ui.log(`══ SCRIPT FAILED ══ ${state.error || ''}`, 'err');
  }
}

function reset() {
  instantiate();
}

// ── sources ───────────────────────────────────────────────────────────────

function buildFromTx(txHex, vin, prevouts, meta) {
  session.source = { type: 'tx', txHex, vin, prevouts };
  session.meta = { ...meta, vin };
  try {
    instantiate();
    ui.log(`loaded ${session.info.kind} — ${session.frames.length} script(s) to execute`, 'cmd');
    for (const e of session.info.errors || []) ui.log(`! ${e}`, 'err');
    ui.log('`step` to advance, `run` to execute to the end, `info` for details', 'info');
  } catch (e) {
    ui.log(errMsg(e), 'err');
  }
}

async function loadTxid(txid, vin = 0) {
  const clean = (txid || '').trim();
  if (!mp.isTxid(clean)) {
    ui.log(`'${clean}' is not a 64-character transaction id`, 'err');
    return;
  }
  ui.log(`fetching ${clean} from mempool.space (${session.network})…`, 'info');
  ui.el.status.textContent = 'fetching';
  ui.el.status.className = 'badge busy';
  try {
    const spend = await mp.loadSpend(session.network, clean);
    if (vin >= spend.tx.vin.length) {
      ui.log(
        `input #${vin} does not exist; this transaction has ${spend.tx.vin.length} input(s)`,
        'err',
      );
      return;
    }
    const where = spend.confirmed ? `block ${spend.blockHeight}` : 'mempool (unconfirmed)';
    ui.log(
      `got ${spend.tx.vin.length} input(s) / ${spend.tx.vout.length} output(s) from ${where}; ` +
        `input #${vin} spends a ${spend.types[vin]} output`,
      'out',
    );
    $('txid').value = clean;
    $('vin').value = String(vin);
    buildFromTx(spend.txHex, vin, spend.prevouts, {
      txid: clean,
      explorerUrl: mp.EXPLORERS[session.network] + clean,
    });
  } catch (e) {
    ui.log(errMsg(e), 'err');
    ui.el.status.textContent = 'idle';
    ui.el.status.className = 'badge';
  }
}

async function loadRawTx(hex, vin) {
  const clean = (hex || '').replace(/\s+/g, '');
  if (!clean) {
    ui.log('paste a raw transaction first', 'err');
    return;
  }
  let parsed;
  try {
    parsed = engine.parseTx(clean, session.network);
  } catch (e) {
    ui.log(errMsg(e), 'err');
    return;
  }
  if (vin >= parsed.inputs.length) {
    ui.log(`input #${vin} does not exist; this transaction has ${parsed.inputs.length}`, 'err');
    return;
  }
  ui.log(`parsed ${parsed.txid} — resolving ${parsed.inputs.length} prevout(s)…`, 'info');
  try {
    const prevouts = await mp.resolvePrevouts(
      session.network,
      parsed.inputs.map((i) => ({ txid: i.txid, vout: i.vout })),
      (i, n, txid) => ui.log(`  [${i + 1}/${n}] ${txid}`, 'info'),
    );
    buildFromTx(clean, vin, prevouts, {
      txid: parsed.txid,
      explorerUrl: mp.EXPLORERS[session.network] + parsed.txid,
    });
  } catch (e) {
    ui.log(errMsg(e), 'err');
  }
}

function loadScript(src, stackText, sigversion) {
  const stack = (stackText || '')
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  session.source = { type: 'script', src, stack, sigversion };
  session.meta = {};
  try {
    instantiate();
    ui.log(`loaded a bare ${sigversion} script with ${stack.length} stack item(s)`, 'cmd');
  } catch (e) {
    ui.log(errMsg(e), 'err');
  }
}

// ── flags ─────────────────────────────────────────────────────────────────

function buildFlagUI() {
  session.flagList = engine.flagInfo();
  session.flags = session.flagList.reduce((acc, f) => acc | f.bit, 0);

  const host = $('flags');
  host.replaceChildren();
  for (const f of session.flagList) {
    const label = document.createElement('label');
    label.className = 'check';
    label.title = f.description;
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.checked = true;
    box.addEventListener('change', () => setFlag(f.bit, box.checked, f.name));
    const span = document.createElement('span');
    span.textContent = f.name;
    label.append(box, span);
    host.appendChild(label);
  }
}

function syncFlagUI() {
  const boxes = $('flags').querySelectorAll('input[type=checkbox]');
  session.flagList.forEach((f, i) => {
    if (boxes[i]) boxes[i].checked = (session.flags & f.bit) !== 0;
  });
  $('assume-sigs').checked = session.assumeSigs;
}

function setFlag(bit, on, name) {
  session.flags = on ? session.flags | bit : session.flags & ~bit;
  syncFlagUI();
  ui.log(`${name || 'flag'} ${on ? 'enabled' : 'disabled'}`, 'info');
  if (session.source) {
    ui.log('restarting the script with the new flags', 'info');
    instantiate();
  }
}

function setAssume(on) {
  session.assumeSigs = on;
  syncFlagUI();
  ui.log(`assume valid signatures: ${on ? 'on' : 'off'}`, 'info');
  if (session.source) instantiate();
}

function setNetwork(net) {
  if (!['mainnet', 'testnet', 'testnet4', 'signet'].includes(net)) {
    ui.log(`unknown network '${net}' (mainnet, testnet4, testnet, signet)`, 'err');
    return;
  }
  session.network = net;
  $('network').value = net;
  ui.log(`network set to ${net}`, 'info');
}

const flagNames = () =>
  session.flagList.filter((f) => (session.flags & f.bit) !== 0).map((f) => f.name);

// ── examples ──────────────────────────────────────────────────────────────

// Real mainnet spends, one per script type. Each was taken from a mined block,
// so every signature in them verifies.
const TX_EXAMPLES = [
  ['P2PKH', 'legacy pay-to-pubkey-hash', '482e66b2799b3454d6ca26b1182d9aaf6e56e872a984bcddf3c616d9c504ffa4', 0],
  ['P2WPKH', 'native segwit v0, BIP143 sighash', 'ae3a35e98c0a2f9e2d662196597a4b1af5ec571e0dc3ff1b4b19e09d6f4831a9', 0],
  ['P2SH-P2WPKH', 'segwit nested in P2SH', '70090949bce2fbcb979e560e09d2d0ff9d211a8094ac7b33efa7d138da53edae', 0],
  ['P2WSH 2-of-3', 'multisig witness script', 'bd2bbd46d394ab3d5864202ee26fa89d8bb260379f658efda0ac253358622cd6', 0],
  ['P2TR key path', 'BIP341 schnorr, one signature', '4b1059b4293113bac1671bd86a69d8b06a900c11c1e000b566ca03807b48bae8', 0],
  ['P2TR script path', 'tapscript leaf + control block', '4bbc5162ddbf780c62cecb3e165245d7f0b8d003bc63238797bb49ed6d7e1fbd', 0],
];

function scriptExamples() {
  const preimage = '62746364656220726f636b73'; // "btcdeb rocks"
  const digest = engine.tf('sha256', preimage);
  return [
    [
      'arithmetic',
      '2 + 3 == 5',
      { src: 'OP_2 OP_3 OP_ADD OP_5 OP_EQUAL', stack: '', sv: 'legacy' },
    ],
    [
      'hash puzzle',
      'reveal a preimage of a sha256 digest',
      { src: `OP_SHA256 ${digest} OP_EQUAL`, stack: preimage, sv: 'legacy' },
    ],
    [
      'branching',
      'OP_IF with the false branch skipped',
      {
        src: 'OP_IF OP_1 OP_ELSE OP_RETURN OP_ENDIF',
        stack: '01',
        sv: 'legacy',
      },
    ],
    [
      'stack juggling',
      'DUP, SWAP, ROT, TOALTSTACK',
      {
        src: 'OP_DUP OP_SWAP OP_TOALTSTACK OP_ROT OP_FROMALTSTACK OP_DROP OP_DROP OP_DROP',
        stack: '01 02 03',
        sv: 'legacy',
      },
    ],
  ];
}

function buildExamples() {
  const host = $('examples');
  host.replaceChildren();

  const add = (title, sub, onClick) => {
    const b = document.createElement('button');
    b.className = 'example';
    b.type = 'button';
    b.appendChild(Object.assign(document.createElement('b'), { textContent: title }));
    b.appendChild(document.createTextNode(sub));
    b.addEventListener('click', onClick);
    host.appendChild(b);
  };

  for (const [title, sub, txid, vin] of TX_EXAMPLES) {
    add(title, sub, () => {
      if (session.network !== 'mainnet') setNetwork('mainnet');
      selectTab('txid');
      loadTxid(txid, vin);
    });
  }
  for (const [title, sub, cfg] of scriptExamples()) {
    add(title, sub, () => {
      selectTab('script');
      $('script-src').value = cfg.src;
      $('script-stack').value = cfg.stack;
      $('script-sigversion').value = cfg.sv;
      loadScript(cfg.src, cfg.stack, cfg.sv);
    });
  }
}

// ── tabs ──────────────────────────────────────────────────────────────────

function selectTab(name) {
  for (const t of document.querySelectorAll('.tab')) {
    t.classList.toggle('active', t.dataset.tab === name);
  }
  for (const p of document.querySelectorAll('.tabpane')) {
    p.classList.toggle('active', p.dataset.pane === name);
  }
}

// ── command context ───────────────────────────────────────────────────────

const ctx = {
  session,
  engine,
  step,
  rewind,
  runAll,
  reset,
  loadTxid,
  setFlag: (bit, on) => setFlag(bit, on),
  setAssume,
  setNetwork,
  flagNames,
};

// ── input wiring ──────────────────────────────────────────────────────────

function wireConsole() {
  const form = $('cmdform');
  const input = $('cmd');
  const history = [];
  let hi = -1;

  form.addEventListener('submit', (e) => {
    e.preventDefault();
    const line = input.value;
    if (!line.trim()) return;
    history.push(line);
    hi = history.length;
    input.value = '';
    runCommand(ctx, line);
  });

  input.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowUp') {
      if (!history.length) return;
      e.preventDefault();
      hi = Math.max(0, hi - 1);
      input.value = history[hi] ?? '';
    } else if (e.key === 'ArrowDown') {
      if (!history.length) return;
      e.preventDefault();
      hi = Math.min(history.length, hi + 1);
      input.value = history[hi] ?? '';
    } else if (e.key === 'Tab') {
      e.preventDefault();
      const word = input.value.trim();
      if (!word || word.includes(' ')) return;
      const hits = commandNames().filter((n) => n.startsWith(word));
      if (hits.length === 1) input.value = `${hits[0]} `;
      else if (hits.length > 1) ui.log(hits.join('  '), 'info');
    }
  });
}

function wireControls() {
  $('btn-step').addEventListener('click', () => step());
  $('btn-rewind').addEventListener('click', () => rewind());
  $('btn-run').addEventListener('click', () => runAll());
  $('btn-reset').addEventListener('click', () => {
    reset();
    ui.log('reset', 'info');
  });

  $('load-txid').addEventListener('click', () =>
    loadTxid($('txid').value, Number($('vin').value) || 0),
  );
  $('txid').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') loadTxid($('txid').value, Number($('vin').value) || 0);
  });
  $('load-raw').addEventListener('click', () =>
    loadRawTx($('rawtx').value, Number($('raw-vin').value) || 0),
  );
  $('load-script').addEventListener('click', () =>
    loadScript($('script-src').value, $('script-stack').value, $('script-sigversion').value),
  );

  $('network').addEventListener('change', (e) => setNetwork(e.target.value));
  $('assume-sigs').addEventListener('change', (e) => setAssume(e.target.checked));

  for (const t of document.querySelectorAll('.tab')) {
    t.addEventListener('click', () => selectTab(t.dataset.tab));
  }

  // Function keys work anywhere. The single-letter shortcuts only apply while
  // the listing itself has focus, so they never swallow ordinary typing or
  // hijack space-to-scroll.
  document.addEventListener('keydown', (e) => {
    if (e.key === 'F10') {
      e.preventDefault();
      step();
    } else if (e.key === 'F9') {
      e.preventDefault();
      rewind();
    } else if (e.key === 'F5') {
      e.preventDefault();
      runAll();
    } else if (document.activeElement === ui.el.listing) {
      if (e.key === 'n' || e.key === ' ') {
        e.preventDefault();
        step();
      } else if (e.key === 'p') {
        e.preventDefault();
        rewind();
      }
    }
  });
}

// ── boot ──────────────────────────────────────────────────────────────────

async function boot() {
  ui.log('btcdeb.wasm — bitcoin script debugger', 'cmd');
  ui.log('loading engine…', 'info');
  try {
    await init();
  } catch (e) {
    ui.log(`could not load the WebAssembly engine: ${errMsg(e)}`, 'err');
    ui.log('the page must be served over http(s) — opening index.html from disk will not work', 'warn');
    $('engine-version').textContent = 'engine failed to load';
    return;
  }

  $('engine-version').textContent = engine.version();
  buildFlagUI();
  buildExamples();
  wireControls();
  wireConsole();

  ui.log(engine.version(), 'info');
  ui.log(
    'pick an example on the left, or type `load <txid>` to fetch a spend from mempool.space. `help` lists commands.',
    'info',
  );

  // Deep links: ?txid=…&vin=…&net=…
  const params = new URLSearchParams(location.search);
  if (params.get('net')) setNetwork(params.get('net'));
  else $('network').value = session.network;
  if (params.get('txid')) {
    await loadTxid(params.get('txid'), Number(params.get('vin')) || 0);
  }
}

// Panel sizing is pure DOM, so it works even if the engine fails to load.
initLayout();
boot();
