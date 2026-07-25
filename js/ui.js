// DOM rendering. Every function here takes engine data and paints it; none of
// them touch the debugger itself.

const $ = (id) => document.getElementById(id);

export const el = {
  listing: $('listing'),
  stack: $('stack'),
  altstack: $('altstack'),
  stackCount: $('stack-count'),
  altstackCount: $('altstack-count'),
  stats: $('stats'),
  detail: $('step-detail'),
  notes: $('spend-notes'),
  status: $('status'),
  spendKind: $('spend-kind'),
  log: $('log'),
};

const SIGVERSION_LABEL = {
  Legacy: 'legacy',
  WitnessV0: 'witness v0',
  Tapscript: 'tapscript',
  TaprootKeyPath: 'taproot key path',
};

export const sigversionLabel = (v) => SIGVERSION_LABEL[v] || String(v || '');

function node(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

// ── console log ───────────────────────────────────────────────────────────

export function log(text, cls = 'out') {
  const line = node('div', `line ${cls}`, text);
  el.log.appendChild(line);
  el.log.scrollTop = el.log.scrollHeight;
  return line;
}

export function logLines(text, cls) {
  String(text)
    .split('\n')
    .forEach((l) => log(l, cls));
}

export function clearLog() {
  el.log.replaceChildren();
}

// ── value formatting ──────────────────────────────────────────────────────

/** Decode a little-endian sign-magnitude script number, for short items. */
function scriptNumOf(hex) {
  if (hex.length === 0 || hex.length > 8) return null;
  const bytes = hex.match(/../g).map((b) => parseInt(b, 16));
  let n = 0;
  for (let i = 0; i < bytes.length; i++) n |= bytes[i] << (8 * i);
  if (bytes[bytes.length - 1] & 0x80) {
    const mask = ~(0x80 << (8 * (bytes.length - 1)));
    return -(n & mask);
  }
  return n;
}

/** A short human label for a stack item, based on its size and shape. */
export function describeItem(hex) {
  const len = hex.length / 2;
  if (len === 0) return 'empty (false)';
  const num = scriptNumOf(hex);
  if (num !== null) return `${len}B · int ${num}`;
  if (len === 20) return '20B · hash160';
  if (len === 32) return '32B · sha256 or x-only key';
  if (len === 33 && /^0[23]/.test(hex)) return '33B · compressed pubkey';
  if (len === 65 && hex.startsWith('04')) return '65B · uncompressed pubkey';
  if (len === 64 || len === 65) return `${len}B · schnorr signature`;
  if (hex.startsWith('30') && len >= 68 && len <= 73) return `${len}B · DER signature`;
  return `${len}B`;
}

// ── script listing ────────────────────────────────────────────────────────

export function renderListing(frames, state) {
  const frag = document.createDocumentFragment();

  frames.forEach((frame, fi) => {
    const isCurrent = fi === state.frame_idx;
    const head = node('div', `frame-head${isCurrent ? ' current' : ''}`);
    head.append(
      node('span', null, frame.label),
      node('span', 'sv', `[${sigversionLabel(frame.sigversion)}]`),
    );
    frag.appendChild(head);

    if (frame.key_path) {
      const row = node('div', `op${isCurrent && !state.finished ? ' current' : ''}`);
      row.append(
        node('span', 'marker', isCurrent && !state.finished ? '▶' : ' '),
        node('span', 'off', '—'),
        node('span', 'txt', 'CHECKSIG (BIP341 key path)'),
      );
      frag.appendChild(row);
      return;
    }

    if (!frame.instructions.length) {
      frag.appendChild(node('div', 'op', '(empty script)'));
      return;
    }

    frame.instructions.forEach((ins, ii) => {
      const done = fi < state.frame_idx || (isCurrent && ii < state.ip);
      const current = isCurrent && ii === state.ip && !state.finished;
      const row = node('div', `op${done ? ' done' : ''}${current ? ' current' : ''}${ins.error ? ' bad' : ''}`);

      const txt = node('span', 'txt');
      if (ins.is_push && ins.data) {
        txt.appendChild(node('span', 'push', ins.text));
        if (!ins.minimal) txt.appendChild(node('span', 'warn', '  ← non-minimal push'));
      } else {
        txt.appendChild(node('span', 'opcode', ins.text));
      }
      if (ins.error) txt.appendChild(node('span', 'warn', `  ${ins.error}`));

      row.append(
        node('span', 'marker', current ? '▶' : ' '),
        node('span', 'off', String(ins.offset)),
        txt,
      );
      frag.appendChild(row);
    });
  });

  el.listing.replaceChildren(frag);
  const current = el.listing.querySelector('.op.current');
  current?.scrollIntoView({ block: 'nearest' });
}

export function listingPlaceholder(text) {
  el.listing.replaceChildren(node('p', 'placeholder', text));
}

// ── stacks ────────────────────────────────────────────────────────────────

function renderStack(target, countTarget, items) {
  const frag = document.createDocumentFragment();
  // Show the top of the stack first, the way btcdeb prints it.
  [...items].reverse().forEach((hex, i) => {
    const li = node('li', i === 0 ? 'top' : null);
    li.appendChild(node('span', 'i', `<${items.length - 1 - i}>`));
    const val = node('span', 'val');
    if (hex.length === 0) {
      val.appendChild(node('span', 'empty', '(empty)'));
    } else {
      val.appendChild(document.createTextNode(hex));
      val.appendChild(node('span', 'len', `  ${describeItem(hex)}`));
    }
    li.appendChild(val);
    frag.appendChild(li);
  });
  target.replaceChildren(frag);
  countTarget.textContent = items.length ? `(${items.length})` : '';
}

export function renderStacks(state) {
  renderStack(el.stack, el.stackCount, state.stack || []);
  renderStack(el.altstack, el.altstackCount, state.altstack || []);
}

// ── stats ─────────────────────────────────────────────────────────────────

export function renderStats(state, meta = {}) {
  const stats = [
    ['step', state.step_n],
    ['script', state.frame_label],
    ['sigversion', sigversionLabel(state.sigversion)],
    ['ops used', state.op_count],
  ];
  if (state.cond?.length) {
    stats.push(['if-depth', `${state.cond.length} [${state.cond.map((c) => (c ? 1 : 0)).join('')}]`]);
  }
  if (state.sigversion === 'Tapscript') stats.push(['sigops budget', state.budget]);
  if (meta.txid) stats.push(['txid', `${meta.txid.slice(0, 10)}…`]);
  if (meta.vin !== undefined) stats.push(['input', `#${meta.vin}`]);

  // The grid is two columns; an odd count would leave a gap-coloured hole.
  if (stats.length % 2) stats.push(['', '']);

  const frag = document.createDocumentFragment();
  for (const [k, v] of stats) {
    const s = node('div', 'stat');
    s.append(node('div', 'k', k), node('div', 'v', String(v)));
    if (k) s.title = `${k}: ${v}`;
    frag.appendChild(s);
  }
  el.stats.replaceChildren(frag);
}

export function setStatus(state) {
  if (state.error) {
    el.status.textContent = 'failed';
    el.status.className = 'badge fail';
  } else if (state.success) {
    el.status.textContent = 'success';
    el.status.className = 'badge ok';
  } else if (state.finished) {
    el.status.textContent = 'finished';
    el.status.className = 'badge';
  } else {
    el.status.textContent = `stepping · #${state.step_n}`;
    el.status.className = 'badge busy';
  }
}

// ── step detail ───────────────────────────────────────────────────────────

export function renderStepDetail(rec) {
  if (!rec) {
    el.detail.replaceChildren(document.createTextNode('—'));
    return;
  }
  const frag = document.createDocumentFragment();
  frag.appendChild(node('div', 'op-name', `#${String(rec.n).padStart(3, '0')}  ${rec.op}`));

  const dl = node('dl');
  const row = (k, v) => {
    dl.append(node('dt', null, k), node('dd', null, v));
  };
  if (rec.data) row('pushes', `${rec.data.length / 2}B  ${describeItem(rec.data)}`);
  if (rec.skipped) row('skipped', 'inside an unexecuted branch');
  if (dl.children.length) frag.appendChild(dl);

  // Engine-indented notes are continuations of the note above (see logRecord).
  for (const n of rec.notes || []) {
    const cont = n.startsWith('  ');
    frag.appendChild(node('div', cont ? 'note good cont' : 'note good', cont ? n.trim() : n));
  }
  if (rec.error) frag.appendChild(node('div', 'note err', rec.error));

  for (const sig of rec.sigs || []) {
    const cls = sig.assumed ? 'assumed' : sig.valid ? 'ok' : 'bad';
    const box = node('div', `sig ${cls}`);
    box.appendChild(
      node(
        'div',
        'verdict',
        sig.assumed ? '⚠ signature not verified' : sig.valid ? '✓ signature valid' : '✗ signature invalid',
      ),
    );
    const sdl = node('dl');
    const srow = (k, v) => sdl.append(node('dt', null, k), node('dd', null, v));
    if (sig.pubkey) srow('pubkey', sig.pubkey);
    if (sig.signature) srow('signature', sig.signature);
    if (sig.sighash_type) srow('sighash type', sig.sighash_type);
    if (sig.sighash) srow('sighash', sig.sighash);
    if (sig.detail) srow('detail', sig.detail);
    box.appendChild(sdl);
    for (const w of sig.warnings || []) box.appendChild(node('div', 'note warn', w));
    frag.appendChild(box);
  }

  el.detail.replaceChildren(frag);
}

// ── spend info ────────────────────────────────────────────────────────────

export function renderSpendInfo(info, meta = {}) {
  el.spendKind.textContent = info.kind;
  el.spendKind.className = info.errors?.length ? 'badge fail' : 'badge ok';

  const frag = document.createDocumentFragment();
  for (const e of info.errors || []) frag.appendChild(node('div', 'note err', e));
  for (const n of info.notes || []) frag.appendChild(node('div', 'note', n));
  if (info.output_key) {
    frag.appendChild(node('div', 'note', `output key: ${info.output_key}`));
  }
  if (info.annex) frag.appendChild(node('div', 'note warn', `annex present: ${info.annex}`));
  if (meta.explorerUrl) {
    const a = document.createElement('a');
    a.href = meta.explorerUrl;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = 'view this transaction on mempool.space →';
    const wrap = node('div', 'note');
    wrap.appendChild(a);
    frag.appendChild(wrap);
  }
  el.notes.replaceChildren(frag);
}

export function clearSpendInfo() {
  el.notes.replaceChildren();
  el.spendKind.textContent = 'no spend loaded';
  el.spendKind.className = 'badge';
}
