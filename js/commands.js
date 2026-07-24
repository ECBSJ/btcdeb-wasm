// The console command set. Names and behaviour follow btcdeb's interactive
// commands where they map onto a browser session, plus a few extras (`load`,
// `btcc`, `net`) that only make sense here.

import * as ui from './ui.js';
import { describeItem, sigversionLabel } from './ui.js';

const need = (ctx) => {
  if (!ctx.session.dbg) throw new Error('nothing loaded — try `load <txid>` or pick an example');
  return ctx.session.dbg;
};

function printStack(items, label) {
  if (!items.length) {
    ui.log(`${label}: empty`, 'info');
    return;
  }
  ui.log(`${label} (top first):`, 'info');
  [...items].reverse().forEach((hex, i) => {
    const idx = items.length - 1 - i;
    ui.log(`  <${idx}> ${hex || '(empty)'}${hex ? `   ${describeItem(hex)}` : ''}`, 'trace');
  });
}

export const COMMANDS = {
  help: {
    usage: 'help [command]',
    blurb: 'list commands, or explain one',
    run(ctx, args) {
      if (args[0]) {
        const c = COMMANDS[args[0]];
        if (!c) throw new Error(`no such command: ${args[0]}`);
        ui.log(`${c.usage}`, 'out');
        ui.log(`  ${c.blurb}`, 'info');
        return;
      }
      ui.log('commands:', 'info');
      const names = Object.keys(COMMANDS).sort();
      const width = Math.max(...names.map((n) => COMMANDS[n].usage.length));
      for (const n of names) {
        ui.log(`  ${COMMANDS[n].usage.padEnd(width)}   ${COMMANDS[n].blurb}`, 'out');
      }
      ui.log('keys: F10 step · F9 rewind · F5 run · ↑/↓ history', 'info');
    },
  },

  step: {
    usage: 'step [n]',
    blurb: 'execute the next instruction (default 1)',
    run(ctx, args) {
      need(ctx);
      const n = args[0] ? parseCount(args[0]) : 1;
      for (let i = 0; i < n; i++) if (!ctx.step()) break;
    },
  },

  rewind: {
    usage: 'rewind [n]',
    blurb: 'step backwards through history',
    run(ctx, args) {
      need(ctx);
      const n = args[0] ? parseCount(args[0]) : 1;
      for (let i = 0; i < n; i++) if (!ctx.rewind()) break;
    },
  },

  run: {
    usage: 'run',
    blurb: 'execute until the script finishes or fails',
    run(ctx) {
      need(ctx);
      ctx.runAll();
    },
  },

  reset: {
    usage: 'reset',
    blurb: 'reload the current spend from the start',
    run(ctx) {
      need(ctx);
      ctx.reset();
      ui.log('reset to the first instruction', 'info');
    },
  },

  stack: {
    usage: 'stack',
    blurb: 'print the stack',
    run(ctx) {
      printStack(need(ctx).state().stack, 'stack');
    },
  },

  altstack: {
    usage: 'altstack',
    blurb: 'print the altstack',
    run(ctx) {
      printStack(need(ctx).state().altstack, 'altstack');
    },
  },

  vfexec: {
    usage: 'vfexec',
    blurb: 'print the conditional (OP_IF) execution stack',
    run(ctx) {
      const cond = need(ctx).state().cond;
      if (!cond.length) {
        ui.log('vfexec: empty (not inside any OP_IF)', 'info');
        return;
      }
      ui.log(`vfexec: [${cond.map((c) => (c ? 'true' : 'false')).join(', ')}]`, 'trace');
    },
  },

  print: {
    usage: 'print',
    blurb: 'print the full script listing with the current position',
    run(ctx) {
      const dbg = need(ctx);
      const state = dbg.state();
      ctx.session.frames.forEach((frame, fi) => {
        ui.log(`── ${frame.label} [${sigversionLabel(frame.sigversion)}] ──`, 'info');
        if (frame.key_path) {
          ui.log(`${fi === state.frame_idx ? ' ▶' : '  '}  CHECKSIG (BIP341 key path)`, 'out');
          return;
        }
        frame.instructions.forEach((ins, ii) => {
          const cur = fi === state.frame_idx && ii === state.ip && !state.finished;
          ui.log(
            `${cur ? ' ▶' : '  '} ${String(ins.offset).padStart(4)}  ${ins.text}` +
              (ins.is_push && !ins.minimal ? '   (non-minimal push)' : ''),
            cur ? 'cmd' : 'out',
          );
        });
      });
    },
  },

  info: {
    usage: 'info',
    blurb: 'describe the loaded spend',
    run(ctx) {
      need(ctx);
      const info = ctx.session.info;
      ui.log(`spend type: ${info.kind}`, 'cmd');
      if (ctx.session.meta.txid) {
        ui.log(`txid ${ctx.session.meta.txid} input #${ctx.session.meta.vin}`, 'out');
      }
      for (const n of info.notes || []) ui.log(`  · ${n}`, 'info');
      for (const e of info.errors || []) ui.log(`  ! ${e}`, 'err');
      if (info.output_key) ui.log(`  output key: ${info.output_key}`, 'out');
      ui.log(
        `flags: ${ctx.flagNames().join(' | ') || '(none)'}${
          ctx.session.assumeSigs ? '   [assuming valid signatures]' : ''
        }`,
        'info',
      );
    },
  },

  tx: {
    usage: 'tx',
    blurb: 'show the parsed transaction',
    run(ctx) {
      const { txHex } = ctx.session.source || {};
      if (!txHex) throw new Error('no transaction loaded (script mode has none)');
      const tx = ctx.engine.parseTx(txHex, ctx.session.network);
      ui.log(`txid    ${tx.txid}`, 'cmd');
      if (tx.is_segwit) ui.log(`wtxid   ${tx.wtxid}`, 'out');
      ui.log(
        `version ${tx.version}   locktime ${tx.lock_time}   ${tx.size}B / ${tx.vsize}vB / ${tx.weight}wu`,
        'out',
      );
      for (const i of tx.inputs) {
        const mark = i.index === ctx.session.meta.vin ? '▶' : ' ';
        ui.log(`${mark} in  #${i.index}  ${i.txid}:${i.vout}  seq ${i.sequence}`, mark === '▶' ? 'cmd' : 'out');
        if (i.script_sig) ui.log(`      scriptSig  ${i.script_sig_asm.join(' ')}`, 'trace');
        i.witness.forEach((w, wi) => ui.log(`      witness[${wi}] ${w || '(empty)'}`, 'trace'));
      }
      for (const o of tx.outputs) {
        ui.log(`  out #${o.index}  ${o.value} sat  ${o.address || o.script_pubkey_asm.join(' ')}`, 'out');
      }
    },
  },

  load: {
    usage: 'load <txid> [vin]',
    blurb: 'fetch a transaction from mempool.space and debug an input',
    run(ctx, args) {
      if (!args[0]) throw new Error('usage: load <txid> [vin]');
      const vin = args[1] ? parseCount(args[1], 0) : 0;
      ctx.loadTxid(args[0], vin);
    },
  },

  tf: {
    usage: 'tf <fn> <value>',
    blurb: 'transform a value: sha256, hash160, reverse, int, num, str, x, …',
    run(ctx, args) {
      if (args.length < 2) {
        throw new Error(
          'usage: tf <fn> <value>   fns: sha256 sha256d hash160 ripemd160 sha1 reverse int num str unstr x tagged-hash',
        );
      }
      const out = ctx.engine.tf(args[0], args.slice(1).join(' '));
      ui.log(out, 'trace');
    },
  },

  btcc: {
    usage: 'btcc <script…>',
    blurb: 'assemble script assembly into hex',
    run(ctx, args) {
      if (!args.length) throw new Error('usage: btcc OP_DUP OP_HASH160 <20-byte-hex> …');
      ui.log(ctx.engine.btcc(args.join(' ')), 'trace');
    },
  },

  asm: {
    usage: 'asm <hex>',
    blurb: 'disassemble script hex',
    run(ctx, args) {
      if (!args.length) throw new Error('usage: asm <script hex>');
      const lines = ctx.engine.disasm(args.join(''));
      ui.log(lines.join(' '), 'trace');
    },
  },

  exec: {
    usage: 'exec <script…>',
    blurb: 'try a script against a copy of the current stack (does not affect the session)',
    run(ctx, args) {
      if (!args.length) throw new Error('usage: exec OP_SHA256 OP_DUP …');
      const dbg = need(ctx);
      const state = dbg.state();
      const probe = ctx.engine.Debugger.fromScript(
        args.join(' '),
        state.stack,
        state.sigversion === 'Tapscript' ? 'tapscript' : 'legacy',
        ctx.session.flags,
        true,
      );
      const records = probe.run(10000);
      for (const r of records) {
        if (r.error) ui.log(`  #${r.n} ${r.op}: ${r.error}`, 'err');
      }
      const after = probe.state();
      ui.log('exec on a copy of the stack — the session is untouched:', 'info');
      printStack(after.stack, 'result');
    },
  },

  flags: {
    usage: 'flags [NAME on|off]',
    blurb: 'show or change script verification flags',
    run(ctx, args) {
      if (!args.length) {
        for (const f of ctx.session.flagList) {
          const on = (ctx.session.flags & f.bit) !== 0;
          ui.log(`  [${on ? 'x' : ' '}] ${f.name.padEnd(20)} ${f.description}`, on ? 'out' : 'info');
        }
        ui.log(
          `assume valid signatures: ${ctx.session.assumeSigs ? 'on' : 'off'}`,
          'info',
        );
        return;
      }
      const name = args[0].toUpperCase();
      if (name === 'ASSUME') {
        ctx.setAssume(args[1] !== 'off');
        return;
      }
      const flag = ctx.session.flagList.find((f) => f.name === name);
      if (!flag) throw new Error(`unknown flag ${name} (run \`flags\` to list them)`);
      if (!args[1]) throw new Error(`usage: flags ${name} on|off`);
      ctx.setFlag(flag.bit, args[1] !== 'off');
    },
  },

  sighash: {
    usage: 'sighash',
    blurb: 'show the signature checks from the last step',
    run(ctx) {
      const dbg = need(ctx);
      // Walk back to the most recent step that actually checked something; the
      // last step is often just an end-of-script transition.
      const records = dbg.records();
      const rec = [...records].reverse().find((r) => r.sigs?.length);
      if (!rec) {
        throw new Error('no signature checks have run yet');
      }
      ui.log(`from step #${String(rec.n).padStart(3, '0')} ${rec.op}:`, 'info');
      for (const s of rec.sigs) {
        ui.log(
          s.assumed ? '⚠ not verified (no transaction)' : s.valid ? '✓ valid' : '✗ invalid',
          s.valid && !s.assumed ? 'cmd' : s.assumed ? 'warn' : 'err',
        );
        if (s.sighash_type) ui.log(`  type    ${s.sighash_type}`, 'out');
        if (s.sighash) ui.log(`  sighash ${s.sighash}`, 'trace');
        if (s.detail) ui.log(`  ${s.detail}`, 'info');
        for (const w of s.warnings || []) ui.log(`  ! ${w}`, 'warn');
      }
    },
  },

  net: {
    usage: 'net [mainnet|testnet4|testnet|signet]',
    blurb: 'show or switch which mempool.space instance is queried',
    run(ctx, args) {
      if (!args[0]) {
        ui.log(`network: ${ctx.session.network}`, 'info');
        return;
      }
      ctx.setNetwork(args[0]);
    },
  },

  clear: {
    usage: 'clear',
    blurb: 'clear the console',
    run() {
      ui.clearLog();
    },
  },

  version: {
    usage: 'version',
    blurb: 'engine build info',
    run(ctx) {
      ui.log(ctx.engine.version(), 'info');
    },
  },
};

// A couple of single-letter aliases, as btcdeb accepts.
const ALIASES = { s: 'step', r: 'rewind', p: 'print', h: 'help', '?': 'help', q: 'clear' };

function parseCount(raw, min = 1) {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min) {
    throw new Error(`expected an integer >= ${min}, got '${raw}'`);
  }
  return n;
}

/** Split a command line, honouring quoted strings. */
function tokenize(line) {
  const out = [];
  const re = /'[^']*'|"[^"]*"|\S+/g;
  let m;
  while ((m = re.exec(line))) out.push(m[0]);
  return out;
}

export function runCommand(ctx, line) {
  const trimmed = line.trim();
  if (!trimmed) return;
  ui.log(`btcdeb> ${trimmed}`, 'cmd');

  const parts = tokenize(trimmed);
  const name = ALIASES[parts[0]] || parts[0];
  const cmd = COMMANDS[name];
  if (!cmd) {
    ui.log(`unknown command '${parts[0]}' — try \`help\``, 'err');
    return;
  }
  try {
    cmd.run(ctx, parts.slice(1));
  } catch (e) {
    ui.log(String(e?.message || e), 'err');
  }
}

export const commandNames = () => [...Object.keys(COMMANDS), ...Object.keys(ALIASES)];
