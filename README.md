# btcdeb.wasm

A Bitcoin Script debugger that runs entirely in the browser. Step through real
spends op by op, watch the stack change, and see exactly which sighash each
signature commits to — with transactions pulled live from
[mempool.space](https://mempool.space).

Static site, no backend: it deploys to GitHub Pages as-is.

## What this is (and what it isn't)

[btcdeb](https://github.com/bitcoin-core/btcdeb) is a native C++ program.
GitHub Pages serves static files and cannot execute one, so this is **not**
btcdeb compiled and shelled out to. It is a btcdeb-*shaped* debugger built on
[rust-bitcoin](https://github.com/rust-bitcoin/rust-bitcoin) compiled to
WebAssembly:

| Concern | Where it comes from |
| --- | --- |
| Transaction and script parsing | `bitcoin` crate (consensus decoding) |
| Legacy, BIP143, and BIP341 sighashes | `bitcoin::sighash::SighashCache` |
| ECDSA and BIP340 Schnorr verification | `libsecp256k1`, compiled to wasm |
| Taproot leaf hashes and control blocks | `bitcoin::taproot` |
| The stepping evaluator | `engine/src/interp.rs` — written here, because rust-bitcoin ships no script VM |

The command names (`step`, `rewind`, `stack`, `altstack`, `vfexec`, `print`,
`tf`, `exec`) and the two-pane script/stack layout follow btcdeb so muscle
memory carries over.

## Features

- **Real spends.** Give it a txid and an input index; it fetches the
  transaction and every prevout it spends, then works out whether it is P2PKH,
  P2SH, P2WPKH, P2WSH, nested segwit, or taproot — key path or script path.
- **Honest signature checking.** Signatures are verified against sighashes
  computed from the actual transaction. The sighash and its type are shown for
  every check, alongside the exact pubkey and signature bytes it ran against —
  so a multisig says which signature matched which key, in full hex, not just
  "signature 2 matched key 3". Without a transaction loaded, checks are reported as *not
  verified* rather than quietly passing (there is an opt-in "assume valid
  signatures" toggle for exploring script logic).
- **Taproot aware.** Control blocks are decoded and the commitment is verified
  against the output key, so you can see whether a leaf is really in the tree.
  Tapscript rules apply: `OP_CHECKSIGADD`, no `OP_CHECKMULTISIG`,
  `OP_SUCCESSx`, and the sigops budget.
- **Step backwards.** Every step snapshots machine state, so `rewind` works.
- **Assembler and transforms.** `btcc` compiles assembly to hex, `asm`
  disassembles, and `tf` applies sha256 / hash160 / ripemd160 / script-number
  conversions.
- **Flag toggles.** Turn `MINIMALDATA`, `CLEANSTACK`, `LOW_S`, `NULLFAIL` and
  friends on and off to see which rule a script actually trips over.
- **Deep links.** `?txid=<txid>&vin=<n>&net=mainnet` loads a spend directly.
- **Resizable panels.** Drag the dividers between the columns and above the
  console, or use the sliders under *layout*; arrow keys nudge a focused
  divider, double-clicking one resets it. Sizes persist in `localStorage`.

## Running it locally

The page fetches WebAssembly, so it needs to be served over HTTP — opening
`index.html` from disk will not work.

```sh
python3 -m http.server 8000
# then open http://localhost:8000/
```

## Building the engine

Requires a Rust toolchain, the `wasm32-unknown-unknown` target,
[wasm-pack](https://rustwasm.github.io/wasm-pack/), and `clang` (libsecp256k1
is C).

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

cd engine
cargo test --release                                   # run the test suite
wasm-pack build --target web --out-dir ../pkg --release # emit pkg/
rm -f ../pkg/.gitignore                                # keep the build output
```

`pkg/` is committed so the site works on GitHub Pages without CI, and
`.github/workflows/pages.yml` rebuilds and redeploys it on every push to
`main`.

### Tests

`engine/tests/real_spends.rs` replays real mainnet spends — P2PKH, P2SH-P2WPKH,
P2WPKH, P2WSH multisig, P2TR key path, and P2TR script path — from fixtures in
`real_spends.json`. Each was taken from a mined block, so it is consensus-valid
by construction: the interpreter must run every one to a true stack top with
its signatures genuinely verifying. Two further tests check that tampering with
an output value invalidates the signature, and that `rewind` restores state
exactly.

The fixtures are checked in, so the suite needs no network access.

## Deploying to GitHub Pages

```sh
git init -b main
git add .
git commit -m "btcdeb.wasm: bitcoin script debugger"
git remote add origin git@github.com:<you>/<repo>.git
git push -u origin main
```

Then in **Settings → Pages**, set **Source** to **GitHub Actions**. The
included workflow tests the engine, rebuilds the WebAssembly, and publishes.

If you would rather skip CI, set Source to *Deploy from a branch* → `main` /
`root`; the committed `pkg/` directory makes that work. `.nojekyll` is present
so nothing gets filtered on the way out.

## Layout

```
index.html              markup
css/theme.css           phosphor-green terminal theme
js/main.js              session wiring: boot, load, step, flags
js/ui.js                rendering: listing, stacks, step detail
js/commands.js          the console command set
js/layout.js            panel sizing: gutters, sliders, persistence
js/mempool.js           mempool.space REST client
pkg/                    wasm-pack output (committed)
engine/src/interp.rs    the stepping evaluator
engine/src/spend.rs     spend-type resolution
engine/src/sig.rs       sighash construction and signature checks
engine/src/asm.rs       decoder, disassembler, assembler (btcc)
engine/src/num.rs       CScriptNum arithmetic
engine/src/opnames.rs   opcode name tables
engine/src/lib.rs       the WASM API surface
```

## Caveats

- The evaluator follows Bitcoin Core's `EvalScript` closely but is an
  independent implementation. Use it to understand and debug scripts, not as a
  consensus oracle.
- mempool.space is a third party and rate limits; the network selector covers
  mainnet, testnet3, testnet4, and signet.
- `exec` runs a script against a *copy* of the current stack and reports the
  result; it does not mutate the debug session.

## Licence

The engine depends on rust-bitcoin and libsecp256k1, both MIT licensed.
