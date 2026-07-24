// mempool.space REST client.
//
// Only the handful of endpoints the debugger needs: a transaction, its raw
// hex, and the outputs it spends. Everything is public and CORS-enabled, so
// this works from a static page with no key and no proxy.

const BASES = {
  mainnet: 'https://mempool.space/api',
  testnet: 'https://mempool.space/testnet/api',
  testnet4: 'https://mempool.space/testnet4/api',
  signet: 'https://mempool.space/signet/api',
};

export const EXPLORERS = {
  mainnet: 'https://mempool.space/tx/',
  testnet: 'https://mempool.space/testnet/tx/',
  testnet4: 'https://mempool.space/testnet4/tx/',
  signet: 'https://mempool.space/signet/tx/',
};

export function baseFor(network) {
  return BASES[network] || BASES.mainnet;
}

async function req(network, path, { json = true } = {}) {
  const url = baseFor(network) + path;
  let res;
  try {
    res = await fetch(url);
  } catch (cause) {
    throw new Error(`network request to mempool.space failed (${path})`, { cause });
  }
  if (!res.ok) {
    const body = (await res.text().catch(() => '')).trim();
    if (res.status === 404) {
      throw new Error(`not found on ${network}: ${path.replace('/tx/', '')}`);
    }
    throw new Error(`mempool.space returned ${res.status} for ${path}${body ? `: ${body}` : ''}`);
  }
  return json ? res.json() : (await res.text()).trim();
}

export const isTxid = (s) => /^[0-9a-fA-F]{64}$/.test((s || '').trim());

/** Fetch the decoded transaction JSON. */
export const getTx = (network, txid) => req(network, `/tx/${txid}`);

/** Fetch the raw transaction, hex encoded. */
export const getTxHex = (network, txid) => req(network, `/tx/${txid}/hex`, { json: false });

export const getTipHeight = (network) =>
  req(network, '/blocks/tip/height', { json: false });

/**
 * Everything needed to debug one input of a confirmed or mempool transaction.
 *
 * mempool.space includes each input's prevout inline, which is exactly what
 * BIP143 and BIP341 sighashes need — no extra round trips.
 */
export async function loadSpend(network, txid) {
  const [tx, hex] = await Promise.all([getTx(network, txid), getTxHex(network, txid)]);

  if (tx.vin.some((v) => v.is_coinbase)) {
    throw new Error('coinbase transactions have no prevouts to verify against');
  }
  const missing = tx.vin.findIndex((v) => !v.prevout);
  if (missing !== -1) {
    throw new Error(`mempool.space did not return a prevout for input ${missing}`);
  }

  return {
    txid: tx.txid,
    txHex: hex,
    tx,
    confirmed: !!tx.status?.confirmed,
    blockHeight: tx.status?.block_height ?? null,
    prevouts: tx.vin.map((v) => ({
      value: v.prevout.value,
      script_pubkey: v.prevout.scriptpubkey,
    })),
    // Handy for the UI even though the engine re-derives them from the tx.
    types: tx.vin.map((v) => v.prevout.scriptpubkey_type),
    addresses: tx.vin.map((v) => v.prevout.scriptpubkey_address || null),
  };
}

/**
 * Resolve prevouts for a transaction we only have as raw hex — a locally built
 * or unbroadcast one. Each input's parent transaction is fetched to recover the
 * scriptPubKey and value being spent.
 *
 * `inputs` comes from the engine's parseTx: [{txid, vout}, ...].
 */
export async function resolvePrevouts(network, inputs, onProgress) {
  const cache = new Map();
  const out = [];
  for (const [i, input] of inputs.entries()) {
    onProgress?.(i, inputs.length, input.txid);
    if (/^0{64}$/.test(input.txid)) {
      throw new Error(`input ${i} is a coinbase input; nothing to verify against`);
    }
    let parent = cache.get(input.txid);
    if (!parent) {
      parent = await getTx(network, input.txid);
      cache.set(input.txid, parent);
    }
    const vout = parent.vout?.[input.vout];
    if (!vout) {
      throw new Error(
        `input ${i} spends ${input.txid}:${input.vout}, which that transaction does not have`,
      );
    }
    out.push({ value: vout.value, script_pubkey: vout.scriptpubkey });
  }
  return out;
}
