/* tslint:disable */
/* eslint-disable */

export class Debugger {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Debug a bare script with a hand-made initial stack — no transaction, so
     * signature checks are reported as unverified unless `assume_valid_sigs`.
     *
     * `source` accepts hex or assembly. `sigversion` is one of
     * `legacy`, `witness_v0`, `tapscript`.
     */
    static fromScript(source: string, stack: any, sigversion: string, flags: number, assume_valid_sigs: boolean): Debugger;
    /**
     * Debug a real spend: a transaction, which input to examine, and the
     * prevouts being spent (needed for segwit and taproot sighashes).
     */
    static fromTx(tx_hex: string, input_index: number, prevouts: any, flags: number, assume_valid_sigs: boolean): Debugger;
    /**
     * Detected spend type, notes, and any structural errors.
     */
    info(): any;
    /**
     * Everything the UI needs to render the script listing.
     */
    listing(): any;
    /**
     * All step records so far.
     */
    records(): any;
    /**
     * Undo the last step.
     */
    rewind(): any;
    /**
     * Run up to `max` steps, stopping on completion or error.
     */
    run(max: number): any;
    state(): any;
    /**
     * Execute one instruction.
     */
    step(): any;
}

/**
 * `btcc`: assemble script assembly into hex.
 */
export function btcc(source: string): string;

/**
 * Resolve a spend without building a debugger, for the "what is this input?"
 * summary line.
 */
export function describeSpend(script_sig_hex: string, witness: any, script_pubkey_hex: string): any;

/**
 * Disassemble script hex into one instruction per line.
 */
export function disasm(script_hex: string): any;

/**
 * Script verification flags, exposed so the UI can build its toggles.
 */
export function flagInfo(): any;

/**
 * Parse a raw transaction for display.
 */
export function parseTx(tx_hex: string, network: string): any;

/**
 * Derive the address for a scriptPubKey, when it has one.
 */
export function scriptAddress(script_hex: string, network: string): string;

/**
 * `tf`: apply a transform to a value, as btcdeb's `tf` command does.
 */
export function tf(func: string, arg: string): string;

export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_debugger_free: (a: number, b: number) => void;
    readonly btcc: (a: number, b: number) => [number, number, number, number];
    readonly debugger_fromScript: (a: number, b: number, c: any, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly debugger_fromTx: (a: number, b: number, c: number, d: any, e: number, f: number) => [number, number, number];
    readonly debugger_info: (a: number) => [number, number, number];
    readonly debugger_listing: (a: number) => [number, number, number];
    readonly debugger_records: (a: number) => [number, number, number];
    readonly debugger_rewind: (a: number) => [number, number, number];
    readonly debugger_run: (a: number, b: number) => [number, number, number];
    readonly debugger_state: (a: number) => [number, number, number];
    readonly debugger_step: (a: number) => [number, number, number];
    readonly describeSpend: (a: number, b: number, c: any, d: number, e: number) => [number, number, number];
    readonly disasm: (a: number, b: number) => [number, number, number];
    readonly flagInfo: () => [number, number, number];
    readonly parseTx: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly scriptAddress: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly tf: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly version: () => [number, number];
    readonly rustsecp256k1_v0_10_0_context_create: (a: number) => number;
    readonly rustsecp256k1_v0_10_0_context_destroy: (a: number) => void;
    readonly rustsecp256k1_v0_10_0_default_error_callback_fn: (a: number, b: number) => void;
    readonly rustsecp256k1_v0_10_0_default_illegal_callback_fn: (a: number, b: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
