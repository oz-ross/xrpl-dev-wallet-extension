/**
 * Typed view of the Emscripten-generated `mpt_crypto` WASM module. Only the
 * exports vendored by `.github/scripts/build-wasm.sh` are declared. All `uint64_t` parameters
 * are passed as JS `bigint` (the module is built with `-sWASM_BIGINT=1`); all
 * pointer parameters are byte offsets into {@link WasmModule.HEAPU8}.
 *
 * The C `account_id` / `mpt_issuance_id` by-value struct parameters of the
 * context-hash functions are lowered by the wasm32 ABI to pointers, so they are
 * declared as `number` here (verified against the reference harness).
 */
export interface WasmModule {
    HEAPU8: Uint8Array;
    _malloc: (size: number) => number;
    _free: (ptr: number) => void;
    _mpt_secp256k1_context: () => number;
    _mpt_generate_blinding_factor: (outFactor: number) => number;
    _mpt_encrypt_amount: (amount: bigint, pubkey: number, blinding: number, outCiphertext: number) => number;
    _mpt_decrypt_amount: (ciphertext: number, privkey: number, outAmount: number, rangeLow: bigint, rangeHigh: bigint) => number;
    _mpt_get_pedersen_commitment: (amount: bigint, blinding: number, outCommitment: number) => number;
    _mpt_get_convert_context_hash: (account: number, issuance: number, sequence: number, outHash: number) => number;
    _mpt_get_convert_back_context_hash: (account: number, issuance: number, sequence: number, version: number, outHash: number) => number;
    _mpt_get_send_context_hash: (account: number, issuance: number, sequence: number, destination: number, version: number, outHash: number) => number;
    _mpt_get_clawback_context_hash: (account: number, issuance: number, sequence: number, holder: number, outHash: number) => number;
    _mpt_get_convert_proof: (pubkey: number, privkey: number, contextHash: number, outProof: number) => number;
    _mpt_get_clawback_proof: (privkey: number, pubkey: number, contextHash: number, amount: bigint, ciphertext: number, outProof: number) => number;
    _mpt_get_convert_back_proof: (privkey: number, pubkey: number, contextHash: number, amount: bigint, params: number, outProof: number) => number;
    _mpt_get_confidential_send_proof: (privkey: number, pubkey: number, amount: bigint, participants: number, nParticipants: number, txBlindingFactor: number, contextHash: number, amountCommitment: number, balanceParams: number, outProof: number, outLen: number) => number;
    _mpt_make_ec_pair: (buffer: number, out1: number, out2: number) => number;
    _mpt_serialize_ec_pair: (in1: number, in2: number, out: number) => number;
    _secp256k1_elgamal_add: (ctx: number, sumC1: number, sumC2: number, aC1: number, aC2: number, bC1: number, bC2: number) => number;
    _secp256k1_elgamal_subtract: (ctx: number, diffC1: number, diffC2: number, aC1: number, aC2: number, bC1: number, bC2: number) => number;
}
/**
 * Load the module, retrying a transient failure up to {@link MAX_LOAD_ATTEMPTS}.
 *
 * `load` is injectable so the retry/backoff behavior can be unit-tested without a
 * real WASM import; production callers rely on the {@link loadOnce} default.
 *
 * @param load - One load attempt (defaults to {@link loadOnce}).
 * @param attempt - The current (1-based) attempt number.
 * @returns The initialized module.
 * @throws The failure from the final attempt.
 */
export declare function loadWithRetry(load?: () => Promise<WasmModule>, attempt?: number): Promise<WasmModule>;
/**
 * Load (once) and return the vendored WASM module.
 *
 * The glue is imported via this package's own `./wasm` subpath export so one line
 * serves every target: `require`/Jest get the CJS glue, Node `import` the full ESM
 * glue, and bundlers/browsers a Node-free ESM glue (`mpt_crypto.web.mjs`). All three
 * wrap the same `.wasm`; both ESM glues use `new URL(import.meta.url)` so bundlers
 * emit it as an asset. See the `package.json` exports and `src/wasm.d.ts`.
 *
 * A transient load failure is retried automatically; if every attempt still
 * fails the rejection is not cached, so a later call retries afresh rather than
 * returning the same permanent rejection.
 *
 * Provenance: `mpt_crypto.{js,mjs,wasm}` come from mpt-crypto's
 * `.github/scripts/build-wasm.sh` and are vendored by `scripts/fetch-wasm.sh`.
 *
 * @returns A promise resolving to the initialized WASM module.
 */
export declare function loadWasmModule(): Promise<WasmModule>;
