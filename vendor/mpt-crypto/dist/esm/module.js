/* eslint-disable @typescript-eslint/naming-convention -- WASM exports keep their C names */
/* eslint-disable max-params -- this interface mirrors the C ABI; many byte-pointer args are inherent */
let cached;
// A load can hit a transient failure (e.g. a browser chunk-fetch hiccup), so it
// is retried a few times, backing off between attempts to give the condition
// time to clear (immediate retries would just hit the same failure).
const MAX_LOAD_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 100;
/**
 * Import, instantiate, and initialize the WASM module — a single load attempt.
 *
 * @returns The initialized module.
 * @throws If the import/instantiation fails or the secp256k1 context can't init.
 */
async function loadOnce() {
    /* eslint-disable no-inline-comments -- the webpack chunk-name hint must lead the import specifier */
    const { default: factory } = await import(
    /* webpackChunkName: "mpt-crypto-wasm" */ '@xrplf/mpt-crypto/wasm');
    /* eslint-enable no-inline-comments */
    const instance = await factory();
    // A zero return means the shared secp256k1 context failed to initialize; fail
    // loudly here rather than on the first crypto op.
    if (instance._mpt_secp256k1_context() === 0) {
        throw new Error('mpt-crypto: failed to initialize the secp256k1 context');
    }
    return instance;
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
export async function loadWithRetry(load = loadOnce, attempt = 1) {
    try {
        return await load();
    }
    catch (error) {
        if (attempt >= MAX_LOAD_ATTEMPTS) {
            throw error;
        }
        // Linear backoff (100ms, 200ms, …) so a transient failure has time to clear.
        await new Promise((resolve) => {
            setTimeout(resolve, attempt * RETRY_BASE_DELAY_MS);
        });
        return loadWithRetry(load, attempt + 1);
    }
}
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
export async function loadWasmModule() {
    cached ?? (cached = loadWithRetry().catch((error) => {
        // Don't cache a failed load, so a later call can retry.
        cached = undefined;
        throw error;
    }));
    return cached;
}
