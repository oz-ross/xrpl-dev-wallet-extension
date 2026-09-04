/**
 * `@xrplf/mpt-crypto` — Confidential MPT (XLS-0096) cryptographic primitives for
 * the XRP Ledger, exposed as a hex-in/hex-out API over a vendored WebAssembly
 * build of the reference C library.
 *
 * Every byte argument and return value is an uppercase, even-length hex string
 * (no `0x` prefix); integer amounts are `bigint`. The WASM module is loaded
 * lazily and cached on first use, so it only pays its load cost when a
 * confidential operation is actually invoked.
 */
export { PUBKEY_SIZE, PRIVKEY_SIZE, BLINDING_FACTOR_SIZE, ELGAMAL_TOTAL_SIZE, PEDERSEN_COMMIT_SIZE, CONTEXT_HASH_SIZE, ACCOUNT_ID_SIZE, ISSUANCE_ID_SIZE, CONVERT_PROOF_SIZE, CLAWBACK_PROOF_SIZE, CONVERT_BACK_PROOF_SIZE, SEND_PROOF_SIZE, } from './constants.js';
export { bytesToHex, hexToBytes } from './hex.js';
export { loadWasmModule } from './module.js';
export { generateBlindingFactor, encryptAmount, decryptAmount, getPedersenCommitment, } from './primitives.js';
export { addCiphertexts, subtractCiphertexts } from './homomorphic.js';
export { getConvertContextHash, getConvertBackContextHash, getSendContextHash, getClawbackContextHash, } from './context.js';
export { getConvertProof, getClawbackProof, getConvertBackProof, getConfidentialSendProof, } from './proofs.js';
