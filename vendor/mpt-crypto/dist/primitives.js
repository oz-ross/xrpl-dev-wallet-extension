"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateBlindingFactor = generateBlindingFactor;
exports.encryptAmount = encryptAmount;
exports.decryptAmount = decryptAmount;
exports.getPedersenCommitment = getPedersenCommitment;
const constants_1 = require("./constants");
const hex_1 = require("./hex");
const internal_1 = require("./internal");
const runtime_1 = require("./runtime");
const U64_BYTES = 8;
// The C `mpt_decrypt_amount` rejects `range_high == UINT64_MAX` (secp256k1_mpt.h),
// so the largest legal search bound is one less.
const MAX_DECRYPT_RANGE_HIGH = internal_1.U64_MAX - 1n;
// mpt-crypto decrypts an ElGamal amount by brute-forcing the discrete log over
// [0, rangeHigh]; the search stops at the recovered value, so cost scales with
// the amount, not the window. rangeHigh must be < UINT64_MAX (secp256k1_mpt.h).
const DECRYPT_RANGE_LOW = 0n;
/**
 * Generate a 32-byte blinding factor / ElGamal randomness scalar.
 *
 * @returns The hex-encoded blinding factor.
 * @throws If the underlying WASM call fails.
 */
async function generateBlindingFactor() {
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const ptr = marshaller.alloc(constants_1.BLINDING_FACTOR_SIZE);
        if (mod._mpt_generate_blinding_factor(ptr) !== 0) {
            throw new Error('mpt_generate_blinding_factor failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(ptr, constants_1.BLINDING_FACTOR_SIZE));
    });
}
/**
 * ElGamal-encrypt an amount under a public key.
 *
 * @param amount - The integer amount to encrypt.
 * @param publicKey - The 33-byte hex public key.
 * @param blindingFactor - The 32-byte hex randomness scalar.
 * @returns The 66-byte hex ciphertext (C1 || C2).
 * @throws If inputs are malformed or the WASM call fails.
 */
async function encryptAmount(amount, publicKey, blindingFactor) {
    (0, internal_1.assertUint64)(amount, 'amount');
    const pub = (0, hex_1.hexToBytes)(publicKey, 'publicKey', constants_1.PUBKEY_SIZE);
    const blinding = (0, hex_1.hexToBytes)(blindingFactor, 'blindingFactor', constants_1.BLINDING_FACTOR_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const pubPtr = marshaller.allocBytes(pub);
        const blindingPtr = marshaller.allocBytes(blinding);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        blinding.fill(0);
        const outPtr = marshaller.alloc(constants_1.ELGAMAL_TOTAL_SIZE);
        if (mod._mpt_encrypt_amount(amount, pubPtr, blindingPtr, outPtr) !== 0) {
            throw new Error('mpt_encrypt_amount failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.ELGAMAL_TOTAL_SIZE));
    });
}
/**
 * Decrypt an ElGamal ciphertext with a private key.
 *
 * The amount is recovered by brute-forcing the discrete log over `[0, rangeHigh]`;
 * cost is O(rangeHigh) (~3s per 1,000,000), so pass the tightest correct bound
 * available (e.g. the issuance's confidential outstanding amount). An amount
 * above `rangeHigh` cannot be recovered.
 *
 * @param ciphertext - The 66-byte hex ciphertext.
 * @param privateKey - The 32-byte hex private key.
 * @param rangeHigh - Inclusive upper bound for the search; must be < 2^64 - 1.
 * @returns The decrypted integer amount.
 * @throws If inputs are malformed, the amount is outside [0, rangeHigh], or the
 * WASM call fails.
 */
async function decryptAmount(ciphertext, privateKey, rangeHigh) {
    (0, internal_1.assertUint64)(rangeHigh, 'rangeHigh', MAX_DECRYPT_RANGE_HIGH);
    const ct = (0, hex_1.hexToBytes)(ciphertext, 'ciphertext', constants_1.ELGAMAL_TOTAL_SIZE);
    const priv = (0, hex_1.hexToBytes)(privateKey, 'privateKey', constants_1.PRIVKEY_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const ctPtr = marshaller.allocBytes(ct);
        const privPtr = marshaller.allocBytes(priv);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        priv.fill(0);
        const outPtr = marshaller.alloc(U64_BYTES);
        if (mod._mpt_decrypt_amount(ctPtr, privPtr, outPtr, DECRYPT_RANGE_LOW, rangeHigh) !== 0) {
            throw new Error('mpt_decrypt_amount failed');
        }
        return marshaller.readU64(outPtr);
    });
}
/**
 * Compute a Pedersen commitment `amount*G + blindingFactor*H`.
 *
 * @param amount - The integer amount to commit to.
 * @param blindingFactor - The 32-byte hex blinding scalar (rho).
 * @returns The 33-byte hex commitment point.
 * @throws If inputs are malformed or the WASM call fails.
 */
async function getPedersenCommitment(amount, blindingFactor) {
    (0, internal_1.assertUint64)(amount, 'amount');
    const blinding = (0, hex_1.hexToBytes)(blindingFactor, 'blindingFactor', constants_1.BLINDING_FACTOR_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const blindingPtr = marshaller.allocBytes(blinding);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        blinding.fill(0);
        const outPtr = marshaller.alloc(constants_1.PEDERSEN_COMMIT_SIZE);
        if (mod._mpt_get_pedersen_commitment(amount, blindingPtr, outPtr) !== 0) {
            throw new Error('mpt_get_pedersen_commitment failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.PEDERSEN_COMMIT_SIZE));
    });
}
//# sourceMappingURL=primitives.js.map