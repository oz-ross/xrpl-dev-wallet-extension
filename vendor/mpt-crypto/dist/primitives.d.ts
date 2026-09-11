/**
 * Generate a 32-byte blinding factor / ElGamal randomness scalar.
 *
 * @returns The hex-encoded blinding factor.
 * @throws If the underlying WASM call fails.
 */
export declare function generateBlindingFactor(): Promise<string>;
/**
 * ElGamal-encrypt an amount under a public key.
 *
 * @param amount - The integer amount to encrypt.
 * @param publicKey - The 33-byte hex public key.
 * @param blindingFactor - The 32-byte hex randomness scalar.
 * @returns The 66-byte hex ciphertext (C1 || C2).
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function encryptAmount(amount: bigint, publicKey: string, blindingFactor: string): Promise<string>;
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
export declare function decryptAmount(ciphertext: string, privateKey: string, rangeHigh: bigint): Promise<bigint>;
/**
 * Compute a Pedersen commitment `amount*G + blindingFactor*H`.
 *
 * @param amount - The integer amount to commit to.
 * @param blindingFactor - The 32-byte hex blinding scalar (rho).
 * @returns The 33-byte hex commitment point.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getPedersenCommitment(amount: bigint, blindingFactor: string): Promise<string>;
