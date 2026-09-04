/**
 * Homomorphic addition of two same-key ElGamal ciphertexts.
 *
 * @param a - A 66-byte hex ciphertext (`C1 || C2`).
 * @param b - A 66-byte hex ciphertext under the same key.
 * @returns A 66-byte hex ciphertext encrypting `plaintext(a) + plaintext(b)`.
 * @throws If either input is malformed or a WASM call fails.
 */
export declare function addCiphertexts(a: string, b: string): Promise<string>;
/**
 * Homomorphic subtraction of two same-key ElGamal ciphertexts.
 *
 * @param a - A 66-byte hex ciphertext (`C1 || C2`).
 * @param b - A 66-byte hex ciphertext under the same key.
 * @returns A 66-byte hex ciphertext encrypting `plaintext(a) - plaintext(b)`.
 * @throws If either input is malformed or a WASM call fails.
 */
export declare function subtractCiphertexts(a: string, b: string): Promise<string>;
