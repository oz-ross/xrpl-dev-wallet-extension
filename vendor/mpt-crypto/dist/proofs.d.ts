import { PedersenParams, SendProofParams } from './types';
/**
 * Generate the 64-byte Schnorr proof for a ConfidentialMPTConvert transaction.
 *
 * @param publicKey - The 33-byte hex public key.
 * @param privateKey - The 32-byte hex private key.
 * @param contextHash - The 32-byte hex transaction context hash.
 * @returns The 64-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getConvertProof(publicKey: string, privateKey: string, contextHash: string): Promise<string>;
/**
 * Generate the 64-byte sigma proof for a ConfidentialMPTClawback transaction.
 *
 * @param privateKey - The issuer's 32-byte hex private key.
 * @param publicKey - The issuer's 33-byte hex public key.
 * @param contextHash - The 32-byte hex transaction context hash.
 * @param amount - The publicly known amount being clawed back.
 * @param ciphertext - The holder's 66-byte hex balance ciphertext.
 * @returns The 64-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getClawbackProof(privateKey: string, publicKey: string, contextHash: string, amount: bigint, ciphertext: string): Promise<string>;
/**
 * Generate the 816-byte proof for a ConfidentialMPTConvertBack transaction.
 *
 * @param privateKey - The holder's 32-byte hex private key.
 * @param publicKey - The holder's 33-byte hex public key.
 * @param contextHash - The 32-byte hex transaction context hash.
 * @param amount - The publicly revealed conversion amount.
 * @param params - The holder's balance Pedersen witness.
 * @returns The 816-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getConvertBackProof(privateKey: string, publicKey: string, contextHash: string, amount: bigint, params: PedersenParams): Promise<string>;
/**
 * Generate the 946-byte proof for a ConfidentialMPTSend transaction.
 *
 * @param params - The send-proof inputs (sender keys, participants, witnesses).
 * @returns The 946-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getConfidentialSendProof(params: SendProofParams): Promise<string>;
