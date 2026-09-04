/**
 * Context hash bound to a ConfidentialMPTConvert transaction.
 *
 * @param account - The 20-byte hex AccountID of the converting holder.
 * @param issuance - The 24-byte hex MPTokenIssuanceID.
 * @param sequence - The transaction sequence number.
 * @returns The 32-byte hex context hash.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getConvertContextHash(account: string, issuance: string, sequence: number): Promise<string>;
/**
 * Context hash bound to a ConfidentialMPTConvertBack transaction.
 *
 * @param account - The 20-byte hex AccountID of the holder.
 * @param issuance - The 24-byte hex MPTokenIssuanceID.
 * @param sequence - The transaction sequence number.
 * @param version - The confidential balance version.
 * @returns The 32-byte hex context hash.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getConvertBackContextHash(account: string, issuance: string, sequence: number, version: number): Promise<string>;
/**
 * Context hash bound to a ConfidentialMPTSend transaction.
 *
 * @param account - The 20-byte hex AccountID of the sender.
 * @param issuance - The 24-byte hex MPTokenIssuanceID.
 * @param sequence - The transaction sequence number.
 * @param destination - The 20-byte hex AccountID of the destination.
 * @param version - The confidential balance version.
 * @returns The 32-byte hex context hash.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getSendContextHash(account: string, issuance: string, sequence: number, destination: string, version: number): Promise<string>;
/**
 * Context hash bound to a ConfidentialMPTClawback transaction.
 *
 * @param account - The 20-byte hex AccountID of the issuer.
 * @param issuance - The 24-byte hex MPTokenIssuanceID.
 * @param sequence - The transaction sequence number.
 * @param holder - The 20-byte hex AccountID of the holder being clawed back.
 * @returns The 32-byte hex context hash.
 * @throws If inputs are malformed or the WASM call fails.
 */
export declare function getClawbackContextHash(account: string, issuance: string, sequence: number, holder: string): Promise<string>;
