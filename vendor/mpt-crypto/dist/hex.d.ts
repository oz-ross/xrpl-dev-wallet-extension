/**
 * Minimal hex <-> byte helpers for the hex-in/hex-out public API. Hex strings
 * are case-insensitive and must contain an even number of `[0-9a-fA-F]`
 * characters with no `0x` prefix, matching the convention used throughout
 * `xrpl.js` for serialized blobs.
 */
/**
 * Decode a hex string into a Uint8Array.
 *
 * @param hex - The hex string to decode.
 * @param label - A human-readable name used in error messages.
 * @param expectedBytes - Optional exact byte length the result must have.
 * @returns The decoded bytes.
 * @throws If `hex` is malformed or has the wrong length.
 */
export declare function hexToBytes(hex: string, label: string, expectedBytes?: number): Uint8Array;
/**
 * Encode a Uint8Array as an uppercase hex string.
 *
 * @param bytes - The bytes to encode.
 * @returns The uppercase hex representation.
 */
export declare function bytesToHex(bytes: Uint8Array): string;
