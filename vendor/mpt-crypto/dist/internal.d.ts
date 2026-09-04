import { RawParticipant, RawPedersenParams } from './marshal';
import { Participant, PedersenParams } from './types';
/** Largest unsigned 64-bit integer — the width of the C `uint64_t` amounts. */
export declare const U64_MAX: bigint;
/**
 * Assert that a bigint fits an unsigned 64-bit WASM parameter.
 *
 * Amounts and ranges are passed straight to WASM `i64` parameters, and the
 * JS→WASM BigInt marshalling wraps modulo 2^64 *without throwing* — so e.g.
 * `2n ** 64n` would be silently encoded as `0`. This guards that at the public
 * API boundary instead.
 *
 * @param value - The value to check.
 * @param label - A human-readable name used in error messages.
 * @param max - Inclusive upper bound (defaults to {@link U64_MAX}).
 * @throws If `value` is negative or greater than `max`.
 */
export declare function assertUint64(value: bigint, label: string, max?: bigint): void;
/** Largest unsigned 32-bit integer — the width of the C `uint32_t` sequence/version. */
export declare const U32_MAX = 4294967295;
/**
 * Assert that a number fits an unsigned 32-bit WASM parameter.
 *
 * Sequence and version are passed straight to WASM `i32` parameters, where a
 * negative, fractional, or out-of-range value would be silently truncated or
 * wrapped rather than rejected. This guards that at the public API boundary.
 *
 * @param value - The value to check.
 * @param label - A human-readable name used in error messages.
 * @throws If `value` is not an integer in [0, 2^32 - 1].
 */
export declare function assertUint32(value: number, label: string): void;
/**
 * Decode a hex-encoded {@link Participant} into its byte-struct form.
 *
 * @param participant - The hex participant to decode.
 * @param label - A human-readable name used in error messages.
 * @returns The decoded {@link RawParticipant}.
 * @throws If either field is malformed or the wrong length.
 */
export declare function rawParticipant(participant: Participant, label: string): RawParticipant;
/**
 * Decode a hex-encoded {@link PedersenParams} into its byte-struct form.
 *
 * @param params - The hex Pedersen witness to decode.
 * @param label - A human-readable name used in error messages.
 * @returns The decoded {@link RawPedersenParams}.
 * @throws If any field is malformed or the wrong length.
 */
export declare function rawPedersenParams(params: PedersenParams, label: string): RawPedersenParams;
