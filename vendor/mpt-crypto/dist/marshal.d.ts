import { WasmModule } from './module';
/**
 * Byte-level view of a `mpt_confidential_participant` struct, as consumed by
 * {@link Marshaller.allocParticipants}. This is the internal counterpart of the
 * hex-based public `Participant` type.
 */
export interface RawParticipant {
    publicKey: Uint8Array;
    ciphertext: Uint8Array;
}
/**
 * Byte-level view of a `mpt_pedersen_proof_params` struct, as consumed by
 * {@link Marshaller.allocPedersenParams}. Internal counterpart of the hex-based
 * public `PedersenParams` type.
 */
export interface RawPedersenParams {
    commitment: Uint8Array;
    amount: bigint;
    ciphertext: Uint8Array;
    blindingFactor: Uint8Array;
}
/**
 * Scratch-memory helper bound to a single {@link WasmModule} instance. Tracks
 * every allocation so a call site can release all of them at once via
 * {@link Marshaller.dispose}. A fresh {@link DataView}/`HEAPU8` is taken on each
 * access because the module is built with `ALLOW_MEMORY_GROWTH=1`, which can
 * replace the underlying `ArrayBuffer` after any `_malloc`.
 */
export declare class Marshaller {
    private readonly mod;
    private readonly ptrs;
    constructor(mod: WasmModule);
    /** Allocate `size` bytes of zero-initialized scratch memory. */
    alloc(size: number): number;
    /** Allocate and copy `data` into WASM memory; returns the pointer. */
    allocBytes(data: Uint8Array): number;
    /** Copy `len` bytes back out of WASM memory into a detached Uint8Array. */
    readBytes(ptr: number, len: number): Uint8Array;
    private view;
    /** Write a little-endian uint32 at `ptr`. */
    writeU32(ptr: number, value: number): void;
    /** Read a little-endian uint32 at `ptr`. */
    readU32(ptr: number): number;
    /** Read a little-endian uint64 at `ptr`. */
    readU64(ptr: number): bigint;
    /** Allocate and populate an `mpt_pedersen_proof_params` struct. */
    allocPedersenParams(params: RawPedersenParams): number;
    /** Allocate and populate a contiguous array of participant structs. */
    allocParticipants(participants: RawParticipant[]): number;
    /** Free every allocation made through this marshaller. */
    dispose(): void;
}
