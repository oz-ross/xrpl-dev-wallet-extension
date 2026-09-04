/* eslint-disable @typescript-eslint/member-ordering, @typescript-eslint/naming-convention -- internal WASM helper */
import { PARTICIPANT_CIPHERTEXT_OFFSET, PARTICIPANT_PUBKEY_OFFSET, PARTICIPANT_STRUCT_SIZE, PEDERSEN_PARAMS_AMOUNT_OFFSET, PEDERSEN_PARAMS_BLINDING_OFFSET, PEDERSEN_PARAMS_CIPHERTEXT_OFFSET, PEDERSEN_PARAMS_COMMITMENT_OFFSET, PEDERSEN_PARAMS_STRUCT_SIZE, } from './constants.js';
/**
 * Scratch-memory helper bound to a single {@link WasmModule} instance. Tracks
 * every allocation so a call site can release all of them at once via
 * {@link Marshaller.dispose}. A fresh {@link DataView}/`HEAPU8` is taken on each
 * access because the module is built with `ALLOW_MEMORY_GROWTH=1`, which can
 * replace the underlying `ArrayBuffer` after any `_malloc`.
 */
export class Marshaller {
    constructor(mod) {
        // Track size alongside each pointer so dispose() can zero key material.
        this.ptrs = [];
        this.mod = mod;
    }
    /** Allocate `size` bytes of zero-initialized scratch memory. */
    alloc(size) {
        const ptr = this.mod._malloc(size);
        // `_malloc` returns 0 on failure; writing at address 0 would corrupt the
        // WASM heap, so fail loudly instead.
        if (ptr === 0) {
            throw new Error(`mpt-crypto: failed to allocate ${size} bytes`);
        }
        this.mod.HEAPU8.fill(0, ptr, ptr + size);
        this.ptrs.push({ ptr, size });
        return ptr;
    }
    /** Allocate and copy `data` into WASM memory; returns the pointer. */
    allocBytes(data) {
        const ptr = this.mod._malloc(data.length);
        if (ptr === 0) {
            throw new Error(`mpt-crypto: failed to allocate ${data.length} bytes`);
        }
        this.mod.HEAPU8.set(data, ptr);
        this.ptrs.push({ ptr, size: data.length });
        return ptr;
    }
    /** Copy `len` bytes back out of WASM memory into a detached Uint8Array. */
    readBytes(ptr, len) {
        return this.mod.HEAPU8.slice(ptr, ptr + len);
    }
    view() {
        return new DataView(this.mod.HEAPU8.buffer);
    }
    /** Write a little-endian uint32 at `ptr`. */
    writeU32(ptr, value) {
        this.view().setUint32(ptr, value, true);
    }
    /** Read a little-endian uint32 at `ptr`. */
    readU32(ptr) {
        return this.view().getUint32(ptr, true);
    }
    /** Read a little-endian uint64 at `ptr`. */
    readU64(ptr) {
        return this.view().getBigUint64(ptr, true);
    }
    /** Allocate and populate an `mpt_pedersen_proof_params` struct. */
    allocPedersenParams(params) {
        const ptr = this.alloc(PEDERSEN_PARAMS_STRUCT_SIZE);
        this.mod.HEAPU8.set(params.commitment, ptr + PEDERSEN_PARAMS_COMMITMENT_OFFSET);
        this.view().setBigUint64(ptr + PEDERSEN_PARAMS_AMOUNT_OFFSET, params.amount, true);
        this.mod.HEAPU8.set(params.ciphertext, ptr + PEDERSEN_PARAMS_CIPHERTEXT_OFFSET);
        this.mod.HEAPU8.set(params.blindingFactor, ptr + PEDERSEN_PARAMS_BLINDING_OFFSET);
        return ptr;
    }
    /** Allocate and populate a contiguous array of participant structs. */
    allocParticipants(participants) {
        const ptr = this.alloc(PARTICIPANT_STRUCT_SIZE * participants.length);
        participants.forEach((participant, index) => {
            const base = ptr + index * PARTICIPANT_STRUCT_SIZE;
            this.mod.HEAPU8.set(participant.publicKey, base + PARTICIPANT_PUBKEY_OFFSET);
            this.mod.HEAPU8.set(participant.ciphertext, base + PARTICIPANT_CIPHERTEXT_OFFSET);
        });
        return ptr;
    }
    /** Free every allocation made through this marshaller. */
    dispose() {
        // Zero each region before freeing so private keys / blinding factors don't
        // linger in the freed WASM heap until a later allocation overwrites them.
        for (const { ptr, size } of this.ptrs) {
            this.mod.HEAPU8.fill(0, ptr, ptr + size);
            this.mod._free(ptr);
        }
        this.ptrs.length = 0;
    }
}
