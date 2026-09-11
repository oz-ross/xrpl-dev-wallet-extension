"use strict";
/**
 * Byte sizes mirroring `mpt-crypto/include/mpt_protocol.h`. These are the
 * authoritative wire/buffer sizes for the Confidential MPT (XLS-0096) crypto
 * primitives compiled into the vendored WASM module.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.PEDERSEN_PARAMS_STRUCT_SIZE = exports.PEDERSEN_PARAMS_BLINDING_OFFSET = exports.PEDERSEN_PARAMS_CIPHERTEXT_OFFSET = exports.PEDERSEN_PARAMS_AMOUNT_OFFSET = exports.PEDERSEN_PARAMS_COMMITMENT_OFFSET = exports.PARTICIPANT_STRUCT_SIZE = exports.PARTICIPANT_CIPHERTEXT_OFFSET = exports.PARTICIPANT_PUBKEY_OFFSET = exports.SEND_PROOF_SIZE = exports.CONVERT_BACK_PROOF_SIZE = exports.CLAWBACK_PROOF_SIZE = exports.CONVERT_PROOF_SIZE = exports.ISSUANCE_ID_SIZE = exports.ACCOUNT_ID_SIZE = exports.CONTEXT_HASH_SIZE = exports.PEDERSEN_COMMIT_SIZE = exports.ELGAMAL_TOTAL_SIZE = exports.BLINDING_FACTOR_SIZE = exports.PRIVKEY_SIZE = exports.PUBKEY_SIZE = void 0;
/** secp256k1 compressed public / ElGamal key. */
exports.PUBKEY_SIZE = 33;
/** secp256k1 private key. */
exports.PRIVKEY_SIZE = 32;
/** ElGamal randomness / Pedersen blinding factor scalar. */
exports.BLINDING_FACTOR_SIZE = 32;
/** A full ElGamal ciphertext (C1 || C2). */
exports.ELGAMAL_TOTAL_SIZE = 66;
/** A Pedersen commitment point. */
exports.PEDERSEN_COMMIT_SIZE = 33;
/** The 32-byte transaction context hash (challenge) consumed by the proofs. */
exports.CONTEXT_HASH_SIZE = 32;
/** 20-byte XRPL AccountID. */
exports.ACCOUNT_ID_SIZE = 20;
/** 24-byte MPTokenIssuanceID. */
exports.ISSUANCE_ID_SIZE = 24;
/** ConfidentialMPTConvert ZKProof length. */
exports.CONVERT_PROOF_SIZE = 64;
/** ConfidentialMPTClawback ZKProof length. */
exports.CLAWBACK_PROOF_SIZE = 64;
/** ConfidentialMPTConvertBack ZKProof length (128 sigma + 688 bulletproof). */
exports.CONVERT_BACK_PROOF_SIZE = 816;
/** ConfidentialMPTSend ZKProof length (192 sigma + 754 bulletproof). */
exports.SEND_PROOF_SIZE = 946;
/**
 * In-memory layout of the C `mpt_confidential_participant` struct
 * (`{ uint8_t pubkey[33]; uint8_t ciphertext[66]; }`, alignment 1).
 */
exports.PARTICIPANT_PUBKEY_OFFSET = 0;
exports.PARTICIPANT_CIPHERTEXT_OFFSET = exports.PUBKEY_SIZE;
exports.PARTICIPANT_STRUCT_SIZE = exports.PUBKEY_SIZE + exports.ELGAMAL_TOTAL_SIZE;
/**
 * In-memory layout of the C `mpt_pedersen_proof_params` struct:
 * `{ uint8_t pedersen_commitment[33]; uint64_t amount; uint8_t ciphertext[66];
 *    uint8_t blinding_factor[32]; }`. The `uint64_t` forces 8-byte alignment,
 * so the commitment is padded from 33 to 40 and the struct size is rounded up
 * to a multiple of 8.
 */
exports.PEDERSEN_PARAMS_COMMITMENT_OFFSET = 0;
exports.PEDERSEN_PARAMS_AMOUNT_OFFSET = 40;
exports.PEDERSEN_PARAMS_CIPHERTEXT_OFFSET = 48;
exports.PEDERSEN_PARAMS_BLINDING_OFFSET = 114;
exports.PEDERSEN_PARAMS_STRUCT_SIZE = 152;
//# sourceMappingURL=constants.js.map