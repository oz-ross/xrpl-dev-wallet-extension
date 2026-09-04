/**
 * Byte sizes mirroring `mpt-crypto/include/mpt_protocol.h`. These are the
 * authoritative wire/buffer sizes for the Confidential MPT (XLS-0096) crypto
 * primitives compiled into the vendored WASM module.
 */
/** secp256k1 compressed public / ElGamal key. */
export declare const PUBKEY_SIZE = 33;
/** secp256k1 private key. */
export declare const PRIVKEY_SIZE = 32;
/** ElGamal randomness / Pedersen blinding factor scalar. */
export declare const BLINDING_FACTOR_SIZE = 32;
/** A full ElGamal ciphertext (C1 || C2). */
export declare const ELGAMAL_TOTAL_SIZE = 66;
/** A Pedersen commitment point. */
export declare const PEDERSEN_COMMIT_SIZE = 33;
/** The 32-byte transaction context hash (challenge) consumed by the proofs. */
export declare const CONTEXT_HASH_SIZE = 32;
/** 20-byte XRPL AccountID. */
export declare const ACCOUNT_ID_SIZE = 20;
/** 24-byte MPTokenIssuanceID. */
export declare const ISSUANCE_ID_SIZE = 24;
/** ConfidentialMPTConvert ZKProof length. */
export declare const CONVERT_PROOF_SIZE = 64;
/** ConfidentialMPTClawback ZKProof length. */
export declare const CLAWBACK_PROOF_SIZE = 64;
/** ConfidentialMPTConvertBack ZKProof length (128 sigma + 688 bulletproof). */
export declare const CONVERT_BACK_PROOF_SIZE = 816;
/** ConfidentialMPTSend ZKProof length (192 sigma + 754 bulletproof). */
export declare const SEND_PROOF_SIZE = 946;
/**
 * In-memory layout of the C `mpt_confidential_participant` struct
 * (`{ uint8_t pubkey[33]; uint8_t ciphertext[66]; }`, alignment 1).
 */
export declare const PARTICIPANT_PUBKEY_OFFSET = 0;
export declare const PARTICIPANT_CIPHERTEXT_OFFSET = 33;
export declare const PARTICIPANT_STRUCT_SIZE: number;
/**
 * In-memory layout of the C `mpt_pedersen_proof_params` struct:
 * `{ uint8_t pedersen_commitment[33]; uint64_t amount; uint8_t ciphertext[66];
 *    uint8_t blinding_factor[32]; }`. The `uint64_t` forces 8-byte alignment,
 * so the commitment is padded from 33 to 40 and the struct size is rounded up
 * to a multiple of 8.
 */
export declare const PEDERSEN_PARAMS_COMMITMENT_OFFSET = 0;
export declare const PEDERSEN_PARAMS_AMOUNT_OFFSET = 40;
export declare const PEDERSEN_PARAMS_CIPHERTEXT_OFFSET = 48;
export declare const PEDERSEN_PARAMS_BLINDING_OFFSET = 114;
export declare const PEDERSEN_PARAMS_STRUCT_SIZE = 152;
