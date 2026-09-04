"use strict";
/**
 * `@xrplf/mpt-crypto` — Confidential MPT (XLS-0096) cryptographic primitives for
 * the XRP Ledger, exposed as a hex-in/hex-out API over a vendored WebAssembly
 * build of the reference C library.
 *
 * Every byte argument and return value is an uppercase, even-length hex string
 * (no `0x` prefix); integer amounts are `bigint`. The WASM module is loaded
 * lazily and cached on first use, so it only pays its load cost when a
 * confidential operation is actually invoked.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.getConfidentialSendProof = exports.getConvertBackProof = exports.getClawbackProof = exports.getConvertProof = exports.getClawbackContextHash = exports.getSendContextHash = exports.getConvertBackContextHash = exports.getConvertContextHash = exports.subtractCiphertexts = exports.addCiphertexts = exports.getPedersenCommitment = exports.decryptAmount = exports.encryptAmount = exports.generateBlindingFactor = exports.loadWasmModule = exports.hexToBytes = exports.bytesToHex = exports.SEND_PROOF_SIZE = exports.CONVERT_BACK_PROOF_SIZE = exports.CLAWBACK_PROOF_SIZE = exports.CONVERT_PROOF_SIZE = exports.ISSUANCE_ID_SIZE = exports.ACCOUNT_ID_SIZE = exports.CONTEXT_HASH_SIZE = exports.PEDERSEN_COMMIT_SIZE = exports.ELGAMAL_TOTAL_SIZE = exports.BLINDING_FACTOR_SIZE = exports.PRIVKEY_SIZE = exports.PUBKEY_SIZE = void 0;
var constants_1 = require("./constants");
Object.defineProperty(exports, "PUBKEY_SIZE", { enumerable: true, get: function () { return constants_1.PUBKEY_SIZE; } });
Object.defineProperty(exports, "PRIVKEY_SIZE", { enumerable: true, get: function () { return constants_1.PRIVKEY_SIZE; } });
Object.defineProperty(exports, "BLINDING_FACTOR_SIZE", { enumerable: true, get: function () { return constants_1.BLINDING_FACTOR_SIZE; } });
Object.defineProperty(exports, "ELGAMAL_TOTAL_SIZE", { enumerable: true, get: function () { return constants_1.ELGAMAL_TOTAL_SIZE; } });
Object.defineProperty(exports, "PEDERSEN_COMMIT_SIZE", { enumerable: true, get: function () { return constants_1.PEDERSEN_COMMIT_SIZE; } });
Object.defineProperty(exports, "CONTEXT_HASH_SIZE", { enumerable: true, get: function () { return constants_1.CONTEXT_HASH_SIZE; } });
Object.defineProperty(exports, "ACCOUNT_ID_SIZE", { enumerable: true, get: function () { return constants_1.ACCOUNT_ID_SIZE; } });
Object.defineProperty(exports, "ISSUANCE_ID_SIZE", { enumerable: true, get: function () { return constants_1.ISSUANCE_ID_SIZE; } });
Object.defineProperty(exports, "CONVERT_PROOF_SIZE", { enumerable: true, get: function () { return constants_1.CONVERT_PROOF_SIZE; } });
Object.defineProperty(exports, "CLAWBACK_PROOF_SIZE", { enumerable: true, get: function () { return constants_1.CLAWBACK_PROOF_SIZE; } });
Object.defineProperty(exports, "CONVERT_BACK_PROOF_SIZE", { enumerable: true, get: function () { return constants_1.CONVERT_BACK_PROOF_SIZE; } });
Object.defineProperty(exports, "SEND_PROOF_SIZE", { enumerable: true, get: function () { return constants_1.SEND_PROOF_SIZE; } });
var hex_1 = require("./hex");
Object.defineProperty(exports, "bytesToHex", { enumerable: true, get: function () { return hex_1.bytesToHex; } });
Object.defineProperty(exports, "hexToBytes", { enumerable: true, get: function () { return hex_1.hexToBytes; } });
var module_1 = require("./module");
Object.defineProperty(exports, "loadWasmModule", { enumerable: true, get: function () { return module_1.loadWasmModule; } });
var primitives_1 = require("./primitives");
Object.defineProperty(exports, "generateBlindingFactor", { enumerable: true, get: function () { return primitives_1.generateBlindingFactor; } });
Object.defineProperty(exports, "encryptAmount", { enumerable: true, get: function () { return primitives_1.encryptAmount; } });
Object.defineProperty(exports, "decryptAmount", { enumerable: true, get: function () { return primitives_1.decryptAmount; } });
Object.defineProperty(exports, "getPedersenCommitment", { enumerable: true, get: function () { return primitives_1.getPedersenCommitment; } });
var homomorphic_1 = require("./homomorphic");
Object.defineProperty(exports, "addCiphertexts", { enumerable: true, get: function () { return homomorphic_1.addCiphertexts; } });
Object.defineProperty(exports, "subtractCiphertexts", { enumerable: true, get: function () { return homomorphic_1.subtractCiphertexts; } });
var context_1 = require("./context");
Object.defineProperty(exports, "getConvertContextHash", { enumerable: true, get: function () { return context_1.getConvertContextHash; } });
Object.defineProperty(exports, "getConvertBackContextHash", { enumerable: true, get: function () { return context_1.getConvertBackContextHash; } });
Object.defineProperty(exports, "getSendContextHash", { enumerable: true, get: function () { return context_1.getSendContextHash; } });
Object.defineProperty(exports, "getClawbackContextHash", { enumerable: true, get: function () { return context_1.getClawbackContextHash; } });
var proofs_1 = require("./proofs");
Object.defineProperty(exports, "getConvertProof", { enumerable: true, get: function () { return proofs_1.getConvertProof; } });
Object.defineProperty(exports, "getClawbackProof", { enumerable: true, get: function () { return proofs_1.getClawbackProof; } });
Object.defineProperty(exports, "getConvertBackProof", { enumerable: true, get: function () { return proofs_1.getConvertBackProof; } });
Object.defineProperty(exports, "getConfidentialSendProof", { enumerable: true, get: function () { return proofs_1.getConfidentialSendProof; } });
//# sourceMappingURL=index.js.map