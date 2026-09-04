"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getConvertProof = getConvertProof;
exports.getClawbackProof = getClawbackProof;
exports.getConvertBackProof = getConvertBackProof;
exports.getConfidentialSendProof = getConfidentialSendProof;
/* eslint-disable max-params, max-lines-per-function -- proof builders mirror the C ABI */
const constants_1 = require("./constants");
const hex_1 = require("./hex");
const internal_1 = require("./internal");
const runtime_1 = require("./runtime");
const SIZE_T_BYTES = 4;
/**
 * Generate the 64-byte Schnorr proof for a ConfidentialMPTConvert transaction.
 *
 * @param publicKey - The 33-byte hex public key.
 * @param privateKey - The 32-byte hex private key.
 * @param contextHash - The 32-byte hex transaction context hash.
 * @returns The 64-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
async function getConvertProof(publicKey, privateKey, contextHash) {
    const pub = (0, hex_1.hexToBytes)(publicKey, 'publicKey', constants_1.PUBKEY_SIZE);
    const priv = (0, hex_1.hexToBytes)(privateKey, 'privateKey', constants_1.PRIVKEY_SIZE);
    const ctx = (0, hex_1.hexToBytes)(contextHash, 'contextHash', constants_1.CONTEXT_HASH_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const pubPtr = marshaller.allocBytes(pub);
        const privPtr = marshaller.allocBytes(priv);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        priv.fill(0);
        const ctxPtr = marshaller.allocBytes(ctx);
        const outPtr = marshaller.alloc(constants_1.CONVERT_PROOF_SIZE);
        if (mod._mpt_get_convert_proof(pubPtr, privPtr, ctxPtr, outPtr) !== 0) {
            throw new Error('mpt_get_convert_proof failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONVERT_PROOF_SIZE));
    });
}
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
async function getClawbackProof(privateKey, publicKey, contextHash, amount, ciphertext) {
    (0, internal_1.assertUint64)(amount, 'amount');
    const priv = (0, hex_1.hexToBytes)(privateKey, 'privateKey', constants_1.PRIVKEY_SIZE);
    const pub = (0, hex_1.hexToBytes)(publicKey, 'publicKey', constants_1.PUBKEY_SIZE);
    const ctx = (0, hex_1.hexToBytes)(contextHash, 'contextHash', constants_1.CONTEXT_HASH_SIZE);
    const ct = (0, hex_1.hexToBytes)(ciphertext, 'ciphertext', constants_1.ELGAMAL_TOTAL_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const privPtr = marshaller.allocBytes(priv);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        priv.fill(0);
        const pubPtr = marshaller.allocBytes(pub);
        const ctxPtr = marshaller.allocBytes(ctx);
        const ctPtr = marshaller.allocBytes(ct);
        const outPtr = marshaller.alloc(constants_1.CLAWBACK_PROOF_SIZE);
        if (mod._mpt_get_clawback_proof(privPtr, pubPtr, ctxPtr, amount, ctPtr, outPtr) !== 0) {
            throw new Error('mpt_get_clawback_proof failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CLAWBACK_PROOF_SIZE));
    });
}
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
async function getConvertBackProof(privateKey, publicKey, contextHash, amount, params) {
    (0, internal_1.assertUint64)(amount, 'amount');
    const priv = (0, hex_1.hexToBytes)(privateKey, 'privateKey', constants_1.PRIVKEY_SIZE);
    const pub = (0, hex_1.hexToBytes)(publicKey, 'publicKey', constants_1.PUBKEY_SIZE);
    const ctx = (0, hex_1.hexToBytes)(contextHash, 'contextHash', constants_1.CONTEXT_HASH_SIZE);
    const rawParams = (0, internal_1.rawPedersenParams)(params, 'params');
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const privPtr = marshaller.allocBytes(priv);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        priv.fill(0);
        const pubPtr = marshaller.allocBytes(pub);
        const ctxPtr = marshaller.allocBytes(ctx);
        const paramsPtr = marshaller.allocPedersenParams(rawParams);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        rawParams.blindingFactor.fill(0);
        const outPtr = marshaller.alloc(constants_1.CONVERT_BACK_PROOF_SIZE);
        if (mod._mpt_get_convert_back_proof(privPtr, pubPtr, ctxPtr, amount, paramsPtr, outPtr) !== 0) {
            throw new Error('mpt_get_convert_back_proof failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONVERT_BACK_PROOF_SIZE));
    });
}
/**
 * Generate the 946-byte proof for a ConfidentialMPTSend transaction.
 *
 * @param params - The send-proof inputs (sender keys, participants, witnesses).
 * @returns The 946-byte hex proof.
 * @throws If inputs are malformed or the WASM call fails.
 */
async function getConfidentialSendProof(params) {
    (0, internal_1.assertUint64)(params.amount, 'amount');
    if (params.participants.length === 0) {
        throw new Error('getConfidentialSendProof: participants must not be empty');
    }
    const priv = (0, hex_1.hexToBytes)(params.privateKey, 'privateKey', constants_1.PRIVKEY_SIZE);
    const pub = (0, hex_1.hexToBytes)(params.publicKey, 'publicKey', constants_1.PUBKEY_SIZE);
    const txBlinding = (0, hex_1.hexToBytes)(params.txBlindingFactor, 'txBlindingFactor', constants_1.BLINDING_FACTOR_SIZE);
    const ctx = (0, hex_1.hexToBytes)(params.contextHash, 'contextHash', constants_1.CONTEXT_HASH_SIZE);
    const amountCommitment = (0, hex_1.hexToBytes)(params.amountCommitment, 'amountCommitment', constants_1.PEDERSEN_COMMIT_SIZE);
    const participants = params.participants.map((participant, index) => (0, internal_1.rawParticipant)(participant, `participants[${index}]`));
    const balanceParams = (0, internal_1.rawPedersenParams)(params.balanceParams, 'balanceParams');
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const privPtr = marshaller.allocBytes(priv);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        priv.fill(0);
        const pubPtr = marshaller.allocBytes(pub);
        const participantsPtr = marshaller.allocParticipants(participants);
        const txBlindingPtr = marshaller.allocBytes(txBlinding);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        txBlinding.fill(0);
        const ctxPtr = marshaller.allocBytes(ctx);
        const amountCommitmentPtr = marshaller.allocBytes(amountCommitment);
        const balancePtr = marshaller.allocPedersenParams(balanceParams);
        // Wipe the transient JS copy; WASM scratch is zeroed on dispose().
        balanceParams.blindingFactor.fill(0);
        const outPtr = marshaller.alloc(constants_1.SEND_PROOF_SIZE);
        const outLenPtr = marshaller.alloc(SIZE_T_BYTES);
        marshaller.writeU32(outLenPtr, constants_1.SEND_PROOF_SIZE);
        if (mod._mpt_get_confidential_send_proof(privPtr, pubPtr, params.amount, participantsPtr, participants.length, txBlindingPtr, ctxPtr, amountCommitmentPtr, balancePtr, outPtr, outLenPtr) !== 0) {
            throw new Error('mpt_get_confidential_send_proof failed');
        }
        const outLen = marshaller.readU32(outLenPtr);
        if (outLen > constants_1.SEND_PROOF_SIZE) {
            throw new Error('mpt_get_confidential_send_proof wrote more than the allocated buffer');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, outLen));
    });
}
//# sourceMappingURL=proofs.js.map