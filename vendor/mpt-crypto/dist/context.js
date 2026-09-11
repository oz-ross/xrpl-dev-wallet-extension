"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getConvertContextHash = getConvertContextHash;
exports.getConvertBackContextHash = getConvertBackContextHash;
exports.getSendContextHash = getSendContextHash;
exports.getClawbackContextHash = getClawbackContextHash;
/* eslint-disable max-params, max-lines-per-function -- context-hash builders mirror the C ABI argument lists */
const constants_1 = require("./constants");
const hex_1 = require("./hex");
const internal_1 = require("./internal");
const runtime_1 = require("./runtime");
/**
 * Context hash bound to a ConfidentialMPTConvert transaction.
 *
 * @param account - The 20-byte hex AccountID of the converting holder.
 * @param issuance - The 24-byte hex MPTokenIssuanceID.
 * @param sequence - The transaction sequence number.
 * @returns The 32-byte hex context hash.
 * @throws If inputs are malformed or the WASM call fails.
 */
async function getConvertContextHash(account, issuance, sequence) {
    (0, internal_1.assertUint32)(sequence, 'sequence');
    const acc = (0, hex_1.hexToBytes)(account, 'account', constants_1.ACCOUNT_ID_SIZE);
    const iss = (0, hex_1.hexToBytes)(issuance, 'issuance', constants_1.ISSUANCE_ID_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const accPtr = marshaller.allocBytes(acc);
        const issPtr = marshaller.allocBytes(iss);
        const outPtr = marshaller.alloc(constants_1.CONTEXT_HASH_SIZE);
        if (mod._mpt_get_convert_context_hash(accPtr, issPtr, sequence, outPtr) !== 0) {
            throw new Error('mpt_get_convert_context_hash failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONTEXT_HASH_SIZE));
    });
}
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
async function getConvertBackContextHash(account, issuance, sequence, version) {
    (0, internal_1.assertUint32)(sequence, 'sequence');
    (0, internal_1.assertUint32)(version, 'version');
    const acc = (0, hex_1.hexToBytes)(account, 'account', constants_1.ACCOUNT_ID_SIZE);
    const iss = (0, hex_1.hexToBytes)(issuance, 'issuance', constants_1.ISSUANCE_ID_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const accPtr = marshaller.allocBytes(acc);
        const issPtr = marshaller.allocBytes(iss);
        const outPtr = marshaller.alloc(constants_1.CONTEXT_HASH_SIZE);
        if (mod._mpt_get_convert_back_context_hash(accPtr, issPtr, sequence, version, outPtr) !== 0) {
            throw new Error('mpt_get_convert_back_context_hash failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONTEXT_HASH_SIZE));
    });
}
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
async function getSendContextHash(account, issuance, sequence, destination, version) {
    (0, internal_1.assertUint32)(sequence, 'sequence');
    (0, internal_1.assertUint32)(version, 'version');
    const acc = (0, hex_1.hexToBytes)(account, 'account', constants_1.ACCOUNT_ID_SIZE);
    const iss = (0, hex_1.hexToBytes)(issuance, 'issuance', constants_1.ISSUANCE_ID_SIZE);
    const dest = (0, hex_1.hexToBytes)(destination, 'destination', constants_1.ACCOUNT_ID_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const accPtr = marshaller.allocBytes(acc);
        const issPtr = marshaller.allocBytes(iss);
        const destPtr = marshaller.allocBytes(dest);
        const outPtr = marshaller.alloc(constants_1.CONTEXT_HASH_SIZE);
        if (mod._mpt_get_send_context_hash(accPtr, issPtr, sequence, destPtr, version, outPtr) !== 0) {
            throw new Error('mpt_get_send_context_hash failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONTEXT_HASH_SIZE));
    });
}
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
async function getClawbackContextHash(account, issuance, sequence, holder) {
    (0, internal_1.assertUint32)(sequence, 'sequence');
    const acc = (0, hex_1.hexToBytes)(account, 'account', constants_1.ACCOUNT_ID_SIZE);
    const iss = (0, hex_1.hexToBytes)(issuance, 'issuance', constants_1.ISSUANCE_ID_SIZE);
    const hold = (0, hex_1.hexToBytes)(holder, 'holder', constants_1.ACCOUNT_ID_SIZE);
    return (0, runtime_1.withModule)((mod, marshaller) => {
        const accPtr = marshaller.allocBytes(acc);
        const issPtr = marshaller.allocBytes(iss);
        const holdPtr = marshaller.allocBytes(hold);
        const outPtr = marshaller.alloc(constants_1.CONTEXT_HASH_SIZE);
        if (mod._mpt_get_clawback_context_hash(accPtr, issPtr, sequence, holdPtr, outPtr) !== 0) {
            throw new Error('mpt_get_clawback_context_hash failed');
        }
        return (0, hex_1.bytesToHex)(marshaller.readBytes(outPtr, constants_1.CONTEXT_HASH_SIZE));
    });
}
//# sourceMappingURL=context.js.map