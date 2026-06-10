# Multisig — Collect Signatures & Submit — Design Spec

**Date:** 2026-06-10
**Branch:** feat/multisign-workflow
**Status:** Approved

---

## Overview

The "Transactions Gathering Signatures" dispatcher view gains quorum progress tracking and a Submit capability. Each list row shows `X/Y` (current weight / quorum), green when quorum is met. The detail view shows a quorum summary and a Submit button when quorum is reached. Submit collects the partial signatures from accepted credential memos, builds a correctly ordered `Signers` array, and submits the multisigned transaction; on success it runs the standard cleanup (CredentialDelete + MPTokenIssuanceDestroy).

---

## Section 1: Enriched msSentList

### Enrichment in `loadMultisignData()`

After `msSentList` is populated, enrich each entry by querying credential acceptance for every signer in parallel:

```js
// For each mpt object in msSentList:
const signerStatus = await Promise.all(
  (msSignerList?.SignerEntries ?? []).map(async e => {
    const addr   = e.SignerEntry.Account;
    const weight = e.SignerEntry.SignerWeight;
    try {
      const credResp = await state.client.request({
        command: 'ledger_entry',
        credential: {
          subject: addr,
          issuer: msMessengerAddress,
          credential_type: '4D554C5449534947',
        },
        ledger_index: 'validated',
      });
      const cred     = credResp.result.node ?? {};
      const accepted = !!(cred.Flags & LSF_ACCEPTED);
      return { address: addr, weight, accepted, prevTxnId: accepted ? cred.PreviousTxnID : null };
    } catch {
      return { address: addr, weight, accepted: false, prevTxnId: null };
    }
  })
);
const currentWeight = signerStatus.filter(s => s.accepted).reduce((sum, s) => sum + s.weight, 0);
const quorum        = msSignerList?.SignerQuorum ?? 0;
```

**Enriched entry shape:**
```js
{
  mptObj,           // raw MPTokenIssuance ledger object
  txType,           // 'Payment', 'SignerListSet', etc.
  txHash,           // first 8 chars of hash from metadata
  currentWeight,    // sum of accepted signer weights
  quorum,           // msSignerList.SignerQuorum
  signerStatus,     // [{ address, weight, accepted, prevTxnId }]
}
```

**Failure handling:** If `msSignerList` is null (no signer list set up), skip enrichment entirely — `msSentList` entries get `currentWeight: 0, quorum: 0, signerStatus: []` and no Submit button appears.

The enrichment is intentionally done **once** during load, not on each render, to avoid excessive RPC calls.

---

## Section 2: List Row — Quorum Badge

Each `ms-sent-item` row gains a right-side badge showing `X/Y`:
```
Payment: A3F8B2C1…    3/5
SignerListSet: 9D4E…  ✓ 5/5
```

- `X/Y` badge uses class `ms-sent-weight-badge`
- Green (`.met`) when `X >= Y`, muted (`.pending`) otherwise
- Replaces the existing `›` chevron (the badge doubles as the visual affordance for clickability)

---

## Section 3: Detail View — Quorum Summary + Submit

### State extension

`msTrxnDetail` is extended to `{ mptObj, decodedTxJson, entry }` where `entry` is the enriched `msSentList[idx]`.

### New quorum card in `view-ms-trxn-detail`

Below `ms-trxn-detail-rows`, add `ms-trxn-quorum-card` (tx-card):
```
┌─────────────────────────────────────┐
│  Quorum required   5                │
│  Current weight    3 / 5  (red)     │
│  or               5 / 5  (green)    │
└─────────────────────────────────────┘
```

Elements: `ms-trxn-quorum-required`, `ms-trxn-current-weight` (with colour class).

### Submit button

`ms-trxn-submit-btn` appears in the action row alongside Cancel. Enabled only when:
1. `currentWeight >= quorum`
2. `LastLedgerSequence` in `decodedTxJson` > current validated ledger sequence (checked via `server_info` on detail open)

If expired: show `ms-trxn-expired-warn` alert: "Transaction has expired and cannot be submitted."

---

## Section 4: Submit Flow — `submitMultisigTx()`

### Step 1: Collect signatures from accepted credential memos

For each `signerStatus` entry where `accepted === true` and `prevTxnId !== null`:
```js
const txResp   = await state.client.request({ command: 'tx', transaction: prevTxnId });
const memos    = txResp.result?.tx_json?.Memos ?? [];
const pubKey   = hexFromMemo(memos, 'SigningPubKey');  // hex value
const sig      = hexFromMemo(memos, 'TxnSignature');   // hex value
```

Helper `hexFromMemo(memos, memoTypeName)`:
```js
function hexFromMemo(memos, typeName) {
  const typeHex = Buffer.from(typeName).toString('hex').toUpperCase();
  const found   = memos.find(m => m.Memo?.MemoType?.toUpperCase() === typeHex);
  return found?.Memo?.MemoData ?? null;
}
```

### Step 2: Build sorted Signers array

```js
import { decodeAccountID } from 'xrpl';  // add to existing xrpl import

const signers = acceptedSigners
  .map(s => ({ Signer: { Account: s.address, SigningPubKey: s.pubKey, TxnSignature: s.sig } }))
  .sort((a, b) => Buffer.compare(
    Buffer.from(decodeAccountID(a.Signer.Account)),
    Buffer.from(decodeAccountID(b.Signer.Account))
  ));
```

### Step 3: Encode and submit

```js
const finalTx  = { ...decodedTxJson, Signers: signers };
const tx_blob  = encode(finalTx);
const response = await state.client.submitAndWait(tx_blob);
```

### Step 4: On `tesSUCCESS` — cleanup

Reuse the exact same cleanup sequence as `cancelMsTrxn`:
- `CredentialDelete` for each signer that has a credential on ledger (signed with `msMessengerAddress`)
- `MPTokenIssuanceDestroy` for the MPT issuance

Show inline progress rows (same pattern as cancel flow). On completion navigate to `openMultisignView()`.

### Step 5: On failure

Show error in `ms-trxn-detail-error`, re-enable Submit button for retry. User can attempt resubmission if the error is transient (e.g. network blip). Permanent failures (e.g. `tefPAST_SEQ` from expired `LastLedgerSequence`) are shown clearly.

---

## New Import

Add `decodeAccountID` to the existing xrpl import (line 2):
```js
import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeAccountID, decodeMPTokenMetadata, isValidClassicAddress } from 'xrpl';
```

---

## State Changes

`msTrxnDetail` extended from `{ mptObj, decodedTxJson }` to `{ mptObj, decodedTxJson, entry }`. No new top-level state variables needed.

---

## Files Changed

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-trxn-quorum-card` + `ms-trxn-submit-btn` + `ms-trxn-expired-warn` to `view-ms-trxn-detail` |
| `src/popup/popup.css` | `.ms-sent-weight-badge`, `.ms-trxn-quorum-row`, `.ms-trxn-weight-met`, `.ms-trxn-weight-pending` |
| `src/popup/popup.js` | `decodeAccountID` import; enrich `msSentList` in `loadMultisignData`; update list row render; extend `openMsTrxnDetail`; add `hexFromMemo`; add `submitMultisigTx`; add event listener |

---

## Error Cases

| Case | Handling |
|------|----------|
| `msSignerList` null on enrich | Skip enrichment; no Submit button shown |
| Signer credential fetch fails | That signer treated as not accepted (weight 0) |
| CredentialAccept tx has no matching memo | That signer omitted from Signers array; warning shown if this causes quorum to drop below threshold at submit time |
| `LastLedgerSequence` expired | `ms-trxn-expired-warn` shown; Submit disabled |
| Submit returns non-tesSUCCESS | Show TEC/TEF code in error, re-enable Submit |
| Cleanup fails after success | Show per-step errors inline; user can retry via Cancel button path |
