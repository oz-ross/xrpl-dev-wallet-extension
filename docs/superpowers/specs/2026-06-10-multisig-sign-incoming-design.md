# Multisig — Transactions for Signature — Design Spec

**Date:** 2026-06-10
**Branch:** feat/multisign-workflow
**Status:** Approved

---

## Overview

Add a "Transactions for Signature" section to the Multisig screen for the receiving signer side. The current account's MULTISIG-type credentials are loaded; each represents a pending transaction dispatched by a messenger account. The signer can inspect the transaction, verify the sender's identity via `MessageKey`, and submit a partial signature embedded in a `CredentialAccept` transaction.

---

## Section 1: TRANSACTIONS FOR SIGNATURE List

### Data loading

Added to `loadMultisignData()`. New state variable:

```js
let msIncomingList = [];  // [{ credential, txType, txHash, mptNode }]
```

Reset to `[]` and hide card at the start of `loadMultisignData()`. After the existing fetches, fetch `account_objects` for `state.activeAccount` (no type filter), then:

1. Filter for `LedgerEntryType === 'Credential'` where `hexToUtf8(o.CredentialType ?? '') === 'MULTISIG'`
2. For each matching credential, fetch the MPT via:
   ```js
   ledger_entry { mpt_issuance: credential.URI, ledger_index: 'validated' }
   ```
   Parse metadata raw: `JSON.parse(Buffer.from(node.MPTokenMetadata, 'hex').toString('utf8'))`
3. Extract `meta.ai.transaction_type` → `txType`, `meta.ai.hash` → `txHash`
4. Store `{ credential, txType, txHash, mptNode: node }` in `msIncomingList`

Failures on individual MPT fetches are swallowed — that item is simply omitted. The whole section silently stays hidden if `msIncomingList` is empty.

### Card: `ms-incoming-card`

HTML: `iou-balance-card hidden` containing header "Transactions for Signature" and list container `ms-incoming-list`. Positioned after `ms-sent-card` in `view-multisign`.

Each row:
```
Payment: A3F8B2C1…       ○ Waiting
SignerListSet: 9D4E71F0…  ✓ Signed
```

- `txType` + `:` + `txHash.slice(0, 8)` + `…`
- Status: `!!(credential.Flags & LSF_ACCEPTED)` → `✓ Signed` (green) or `○ Waiting` (muted)
- Clicking a row calls `openMsSignDetail(idx)`

---

## Section 2: Detail View — `view-ms-sign-detail`

### Entry: `openMsSignDetail(idx)`

Navigate to `view-ms-sign-detail` immediately, then async:

1. `ledger_entry { mpt_issuance: credential.URI }` → `node.PreviousTxnID`
2. `{ command: 'tx', transaction: PreviousTxnID }` → `result.tx_json.Memos[0].Memo.MemoData`
3. `decode(memoData)` from ripple-binary-codec → `decodedTxJson`
4. `account_info` for `decodedTxJson.Account` → `account_data.MessageKey`
5. `deriveAddress(MessageKey)` (imported from `ripple-keypairs`) → compare to `credential.Issuer`

State variable: `msMsSignDetail = null;` holds `{ credential, decodedTxJson, verified, alreadySigned }` while view is open.

### View layout

```
┌─ Transaction Details ────────────────────────────────┐
│  From:  rTxAccount… (resolveAddrDisplay)             │
│  Via:   rIssuer…    (resolveAddrDisplay)             │
│                                                      │
│  ● Sender Verified          (green, if match)        │
│  ● Sender Failed Verification  (red, if mismatch)   │
│                                                      │
│  [buildTxRows output]                                │
│  <details> Raw JSON (collapsed)                      │
│                                                      │
│  [Close]   [Sign Transaction]                        │
└──────────────────────────────────────────────────────┘
```

- `verified` = `deriveAddress(MessageKey) === credential.Issuer`
- Sign button disabled if `!verified` OR `alreadySigned` (`!!(credential.Flags & LSF_ACCEPTED)`)
- Error shown in `ms-sign-detail-error` alert if any async step fails

---

## Section 3: Sign Flow

### `signMsTransaction()`

Triggered by "Sign Transaction" button.

**Step 1 — Create partial multisig signature:**

The decoded tx already has `SigningPubKey: ''` (set during dispatch). New helper `getSignatureForAddress(txJson, address)` → `{ pubKey, sig }`:

```js
async function getSignatureForAddress(txJson, address) {
  const wallet = getWalletForAddress(address);
  if (wallet) {
    const sig = keypairsSign(encodeForSigning(txJson), wallet.privateKey).toUpperCase();
    return { pubKey: wallet.publicKey, sig };
  }
  const ledgerKr = state.keyrings.find(k => k.type === 'ledger' && k.address === address);
  if (ledgerKr) {
    // Ledger XRP app signs the pre-encoded tx bytes
    const txBlob = encode(txJson);
    let transport;
    try {
      transport = await TransportWebHID.create();
      const xrpApp = new Xrp(transport);
      const sig = await xrpApp.signTransaction(ledgerKr.derivationPath, txBlob);
      return { pubKey: ledgerKr.publicKey, sig: sig.toUpperCase() };
    } finally {
      if (transport) await transport.close().catch(() => {});
    }
  }
  throw new Error(`No signing key available for ${truncAddr(address)}.`);
}
```

If `isActiveAccountReadOnly()` (watch-only), the sign button is disabled before this is reached.

**Step 2 — Build and submit CredentialAccept with signature memos:**

```js
{
  TransactionType: 'CredentialAccept',
  Account: state.activeAccount,
  Issuer: credential.Issuer,
  CredentialType: '4D554C5449534947',
  Memos: [
    { Memo: {
        MemoType: Buffer.from('SigningPubKey').toString('hex').toUpperCase(),
        MemoData: pubKey
    }},
    { Memo: {
        MemoType: Buffer.from('TxnSignature').toString('hex').toUpperCase(),
        MemoData: sig
    }}
  ]
}
```

Routed through `reviewMultisignTx(txJson, 'Signature submitted.')` — the existing review/sign/submit flow. `backView: 'multisign'` causes reload after confirmation.

---

## New Imports

Add `deriveAddress` to the `ripple-keypairs` import (line 10):
```js
import { sign as keypairsSign, deriveAddress } from 'ripple-keypairs';
```

---

## State Variables

```js
let msIncomingList  = [];     // [{ credential, txType, txHash, mptNode }] for current account
let msMsSignDetail  = null;   // { credential, decodedTxJson, verified, alreadySigned }
```

---

## Files Changed

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-incoming-card` to `view-multisign`; add `view-ms-sign-detail` |
| `src/popup/popup.css` | Incoming list row styles, status indicator styles, verification badge styles |
| `src/popup/popup.js` | `deriveAddress` import; 2 state vars; load incoming in `loadMultisignData`; render section in `renderMultisignScreen`; `openMsSignDetail`; `getSignatureForAddress` helper; `signMsTransaction`; event listeners |

---

## Error Cases

| Case | Handling |
|------|----------|
| No MULTISIG credentials | `ms-incoming-card` stays hidden |
| MPT fetch fails for a credential | That item is omitted from the list |
| Tx memo fetch fails on detail open | Show error in `ms-sign-detail-error`, keep close button active |
| MessageKey absent on tx account | Treat as verification failure (red indicator, sign disabled) |
| `deriveAddress` throws | Treat as verification failure |
| Active account is watch-only | Sign button disabled (detected via `isActiveAccountReadOnly()`) |
| Credential already accepted | `alreadySigned = true`, sign button disabled |
