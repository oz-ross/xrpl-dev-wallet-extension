# Multisig TRXN SENT — Design Spec

**Date:** 2026-06-10
**Branch:** feat/multisign-workflow
**Status:** Approved

---

## Overview

Three connected changes:
1. Filter MULTISIG-type credentials out of the main Credentials section
2. Add a "TRXN SENT" card to the Multisig screen showing dispatched MPT issuances from the messenger account
3. A detail view for each sent transaction with a Cancel action that revokes the credentials and destroys the MPT

---

## Section 1: Credential Filter

**Location:** `renderCredentials()` in popup.js

Filter credentials before rendering:
```js
const visibleCreds = creds.filter(c => hexToUtf8(c.CredentialType ?? '') !== 'MULTISIG');
```

If `visibleCreds` is empty, hide the card as normal. MULTISIG credentials are silently excluded — no UI indicator. This is a pure display filter; the data is not changed.

---

## Section 2: TRXN SENT Card

### Data loading

**New state variable:**
```js
let msSentList = [];   // MPTokenIssuance objects with ac === 'multisig' from messenger account
```

Reset to `[]` in `loadMultisignData()` along with other card hides. After `msMessengerAddress` is loaded, if it is non-null, fetch all `account_objects` for the messenger address and filter:
```js
// type: 'mpt_issuance' is not a supported filter — fetch all objects and filter locally
const resp = await fetchAllAccountObjects(msMessengerAddress);
msSentList = resp.filter(o =>
  o.LedgerEntryType === 'MPTokenIssuance' &&
  decodeMPTokenMetadata(o.MPTokenMetadata ?? '')?.ac === 'multisig'
);
```

`fetchAllAccountObjects(address)` is an existing pagination helper in popup.js (lines 2182–2194).

**Error handling:** If the fetch fails, `msSentList = []` and the card stays hidden — silent failure, multisig screen still loads.

### Rendering

**HTML:** New `ms-sent-card` (iou-balance-card) after `ms-messenger-card`, hidden by default. Contains:
- Header: "Transactions Sent"
- `ms-sent-list` container: rendered row per MPT object
- Hidden if `msSentList.length === 0`

**Each row:**
```
Payment: A3F8B2C1…          >
```
- `ai.transaction_type` from decoded metadata
- `ai.hash` truncated to 8 chars + `…`
- Chevron indicator (right-aligned)
- Click → opens detail view

**Rendering in `renderMultisignScreen()`:** New section after the Messenger Account card block.

---

## Section 3: Detail View + Cancel Flow

### State

```js
let msTrxnDetail = null;  // { mptObj, decodedTxJson } for the currently open detail
```

### Entry (on row click)

1. Set `msTrxnDetail = null`, show loading state, navigate to `view-ms-trxn-detail`
2. Fetch: `{ command: 'tx', transaction: mptObj.PreviousTxnID }` → the `MPTokenIssuanceCreate` tx
3. Extract `Memos[0].Memo.MemoData` (hex) → `Buffer.from(hex, 'hex')` → tx blob
4. `decode(blob)` from `ripple-binary-codec` → `decodedTxJson`
5. Set `msTrxnDetail = { mptObj, decodedTxJson }`
6. Render: `buildTxRows(decodedTxJson)` + raw JSON `<details>` panel (collapsed)
7. Show Close + Cancel Transaction buttons

### `view-ms-trxn-detail` HTML structure

- View header: "Transaction Details" (no back button — Close button navigates back)
- `ms-trxn-detail-rows` — populated by `buildTxRows`
- Raw JSON `<details>` panel (same pattern as `review-json-details` in send-review)
- `ms-trxn-cancel-progress` — hidden by default; shown during cancel with per-step status
- `ms-trxn-detail-error` — inline error alert
- Action row: `ms-trxn-close-btn` (Close) + `ms-trxn-cancel-btn` (Cancel Transaction)

### Cancel Flow

**Triggered by:** `ms-trxn-cancel-btn` click

1. Disable both buttons, show `ms-trxn-cancel-progress`
2. For each signer in `msSignerList.SignerEntries`:
   - Build `CredentialDelete { Account: msMessengerAddress, Subject: e.SignerEntry.Account, CredentialType: '4D554C5449534947' }`
   - `autofill` → `signWithAddress(prepared, msMessengerAddress)` → `submitAndWait`
   - Update per-row status (✓ / ✗)
   - Continue on individual failure
3. Build `MPTokenIssuanceDestroy { Account: msMessengerAddress, MPTokenIssuanceID: msTrxnDetail.mptObj.MPTokenIssuanceID }`
   - `autofill` → `signWithAddress` → `submitAndWait`
   - Show result
4. After all steps complete: show Close button, hide Cancel button
5. On Close: navigate back to multisign, reload multisign data (so the cancelled entry disappears)

**Signer source:** `msSignerList` (current on-chain signer list). If the signer list changed since the credentials were issued, some CredentialDeletes may fail with `tecNO_ENTRY` — these are treated as already-gone and don't block completion.

---

## Files Changed

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-sent-card`, `view-ms-trxn-detail` |
| `src/popup/popup.css` | Sent list row styles, cancel progress styles |
| `src/popup/popup.js` | 3 new state vars; credential filter; `msSentList` load; `renderMultisignScreen` extension; `openMsTrxnDetail`; `cancelMsTrxn`; event listeners |

---

## Error Cases

| Case | Handling |
|------|----------|
| No messenger account set | `ms-sent-card` stays hidden |
| Messenger has no MULTISIG MPTs | `ms-sent-card` stays hidden |
| `tx` fetch fails for detail | Show error in `ms-trxn-detail-error`, keep buttons active |
| MemoData decode fails | Show "Could not decode transaction data." error |
| CredentialDelete tecNO_ENTRY | Treated as success (already gone) |
| MPTokenIssuanceDestroy fails | Show ✗ with error code; user can retry via Close + re-enter |
| `msSignerList` is null when Cancel clicked | Show error "Signer list not loaded. Return to Multisig screen and try again." |
