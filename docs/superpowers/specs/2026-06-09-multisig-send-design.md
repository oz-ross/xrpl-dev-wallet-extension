# Multisig Send (Credential Dispatch) — Design Spec

**Date:** 2026-06-09
**Branch:** feat/multisign-workflow
**Status:** Approved

---

## Overview

When the multisign dev flag is enabled and the active account has an on-chain SignerList, every transaction review screen gains a "Send for Multisig" button. Clicking it autofills the pending transaction, encodes it to hex, and navigates to a new `view-multisig-send` confirmation + progress screen. On final confirm, the extension submits one `CredentialCreate` transaction per signer — each carrying the hex-encoded unsigned transaction in a memo — so signers can retrieve, sign, and co-submit it.

---

## Scope

- **In scope:** Signer list detection on review screen, new `view-multisig-send` view, sequential CredentialCreate submission with inline progress
- **Out of scope:** The receiving side (signer reading credentials and co-signing), expiry of credentials, credential revocation

---

## Section 1: Signer List Detection on Review Screen

### Trigger

Runs when `showView('send-review')` is called AND `state.devSettings.multisignEnabled === true`.

### Probe

```js
// module-level
let reviewSignerList = null; // null = unknown, [] = none, [...] = has signers
```

On entry to `send-review`, if the flag is on, fire an async `account_objects` request for the active account filtered to `type: 'signer_list'`. While pending, show the button in a loading/disabled state. On result:
- Found SignerList → populate `reviewSignerList` with `SignerEntries`, un-hide and enable the button
- No SignerList → set `reviewSignerList = []`, keep button hidden
- Request error → keep button hidden (fail silently, normal flow unaffected)

### "Send for Multisig" button

Always present in `view-send-review` HTML, initially `hidden`. Positioned after the existing "Confirm & Send" button. Element ID: `send-multisig-btn`.

The normal "Confirm & Send" button is always available immediately — the probe is non-blocking.

---

## Section 2: `view-multisig-send` View

### Entry (on `send-multisig-btn` click)

1. `await client.autofill(state.pendingTxReview.txJson)` — populates `Fee`, `Sequence`, `LastLedgerSequence`
2. `encode(autofilled)` from `ripple-binary-codec` → `msDispatchTxHex` (unsigned hex blob for signers)
3. Estimate total fee: use the `Fee` value from the autofilled original tx (a reliable per-tx baseline) × signer count. Display as "~N drops"
4. Store in module-level vars:
   - `msDispatchTxHex` — the hex-encoded autofilled transaction
   - `msDispatchSigners` — array of `{ address, name }` built from `reviewSignerList.SignerEntries` where `address = entry.SignerEntry.Account` and `name = resolveAddrDisplay(address)`
5. `showView('multisig-send')`

### Phase 1 — Confirmation

HTML elements:
- `ms-dispatch-tx-summary` — original tx rendered via the existing `buildTxRows(txJson)` helper (same as send-review), scoped to a compact card
- `ms-dispatch-signer-rows` — list of signers (name + truncated address per row)
- `ms-dispatch-fee-estimate` — "Est. fee: ~N drops (M credentials)"
- `ms-dispatch-error` — inline error alert, hidden by default
- `ms-dispatch-cancel-btn` — navigates back to `send-review`
- `ms-dispatch-confirm-btn` — triggers execution, transitions to Phase 2

### Phase 2 — Progress (in-place)

After confirm is clicked:
- `ms-dispatch-confirm-btn` becomes disabled with spinner text
- Each signer row gains a status indicator updated as each credential completes:
  - Pending: `⋯`
  - Success: `✓ Credential sent`
  - Failure: `✗ <error code>`
- After all signers processed, show `ms-dispatch-summary` line: "N of M credentials sent."
- Show `ms-dispatch-close-btn` → navigates to `state.pendingTxReview.backView`

---

## Section 3: CredentialCreate Execution

### Transaction shape (per signer)

```js
{
  TransactionType: 'CredentialCreate',
  Account: state.activeAccount,
  Subject: signerAddress,
  CredentialType: '4D554C5449534947',   // hex("MULTISIG"), 8 bytes
  Memos: [{
    Memo: {
      MemoType: '5458',                 // hex("TX")
      MemoData: msDispatchTxHex         // autofilled + encoded unsigned original tx
    }
  }]
}
```

### Execution loop

Function: `executeMultisigDispatch()`

For each signer in `msDispatchSigners`, sequentially:
1. Build the `CredentialCreate` txJson
2. `await client.autofill(txJson)` — because `submitAndWait` in step 4 waits for ledger validation, the account's on-ledger sequence is already incremented by the time the next iteration autofills, so each call correctly receives the next sequence number
3. `signPreparedTx(autofilled)` — signs with active account key (same pattern as `executeReviewedTx`)
4. `client.submitAndWait(tx_blob)` — waits for validation
5. Update the corresponding signer row with ✓ or ✗ + result code
6. Continue to next signer regardless of individual result

**Partial success is valid** — some signers may already have a credential (`tecDUPLICATE`) or other errors. All rows are always processed.

**Connection failure mid-loop:** Catch block marks remaining rows as "Connection lost" and stops.

### Final state

After the loop, `ms-dispatch-summary` shows "N of M credentials sent." and `ms-dispatch-close-btn` appears. Close navigates to `state.pendingTxReview.backView`.

---

## State Variables

```js
let reviewSignerList   = null;  // null | [] | [{Account, SignerWeight},...] — for send-review probe
let msDispatchTxHex    = '';    // autofilled+encoded unsigned tx blob for dispatch
let msDispatchSigners  = [];    // [{ address, name }] — signers for current dispatch
```

Both `msDispatchTxHex` and `msDispatchSigners` are reset when `openMultisigSendView()` is called. `reviewSignerList` is reset to `null` each time `send-review` is entered.

---

## Files Changed

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `send-multisig-btn` to `view-send-review`; add full `view-multisig-send` |
| `src/popup/popup.css` | Add styles for dispatch view: signer rows, status indicators, summary line |
| `src/popup/popup.js` | Add 3 state vars; probe in `showView` send-review handler; `openMultisigSendView()`; `renderMultisigDispatchView()`; `executeMultisigDispatch()`; event listeners |

---

## Encoding Constants

| Value | UTF-8 | Hex |
|-------|-------|-----|
| CredentialType | `MULTISIG` | `4D554C5449534947` |
| MemoType | `TX` | `5458` |

---

## Error Cases

| Case | Handling |
|------|----------|
| Probe fails (no connection) | Button stays hidden; normal flow unaffected |
| Autofill of original tx fails on dispatch | Show error in `ms-dispatch-error`, stay on confirm view |
| Individual CredentialCreate fails | Mark row ✗ with error code; continue to next signer |
| All CredentialCreates fail | Summary shows "0 of N credentials sent" |
| Connection drops mid-loop | Remaining rows show "Connection lost"; stop loop |
| No signers in list | Button stays hidden (caught by probe) |
