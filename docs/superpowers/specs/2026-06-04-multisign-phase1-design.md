# Multisign Phase 1 — Design Spec

**Date:** 2026-06-04  
**Branch:** feat/multisign-workflow  
**Scope:** Settings toggle, main page section, Multisign management screen (SignerList + master key), view-send-review raw JSON enhancement.

---

## Overview

Phase 1 introduces multisign account management to the XRPL dev wallet. It is gated behind a settings toggle (default off) so existing workflows are unaffected when the feature is disabled. When enabled, a MULTISIGN section appears on the main wallet screen and navigates to a dedicated management screen where the user can configure a SignerList and toggle the master key.

---

## 1. Settings Toggle

**Storage:** `multisignEnabled: false` is added to the existing `devSettings` object, persisted in `chrome.storage.local` alongside `printTxJson`, `wideMode`, etc.

**UI:** A toggle row labelled "Multisign" is added to `view-settings` in the developer settings group, following the same pattern as the existing boolean toggles.

**Effect:** When `multisignEnabled` is `false`, the MULTISIGN card on the main page is hidden (`display: none`). All other behaviour is unchanged. The `updateWalletUI()` function reads the flag when rendering the wallet view.

---

## 2. Main Page — MULTISIGN Section

A clickable card row is inserted in `view-wallet` HTML between the Account card and the WalletConnect section. It uses the same `iou-balance-card` card structure with an uppercase section label ("MULTISIGN") and a `›` chevron indicating navigation. Clicking calls `openMultisignView()`. The element is shown/hidden by `updateWalletUI()` based on `devSettings.multisignEnabled`.

---

## 3. Multisign Screen (`view-multisign`)

### 3.1 Navigation

- Back button (`‹`) returns to `view-wallet`.
- Entry point: `openMultisignView()` calls `showView('view-multisign')` then `loadMultisignData()`.

### 3.2 Data Loading

`loadMultisignData()` issues two XRPL requests:

1. `account_objects` with `ledger_index: 'validated'` — filters results for `LedgerEntryType === 'SignerList'` to obtain the existing signer list (or none).
2. `account_info` with `ledger_index: 'validated'` — reads `account_data.Flags` and tests bit `0x00100000` (`lsfDisableMaster`) to determine master key status.

Both requests use the existing `state.client.request()` pattern. Results are stored in module-level variables (`msSignerList`, `msMasterKeyDisabled`) and used to render the two cards.

### 3.3 Local Form State

```js
// Module-level, reset on each entry to the screen
let msFormState = {
  quorum: '',
  signers: [{ address: '', weight: 1 }]
};
let msFormVisible = false; // setup form open/closed (no-setup state)
let msUpdateMode  = false; // true when editing an existing signer list
```

Every add/remove/field-change updates `msFormState` and calls `renderMsSignerRows()`, which re-renders only the signer row container from the array. Submit reads directly from `msFormState`.

### 3.4 SignerList Card — No Setup State

- Displays: "No Multisig Setup" message.
- "Setup Multisig" button toggles `msFormVisible`. When toggled open it shows the Configure form below; when toggled closed it hides it.

### 3.5 SignerList Card — Configured State

Displays:
- Quorum Threshold value.
- One row per signer entry: resolved name via `resolveAddrDisplay(address)`, truncated address, weight badge.

"Update" button:
- Sets `msUpdateMode = true`.
- Pre-populates `msFormState` from the fetched `msSignerList` data.
- Hides the summary card entirely and shows the Update form in its place.

### 3.6 Configure / Update Form

Fields:
- **Quorum Threshold** — number input, must be a positive integer.
- **Signer rows** — one row per `msFormState.signers` entry, each containing:
  - Address input (free-text) + picker button (⊞)
  - Weight input (positive integer)
  - ✕ remove button (disabled if only one row remains)
- **"+ Add Signer"** button — appends `{ address: '', weight: 1 }` to `msFormState.signers` and re-renders.
- **Submit** button — runs validation then builds and routes the transaction.
- **Cancel** button (update mode only) — resets `msUpdateMode`, restores summary view.

**Validation before submit:**
- Quorum is a positive integer.
- At least one signer row.
- All address fields are non-empty and valid r-addresses.
- No duplicate addresses in the signer list.
- All weight fields are positive integers.
- Sum of weights must be ≥ quorum (warning, not block — XRPL enforces this at ledger level but showing an inline warning is good UX).

### 3.7 Address Picker Modal

A small overlay reusing the existing modal backdrop pattern (same structure as `#qr-modal`). Contains:
- Search/filter text input.
- Scrollable list combining project accounts (label + address) and address book entries (name + address), filtered live by the search input.
- Clicking an entry writes the address to `msFormState.signers[i].address`, re-renders, and closes the modal.

The picker button stores the target signer index as a data attribute so the modal knows which row to update.

### 3.8 Master Key Card

Always visible below the SignerList card.

Status display:
- `lsfDisableMaster` bit **clear** → green status dot + "Master key is active".
- `lsfDisableMaster` bit **set** → red status dot + "Master key is disabled".

Buttons:
- Active state → "Disable Master Key" (red outline button).
- Disabled state → "Re-enable Master Key" (green outline button).

Clicking either button builds an `AccountSet` transaction and routes it to `view-send-review`.

---

## 4. `view-send-review` Enhancement

A `<details>` element labelled "Raw Transaction JSON" is appended at the bottom of the `view-send-review` card, collapsed by default. It is only visible when a multisign transaction is being reviewed; existing payment flows (`reviewSendPayment()`) are not modified and the element remains hidden for them.

Multisign transactions are routed via a new `reviewMultisignTx(txJson)` function. This function populates `view-send-review` with a human-readable summary (using the existing `buildTxRows()` renderer), fills the raw JSON `<details>` content, and shows `view-send-review`. The approve/sign/submit flow from that point is identical to the payment flow.

---

## 5. Transaction Building

### 5.1 SignerListSet

Built in `submitSignerListSet()` after validation passes:

```js
{
  TransactionType: 'SignerListSet',
  Account: state.activeAccount,
  SignerQuorum: Number(msFormState.quorum),
  SignerEntries: msFormState.signers.map(s => ({
    SignerEntry: {
      Account: s.address,
      SignerWeight: Number(s.weight)
    }
  }))
}
```

Routed to `view-send-review` with the raw JSON passed for the collapsible section.

### 5.2 AccountSet — Master Key Toggle

Built in `submitMasterKeyToggle()`:

```js
// Disable master key
{ TransactionType: 'AccountSet', Account: state.activeAccount, SetFlag: 4 }

// Re-enable master key
{ TransactionType: 'AccountSet', Account: state.activeAccount, ClearFlag: 4 }
```

`4` is `asfDisableMaster`. Routed to `view-send-review` with raw JSON.

---

## 6. Files Changed

| File | Changes |
|------|---------|
| `src/popup/popup.html` | Add `view-multisign` view, MULTISIGN card in `view-wallet`, multisign settings toggle in `view-settings`, address picker modal, raw JSON `<details>` in `view-send-review` |
| `src/popup/popup.js` | `openMultisignView()`, `loadMultisignData()`, `renderMsSignerRows()`, `submitSignerListSet()`, `submitMasterKeyToggle()`, `reviewMultisignTx()`, picker modal open/close, `msFormState` / `msSignerList` / `msMasterKeyDisabled` module-level state, `devSettings.multisignEnabled` toggle wiring, `updateWalletUI()` guard |
| `src/popup/popup.css` | Styles for `view-multisign` cards, signer rows, picker modal, master key status dots, raw JSON details element |

---

## 7. Out of Scope (Phase 1)

- Actually co-signing transactions with multiple keys (Phase 2+).
- WalletConnect multisig request handling.
- Removing a SignerList entirely (sending `SignerListSet` with `SignerQuorum: 0`).
- Any changes when `multisignEnabled` is false — the feature must be invisible.
