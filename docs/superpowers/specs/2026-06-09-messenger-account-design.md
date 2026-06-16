# Messenger Account — Design Spec

**Date:** 2026-06-09
**Branch:** feat/multisign-workflow
**Status:** Approved

---

## Overview

Add a "Messenger Account" card to the Multisig screen. The user selects any signable account from the current project; on confirmation, the extension:

1. Stores a local link from the active account → messenger account address in `chrome.storage.local`
2. Submits an `AccountSet` transaction that sets the `MessageKey` field on the active account to the public key of the selected messenger account

---

## Scope

- **In scope:** UI card, local link storage, public key derivation, AccountSet submission
- **Out of scope:** Encryption/messaging logic that consumes the MessageKey (future feature)

---

## UI

A new `ms-messenger-card` section rendered on the Multisig screen, positioned after the existing `ms-master-key-card`. Always visible after data loads (same lifecycle as the master key card).

**Card contents:**
- **Status line** (`ms-messenger-current`): "Current: Alice (rNPi3…)" if a link is stored, otherwise "No messenger account set."
- **`<select>` dropdown** (`ms-messenger-select`): Options populated from `getProjectAccounts()` filtered to exclude watch-only accounts. Each option shows `[label] ([truncAddr])`.
- **Inline error alert** (`ms-messenger-error`): hidden by default
- **Button** (`ms-messenger-btn`): "Set Messenger Account"

Watch-only accounts are excluded from the dropdown because they have no derivable public key.

---

## State

New module-level variable alongside existing `msSignerList`, `msMasterKeyDisabled`, etc.:

```js
let msMessengerAddress = null;
```

Holds the locally stored messenger account address for the current active account. `null` means none set.

---

## Data Flow

### On view open — `openMultisignView()`
- Reset: `msMessengerAddress = null`
- Hide: `$('ms-messenger-card').classList.add('hidden')`

### On data load — `loadMultisignData()`
After the existing `await refreshAddressNames()` call:
```js
msMessengerAddress = await loadMessengerLink(state.activeAccount);
```
Then `renderMultisignScreen()` is called as normal.

### On render — `renderMultisignScreen()`
New section after the master key block:
1. Populate dropdown from `getProjectAccounts().filter(a => !a.isWatch)`
2. Set status line text from `msMessengerAddress` (resolved via `resolveAddrDisplay`)
3. Un-hide card

### On submit — `submitMessengerAccountSet()`
1. Read `messengerAddress` from dropdown value; error if empty
2. Call `getPublicKeyForAddress(messengerAddress)`; error if null
3. `await saveMessengerLink(state.activeAccount, messengerAddress)` — save before entering review flow
4. Update `msMessengerAddress = messengerAddress`
5. Build tx: `{ TransactionType: 'AccountSet', Account: state.activeAccount, MessageKey: publicKey }`
6. Call `reviewMultisignTx(txJson, 'Messenger key set.')`

---

## New Functions

### `loadMessengerLink(address) → Promise<string|null>`
```js
async function loadMessengerLink(address) {
  const key = `messengerLink_${address}`;
  const data = await chrome.storage.local.get(key);
  return data[key] ?? null;
}
```

### `saveMessengerLink(address, messengerAddress) → Promise<void>`
```js
async function saveMessengerLink(address, messengerAddress) {
  await chrome.storage.local.set({ [`messengerLink_${address}`]: messengerAddress });
}
```

### `getPublicKeyForAddress(address) → string|null`
```js
function getPublicKeyForAddress(address) {
  const wallet = getWalletForAddress(address);   // handles HD + simple
  if (wallet) return wallet.publicKey;
  const kr = state.keyrings.find(k => k.type === 'ledger' && k.address === address);
  return kr?.publicKey ?? null;                  // Ledger stores publicKey directly
}
```

### `submitMessengerAccountSet() → Promise<void>`
See data flow above.

---

## Storage

**Key pattern:** `messengerLink_<activeAddress>`
**Value:** messenger account address string
**Scope:** `chrome.storage.local` (per-device, not synced)

Consistent with the existing `addressBook_<projectId>` and `messengerLink_<address>` pattern.

---

## Transaction

```js
{
  TransactionType: 'AccountSet',
  Account: state.activeAccount,
  MessageKey: publicKey   // hex-encoded 33-byte public key from xrpl.js Wallet.publicKey
}
```

`wallet.publicKey` from xrpl.js is already in the correct XRPL hex format (secp256k1: 02/03 prefix, 66 chars; ed25519: ED prefix, 66 chars).

Routed through the existing `reviewMultisignTx(txJson, successMsg)` → review card → sign → submit flow. No new signing logic required.

---

## Files Changed

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-messenger-card` HTML block after `ms-master-key-card` |
| `src/popup/popup.css` | Add `.ms-messenger-current` style rule |
| `src/popup/popup.js` | Add state var, 4 new functions, extend `openMultisignView`, `loadMultisignData`, `renderMultisignScreen`, add event listener |

---

## Error Cases

| Case | Handling |
|------|----------|
| No account selected | Inline error: "Please select a messenger account." |
| Public key not derivable | Inline error: "Could not derive public key for selected account." (defensive; shouldn't occur after watch-only filter) |
| Ledger not connected | Handled by existing `signPreparedTx` / Ledger signing flow |
| Watch-only active account | User can still set up the link locally; tx will fail at signing (same as master key toggle) |
