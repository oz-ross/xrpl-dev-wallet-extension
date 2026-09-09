# Confidential Transfers — Phase 1: ElGamal Key Management

**Date:** 2026-09-04  
**Branch:** `feature-confidential-transfers`  
**Status:** Approved for implementation

---

## Overview

Adds foundational infrastructure for XLS-0096 confidential MPT transfers to the XRPL dev wallet extension. Phase 1 covers: an Advanced settings toggle to enable the feature, a per-account ElGamal key management screen accessible from the account card, and the cryptographic library integration. Further confidential transfer operations (encrypt, decrypt, send) will be added in subsequent phases once this foundation is in place.

---

## Library: `@xrplf/mpt-crypto` (GitHub `main`)

The npm-published release (`0.1.1`) does not include the BSGS decryption algorithm. The `main` branch of `XRPLF/xrpl.js` at `packages/mpt-crypto` does (WASM version `1.0.5`), so it is pulled directly from source.

### Installation strategy

Because `@xrplf/mpt-crypto` lives in a monorepo subdirectory, `npm install github:XRPLF/xrpl.js` would install the root package, not the subpackage. The solution:

1. `scripts/setup-mpt-crypto.sh` — a one-time developer script that:
   - Sparse-clones `XRPLF/xrpl.js` (only `packages/mpt-crypto/`) to a temp directory
   - Runs `npm install` and `npm run build` inside it
   - Copies the built output to `vendor/mpt-crypto/`
2. `package.json` references it as `"@xrplf/mpt-crypto": "file:vendor/mpt-crypto"`
3. `vendor/mpt-crypto/` is committed (built artefacts including the ~2.5 MB WASM binary) so collaborators and CI can build the extension with a plain `npm install` without running the setup script.
4. When updating to a newer `main` commit, re-run `scripts/setup-mpt-crypto.sh` and commit the updated `vendor/`.

The library ships a browser WASM glue (`mpt_crypto.web.mjs`) selected via the package's `browser` export condition. Webpack picks this up automatically — no additional configuration required beyond what already handles other WASM-bearing dependencies.

### ElGamal key generation

`@xrplf/mpt-crypto` provides encryption, decryption, and proof primitives but does not explicitly export a key-pair generation function. ElGamal private keys are standard secp256k1 scalars (32 bytes); public keys are compressed secp256k1 points (33 bytes).

Key generation uses:
- **`@noble/curves/secp256k1`** — already installed as a transitive dependency of `xrpl`, so no new package is added. Added as a direct dependency in `package.json` (`"@noble/curves": "^2.4.0"`) to make the dependency explicit and stable against tree changes.
- Private key: `crypto.getRandomValues(new Uint8Array(32))`, validated as a legal secp256k1 scalar via `secp256k1.utils.isValidPrivateKey(privKey)`.
- Public key: `secp256k1.getPublicKey(privKey, true)` → 33-byte compressed point.

Both are stored as uppercase hex strings (no `0x` prefix), matching mpt-crypto's convention.

---

## Data Model

### Vault payload extension

The encrypted vault currently stores `{ keyrings, activeAccount }`. This is extended to:

```js
{
  keyrings:     [...],
  activeAccount: "r...",
  elgamalKeys:  {
    "r...address...": { pubKey: "02...", privKey: "..." },
    // one entry per account that has generated a key
  }
}
```

`elgamalKeys` is inside the AES-256-GCM encrypted vault blob — it receives the same encryption and PBKDF2 key derivation as all other sensitive account data. No separate storage mechanism is required.

### Backward compatibility

`loadAndDecryptVault()`, `restoreFromSession()`, and every other vault load site read the field as:

```js
state.elgamalKeys = payload.elgamalKeys ?? {};
```

Existing vaults without the field continue to work; they simply have no keys yet.

### State

```js
state.elgamalKeys = {};  // { [rAddress]: { pubKey: hex, privKey: hex } }
```

Added to the `state` object alongside `keyrings`.

### Lifecycle

- **Generate:** user clicks Generate on the CT view → key pair created → stored in `state.elgamalKeys[address]` → `saveVault()` called.
- **Account deletion:** when an account is removed from the wallet, its entry is deleted from `state.elgamalKeys` before `saveVault()`.
- **Account add:** no key is created automatically; the user generates one explicitly.

---

## Settings Toggle

Location: **Advanced** section of the Settings view, above the existing Multisign toggle.

```
Advanced
  ┌─────────────────────────────────────────────┐
  │ Confidential Transfers              [ toggle ]│
  │ Multisign                           [ toggle ]│
  └─────────────────────────────────────────────┘
```

- `devSettings.confidentialTransfersEnabled` (boolean, default `false`)
- Persisted to `chrome.storage.local` as part of `devSettings` via the existing `saveDevSettings()` / `loadDevSettings()` pattern.
- Toggling calls `updateWalletUI()` to show/hide the CT button on the account card immediately.

---

## Account Card: CT Button

A new icon button is appended to the `.account-actions` row in the account card:

```
ℹ  ⊞  ⧉  ↗  ⛨
```

The button (`id="ct-key-btn"`, title `"Confidential transfers"`) uses `⛨` (U+26E8, BLACK CROSS ON SHIELD) as its icon character, matching the all-Unicode style of the existing buttons.

Visibility rules (evaluated in `updateWalletUI()`):
- Hidden when `devSettings.confidentialTransfersEnabled` is `false`
- Hidden when the active account is watch-only
- Visible for simple, HD-derived, and Ledger accounts

Clicking the button calls `openConfidentialKeyView()`, which sets up and shows `view-confidential-key`.

---

## View: `view-confidential-key`

### State: no key generated

```
‹  Confidential Transfers

  [Account name]
  rXXX…XXX

  ─────────────────────────────────────────────
  Generate an ElGamal key pair to enable
  confidential MPT transfers for this account.
  ─────────────────────────────────────────────

  [Generate Key]
```

Clicking **Generate Key**:
1. Generates a secp256k1 key pair (described above).
2. Stores it in `state.elgamalKeys[address]`.
3. Calls `saveVault()`.
4. Re-renders the view into the "key exists" state without a full navigation.

### State: key exists

```
‹  Confidential Transfers

  [Account name]
  rXXX…XXX

  Public Key
  ┌──────────────────────────────────────────────┐
  │ 02abcd1234ef5678...                    [⧉]   │
  └──────────────────────────────────────────────┘

  Private Key
  ┌──────────────────────────────────────────────┐
  │ ••••••••••••••••••••••••••••••••••••••••••   │
  └──────────────────────────────────────────────┘

  [Reveal Private Key]
```

### Reveal flow

Mirrors the existing `export-key` view exactly:

1. Clicking **Reveal Private Key** shows a password field and warning text:
   > ⚠ Your private key gives full access to your confidential balances. Never share it with anyone.
2. User enters their wallet password and clicks **Confirm**.
3. Password is verified by attempting vault decrypt (same as `confirmExportKey` — re-derives the PBKDF2 key and decrypts; a wrong password throws and shows an error).
4. On success:
   - Password field and Reveal button are hidden.
   - Private key is shown in plain text.
   - A 60-second auto-hide countdown is started (same pattern as `export-key`); when it fires the view resets to the obfuscated state.
5. A **Copy** button is shown alongside the revealed key.

---

## Files Changed

| File | Change |
|---|---|
| `package.json` | Add `"@xrplf/mpt-crypto": "file:vendor/mpt-crypto"` and `"@noble/curves": "^2.4.0"` (explicit direct dep; already a transitive dep) |
| `scripts/setup-mpt-crypto.sh` | Sparse-clone + build script for updating the vendored library |
| `vendor/mpt-crypto/` | Committed built output (dist + wasm) |
| `src/popup/popup.js` | `state.elgamalKeys`, devSettings default + load/save, vault payload read/write, CT button show/hide in `updateWalletUI`, account deletion cleanup, `openConfidentialKeyView`, `generateElGamalKey`, `renderConfidentialKeyView`, `confirmRevealElGamalPrivKey` |
| `src/popup/popup.html` | Settings toggle, `ct-key-btn` in account card, `view-confidential-key` |
| `src/popup/popup.css` | Any layout classes not already covered by existing patterns (expected minimal) |

---

## Security Notes

- The ElGamal private key is stored exclusively inside the AES-256-GCM encrypted vault. It is never written to `chrome.storage.session`, never logged, and wiped from JS memory immediately after key generation writes it to `state.elgamalKeys` (the state object holds it for the lifetime of the unlock session, same as seed phrases and mnemonics in keyrings).
- The reveal flow always re-verifies the password against the vault, regardless of whether `_sessionPassword` is available in memory. This matches the existing export-key security posture.
- `@noble/curves/secp256k1`'s `isValidPrivateKey()` validates the generated scalar is in the legal secp256k1 range `[1, n-1]` before storing it; if the check fails (astronomically unlikely), key generation retries.
