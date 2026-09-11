# Confidential Transfers — Phase 2: Per-MPT-Holding UI

**Date:** 2026-09-08
**Branch:** `feature-confidential-transfers`
**Status:** Approved for implementation
**Depends on:** Phase 1 (`docs/superpowers/specs/2026-09-04-confidential-transfers-key-management-design.md`)

---

## Overview

Extends the MPT holdings display to reflect each holding's confidential-transfer state and to support the initial conversion of public balance to confidential balance via a `ConfidentialMPTConvert` transaction. Phase 2 covers three per-holding states, balance decryption via BSGS, and the convert flow. It does not cover merge-inbox, confidential send, or convert-back — those are later phases.

---

## Background: XLS-0096 Data Model

### MPToken ledger object (account_objects)

An MPToken may carry additional fields when the holder has enabled confidential transfers for that issuance:

| Field | Type | Meaning |
|---|---|---|
| `HolderEncryptionKey` | hex (33 bytes) | Holder's ElGamal public key; absent until first `ConfidentialMPTConvert` |
| `ConfidentialBalanceSpending` | hex (66 bytes) | ElGamal ciphertext — spendable confidential balance |
| `ConfidentialBalanceInbox` | hex (66 bytes) | ElGamal ciphertext — inbox (unconverted/received, pending merge) |

`HolderEncryptionKey` matches the account's ElGamal public key stored in `state.elgamalKeys[address].pubKey` (generated in Phase 1).

### MPTokenIssuance ledger object (ledger_entry)

| Field | Type | Meaning |
|---|---|---|
| `IssuerEncryptionKey` | hex (33 bytes) | Issuer's ElGamal public key; required for `IssuerEncryptedAmount` in convert tx |
| `AuditorEncryptionKey` | hex (33 bytes) | Optional auditor key; when present, `AuditorEncryptedAmount` must be included |

### ConfidentialMPTConvert transaction

Converts public MPT balance to confidential balance. Amounts appear in the holder's inbox and require a subsequent `ConfidentialMPTMergeInbox` to become spendable (future phase).

| Field | Required | Description |
|---|---|---|
| `MPTokenIssuanceID` | yes | UInt192 — the issuance |
| `MPTAmount` | yes | UInt64 — plaintext amount to convert (may be 0 for opt-in only) |
| `BlindingFactor` | yes | UInt256 — 32-byte randomness scalar |
| `HolderEncryptedAmount` | yes | Blob — 66-byte ElGamal ciphertext (holder key) |
| `IssuerEncryptedAmount` | yes | Blob — 66-byte ElGamal ciphertext (issuer key) |
| `HolderEncryptionKey` | first use only | Blob — holder's ElGamal public key |
| `ZKProof` | when `HolderEncryptionKey` present | Blob — 64-byte Schnorr proof |
| `AuditorEncryptedAmount` | if `AuditorEncryptionKey` on issuance | Blob — 66-byte ElGamal ciphertext (auditor key) |

---

## Cryptography Library: `@xrplf/mpt-crypto`

Already vendored at `vendor/mpt-crypto/` (Phase 1). Functions used in Phase 2:

```js
import {
  generateBlindingFactor,   // (): Promise<string>  — 32-byte hex scalar
  encryptAmount,            // (amount: bigint, publicKey: string, blindingFactor: string): Promise<string>  — 66-byte hex ciphertext
  decryptAmount,            // (ciphertext: string, privateKey: string, rangeHigh: bigint): Promise<bigint>  — BSGS
  getConvertContextHash,    // (account: string, issuance: string, sequence: number): Promise<string>
  getConvertProof,          // (publicKey: string, privateKey: string, contextHash: string): Promise<string>  — 64-byte hex
} from '@xrplf/mpt-crypto';
```

All inputs/outputs are uppercase hex strings with no `0x` prefix. All functions are async (lazy WASM load on first call).

**Decryption ceiling:** `decryptAmount` takes `rangeHigh: bigint` as the BSGS search ceiling. Use `BigInt(10 ** 15)` as the default upper bound. If the true amount exceeds `rangeHigh`, decryption returns an incorrect result or fails; in that case display `[encrypted]`.

---

## Per-Holding UI States

Evaluated at render time in `renderMptBalances` for each MPToken holding (not issuance rows).

### State A — No ElGamal key in wallet

`state.elgamalKeys[activeAccount]` is absent. No CT UI changes. Row renders exactly as today.

### State B — ElGamal key exists, issuance supports CT, no `HolderEncryptionKey` on MPToken

`state.elgamalKeys[activeAccount]` exists, `issuanceMap[id].issuerEncryptionKey` is non-null (the MPT issuance has CT configured), and `MPToken.HolderEncryptionKey` is absent.

Row renders as today, with a `⛨ Add Confidentiality` button appended to the row. Clicking it opens `view-confidential-convert` pre-filled with this issuance.

### State C — `HolderEncryptionKey` present on MPToken

`MPToken.HolderEncryptionKey` equals `state.elgamalKeys[activeAccount].pubKey`.

Row shows a **▶ / ▼ toggle** and a **total balance** (public + decrypted spendable + decrypted inbox, formatted with `assetScale`). Expanding the toggle shows three sub-rows:

```
[▼] TOKEN_NAME    Total: X.XX
    rIssuer…
    ├ Public:                   A.AA
    ├ Confidential (spendable): B.BB
    └ Confidential (inbox):     C.CC
```

If either BSGS decryption fails (amount exceeds `rangeHigh`), the affected sub-row shows `[encrypted]` and the total omits that component (shows a `~` prefix to indicate it's partial).

---

## Data Layer Changes

### `fetchMptIssuanceInfo`

Extend the `ledger_entry` result extraction to also return:

```js
issuerEncryptionKey:  result.IssuerEncryptionKey ?? null,   // hex string or null
auditorEncryptionKey: result.AuditorEncryptionKey ?? null,  // hex string or null
```

No additional API call needed — both fields are already in the `mpt_issuance` ledger entry response.

### `loadMptBalances` / `renderMptBalances`

`renderMptBalances` receives the existing `regularObjects` (MPToken objects from account_objects) and `issuanceMap`. The MPToken objects already carry `HolderEncryptionKey`, `ConfidentialBalanceSpending`, and `ConfidentialBalanceInbox` when set — no extra fetch needed.

`renderMptBalances` becomes `async`. For each State C holding, it awaits:

```js
const [spendable, inbox] = await Promise.all([
  decryptAmount(obj.ConfidentialBalanceSpending, privKeyHex, BigInt(10 ** 15)).catch(() => null),
  decryptAmount(obj.ConfidentialBalanceInbox,    privKeyHex, BigInt(10 ** 15)).catch(() => null),
]);
```

`privKeyHex` is `state.elgamalKeys[state.activeAccount].privKey`. A `null` result renders as `[encrypted]`.

The caller of `renderMptBalances` (`loadMptBalances`) already uses `await` for the issuance fetches, so making `renderMptBalances` async requires no structural change.

---

## Convert Flow

### Entry point

`openConfidentialConvertView(issuanceId)` — called from the "⛨ Add Confidentiality" button click. Stores the issuance ID in a module-level variable (`_ctConvertIssuanceId`), populates the view, and calls `showView('confidential-convert')`.

### View: `view-confidential-convert`

```
‹  Add Confidentiality

  TOKEN_NAME
  rIssuerXXX…XXX

  Public balance: X.XX

  Initial conversion amount
  ┌────────────────────────────────┐
  │ 0                              │
  └────────────────────────────────┘
  (Enter 0 to opt-in without converting)

  [Convert]
```

Element IDs:
- `ct-convert-token-name` — display name
- `ct-convert-issuer` — truncated issuer address
- `ct-convert-public-balance` — current public balance
- `ct-convert-amount` — number input, default `0`, min `0`
- `ct-convert-btn` — submit button
- `ct-convert-error` — error display
- `back-from-ct-convert-btn` — back button

### Transaction preparation (`confirmConfidentialConvert`)

```
1. amount = BigInt(raw input × 10^assetScale)
2. blindingFactor = await generateBlindingFactor()
3. holderEncrypted = await encryptAmount(amount, holderPubKey, blindingFactor)
4. issuerEncrypted = await encryptAmount(amount, issuerPubKey, blindingFactor)
5. if auditorEncryptionKey:
     auditorEncrypted = await encryptAmount(amount, auditorEncryptionKey, blindingFactor)
6. sequence = (await client.request({ command: 'account_info', account })).result.account_data.Sequence
7. contextHash = await getConvertContextHash(account, issuanceId, sequence)
8. zkProof = await getConvertProof(holderPubKey, holderPrivKey, contextHash)
9. Build tx:
   {
     TransactionType: 'ConfidentialMPTConvert',
     Account: account,
     MPTokenIssuanceID: issuanceId,
     MPTAmount: String(amount),
     BlindingFactor: blindingFactor,
     HolderEncryptedAmount: holderEncrypted,
     IssuerEncryptedAmount: issuerEncrypted,
     HolderEncryptionKey: holderPubKey,
     ZKProof: zkProof,
     ...(auditorEncrypted ? { AuditorEncryptedAmount: auditorEncrypted } : {}),
   }
10. Sign (existing signing path) and submit
11. On success: showView('wallet'); loadMptBalances()
```

`holderPrivKey` is `state.elgamalKeys[state.activeAccount].privKey`. It is used only in step 8 and not stored or logged.

The convert button is disabled while the async preparation runs to prevent double-submission.

---

## Files Changed

| File | Change |
|---|---|
| `src/popup/popup.js` | `fetchMptIssuanceInfo` adds `issuerEncryptionKey`/`auditorEncryptionKey`; `renderMptBalances` becomes async, handles 3 CT states, decrypts balances; `openConfidentialConvertView`, `confirmConfidentialConvert`, `_ctConvertIssuanceId` variable; mpt-crypto imports; button event listeners |
| `src/popup/popup.html` | `view-confidential-convert` HTML with all 6 element IDs; expand toggle and CT sub-rows injected dynamically by renderer (no static HTML needed) |
| `src/popup/popup.css` | Sub-row indentation styles if not already covered by existing classes |

---

## Security Notes

- `holderPrivKey` is held in `state.elgamalKeys[activeAccount].privKey` for the duration of the unlocked session (same as seed phrases in keyrings). It is never written to any additional storage during the convert flow.
- The blinding factor and intermediate ciphertexts are computed in memory and discarded after the transaction is submitted.
- `decryptAmount` is called with the private key in memory only; the key is not passed outside the popup process.
- Account sequence is fetched fresh immediately before transaction assembly to prevent replay.
