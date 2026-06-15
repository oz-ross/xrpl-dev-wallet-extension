# XRPL Dev Wallet — Multisig Protocol Specification

This document describes the on-chain and off-chain protocol used by the wallet to coordinate multisig transaction dispatch and collection.

---

## Overview

The protocol has five phases:

1. **Setup** — configure the multisig account, nominate a messenger account
2. **Dispatch** — encode an unsigned transaction, create an MPT issuance carrying it, send credentials to signers
3. **Signing** — each signer verifies the sender, produces a partial signature, and accepts the credential
4. **Submission** — collect all signatures, assemble a multisigned transaction, submit to the ledger
5. **Cleanup** — revoke credentials and destroy the MPT issuance

---

## Phase 1 — Setup

### 1.1 Configure the Signer List

```
TransactionType: SignerListSet
Account:         <multisig-account>
SignerQuorum:    <quorum-threshold>
SignerEntries:
  - SignerEntry:
      Account:      <signer-address-1>
      SignerWeight: <weight-1>
  - SignerEntry:
      Account:      <signer-address-2>
      SignerWeight: <weight-2>
  ...
```

This creates a `SignerList` ledger object on the multisig account. The account can no longer submit transactions using its own key alone once `SignerListSet` is in place.

### 1.2 Disable the Master Key (optional but typical)

```
TransactionType: AccountSet
Account:         <multisig-account>
SetFlag:         4          # asfDisableMaster (lsfDisableMaster = 0x00100000)
```

Once disabled, the `lsfDisableMaster` flag (`0x00100000`) appears in the account's `Flags` field. The wallet detects this and disables regular submit buttons for the account.

To re-enable:
```
TransactionType: AccountSet
Account:         <multisig-account>
ClearFlag:       4
```

### 1.3 Set the Messenger Account

```
TransactionType: AccountSet
Account:         <multisig-account>
MessageKey:      <hex-public-key-of-messenger-account>
```

`MessageKey` is a 33-byte compressed public-key hex string (secp256k1: `02`/`03` prefix + 32 bytes, or ed25519: `ED` prefix + 32 bytes). It identifies the trusted messenger account that will dispatch signature requests.

**Local storage:** the wallet persists the messenger-account address in `chrome.storage.local` under key `messengerLink_<multisig-account-address>`.

---

## Phase 2 — Dispatch ("Send for Multisig")

### 2.1 Prepare the Transaction

The original transaction (e.g. a `Payment`) is prepared as follows:

1. `autofill` is called to obtain network fields (`Fee`, `Sequence`).
2. `Fee` is overridden to meet the multisig minimum: `(N + 1) × base_fee` where N is the number of signers.
3. `LastLedgerSequence` is set to `ledger_current_index + ledger_buffer` (user-configurable, default 20).
4. `SigningPubKey` is set to `''` (empty string, the canonical XRPL multisig marker).
5. The transaction is encoded to hex using `ripple-binary-codec encode()`.

**Optional — Ticket:** If the user selects a ticket from the dropdown, `Sequence` is set to `0` and `TicketSequence` is set to the chosen ticket's sequence number.

### 2.2 Create the MPT Issuance

```
TransactionType:  MPTokenIssuanceCreate
Account:          <messenger-account>
MPTokenMetadata:  <hex-encoded JSON — see below>
Memos:
  - Memo:
      MemoType: 5458                  # hex("TX")
      MemoData: <unsigned-tx-hex>     # the encoded tx from step 2.1
```

**MPT Metadata JSON (UTF-8 encoded, then hex):**

```json
{
  "t":  "MS",
  "n":  "Multisig",
  "i":  "X",
  "in": "X",
  "ac": "other",
  "as": "other",
  "ai": {
    "hash":             "<hash-of-unsigned-tx>",
    "transaction_type": "<e.g. Payment>"
  }
}
```

`ai.hash` is computed as `SHA-512-half` of the encoded transaction bytes (same algorithm as XRPL transaction hashing). `ai.transaction_type` is the human-readable `TransactionType` string.

The `MPTokenIssuanceCreate` transaction is signed by the **messenger account**. On success, `meta.mpt_issuance_id` contains the new issuance ID (e.g. 48-character hex string).

### 2.3 Create Credentials for Each Signer

For each signer in the `SignerList`:

```
TransactionType: CredentialCreate
Account:         <messenger-account>         # issuer
Subject:         <signer-address>            # recipient
CredentialType:  4D554C5449534947<mpt-id>    # hex("MULTISIG") + mptIssuanceId
URI:             <mpt-issuance-id>
```

**CredentialType format:** `4D554C5449534947` (hex of `"MULTISIG"`) concatenated with the 48-character `mptIssuanceId`. Total: 64 hex characters = 32 bytes. This makes each dispatch's credentials unique and directly traceable to their MPT.

Each `CredentialCreate` is signed by the **messenger account**, one per signer, submitted sequentially. Because `submitAndWait` is used, the account sequence increments correctly between calls.

---

## Phase 3 — Signing (Signer Side)

### 3.1 Discover Incoming Signature Requests

The signer's wallet detects pending signature requests by fetching `account_objects` for the signer's account and filtering for `Credential` objects whose `CredentialType` starts with `4D554C5449534947`.

### 3.2 Verify the Sender

For each credential:

1. Fetch `ledger_entry { mpt_issuance: credential.URI }` to get the MPT node.
2. Read `node.PreviousTxnID` (the `MPTokenIssuanceCreate` transaction hash).
3. Fetch that transaction and decode `Memos[0].Memo.MemoData` (hex) with `ripple-binary-codec decode()` to recover the original unsigned transaction JSON.
4. Fetch `account_info` for `decodedTx.Account` (the multisig account).
5. Derive the XRPL address from `account_data.MessageKey` using `deriveAddress(publicKey)`.
6. Compare to `credential.Issuer` (the messenger account address).

**Result:**
- Match → ● **Sender Verified** (green)
- Mismatch or missing `MessageKey` → ● **Sender Failed Verification** (red) — Sign button disabled

### 3.3 Create a Partial Multisig Signature

The signing uses `encodeForMultisigning(txJson, signerAddress)` from `ripple-binary-codec`, which applies the XRPL multisig signing prefix (`0x534D5400`) and appends the signer's account ID bytes. This is distinct from `encodeForSigning` (single-signer, prefix `0x53545800`).

```javascript
const encoded = encodeForMultisigning(decodedTxJson, state.activeAccount);
const sig     = keypairsSign(encoded, wallet.privateKey).toUpperCase();
const pubKey  = wallet.publicKey;
```

### 3.4 Accept the Credential (with Signature)

```
TransactionType: CredentialAccept
Account:         <signer-account>
Issuer:          <messenger-account>
CredentialType:  4D554C5449534947<mpt-id>    # same full type as the credential
Memos:
  - Memo:
      MemoType: 5369676E696E675075624B6579   # hex("SigningPubKey")
      MemoData: <signer-public-key-hex>
  - Memo:
      MemoType: 546F6E5369676E6174757265      # hex("TxnSignature")
      MemoData: <partial-signature-hex>
```

The `CredentialAccept` is signed by the **signer's own account** (their master key). On submission, the credential's `lsfAccepted` flag (`0x00010000`) is set on the ledger object, and `credential.PreviousTxnID` is updated to the hash of this `CredentialAccept` transaction.

---

## Phase 4 — Submission (Dispatcher Side)

### 4.1 Assess Quorum Progress

For each signer in the `SignerList`, the wallet calls:

```
ledger_entry {
  credential: {
    subject:         <signer-address>,
    issuer:          <messenger-account>,
    credential_type: 4D554C5449534947<mpt-id>
  }
}
```

If the credential exists and `Flags & 0x00010000` (lsfAccepted), the signer's weight is added to `currentWeight`. The transaction is ready to submit when `currentWeight >= SignerQuorum`.

### 4.2 Collect Partial Signatures

For each accepted signer's credential, fetch the `CredentialAccept` transaction via `credential.PreviousTxnID`:

```
{ command: 'tx', transaction: credential.PreviousTxnID }
```

Extract from `result.tx_json.Memos`:
- `MemoType == hex("SigningPubKey")` → `pubKey`
- `MemoType == hex("TxnSignature")` → `sig`

### 4.3 Build and Submit the Multisigned Transaction

Assemble the `Signers` array. XRPL requires signers to be sorted in **ascending order by account ID** (20-byte account ID derived from address):

```javascript
const Signers = signerData
  .map(s => ({ Signer: { Account: s.address, SigningPubKey: s.pubKey, TxnSignature: s.sig } }))
  .sort((a, b) => Buffer.compare(
    Buffer.from(decodeAccountID(a.Signer.Account)),
    Buffer.from(decodeAccountID(b.Signer.Account))
  ));
```

Build the final transaction:

```javascript
const finalTx = { ...decodedTxJson, Signers };
const tx_blob = encode(finalTx);
await client.submitAndWait(tx_blob);
```

The `finalTx` retains `SigningPubKey: ''` and `Sequence: N` (or `Sequence: 0` + `TicketSequence: T` if a ticket was used) from the original dispatch encoding.

---

## Phase 5 — Cleanup

On successful submission (`tesSUCCESS`), the messenger account revokes credentials and destroys the MPT.

### 5.1 Revoke Credentials

Before attempting deletion, the wallet queries each signer's credential with `ledger_entry` to confirm existence (avoids unnecessary failed transactions). For each existing credential:

```
TransactionType: CredentialDelete
Account:         <messenger-account>
Subject:         <signer-address>
CredentialType:  4D554C5449534947<mpt-id>
```

Signed by the **messenger account**. `tecNO_ENTRY` (credential already gone) is treated as success.

### 5.2 Destroy the MPT Issuance

```
TransactionType:    MPTokenIssuanceDestroy
Account:            <messenger-account>
MPTokenIssuanceID:  <mpt-issuance-id>
```

Signed by the **messenger account**. Succeeds because no tokens were distributed (outstanding balance is zero).

---

## Cancellation

If the multisig process is abandoned (before submission), the same cleanup is performed:
- `CredentialDelete` for all signers that have an outstanding credential
- `MPTokenIssuanceDestroy`

---

## Fee Model

| Transaction | Signatory | Fee |
|---|---|---|
| `SignerListSet` | Multisig account | standard |
| `AccountSet` (disable/enable master, set MessageKey) | Multisig account | standard |
| `MPTokenIssuanceCreate` | Messenger account | standard |
| `CredentialCreate` × N | Messenger account | standard × N |
| `CredentialAccept` | Signer account | standard |
| Multisigned transaction | Submitted as blob | `(N + 1) × base_fee` |
| `CredentialDelete` × N | Messenger account | standard × N |
| `MPTokenIssuanceDestroy` | Messenger account | standard |

The multisigned transaction fee minimum is `(N + 1) × base_fee` where N is the number of actual signers providing signatures.

---

## Local Storage Keys

| Key | Value | Purpose |
|---|---|---|
| `messengerLink_<address>` | messenger account address | Maps multisig account → messenger account |

---

## Object Summary

| XRPL Object | Owner | Purpose |
|---|---|---|
| `SignerList` | Multisig account | Defines quorum and signer weights |
| `MPTokenIssuance` | Messenger account | Carries encoded unsigned transaction in creation memo |
| `Credential` | Subject (signer) | Signals pending signature request; carries partial signature on accept |
| `Ticket` | Multisig account | Optional: allows out-of-sequence transaction dispatch |

---

## Encoding Constants

| Value | Hex | Notes |
|---|---|---|
| `"TX"` (MemoType) | `5458` | Identifies the transaction blob memo |
| `"SigningPubKey"` (MemoType) | `5369676E696E675075624B6579` | Signer's public key in CredentialAccept |
| `"TxnSignature"` (MemoType) | `546F6E5369676E6174757265` | Partial signature in CredentialAccept |
| `"MULTISIG"` (CredentialType prefix) | `4D554C5449534947` | Always prepended to mptIssuanceId |
| `asfDisableMaster` | `4` | AccountSet SetFlag/ClearFlag value |
| `lsfDisableMaster` | `0x00100000` | Account Flags bitmask |
| `lsfAccepted` (Credential) | `0x00010000` | Credential Flags bitmask |
| Multisig signing prefix | `0x534D5400` | Applied by `encodeForMultisigning` |
| Single-sig signing prefix | `0x53545800` | Applied by `encodeForSigning` |
