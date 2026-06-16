# Multisig Coordination Protocol

This document specifies the XRPL transactions and ledger objects used to coordinate multisig transaction dispatch, signing, and submission between a **multisig account**, a **messenger account**, and one or more **signer accounts**.

---

## Accounts

| Role | Description |
|---|---|
| **Multisig account** | The account whose transactions require multiple signatures to authorise |
| **Messenger account** | A designated account trusted to dispatch signature requests on behalf of the multisig account |
| **Signer account(s)** | Accounts listed in the multisig account's `SignerList` |

---

## Overview

The protocol has five phases:

1. **Setup** — configure the multisig account and nominate a messenger account
2. **Dispatch** — encode an unsigned transaction, publish it via an MPT issuance, and notify each signer via a credential
3. **Signing** — each signer verifies the dispatch, produces a partial signature, and accepts their credential
4. **Submission** — collect all partial signatures, assemble the multisigned transaction, and submit it
5. **Cleanup** — revoke credentials and destroy the MPT issuance

---

## Phase 1 — Setup

### 1.1 Configure the Signer List

**Signed by:** multisig account

```
TransactionType: SignerListSet
Account:         <multisig-account>
SignerQuorum:    <integer — minimum total weight required to authorise>
SignerEntries:
  - SignerEntry:
      Account:      <signer-address-1>
      SignerWeight: <integer weight>
  - SignerEntry:
      Account:      <signer-address-2>
      SignerWeight: <integer weight>
  ...
```

Creates a `SignerList` ledger object on the multisig account. A transaction is authorised when the combined weight of valid signer signatures meets or exceeds `SignerQuorum`.

### 1.2 Disable the Master Key *(optional but typical)*

**Signed by:** multisig account

```
TransactionType: AccountSet
Account:         <multisig-account>
SetFlag:         4    # asfDisableMaster
```

Sets `lsfDisableMaster` (`0x00100000`) in the account's `Flags`. The account's own private key can no longer authorise transactions; only the signer list can.

To re-enable:

```
TransactionType: AccountSet
Account:         <multisig-account>
ClearFlag:       4
```

### 1.3 Register the Messenger Account

**Signed by:** multisig account

```
TransactionType: AccountSet
Account:         <multisig-account>
MessageKey:      <33-byte compressed public key of the messenger account, hex-encoded>
```

`MessageKey` records the messenger account's public key on the multisig account's ledger entry. Signers use this to verify that a dispatch genuinely originates from the authorised messenger. The field accepts secp256k1 keys (`02`/`03` prefix) and ed25519 keys (`ED` prefix).

> **Note:** When Permission Delegation (XLS-75) is available, the messenger account will no longer be required; messenger functions can instead be delegated directly to another account.

---

## Phase 2 — Dispatch

### 2.1 The Unsigned Transaction

The transaction to be authorised is prepared with the following fields set before encoding:

| Field | Value |
|---|---|
| `Fee` | At least `(N + 1) × base_fee`, where N is the number of signers |
| `Sequence` | The multisig account's current on-ledger sequence, **or** `0` if a ticket is used |
| `TicketSequence` | The chosen ticket's sequence number *(only when using a ticket)* |
| `LastLedgerSequence` | Current ledger index plus a configurable expiry window |
| `SigningPubKey` | `""` (empty string — canonical XRPL multisig marker) |

The transaction is then binary-encoded to a hex string. This hex blob is what signers will sign and what is ultimately submitted to the ledger.

### 2.2 Publish the Unsigned Transaction via MPT Issuance

**Signed by:** messenger account

```
TransactionType:  MPTokenIssuanceCreate
Account:          <messenger-account>
MPTokenMetadata:  <hex — see metadata schema below>
Memos:
  - Memo:
      MemoType: 5458              # hex("TX")
      MemoData: <unsigned-tx-hex> # hex blob from step 2.1
```

The unsigned transaction blob is stored in `MemoData`. The `MPTokenMetadata` field carries a UTF-8 JSON document (hex-encoded) with the following schema:

```json
{
  "t":  "MS",
  "n":  "Multisig",
  "i":  "X",
  "in": "X",
  "ac": "other",
  "as": "other",
  "ai": {
    "hash":             "<SHA-512-half of the unsigned tx hex>",
    "transaction_type": "<TransactionType string, e.g. Payment>"
  }
}
```

`ai.hash` uses the same SHA-512-half algorithm as standard XRPL transaction hashing.

On validation, `meta.mpt_issuance_id` contains the 48-character hex issuance ID.

### 2.3 Notify Each Signer via Credential

**Signed by:** messenger account  
**One transaction per signer, submitted sequentially**

```
TransactionType: CredentialCreate
Account:         <messenger-account>
Subject:         <signer-address>
CredentialType:  4D554C5449534947<mpt-issuance-id>
URI:             <mpt-issuance-id>
```

**CredentialType** is `4D554C5449534947` (hex of `"MULTISIG"`) concatenated with the full 48-character `mpt-issuance-id` — 64 hex characters (32 bytes) total. This makes each dispatch's credentials unique and directly traceable to their MPT.

**URI** holds the `mpt-issuance-id` so the signer can retrieve the MPT and its transaction data.

---

## Phase 3 — Signing

### 3.1 Locate the Unsigned Transaction

To retrieve the transaction:

1. Fetch the MPT node via `ledger_entry { mpt_issuance: credential.URI }`.
2. The MPT node's `PreviousTxnID` is the hash of the `MPTokenIssuanceCreate` transaction.
3. Fetch that transaction. `Memos[0].Memo.MemoData` (where `MemoType = 5458`) is the unsigned transaction hex blob.
4. Binary-decode the blob to recover the transaction JSON.

### 3.2 Verify the Sender

The signer verifies that the dispatch originates from the authorised messenger:

1. Fetch `account_info` for `decodedTx.Account` (the multisig account).
2. Derive the XRPL address from `account_data.MessageKey` (the registered messenger public key).
3. Compare the derived address to `credential.Issuer`.

If they match, the dispatch is **sender-verified**. If they differ or `MessageKey` is absent, the dispatch should be rejected.

### 3.3 Produce a Partial Multisig Signature

The signer signs the **multisig-encoded** form of the transaction. The multisig encoding prepends the prefix `0x534D5400` and appends the signer's 20-byte account ID to the transaction bytes before hashing. This is distinct from the single-signer encoding (prefix `0x53545800`).

The output is a pair:
- **`SigningPubKey`** — the signer's compressed public key (hex)
- **`TxnSignature`** — the signature over the multisig-encoded bytes (hex)

### 3.4 Accept the Credential

**Signed by:** signer account

```
TransactionType: CredentialAccept
Account:         <signer-account>
Issuer:          <messenger-account>
CredentialType:  4D554C5449534947<mpt-issuance-id>
Memos:
  - Memo:
      MemoType: 5369676E696E675075624B6579   # hex("SigningPubKey")
      MemoData: <signer-public-key-hex>
  - Memo:
      MemoType: 546F6E5369676E6174757265      # hex("TxnSignature")
      MemoData: <partial-signature-hex>
```

On validation, the credential's `lsfAccepted` flag (`0x00010000`) is set and `credential.PreviousTxnID` is updated to the hash of this `CredentialAccept` transaction.

---

## Phase 4 — Submission

### 4.1 Assess Quorum

For each signer in the `SignerList`, retrieve their credential via `ledger_entry`:

```
credential: {
  subject:         <signer-address>
  issuer:          <messenger-account>
  credential_type: 4D554C5449534947<mpt-issuance-id>
}
```

If `credential.Flags & 0x00010000` (`lsfAccepted`) is set, the signer has provided a signature. Sum the weights of all accepted signers. Submission is possible when `currentWeight >= SignerQuorum`.

### 4.2 Collect Signatures

For each accepted credential, retrieve the `CredentialAccept` transaction via `credential.PreviousTxnID`. Extract:

- `Memos[n].Memo.MemoData` where `MemoType = 5369676E696E675075624B6579` → `SigningPubKey`
- `Memos[n].Memo.MemoData` where `MemoType = 546F6E5369676E6174757265` → `TxnSignature`

### 4.3 Assemble and Submit

Build the final transaction by adding a `Signers` array to the decoded unsigned transaction. XRPL requires signers to be sorted in **ascending order by 20-byte account ID**:

```
Signers:
  - Signer:
      Account:        <signer-address>
      SigningPubKey:  <hex>
      TxnSignature:   <hex>
  - Signer:
      ...   # sorted ascending by account ID bytes
```

Binary-encode the assembled transaction and submit. `SigningPubKey` remains `""` at the top level.

---

## Phase 5 — Cleanup

On successful transaction submission, the messenger account revokes all credentials and destroys the MPT.

### 5.1 Revoke Credentials

**Signed by:** messenger account  
**One transaction per signer**

```
TransactionType: CredentialDelete
Account:         <messenger-account>
Subject:         <signer-address>
CredentialType:  4D554C5449534947<mpt-issuance-id>
```

The issuer may delete credentials regardless of whether they have been accepted.

### 5.2 Destroy the MPT Issuance

**Signed by:** messenger account

```
TransactionType:    MPTokenIssuanceDestroy
Account:            <messenger-account>
MPTokenIssuanceID:  <mpt-issuance-id>
```

Succeeds because no tokens were ever distributed (outstanding balance is zero).

---

## Cancellation

If the process is abandoned before submission, the same cleanup applies — `CredentialDelete` for each signer followed by `MPTokenIssuanceDestroy`.

---

## Ledger Objects

| Object | Owned by | Created by | Destroyed by | Purpose |
|---|---|---|---|---|
| `SignerList` | Multisig account | `SignerListSet` | `SignerListSet` (empty entries) | Defines authorised signers and quorum |
| `MPTokenIssuance` | Messenger account | `MPTokenIssuanceCreate` | `MPTokenIssuanceDestroy` | Holds the unsigned transaction blob and dispatch metadata |
| `Credential` | Signer account (subject) | `CredentialCreate` | `CredentialDelete` | Notifies signer; carries their partial signature on acceptance |
| `Ticket` | Multisig account | `TicketCreate` | consumed on use | Allows dispatch with `Sequence: 0` for out-of-order execution |

---

## Fee Requirements

| Transaction | Signatory | Minimum fee |
|---|---|---|
| `SignerListSet` | Multisig account | standard |
| `AccountSet` | Multisig account | standard |
| `MPTokenIssuanceCreate` | Messenger account | standard |
| `CredentialCreate` × N | Messenger account | standard |
| `CredentialAccept` | Signer account | standard |
| Multisigned transaction | — | `(N + 1) × base_fee` where N = number of signing signers |
| `CredentialDelete` × N | Messenger account | standard |
| `MPTokenIssuanceDestroy` | Messenger account | standard |

---

## Field Reference

| Field / Value | Hex | Description |
|---|---|---|
| `MemoType: "TX"` | `5458` | Identifies the unsigned transaction blob in the MPT creation memo |
| `MemoType: "SigningPubKey"` | `5369676E696E675075624B6579` | Signer's public key in `CredentialAccept` |
| `MemoType: "TxnSignature"` | `546F6E5369676E6174757265` | Partial signature in `CredentialAccept` |
| `CredentialType` prefix `"MULTISIG"` | `4D554C5449534947` | Prepended to `mpt-issuance-id` to form the full 32-byte credential type |
| `asfDisableMaster` | `4` | `AccountSet` flag value to disable/enable the master key |
| `lsfDisableMaster` | `0x00100000` | `Flags` bitmask on account ledger entry |
| `lsfAccepted` | `0x00010000` | `Flags` bitmask on `Credential` ledger entry |
| Multisig signing prefix | `0x534D5400` | Prepended to transaction bytes before multisig hashing |
