# Multisig — Transactions for Signature Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Transactions for Signature" section on the Multisig screen showing MULTISIG credentials assigned to the current account, with a detail view for sender verification and partial multisig signing via CredentialAccept.

**Architecture:** Four layers: (1) `deriveAddress` imported from ripple-keypairs for MessageKey verification; (2) incoming credential list loaded during `loadMultisignData`, rendered in `renderMultisignScreen`; (3) `openMsSignDetail` fetches the MPT → tx memo → account_info for verification; (4) `signMsTransaction` produces a partial signature and routes a `CredentialAccept` through the existing review flow.

**Tech Stack:** Vanilla JS, ripple-keypairs `deriveAddress` (new import), ripple-binary-codec `encodeForSigning` (already imported), xrpl.js `account_info`, Chrome Extension HTML/CSS

---

## Files

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-incoming-card` to view-multisign; add `view-ms-sign-detail` |
| `src/popup/popup.css` | Incoming list row styles + verification badge styles |
| `src/popup/popup.js` | `deriveAddress` import; 2 state vars; card hide; incoming load; render section; `openMsSignDetail`; `getSignatureForAddress`; `signMsTransaction`; 2 event listeners |

---

## Task 1: Import deriveAddress

**Files:**
- Modify: `src/popup/popup.js:10`

- [ ] **Step 1: Add `deriveAddress` to ripple-keypairs import**

Find line 10:
```javascript
import { sign as keypairsSign } from 'ripple-keypairs';
```
Replace with:
```javascript
import { sign as keypairsSign, deriveAddress } from 'ripple-keypairs';
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: import deriveAddress from ripple-keypairs"
```

---

## Task 2: HTML — ms-incoming-card + view-ms-sign-detail

**Files:**
- Modify: `src/popup/popup.html`

- [ ] **Step 1: Add `ms-incoming-card` inside view-multisign after `ms-sent-card`**

Find:
```html
  <div id="ms-sent-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Transactions Gathering Signatures</div>
    <div id="ms-sent-list" class="ms-sent-list"></div>
  </div>
</div>
```
Replace with:
```html
  <div id="ms-sent-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Transactions Gathering Signatures</div>
    <div id="ms-sent-list" class="ms-sent-list"></div>
  </div>

  <!-- ── TRXN FOR SIGNATURE card ── -->
  <div id="ms-incoming-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Transactions for Signature</div>
    <div id="ms-incoming-list" class="ms-incoming-list"></div>
  </div>
</div>
```

- [ ] **Step 2: Add `view-ms-sign-detail` after the closing `</div>` of `view-multisign` and before `<!-- ===== MULTISIG TRANSACTION DETAIL ===== -->`**

Insert:
```html
<!-- ===== MULTISIG SIGN INCOMING ===== -->
<div id="view-ms-sign-detail" class="view hidden">
  <div class="view-header">
    <h2>Sign Transaction</h2>
  </div>

  <div class="tx-card" style="margin-bottom:6px">
    <div class="tx-row">
      <span class="tx-label">From</span>
      <span id="ms-sign-from" class="tx-value tx-address">—</span>
    </div>
    <div class="tx-row">
      <span class="tx-label">Via</span>
      <span id="ms-sign-via" class="tx-value tx-address">—</span>
    </div>
  </div>

  <div id="ms-sign-verification" class="ms-sign-verification hidden"></div>

  <div id="ms-sign-detail-rows" class="tx-card"></div>

  <details id="ms-sign-json-details" class="review-json-panel">
    <summary class="review-json-summary">Raw JSON</summary>
    <div class="review-json-body">
      <pre id="ms-sign-raw-json"></pre>
    </div>
  </details>

  <div id="ms-sign-detail-error" class="alert alert-error hidden" style="margin-top:8px"></div>

  <div class="action-row" style="margin-top:12px">
    <button id="ms-sign-close-btn" class="btn btn-ghost">Close</button>
    <button id="ms-sign-submit-btn" class="btn btn-primary">Sign Transaction</button>
  </div>
</div>

```

- [ ] **Step 3: Commit**
```bash
git add src/popup/popup.html
git commit -m "feat: add ms-incoming-card and view-ms-sign-detail HTML"
```

---

## Task 3: CSS — incoming list + verification badge

**Files:**
- Modify: `src/popup/popup.css` — append after `.ms-trxn-cancel-status.error`

- [ ] **Step 1: Add CSS rules**

Find:
```css
.ms-trxn-cancel-status.error { color: #ef4444; font-size: 11px; }
```
After this line add:
```css
/* Incoming transactions list */
.ms-incoming-list { }
.ms-incoming-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border); cursor: pointer; }
.ms-incoming-item:last-child { border-bottom: none; }
.ms-incoming-item:hover { background: var(--surface-2); }
.ms-incoming-item-left { flex: 1; }
.ms-incoming-item-label { font-size: 12px; font-weight: 500; }
.ms-incoming-item-hash { font-family: 'SF Mono', monospace; font-size: 10px; color: var(--text-3); margin-top: 1px; }
.ms-incoming-item-status { font-size: 11px; white-space: nowrap; }
.ms-incoming-item-status.signed { color: var(--success); }
.ms-incoming-item-status.waiting { color: var(--text-3); }
/* Verification badge */
.ms-sign-verification { font-size: 12px; font-weight: 500; padding: 8px 12px; border-radius: var(--radius-sm); margin-bottom: 8px; }
.ms-sign-verification.verified { background: rgba(16,185,129,0.12); color: var(--success); border: 1px solid rgba(16,185,129,0.3); }
.ms-sign-verification.failed { background: var(--danger-dim); color: var(--danger); border: 1px solid rgba(239,68,68,0.3); }
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.css
git commit -m "feat: add incoming list and verification badge CSS"
```

---

## Task 4: JS — state vars + loadMultisignData + renderMultisignScreen

**Files:**
- Modify: `src/popup/popup.js` — three edits

- [ ] **Step 1: Add state variables after `msCancelCredsDone`**

Find:
```javascript
let msCancelCredsDone   = false;  // true after cred revocations complete — skips creds on MPT retry
```
Replace with:
```javascript
let msCancelCredsDone   = false;  // true after cred revocations complete — skips creds on MPT retry
let msIncomingList      = [];     // [{ credential, txType, txHash }] — MULTISIG creds for current account
let msMsSignDetail      = null;   // { credential, decodedTxJson, verified, alreadySigned }
```

- [ ] **Step 2: Hide `ms-incoming-card` in `loadMultisignData` reset block**

Find:
```javascript
  $('ms-sent-card').classList.add('hidden');
```
Replace with:
```javascript
  $('ms-sent-card').classList.add('hidden');
  $('ms-incoming-card').classList.add('hidden');
```

- [ ] **Step 3: Load incoming credentials in `loadMultisignData`**

Find (inside the try block, just before the loading spinner is hidden):
```javascript
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```
Replace with:
```javascript
    msIncomingList = [];
    try {
      const credResp = await state.client.request({
        command: 'account_objects',
        account: state.activeAccount,
        ledger_index: 'validated',
      });
      const multisigCreds = (credResp.result.account_objects ?? [])
        .filter(o => o.LedgerEntryType === 'Credential' && hexToUtf8(o.CredentialType ?? '') === 'MULTISIG');
      for (const cred of multisigCreds) {
        try {
          const mptResp = await state.client.request({
            command: 'ledger_entry',
            mpt_issuance: cred.URI,
            ledger_index: 'validated',
          });
          const node = mptResp.result.node ?? {};
          const meta = JSON.parse(Buffer.from(node.MPTokenMetadata ?? '', 'hex').toString('utf8'));
          msIncomingList.push({
            credential: cred,
            txType: meta?.ai?.transaction_type ?? '—',
            txHash: (meta?.ai?.hash ?? '').slice(0, 8),
          });
        } catch { /* skip this credential */ }
      }
    } catch { /* silent — incoming list is optional */ }
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```

- [ ] **Step 4: Add TRXN FOR SIGNATURE section to `renderMultisignScreen`**

Find the closing brace of `renderMultisignScreen` (the `}` that follows the TRXN SENT block):
```javascript
    $('ms-sent-card').classList.remove('hidden');
  }
}
```
Replace with:
```javascript
    $('ms-sent-card').classList.remove('hidden');
  }

  // ── TRXN FOR SIGNATURE card ──
  const incomingListEl = $('ms-incoming-list');
  if (msIncomingList.length === 0) {
    $('ms-incoming-card').classList.add('hidden');
  } else {
    incomingListEl.innerHTML = msIncomingList.map((item, i) => {
      const signed = !!(item.credential.Flags & LSF_ACCEPTED);
      return `<div class="ms-incoming-item" data-incoming-idx="${i}">
        <div class="ms-incoming-item-left">
          <div class="ms-incoming-item-label">${esc(item.txType)}: ${esc(item.txHash)}…</div>
        </div>
        <span class="ms-incoming-item-status ${signed ? 'signed' : 'waiting'}">${signed ? '✓ Signed' : '○ Waiting'}</span>
      </div>`;
    }).join('');
    incomingListEl.querySelectorAll('.ms-incoming-item').forEach(el => {
      el.addEventListener('click', () => openMsSignDetail(+el.dataset.incomingIdx));
    });
    $('ms-incoming-card').classList.remove('hidden');
  }
}
```

- [ ] **Step 5: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: load and render TRXN FOR SIGNATURE list on multisig screen"
```

---

## Task 5: JS — openMsSignDetail

**Files:**
- Modify: `src/popup/popup.js` — insert in the `// MULTISIG SIGN INCOMING` section, before `renderSignerListSummary`

- [ ] **Step 1: Add the section header and function**

Find `function renderSignerListSummary()` and insert immediately before it:

```javascript
// ─────────────────────────────────────────────
// MULTISIG SIGN INCOMING
// ─────────────────────────────────────────────

async function openMsSignDetail(idx) {
  const item = msIncomingList[idx];
  if (!item) return;
  msMsSignDetail = null;

  $('ms-sign-from').textContent = '—';
  $('ms-sign-via').textContent  = '—';
  $('ms-sign-detail-rows').innerHTML = '';
  $('ms-sign-raw-json').textContent  = '';
  $('ms-sign-json-details').removeAttribute('open');
  $('ms-sign-verification').textContent = '';
  $('ms-sign-verification').className   = 'ms-sign-verification hidden';
  hideAlert('ms-sign-detail-error');
  $('ms-sign-submit-btn').disabled = true;
  $('ms-sign-submit-btn').textContent = 'Sign Transaction';
  $('ms-sign-close-btn').disabled = false;
  showView('ms-sign-detail');

  try {
    await ensureConnected();

    // Get MPT PreviousTxnID
    const mptResp = await state.client.request({
      command: 'ledger_entry',
      mpt_issuance: item.credential.URI,
      ledger_index: 'validated',
    });
    const mptNode  = mptResp.result.node ?? {};
    const prevTxId = mptNode.PreviousTxnID;
    if (!prevTxId) throw new Error('MPT has no PreviousTxnID.');

    // Fetch MPTokenIssuanceCreate tx and decode memo
    const txResp = await state.client.request({
      command: 'tx',
      transaction: prevTxId,
    });
    const memoData = txResp.result?.tx_json?.Memos?.[0]?.Memo?.MemoData ?? '';
    if (!memoData) throw new Error('No transaction data found in memo.');
    const decodedTxJson = decode(memoData);

    // Populate header
    const txAccount = decodedTxJson.Account ?? '';
    const issuer    = item.credential.Issuer ?? '';
    $('ms-sign-from').textContent = `${resolveAddrDisplay(txAccount)} (${truncAddr(txAccount)})`;
    $('ms-sign-via').textContent  = `${resolveAddrDisplay(issuer)} (${truncAddr(issuer)})`;

    // Verify MessageKey → derive address → compare to credential Issuer
    let verified = false;
    try {
      const infoResp = await state.client.request({
        command: 'account_info',
        account: txAccount,
        ledger_index: 'validated',
      });
      const messageKey = infoResp.result.account_data?.MessageKey ?? '';
      if (messageKey) verified = (deriveAddress(messageKey) === issuer);
    } catch { /* treat as unverified */ }

    const verEl = $('ms-sign-verification');
    if (verified) {
      verEl.textContent = '● Sender Verified';
      verEl.className   = 'ms-sign-verification verified';
    } else {
      verEl.textContent = '● Sender Failed Verification';
      verEl.className   = 'ms-sign-verification failed';
    }

    const alreadySigned = !!(item.credential.Flags & LSF_ACCEPTED);
    msMsSignDetail = { credential: item.credential, decodedTxJson, verified, alreadySigned };

    $('ms-sign-detail-rows').innerHTML = buildTxRows(decodedTxJson);
    $('ms-sign-raw-json').textContent  = JSON.stringify(decodedTxJson, null, 2);

    $('ms-sign-submit-btn').disabled =
      !verified || alreadySigned || isActiveAccountReadOnly();
  } catch (err) {
    showAlert('ms-sign-detail-error', `Failed to load: ${err.message || 'Unknown error'}`);
  }
}

```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: add openMsSignDetail function"
```

---

## Task 6: JS — getSignatureForAddress + signMsTransaction

**Files:**
- Modify: `src/popup/popup.js` — insert after `openMsSignDetail`, before `renderSignerListSummary`

- [ ] **Step 1: Add both functions**

Find `function renderSignerListSummary()` and insert immediately before it (after `openMsSignDetail`'s closing `}`):

```javascript
async function getSignatureForAddress(txJson, address) {
  const wallet = getWalletForAddress(address);
  if (wallet) {
    const sig = keypairsSign(encodeForSigning(txJson), wallet.privateKey).toUpperCase();
    return { pubKey: wallet.publicKey, sig };
  }
  const ledgerKr = state.keyrings.find(k => k.type === 'ledger' && k.address === address);
  if (ledgerKr) {
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

async function signMsTransaction() {
  if (!msMsSignDetail) return;

  $('ms-sign-submit-btn').disabled = true;
  $('ms-sign-submit-btn').textContent = 'Signing…';
  hideAlert('ms-sign-detail-error');

  try {
    const { credential, decodedTxJson } = msMsSignDetail;
    const { pubKey, sig } = await getSignatureForAddress(decodedTxJson, state.activeAccount);

    const txJson = {
      TransactionType: 'CredentialAccept',
      Account: state.activeAccount,
      Issuer: credential.Issuer,
      CredentialType: '4D554C5449534947',
      Memos: [
        { Memo: {
          MemoType: Buffer.from('SigningPubKey').toString('hex').toUpperCase(),
          MemoData: pubKey,
        }},
        { Memo: {
          MemoType: Buffer.from('TxnSignature').toString('hex').toUpperCase(),
          MemoData: sig,
        }},
      ],
    };

    reviewMultisignTx(txJson, 'Signature submitted.');
  } catch (err) {
    showAlert('ms-sign-detail-error', `Signing failed: ${err.message || 'Unknown error'}`);
    $('ms-sign-submit-btn').disabled = false;
    $('ms-sign-submit-btn').textContent = 'Sign Transaction';
  }
}

```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: add getSignatureForAddress and signMsTransaction"
```

---

## Task 7: JS — event listeners + build

**Files:**
- Modify: `src/popup/popup.js` — add 2 listeners after the existing `ms-trxn-cancel-btn` listener

- [ ] **Step 1: Add event listeners**

Find:
```javascript
$('ms-trxn-close-btn').addEventListener('click', () => { msTrxnDetail = null; openMultisignView(); });
$('ms-trxn-cancel-btn').addEventListener('click', () => cancelMsTrxn().catch(() => {}));
```
Replace with:
```javascript
$('ms-trxn-close-btn').addEventListener('click', () => { msTrxnDetail = null; openMultisignView(); });
$('ms-trxn-cancel-btn').addEventListener('click', () => cancelMsTrxn().catch(() => {}));
$('ms-sign-close-btn').addEventListener('click', () => { msMsSignDetail = null; openMultisignView(); });
$('ms-sign-submit-btn').addEventListener('click', () => signMsTransaction().catch(() => {}));
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: wire sign incoming event listeners"
```

- [ ] **Step 3: Build**
```bash
npm run build
```
Expected: both `background` and `popup` compiled successfully, no errors.

- [ ] **Step 4: Manual verification**

1. **No MULTISIG credentials:** Open Multisig — `ms-incoming-card` must be hidden.
2. **Has unaccepted MULTISIG credential:** After a "Send for Multisig" dispatch (on the receiving signer's wallet), open Multisig — card shows with `○ Waiting` status.
3. **Click row:** `view-ms-sign-detail` opens; From/Via fields populated; `● Sender Verified` (green) if MessageKey matches issuer.
4. **Verification fails:** Red `● Sender Failed Verification` + Sign button disabled.
5. **Sign Transaction:** Review screen appears with CredentialAccept tx showing two Memos (SigningPubKey + TxnSignature). Confirm → success.
6. **Already signed:** Row shows `✓ Signed`; Sign button disabled when opened.

---

## Self-Review Notes

- `hexToUtf8` is defined at line 2306, accessible in module scope for the `loadMultisignData` filter.
- `LSF_ACCEPTED = 0x00010000` is a module-level const (line 2304), accessible in `renderMultisignScreen`.
- `deriveAddress(publicKeyHex)` from ripple-keypairs takes a compressed public key hex string (same format as `wallet.publicKey` and `MessageKey`) and returns an XRPL r-address.
- `credential.URI` on ledger credential objects is the raw hex mpt_issuance_id (stored that way by `executeMultisigDispatch`).
- `reviewMultisignTx(txJson, successMsg)` sets `backView: 'multisign'` which triggers `openMultisignView()` on tx completion — the incoming list will reload and show `✓ Signed`.
- `encode(txJson)` is used for Ledger signing (the Ledger XRP app handles the signing prefix internally). For software wallets, `encodeForSigning(txJson)` is used directly.
