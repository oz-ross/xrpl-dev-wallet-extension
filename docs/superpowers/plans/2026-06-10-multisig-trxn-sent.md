# Multisig TRXN SENT Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a TRXN SENT history section to the Multisig screen, filter MULTISIG credentials from the main list, and implement a detail/cancel flow for dispatched transactions.

**Architecture:** Three independent changes wired together: (1) display filter on `renderCredentials`; (2) `ms-sent-card` in the Multisig screen fed by `msSentList` loaded from the messenger account's MPTokenIssuance objects; (3) `view-ms-trxn-detail` that decodes the tx memo and drives a sequential cancel flow using `signWithAddress`.

**Tech Stack:** Vanilla JS, ripple-binary-codec `decode` (newly imported), xrpl.js `decodeMPTokenMetadata` (already imported), Chrome Extension HTML/CSS

---

## Files

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-sent-card` to view-multisign; add `view-ms-trxn-detail` |
| `src/popup/popup.css` | Add sent list row styles and cancel progress styles |
| `src/popup/popup.js` | Add `decode` import; 2 new state vars; credential filter; sent list load; render extension; `openMsTrxnDetail`; `cancelMsTrxn`; event listeners |

---

## Task 1: Add `decode` import

**Files:**
- Modify: `src/popup/popup.js:9`

- [ ] **Step 1: Add `decode` to the ripple-binary-codec import**

Find line 9:
```javascript
import { encode, encodeForSigning } from 'ripple-binary-codec';
```

Replace with:
```javascript
import { encode, encodeForSigning, decode } from 'ripple-binary-codec';
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: import decode from ripple-binary-codec"
```

---

## Task 2: Filter MULTISIG credentials from display

**Files:**
- Modify: `src/popup/popup.js:2333–2363` (`renderCredentials`)

- [ ] **Step 1: Add filter at the top of `renderCredentials`**

Find:
```javascript
function renderCredentials(creds) {
  const card   = $('credential-card');
  const listEl = $('credential-list');

  if (!creds.length) {
    card.classList.add('hidden');
    listEl.innerHTML = '';
    return;
  }
```

Replace with:
```javascript
function renderCredentials(creds) {
  const card   = $('credential-card');
  const listEl = $('credential-list');

  const visibleCreds = creds.filter(c => hexToUtf8(c.CredentialType ?? '') !== 'MULTISIG');
  if (!visibleCreds.length) {
    card.classList.add('hidden');
    listEl.innerHTML = '';
    return;
  }
```

Then find the two remaining references to `creds` in the function body (the `.map` and the `_credentials` assignment) and replace with `visibleCreds`:

```javascript
  card.classList.remove('hidden');
  listEl.innerHTML = visibleCreds.map((c, i) => {
    const typeHex    = c.CredentialType ?? '';
    const typeLabel  = hexToUtf8(typeHex) || typeHex.slice(0, 16);
    const issuer     = c.Issuer ?? '';
    const accepted   = !!(c.Flags & LSF_ACCEPTED);
    const statusLabel = accepted ? 'Accepted' : 'Pending';
    const statusClass = accepted ? 'cred-status-accepted' : 'cred-status-pending';
    return `
      <div class="credential-item" data-cred-index="${i}">
        <div class="cred-info">
          <span class="cred-type">${esc(typeLabel)}</span>
          <span class="cred-issuer" title="${esc(issuer)}">${esc(resolveAddrDisplay(issuer))}</span>
        </div>
        <span class="cred-status ${statusClass}">${statusLabel}</span>
      </div>`;
  }).join('');

  // Store credentials on the element for click access
  listEl._credentials = visibleCreds;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: filter MULTISIG credentials from credentials display"
```

---

## Task 3: HTML — ms-sent-card + view-ms-trxn-detail

**Files:**
- Modify: `src/popup/popup.html` — two insertions

- [ ] **Step 1: Add `ms-sent-card` to `view-multisign`**

Find the closing tags of `view-multisign` (the master key card is the last card, then `</div>` closes the view):

```html
    <button id="ms-master-key-btn" class="btn btn-full ms-master-key-btn">…</button>
  </div>
</div>
```

Replace with:

```html
    <button id="ms-master-key-btn" class="btn btn-full ms-master-key-btn">…</button>
  </div>

  <!-- ── TRXN SENT card ── -->
  <div id="ms-sent-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Transactions Sent</div>
    <div id="ms-sent-list" class="ms-sent-list"></div>
  </div>
</div>
```

- [ ] **Step 2: Add `view-ms-trxn-detail` as a new top-level view**

Immediately after the closing `</div>` of `view-multisign` (and before the `<!-- ===== MULTISIGN PICKER MODAL ===== -->` comment), insert:

```html
<!-- ===== MULTISIG TRANSACTION DETAIL ===== -->
<div id="view-ms-trxn-detail" class="view hidden">
  <div class="view-header">
    <h2>Transaction Details</h2>
  </div>

  <div id="ms-trxn-detail-rows" class="tx-card"></div>

  <details id="ms-trxn-json-details" class="review-json-panel">
    <summary class="review-json-summary">Raw JSON</summary>
    <div class="review-json-body">
      <pre id="ms-trxn-raw-json"></pre>
    </div>
  </details>

  <div id="ms-trxn-cancel-progress" class="ms-trxn-cancel-progress hidden"></div>
  <div id="ms-trxn-detail-error" class="alert alert-error hidden" style="margin-top:8px"></div>

  <div class="action-row" style="margin-top:12px">
    <button id="ms-trxn-close-btn" class="btn btn-ghost">Close</button>
    <button id="ms-trxn-cancel-btn" class="btn btn-primary">Cancel Transaction</button>
  </div>
</div>

```

- [ ] **Step 3: Commit**

```bash
git add src/popup/popup.html
git commit -m "feat: add ms-sent-card and view-ms-trxn-detail HTML"
```

---

## Task 4: CSS — sent list and cancel progress styles

**Files:**
- Modify: `src/popup/popup.css` — append after the last multisign dispatch rule (`.ms-dispatch-nft-status.error`)

- [ ] **Step 1: Add styles**

Find:
```css
.ms-dispatch-nft-status.error { color: #ef4444; border-color: rgba(239,68,68,0.3); }
```

After this line add:

```css
/* Sent list */
.ms-sent-list { }
.ms-sent-item { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--border); cursor: pointer; }
.ms-sent-item:last-child { border-bottom: none; }
.ms-sent-item:hover { background: var(--surface-2); }
.ms-sent-item-label { font-size: 12px; font-weight: 500; }
.ms-sent-item-hash { font-family: 'SF Mono', monospace; font-size: 10px; color: var(--text-3); margin-top: 1px; }
.ms-sent-item-chevron { color: var(--text-3); font-size: 16px; line-height: 1; }
/* Cancel progress */
.ms-trxn-cancel-progress { margin-top: 8px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.ms-trxn-cancel-row { display: flex; justify-content: space-between; align-items: center; padding: 7px 14px; border-bottom: 1px solid var(--border); font-size: 12px; }
.ms-trxn-cancel-row:last-child { border-bottom: none; }
.ms-trxn-cancel-label { color: var(--text-2); flex: 1; margin-right: 8px; }
.ms-trxn-cancel-status { min-width: 70px; text-align: right; color: var(--text-3); }
.ms-trxn-cancel-status.success { color: var(--success); }
.ms-trxn-cancel-status.error { color: #ef4444; font-size: 11px; }
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.css
git commit -m "feat: add sent list and cancel progress CSS"
```

---

## Task 5: JS — state vars + loadMultisignData + renderMultisignScreen

**Files:**
- Modify: `src/popup/popup.js` — state vars block, `loadMultisignData`, `renderMultisignScreen`

- [ ] **Step 1: Add state variables**

Find:
```javascript
let msDispatchTxHex     = '';     // autofilled+encoded unsigned tx blob for dispatch
let msDispatchTxType    = '';     // TransactionType of the pending tx, for MPT metadata
let msDispatchSigners   = [];     // [{ address, name }] for current dispatch
```

Replace with:
```javascript
let msDispatchTxHex     = '';     // autofilled+encoded unsigned tx blob for dispatch
let msDispatchTxType    = '';     // TransactionType of the pending tx, for MPT metadata
let msDispatchSigners   = [];     // [{ address, name }] for current dispatch
let msSentList          = [];     // MPTokenIssuance objects with ac==='multisig' from messenger
let msTrxnDetail        = null;   // { mptObj, decodedTxJson } for currently open detail
```

- [ ] **Step 2: Hide `ms-sent-card` in `loadMultisignData` reset block**

Find:
```javascript
  $('ms-master-key-card').classList.add('hidden');
  $('ms-messenger-card').classList.add('hidden');
```

Replace with:
```javascript
  $('ms-master-key-card').classList.add('hidden');
  $('ms-messenger-card').classList.add('hidden');
  $('ms-sent-card').classList.add('hidden');
```

- [ ] **Step 3: Fetch sent list in `loadMultisignData` after messenger link loads**

Find:
```javascript
    await refreshAddressNames();
    msMessengerAddress = await loadMessengerLink(state.activeAccount);
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```

Replace with:
```javascript
    await refreshAddressNames();
    msMessengerAddress = await loadMessengerLink(state.activeAccount);
    msSentList = [];
    if (msMessengerAddress) {
      try {
        const allObjs = await fetchAllAccountObjects(msMessengerAddress);
        msSentList = allObjs.filter(o => {
          if (o.LedgerEntryType !== 'MPTokenIssuance') return false;
          try {
            return decodeMPTokenMetadata(o.MPTokenMetadata ?? '')?.ac === 'multisig';
          } catch { return false; }
        });
      } catch { /* silent — sent list is optional */ }
    }
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```

- [ ] **Step 4: Add TRXN SENT section to `renderMultisignScreen`**

Find the closing brace of `renderMultisignScreen` (after the messenger card section ends):
```javascript
  hideAlert('ms-messenger-error');
  $('ms-messenger-card').classList.remove('hidden');
}
```

Replace with:
```javascript
  hideAlert('ms-messenger-error');
  $('ms-messenger-card').classList.remove('hidden');

  // ── TRXN SENT card ──
  const sentListEl = $('ms-sent-list');
  if (msSentList.length === 0) {
    $('ms-sent-card').classList.add('hidden');
  } else {
    sentListEl.innerHTML = msSentList.map((o, i) => {
      let txType = '—', txHash = '—';
      try {
        const meta = decodeMPTokenMetadata(o.MPTokenMetadata ?? '');
        txType = meta?.ai?.transaction_type ?? '—';
        txHash = (meta?.ai?.hash ?? '').slice(0, 8);
      } catch { /* keep defaults */ }
      return `<div class="ms-sent-item" data-sent-idx="${i}">
        <div>
          <div class="ms-sent-item-label">${esc(txType)}</div>
          <div class="ms-sent-item-hash">${esc(txHash)}…</div>
        </div>
        <span class="ms-sent-item-chevron">›</span>
      </div>`;
    }).join('');
    sentListEl.querySelectorAll('.ms-sent-item').forEach(el => {
      el.addEventListener('click', () => openMsTrxnDetail(+el.dataset.sentIdx));
    });
    $('ms-sent-card').classList.remove('hidden');
  }
}
```

- [ ] **Step 5: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: load and render TRXN SENT list on multisig screen"
```

---

## Task 6: JS — openMsTrxnDetail

**Files:**
- Modify: `src/popup/popup.js` — insert after `renderMultisignScreen` closing brace

- [ ] **Step 1: Add `openMsTrxnDetail` in a new MULTISIG TRXN DETAIL section**

Find the line after `renderMultisignScreen` ends (the `renderSignerListSummary` function follows it):
```javascript
function renderSignerListSummary() {
```

Insert before it:

```javascript
// ─────────────────────────────────────────────
// MULTISIG TRXN DETAIL
// ─────────────────────────────────────────────

async function openMsTrxnDetail(idx) {
  const mptObj = msSentList[idx];
  if (!mptObj) return;
  msTrxnDetail = null;

  $('ms-trxn-detail-rows').innerHTML = '';
  $('ms-trxn-raw-json').textContent = '';
  $('ms-trxn-json-details').removeAttribute('open');
  $('ms-trxn-cancel-progress').classList.add('hidden');
  $('ms-trxn-cancel-progress').innerHTML = '';
  hideAlert('ms-trxn-detail-error');
  $('ms-trxn-cancel-btn').disabled = false;
  $('ms-trxn-cancel-btn').textContent = 'Cancel Transaction';
  $('ms-trxn-cancel-btn').classList.remove('hidden');
  $('ms-trxn-close-btn').disabled = false;
  showView('ms-trxn-detail');

  try {
    await ensureConnected();
    const txResp = await state.client.request({
      command: 'tx',
      transaction: mptObj.PreviousTxnID,
    });
    const memoData = txResp.result?.Memos?.[0]?.Memo?.MemoData ?? '';
    if (!memoData) throw new Error('No transaction data found in memo.');
    const decodedTxJson = decode(memoData);
    msTrxnDetail = { mptObj, decodedTxJson };
    $('ms-trxn-detail-rows').innerHTML = buildTxRows(decodedTxJson);
    $('ms-trxn-raw-json').textContent = JSON.stringify(decodedTxJson, null, 2);
  } catch (err) {
    showAlert('ms-trxn-detail-error', `Failed to load: ${err.message || 'Unknown error'}`);
    $('ms-trxn-cancel-btn').disabled = true;
  }
}

```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add openMsTrxnDetail function"
```

---

## Task 7: JS — cancelMsTrxn

**Files:**
- Modify: `src/popup/popup.js` — insert after `openMsTrxnDetail`

- [ ] **Step 1: Add `cancelMsTrxn`**

Find (the function inserted just before `renderSignerListSummary`):
```javascript
// ─────────────────────────────────────────────
// MULTISIG TRXN DETAIL
// ─────────────────────────────────────────────

async function openMsTrxnDetail(idx) {
```

The close of `openMsTrxnDetail` is followed immediately by `renderSignerListSummary`. Insert `cancelMsTrxn` between them.

After the closing brace of `openMsTrxnDetail` and before `function renderSignerListSummary() {`, insert:

```javascript
async function cancelMsTrxn() {
  if (!msTrxnDetail || !msSignerList) {
    showAlert('ms-trxn-detail-error', 'Signer list not loaded. Return to Multisig screen and try again.');
    return;
  }

  $('ms-trxn-cancel-btn').disabled = true;
  $('ms-trxn-cancel-btn').textContent = 'Cancelling…';
  $('ms-trxn-close-btn').disabled = true;
  hideAlert('ms-trxn-detail-error');

  const { mptObj }  = msTrxnDetail;
  const signers     = msSignerList.SignerEntries ?? [];
  const progressEl  = $('ms-trxn-cancel-progress');
  progressEl.classList.remove('hidden');

  const allSteps = [
    ...signers.map(e => ({
      label: `Revoke: ${resolveAddrDisplay(e.SignerEntry.Account)} (${truncAddr(e.SignerEntry.Account)})`,
      type: 'cred',
      address: e.SignerEntry.Account,
    })),
    { label: 'Destroy MPT issuance', type: 'mpt' },
  ];

  progressEl.innerHTML = allSteps.map((s, i) =>
    `<div class="ms-trxn-cancel-row">
      <span class="ms-trxn-cancel-label">${esc(s.label)}</span>
      <span class="ms-trxn-cancel-status" id="ms-cancel-status-${i}">…</span>
    </div>`
  ).join('');

  try {
    await ensureConnected();
  } catch (err) {
    showAlert('ms-trxn-detail-error', `Connection failed: ${err.message || 'Unknown error'}`);
    $('ms-trxn-cancel-btn').disabled = false;
    $('ms-trxn-cancel-btn').textContent = 'Cancel Transaction';
    $('ms-trxn-close-btn').disabled = false;
    return;
  }

  for (let i = 0; i < signers.length; i++) {
    const signerAddr = signers[i].SignerEntry.Account;
    const statusEl   = $(`ms-cancel-status-${i}`);
    statusEl.textContent = '…';
    statusEl.className = 'ms-trxn-cancel-status';
    try {
      const tx = {
        TransactionType: 'CredentialDelete',
        Account: msMessengerAddress,
        Subject: signerAddr,
        CredentialType: '4D554C5449534947',
      };
      const prepared = await state.client.autofill(tx);
      const tx_blob  = await signWithAddress(prepared, msMessengerAddress);
      const resp     = await state.client.submitAndWait(tx_blob);
      const result   = resp.result?.meta?.TransactionResult;
      if (result === 'tesSUCCESS' || result === 'tecNO_ENTRY') {
        statusEl.textContent = '✓';
        statusEl.className = 'ms-trxn-cancel-status success';
      } else {
        statusEl.textContent = `✗ ${result ?? 'Unknown'}`;
        statusEl.className = 'ms-trxn-cancel-status error';
      }
    } catch (err) {
      statusEl.textContent = `✗ ${(err.message || 'Error').slice(0, 20)}`;
      statusEl.className = 'ms-trxn-cancel-status error';
    }
  }

  const mptStatusEl = $(`ms-cancel-status-${signers.length}`);
  mptStatusEl.textContent = '…';
  mptStatusEl.className = 'ms-trxn-cancel-status';
  try {
    const destroyTx = {
      TransactionType: 'MPTokenIssuanceDestroy',
      Account: msMessengerAddress,
      MPTokenIssuanceID: mptObj.MPTokenIssuanceID,
    };
    const prepared = await state.client.autofill(destroyTx);
    const tx_blob  = await signWithAddress(prepared, msMessengerAddress);
    const resp     = await state.client.submitAndWait(tx_blob);
    const result   = resp.result?.meta?.TransactionResult;
    if (result === 'tesSUCCESS') {
      mptStatusEl.textContent = '✓';
      mptStatusEl.className = 'ms-trxn-cancel-status success';
    } else {
      mptStatusEl.textContent = `✗ ${result ?? 'Unknown'}`;
      mptStatusEl.className = 'ms-trxn-cancel-status error';
    }
  } catch (err) {
    mptStatusEl.textContent = `✗ ${(err.message || 'Error').slice(0, 20)}`;
    mptStatusEl.className = 'ms-trxn-cancel-status error';
  }

  $('ms-trxn-cancel-btn').classList.add('hidden');
  $('ms-trxn-close-btn').disabled = false;
}

```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add cancelMsTrxn function"
```

---

## Task 8: JS — event listeners + build

**Files:**
- Modify: `src/popup/popup.js` — add 2 listeners after the existing ms-messenger-btn listener

- [ ] **Step 1: Add event listeners**

Find:
```javascript
$('ms-master-key-btn').addEventListener('click', submitMasterKeyToggle);
$('ms-messenger-btn').addEventListener('click', submitMessengerAccountSet);
```

Replace with:
```javascript
$('ms-master-key-btn').addEventListener('click', submitMasterKeyToggle);
$('ms-messenger-btn').addEventListener('click', submitMessengerAccountSet);
$('ms-trxn-close-btn').addEventListener('click', () => { msTrxnDetail = null; openMultisignView(); });
$('ms-trxn-cancel-btn').addEventListener('click', () => cancelMsTrxn().catch(() => {}));
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: wire trxn detail event listeners"
```

- [ ] **Step 3: Build**

```bash
npm run build
```

Expected: both `background` and `popup` compiled successfully, no errors.

- [ ] **Step 4: Manual verification**

1. **Credential filter:** Create or view a MULTISIG credential on an account — it must NOT appear in the Credentials section.
2. **No messenger account:** Open Multisig screen with no messenger account set — `ms-sent-card` must be hidden.
3. **Messenger has no MULTISIG MPTs:** Set a messenger account with no dispatched transactions — `ms-sent-card` must be hidden.
4. **Messenger has MULTISIG MPTs:** After a successful "Send for Multisig" dispatch, open Multisig — `ms-sent-card` appears with one row showing `Payment: A3F8B2C1…`.
5. **Click row:** `view-ms-trxn-detail` opens, `buildTxRows` output appears, Raw JSON collapsed.
6. **Cancel:** Clicking "Cancel Transaction" shows the progress list, marks each step ✓ or ✗, destroys MPT. The row disappears from the sent list after Close.

---

## Self-Review Notes

- `decode(memoData)` from ripple-binary-codec takes a hex string directly — `memoData` from the tx response is already hex.
- `tecNO_ENTRY` on `CredentialDelete` means the credential was already gone — treated as success so partial cancels don't block completion.
- Close button calls `openMultisignView()` which resets all state and re-runs `loadMultisignData()` — the destroyed MPT will no longer appear in the refreshed `msSentList`.
- `msSentList[idx]` index is stable between `renderMultisignScreen` and `openMsTrxnDetail` because the list only refreshes on full `loadMultisignData` reload.
- `MPTokenIssuanceID` is the field name on `MPTokenIssuance` ledger objects (confirmed at popup.js line 4033).
