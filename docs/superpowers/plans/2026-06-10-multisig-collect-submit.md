# Multisig — Collect Signatures & Submit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add quorum progress tracking to the "Transactions Gathering Signatures" list and a Submit capability that collects partial signatures from accepted credential memos, constructs a properly sorted XRPL `Signers` array, submits the multisigned transaction, and cleans up on success.

**Architecture:** `msSentList` is enriched during `loadMultisignData` — each entry gains `{ mptObj, txType, txHash, currentWeight, quorum, signerStatus }` via parallel `ledger_entry` credential checks per signer. The detail view gains a quorum card, expiry check, and Submit button. `submitMultisigTx` collects signatures from `CredentialAccept` tx memos, sorts by `decodeAccountID`, encodes, and submits; cleanup reuses the cancel flow pattern.

**Tech Stack:** Vanilla JS, `decodeAccountID` from xrpl.js (new import), `encode`/`encodeForMultisigning` from ripple-binary-codec (already imported), `LSF_ACCEPTED = 0x00010000` (existing constant)

---

## Files

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add quorum card + expired warn + submit btn to `view-ms-trxn-detail` |
| `src/popup/popup.css` | `.ms-sent-weight-badge` + quorum weight colour classes |
| `src/popup/popup.js` | `decodeAccountID` import; enrich `msSentList` build; update TRXN SENT render; extend `openMsTrxnDetail`; add `hexFromMemo`; add `submitMultisigTx`; add event listener |

---

## Task 1: Import decodeAccountID

**Files:**
- Modify: `src/popup/popup.js:2`

- [ ] **Step 1: Add `decodeAccountID` to the xrpl import**

Find line 2:
```javascript
import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeMPTokenMetadata, isValidClassicAddress } from 'xrpl';
```
Replace with:
```javascript
import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeAccountID, decodeMPTokenMetadata, isValidClassicAddress } from 'xrpl';
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: import decodeAccountID from xrpl"
```

---

## Task 2: HTML — quorum card + expired warning + submit button

**Files:**
- Modify: `src/popup/popup.html:1651–1672` (view-ms-trxn-detail)

- [ ] **Step 1: Add quorum card and expired warning after ms-trxn-detail-rows**

Find:
```html
  <div id="ms-trxn-detail-rows" class="tx-card"></div>

  <details id="ms-trxn-json-details" class="review-json-panel">
```
Replace with:
```html
  <div id="ms-trxn-detail-rows" class="tx-card"></div>

  <div id="ms-trxn-quorum-card" class="tx-card hidden" style="margin-top:6px">
    <div class="tx-row">
      <span class="tx-label">Quorum required</span>
      <span id="ms-trxn-quorum-required" class="tx-value">—</span>
    </div>
    <div class="tx-row">
      <span class="tx-label">Current weight</span>
      <span id="ms-trxn-current-weight" class="tx-value">—</span>
    </div>
  </div>

  <div id="ms-trxn-expired-warn" class="alert alert-warn hidden" style="margin-top:8px">
    Transaction has expired and cannot be submitted.
  </div>

  <details id="ms-trxn-json-details" class="review-json-panel">
```

- [ ] **Step 2: Add submit button to the action row**

Find:
```html
  <div class="action-row" style="margin-top:12px">
    <button id="ms-trxn-close-btn" class="btn btn-ghost">Close</button>
    <button id="ms-trxn-cancel-btn" class="btn btn-primary">Cancel Transaction</button>
  </div>
```
Replace with:
```html
  <div class="action-row" style="margin-top:12px">
    <button id="ms-trxn-close-btn" class="btn btn-ghost">Close</button>
    <button id="ms-trxn-cancel-btn" class="btn btn-primary">Cancel Transaction</button>
    <button id="ms-trxn-submit-btn" class="btn btn-primary hidden">Submit</button>
  </div>
```

- [ ] **Step 3: Commit**
```bash
git add src/popup/popup.html
git commit -m "feat: add quorum card and submit button to ms-trxn-detail view"
```

---

## Task 3: CSS — weight badge + quorum colour classes

**Files:**
- Modify: `src/popup/popup.css` — append after `.ms-sent-item-chevron`

- [ ] **Step 1: Add CSS rules**

Find:
```css
.ms-sent-item-chevron { color: var(--text-3); font-size: 16px; line-height: 1; }
```
After this line add:
```css
.ms-sent-weight-badge { font-size: 11px; font-weight: 600; min-width: 36px; text-align: right; white-space: nowrap; }
.ms-sent-weight-badge.met { color: var(--success); }
.ms-sent-weight-badge.pending { color: var(--text-3); }
.ms-trxn-weight-met { color: var(--success); font-weight: 600; }
.ms-trxn-weight-pending { color: var(--text-3); }
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.css
git commit -m "feat: add weight badge and quorum colour CSS"
```

---

## Task 4: JS — enrich msSentList + update TRXN SENT render

**Files:**
- Modify: `src/popup/popup.js` — two edits

- [ ] **Step 1: Replace msSentList build with enriched version**

Find the msSentList block inside `loadMultisignData`:
```javascript
    msSentList = [];
    if (msMessengerAddress) {
      try {
        const allObjs = await fetchAllAccountObjects(msMessengerAddress);
        msSentList = allObjs.filter(o => {
          if (o.LedgerEntryType !== 'MPTokenIssuance') return false;
          try {
            const meta = JSON.parse(Buffer.from(o.MPTokenMetadata ?? '', 'hex').toString('utf8'));
            return meta?.ac === 'multisig';
          } catch { return false; }
        });
      } catch { /* silent — sent list is optional */ }
    }
```
Replace with:
```javascript
    msSentList = [];
    if (msMessengerAddress) {
      try {
        const allObjs = await fetchAllAccountObjects(msMessengerAddress);
        const rawMpts = allObjs.filter(o => {
          if (o.LedgerEntryType !== 'MPTokenIssuance') return false;
          try {
            return JSON.parse(Buffer.from(o.MPTokenMetadata ?? '', 'hex').toString('utf8'))?.ac === 'multisig';
          } catch { return false; }
        });
        msSentList = await Promise.all(rawMpts.map(async mptObj => {
          let txType = '—', txHash = '—';
          try {
            const meta = JSON.parse(Buffer.from(mptObj.MPTokenMetadata ?? '', 'hex').toString('utf8'));
            txType = meta?.ai?.transaction_type ?? '—';
            txHash = (meta?.ai?.hash ?? '').slice(0, 8);
          } catch { /* keep defaults */ }
          const quorum = msSignerList?.SignerQuorum ?? 0;
          let signerStatus = [];
          if (msSignerList && msMessengerAddress) {
            signerStatus = await Promise.all(
              (msSignerList.SignerEntries ?? []).map(async e => {
                const addr   = e.SignerEntry.Account;
                const weight = e.SignerEntry.SignerWeight;
                try {
                  const credResp = await state.client.request({
                    command: 'ledger_entry',
                    credential: {
                      subject: addr,
                      issuer: msMessengerAddress,
                      credential_type: '4D554C5449534947',
                    },
                    ledger_index: 'validated',
                  });
                  const cred     = credResp.result.node ?? {};
                  const accepted = !!(cred.Flags & LSF_ACCEPTED);
                  return { address: addr, weight, accepted, prevTxnId: accepted ? cred.PreviousTxnID : null };
                } catch {
                  return { address: addr, weight, accepted: false, prevTxnId: null };
                }
              })
            );
          }
          const currentWeight = signerStatus
            .filter(s => s.accepted)
            .reduce((sum, s) => sum + s.weight, 0);
          return { mptObj, txType, txHash, currentWeight, quorum, signerStatus };
        }));
      } catch { /* silent — sent list is optional */ }
    }
```

- [ ] **Step 2: Update TRXN SENT render in `renderMultisignScreen` to use enriched entries**

Find the TRXN SENT rendering block:
```javascript
    sentListEl.innerHTML = msSentList.map((o, i) => {
      let txType = '—', txHash = '—';
      try {
        const meta = JSON.parse(Buffer.from(o.MPTokenMetadata ?? '', 'hex').toString('utf8'));
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
```
Replace with:
```javascript
    sentListEl.innerHTML = msSentList.map((entry, i) => {
      const met   = entry.quorum > 0 && entry.currentWeight >= entry.quorum;
      const badge = entry.quorum > 0
        ? `<span class="ms-sent-weight-badge ${met ? 'met' : 'pending'}">${entry.currentWeight}/${entry.quorum}</span>`
        : `<span class="ms-sent-weight-badge pending">—</span>`;
      return `<div class="ms-sent-item" data-sent-idx="${i}">
        <div>
          <div class="ms-sent-item-label">${esc(entry.txType)}</div>
          <div class="ms-sent-item-hash">${esc(entry.txHash)}…</div>
        </div>
        ${badge}
      </div>`;
    }).join('');
```

- [ ] **Step 3: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: enrich msSentList with quorum data and update TRXN SENT render"
```

---

## Task 5: JS — extend openMsTrxnDetail

**Files:**
- Modify: `src/popup/popup.js` — three edits inside `openMsTrxnDetail`

- [ ] **Step 1: Change mptObj access to use enriched entry + extend reset block**

Find:
```javascript
async function openMsTrxnDetail(idx) {
  const mptObj = msSentList[idx];
  if (!mptObj) return;
  msTrxnDetail = null;
  msCancelCredsDone = false;

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
```
Replace with:
```javascript
async function openMsTrxnDetail(idx) {
  const entry = msSentList[idx];
  if (!entry) return;
  const mptObj = entry.mptObj;
  msTrxnDetail = null;
  msCancelCredsDone = false;

  $('ms-trxn-detail-rows').innerHTML = '';
  $('ms-trxn-raw-json').textContent = '';
  $('ms-trxn-json-details').removeAttribute('open');
  $('ms-trxn-cancel-progress').classList.add('hidden');
  $('ms-trxn-cancel-progress').innerHTML = '';
  $('ms-trxn-quorum-card').classList.add('hidden');
  $('ms-trxn-expired-warn').classList.add('hidden');
  $('ms-trxn-submit-btn').classList.add('hidden');
  $('ms-trxn-submit-btn').disabled = true;
  $('ms-trxn-submit-btn').textContent = 'Submit';
  hideAlert('ms-trxn-detail-error');
  $('ms-trxn-cancel-btn').disabled = false;
  $('ms-trxn-cancel-btn').textContent = 'Cancel Transaction';
  $('ms-trxn-cancel-btn').classList.remove('hidden');
  $('ms-trxn-close-btn').disabled = false;
  $('ms-trxn-close-btn').textContent = 'Close';
  showView('ms-trxn-detail');
```

- [ ] **Step 2: Extend msTrxnDetail assignment to include entry**

Find:
```javascript
    msTrxnDetail = { mptObj, decodedTxJson };
    $('ms-trxn-detail-rows').innerHTML = buildTxRows(decodedTxJson);
    $('ms-trxn-raw-json').textContent = JSON.stringify(decodedTxJson, null, 2);
```
Replace with:
```javascript
    msTrxnDetail = { mptObj, decodedTxJson, entry };
    $('ms-trxn-detail-rows').innerHTML = buildTxRows(decodedTxJson);
    $('ms-trxn-raw-json').textContent = JSON.stringify(decodedTxJson, null, 2);

    // Quorum card
    $('ms-trxn-quorum-required').textContent = String(entry.quorum);
    const weightEl = $('ms-trxn-current-weight');
    weightEl.textContent = `${entry.currentWeight} / ${entry.quorum}`;
    weightEl.className   = `tx-value ${entry.currentWeight >= entry.quorum ? 'ms-trxn-weight-met' : 'ms-trxn-weight-pending'}`;
    $('ms-trxn-quorum-card').classList.remove('hidden');

    // Expiry check
    let expired = false;
    try {
      const srvResp  = await state.client.request({ command: 'server_info' });
      const ledgerSeq = srvResp.result.info?.validated_ledger?.seq ?? 0;
      if (decodedTxJson.LastLedgerSequence && decodedTxJson.LastLedgerSequence < ledgerSeq) {
        expired = true;
      }
    } catch { /* assume not expired */ }

    if (expired) {
      $('ms-trxn-expired-warn').classList.remove('hidden');
    } else if (entry.quorum > 0 && entry.currentWeight >= entry.quorum) {
      $('ms-trxn-submit-btn').classList.remove('hidden');
      $('ms-trxn-submit-btn').disabled = false;
    }
```

- [ ] **Step 3: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: extend openMsTrxnDetail with quorum card and submit button"
```

---

## Task 6: JS — hexFromMemo + submitMultisigTx

**Files:**
- Modify: `src/popup/popup.js` — insert in `// MULTISIG TRXN DETAIL` section after `cancelMsTrxn`

- [ ] **Step 1: Add both functions after `cancelMsTrxn`**

Find the comment that ends the MULTISIG TRXN DETAIL section (which is followed by `// MULTISIG SIGN INCOMING`):
```javascript
// ─────────────────────────────────────────────
// MULTISIG SIGN INCOMING
```
Insert before it:
```javascript
function hexFromMemo(memos, typeName) {
  const typeHex = Buffer.from(typeName).toString('hex').toUpperCase();
  const found   = memos.find(m => m.Memo?.MemoType?.toUpperCase() === typeHex);
  return found?.Memo?.MemoData ?? null;
}

async function submitMultisigTx() {
  if (!msTrxnDetail) return;

  const { mptObj, decodedTxJson, entry } = msTrxnDetail;
  $('ms-trxn-submit-btn').disabled = true;
  $('ms-trxn-submit-btn').textContent = 'Collecting signatures…';
  $('ms-trxn-cancel-btn').classList.add('hidden');
  $('ms-trxn-close-btn').disabled = true;
  hideAlert('ms-trxn-detail-error');

  try {
    await ensureConnected();

    // Collect signatures from CredentialAccept tx memos
    const signerData = [];
    for (const s of entry.signerStatus.filter(ss => ss.accepted && ss.prevTxnId)) {
      const txResp = await state.client.request({ command: 'tx', transaction: s.prevTxnId });
      const memos  = txResp.result?.tx_json?.Memos ?? [];
      const pubKey = hexFromMemo(memos, 'SigningPubKey');
      const sig    = hexFromMemo(memos, 'TxnSignature');
      if (pubKey && sig) signerData.push({ address: s.address, pubKey, sig });
    }

    if (signerData.length === 0) {
      throw new Error('No valid signatures found in accepted credentials.');
    }

    // Build Signers array sorted by account ID ascending (XRPL requirement)
    const Signers = signerData
      .map(s => ({ Signer: { Account: s.address, SigningPubKey: s.pubKey, TxnSignature: s.sig } }))
      .sort((a, b) => Buffer.compare(
        Buffer.from(decodeAccountID(a.Signer.Account)),
        Buffer.from(decodeAccountID(b.Signer.Account))
      ));

    // Submit multisigned transaction
    $('ms-trxn-submit-btn').textContent = 'Submitting…';
    const finalTx  = { ...decodedTxJson, Signers };
    const tx_blob  = encode(finalTx);
    const response = await state.client.submitAndWait(tx_blob);
    const txResult = response.result?.meta?.TransactionResult;
    if (txResult !== 'tesSUCCESS') throw new Error(`Transaction failed: ${txResult ?? 'Unknown'}`);

    // Success — clean up credentials + MPT
    $('ms-trxn-submit-btn').textContent = 'Cleaning up…';
    $('ms-trxn-cancel-progress').classList.remove('hidden');
    const cleanupSteps = [
      ...entry.signerStatus.map(s => ({
        label: `Revoke: ${resolveAddrDisplay(s.address)} (${truncAddr(s.address)})`,
        address: s.address,
      })),
      { label: 'Destroy MPT issuance' },
    ];
    $('ms-trxn-cancel-progress').innerHTML = cleanupSteps.map((s, i) =>
      `<div class="ms-trxn-cancel-row">
        <span class="ms-trxn-cancel-label">${esc(s.label)}</span>
        <span class="ms-trxn-cancel-status" id="ms-submit-cleanup-${i}">…</span>
      </div>`
    ).join('');

    for (let i = 0; i < entry.signerStatus.length; i++) {
      const addr     = entry.signerStatus[i].address;
      const statusEl = $(`ms-submit-cleanup-${i}`);
      try {
        const credTx   = {
          TransactionType: 'CredentialDelete',
          Account: msMessengerAddress,
          Subject: addr,
          CredentialType: '4D554C5449534947',
        };
        const prepared = await state.client.autofill(credTx);
        const tx_blob  = await signWithAddress(prepared, msMessengerAddress);
        const resp     = await state.client.submitAndWait(tx_blob);
        const result   = resp.result?.meta?.TransactionResult;
        statusEl.textContent = (result === 'tesSUCCESS' || result === 'tecNO_ENTRY') ? '✓' : `✗ ${result ?? 'Unknown'}`;
        statusEl.className   = (result === 'tesSUCCESS' || result === 'tecNO_ENTRY')
          ? 'ms-trxn-cancel-status success'
          : 'ms-trxn-cancel-status error';
      } catch (err) {
        statusEl.textContent = `✗ ${(err.message || 'Error').slice(0, 20)}`;
        statusEl.className   = 'ms-trxn-cancel-status error';
      }
    }

    const mptStatusEl   = $(`ms-submit-cleanup-${entry.signerStatus.length}`);
    const mptIssuanceId = mptObj.MPTokenIssuanceID ?? mptObj.mpt_issuance_id ?? mptObj.index;
    try {
      const destroyTx = {
        TransactionType: 'MPTokenIssuanceDestroy',
        Account: msMessengerAddress,
        MPTokenIssuanceID: mptIssuanceId,
      };
      const prepared = await state.client.autofill(destroyTx);
      const tx_blob  = await signWithAddress(prepared, msMessengerAddress);
      const resp     = await state.client.submitAndWait(tx_blob);
      const result   = resp.result?.meta?.TransactionResult;
      mptStatusEl.textContent = result === 'tesSUCCESS' ? '✓' : `✗ ${result ?? 'Unknown'}`;
      mptStatusEl.className   = result === 'tesSUCCESS'
        ? 'ms-trxn-cancel-status success'
        : 'ms-trxn-cancel-status error';
    } catch (err) {
      mptStatusEl.textContent = `✗ ${(err.message || 'Error').slice(0, 20)}`;
      mptStatusEl.className   = 'ms-trxn-cancel-status error';
    }

    $('ms-trxn-submit-btn').classList.add('hidden');
    $('ms-trxn-close-btn').disabled = false;
    $('ms-trxn-close-btn').textContent = 'Done';

  } catch (err) {
    showAlert('ms-trxn-detail-error', err.message || 'Submission failed.');
    $('ms-trxn-submit-btn').disabled = false;
    $('ms-trxn-submit-btn').textContent = 'Submit';
    $('ms-trxn-cancel-btn').classList.remove('hidden');
    $('ms-trxn-close-btn').disabled = false;
  }
}

```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: add hexFromMemo and submitMultisigTx"
```

---

## Task 7: JS — event listener + build

**Files:**
- Modify: `src/popup/popup.js` — add 1 listener after existing ms-trxn listeners

- [ ] **Step 1: Add submit event listener**

Find:
```javascript
$('ms-trxn-close-btn').addEventListener('click', () => { msTrxnDetail = null; openMultisignView(); });
$('ms-trxn-cancel-btn').addEventListener('click', () => cancelMsTrxn().catch(() => {}));
```
Replace with:
```javascript
$('ms-trxn-close-btn').addEventListener('click', () => { msTrxnDetail = null; openMultisignView(); });
$('ms-trxn-cancel-btn').addEventListener('click', () => cancelMsTrxn().catch(() => {}));
$('ms-trxn-submit-btn').addEventListener('click', () => submitMultisigTx().catch(() => {}));
```

- [ ] **Step 2: Commit**
```bash
git add src/popup/popup.js
git commit -m "feat: wire submit multisig event listener"
```

- [ ] **Step 3: Build**
```bash
npm run build
```
Expected: both `background` and `popup` compiled successfully, no errors.

- [ ] **Step 4: Manual verification**

1. **No signer list:** Open Multisig on an account without a signer list — TRXN SENT rows show `—` badge.
2. **Some signatures pending:** 0/5 or 2/5 badge is muted. Detail view shows quorum card, no Submit button.
3. **Quorum met:** 5/5 badge is green. Detail view shows Submit button enabled.
4. **Expired tx:** Submit button hidden, expired warning shown.
5. **Submit success:** Progress rows show ✓ for each cleanup step, Close → "Done", navigates to multisign screen (entry gone from list).
6. **Submit failure:** Error shown, Submit re-enabled for retry.

---

## Self-Review Notes

- `msSentList` entries are now `{ mptObj, txType, txHash, currentWeight, quorum, signerStatus }`. `cancelMsTrxn` reads `msTrxnDetail.mptObj` directly — still works since `mptObj` is in the enriched entry.
- `decodeAccountID(address)` from xrpl.js returns a `Uint8Array`. `Buffer.from(Uint8Array)` creates a Buffer; `Buffer.compare` works correctly for sorting.
- `hexFromMemo` compares hex strings case-insensitively (`.toUpperCase()` on both sides) since the MemoType stored in the CredentialAccept tx is `Buffer.from('SigningPubKey').toString('hex').toUpperCase()`.
- The cleanup progress uses IDs `ms-submit-cleanup-${i}` (distinct from `ms-cancel-status-${i}`) to avoid collisions if the cancel-progress element is reused.
- `ms-trxn-close-btn` handler always calls `openMultisignView()` — after a successful submit the user clicks "Done" (same button, text changed) and the reloaded multisign screen will not show the submitted entry (MPT destroyed).
- `encodeForMultisigning` is NOT used in submit — that was for signing, which happens on the signer side. The dispatcher is just assembling pre-made signatures.
