# Multisig Send (Credential Dispatch) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Send for Multisig" button to every transaction review screen that, when confirmed, autofills the pending transaction, encodes it to hex, and sends one `CredentialCreate` per multisig signer containing the unsigned transaction blob in a memo.

**Architecture:** Three layers — (1) a live SignerList probe injected into the existing `showView` send-review handler; (2) a new `view-multisig-send` HTML view that doubles as confirmation screen and inline progress tracker; (3) a sequential `executeMultisigDispatch` loop that signs and submits one `CredentialCreate` per signer using the existing `signPreparedTx` / `client.submitAndWait` pattern.

**Tech Stack:** Vanilla JS, ripple-binary-codec `encode` (already imported at line 9), xrpl.js `client.autofill` / `client.submitAndWait`, Chrome Extension, HTML/CSS

---

## Files

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `send-multisig-btn` to `view-send-review`; add full `view-multisig-send` after it |
| `src/popup/popup.css` | Add dispatch view styles (signer rows, status indicators, section label, summary) |
| `src/popup/popup.js` | Add 3 state vars; `probeSignerListForReview`; extend `showView` send-review block; `openMultisigSendView`; `executeMultisigDispatch`; 4 event listeners |

---

## Task 1: HTML — send-multisig-btn + view-multisig-send

**Files:**
- Modify: `src/popup/popup.html:1272–1276` (add button to send-review action row)
- Modify: `src/popup/popup.html:1276` (insert new view after send-review closing tag)

- [ ] **Step 1: Add the "Send for Multisig" button to send-review**

In `src/popup/popup.html`, find the send-review action row:

```html
    <div class="action-row">
      <button id="send-review-cancel-btn" class="btn btn-ghost">Cancel</button>
      <button id="send-review-submit-btn" class="btn btn-primary">Confirm &amp; Send</button>
    </div>
  </div>
```

Replace with:

```html
    <div class="action-row">
      <button id="send-review-cancel-btn" class="btn btn-ghost">Cancel</button>
      <button id="send-review-submit-btn" class="btn btn-primary">Confirm &amp; Send</button>
    </div>
    <button id="send-multisig-btn" class="btn btn-outline btn-full hidden" style="margin-top:8px">Send for Multisig</button>
  </div>
```

- [ ] **Step 2: Add the view-multisig-send view**

Immediately after the closing `</div>` of `view-send-review` (and before `<!-- ===== ADD TRUST LINE (IOU) ===== -->`), insert:

```html
  <!-- ===== MULTISIG SEND / CREDENTIAL DISPATCH ===== -->
  <div id="view-multisig-send" class="view hidden">
    <div class="view-header">
      <h2>Send for Multisig</h2>
    </div>

    <div id="ms-dispatch-tx-summary" class="tx-card"></div>

    <div class="ms-dispatch-section-label">Credentials will be sent to:</div>
    <div id="ms-dispatch-signer-rows" class="ms-dispatch-signer-list"></div>

    <div class="tx-card review-fee-card" style="margin-top:6px">
      <div class="tx-row">
        <span class="tx-label">Est. Credential Fees</span>
        <span id="ms-dispatch-fee-estimate" class="tx-value">—</span>
      </div>
    </div>

    <div id="ms-dispatch-error" class="alert alert-error hidden" style="margin-top:8px"></div>
    <div id="ms-dispatch-summary" class="ms-dispatch-summary hidden"></div>

    <div class="action-row">
      <button id="ms-dispatch-cancel-btn" class="btn btn-ghost">Cancel</button>
      <button id="ms-dispatch-confirm-btn" class="btn btn-primary">Confirm &amp; Send for Multisig</button>
    </div>
    <button id="ms-dispatch-close-btn" class="btn btn-outline btn-full hidden" style="margin-top:8px">Close</button>
  </div>

```

- [ ] **Step 3: Commit**

```bash
git add src/popup/popup.html
git commit -m "feat: add send-for-multisig button and dispatch view HTML"
```

---

## Task 2: CSS — dispatch view styles

**Files:**
- Modify: `src/popup/popup.css` — append after the last multisign rule (`.ms-info-icon`, around line 2754)

- [ ] **Step 1: Add the styles**

In `src/popup/popup.css`, after the line:
```css
.ms-info-icon { font-size: 11px; color: var(--text-3); margin-left: 4px; cursor: default; }
```

Add:

```css
/* Multisig dispatch view */
.ms-dispatch-section-label { font-size: 11px; font-weight: 600; color: var(--text-3); text-transform: uppercase; letter-spacing: 0.05em; margin: 10px 0 6px; }
.ms-dispatch-signer-list { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; margin-bottom: 4px; }
.ms-dispatch-signer-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 14px; border-bottom: 1px solid var(--border); }
.ms-dispatch-signer-row:last-child { border-bottom: none; }
.ms-dispatch-signer-name { font-size: 12px; font-weight: 500; }
.ms-dispatch-signer-addr { font-family: 'SF Mono', monospace; font-size: 10px; color: var(--text-3); margin-top: 1px; }
.ms-dispatch-signer-status { font-size: 12px; min-width: 90px; text-align: right; color: var(--text-3); }
.ms-dispatch-signer-status.success { color: var(--success); }
.ms-dispatch-signer-status.error { color: #ef4444; font-size: 11px; }
.ms-dispatch-summary { font-size: 12px; color: var(--text-2); text-align: center; padding: 10px 0 4px; }
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.css
git commit -m "feat: add multisig dispatch view CSS"
```

---

## Task 3: JS — state vars + probe + showView integration

**Files:**
- Modify: `src/popup/popup.js` — state vars block near line 5553; `showView` send-review block lines 242–248; insert `probeSignerListForReview` after `fetchReviewFee` (~line 276)

- [ ] **Step 1: Add state variables**

In `src/popup/popup.js`, find the MULTISIGN state vars block:

```javascript
let msSignerList        = null;   // fetched SignerList object, or null if none
let msMasterKeyDisabled = false;
let msMessengerAddress  = null;   // locally stored messenger account for active account
```

Replace with:

```javascript
let msSignerList        = null;   // fetched SignerList object, or null if none
let msMasterKeyDisabled = false;
let msMessengerAddress  = null;   // locally stored messenger account for active account
let reviewSignerList    = null;   // null=unknown, []=none, [entries]=has signers — for send-review probe
let msDispatchTxHex     = '';     // autofilled+encoded unsigned tx blob for dispatch
let msDispatchSigners   = [];     // [{ address, name }] for current dispatch
```

- [ ] **Step 2: Extend the showView send-review block**

In `src/popup/popup.js`, find the existing send-review block inside `showView` (around line 242):

```javascript
  if (name === 'send-review') {
    if (state.pendingTxReview?.title) {
      $('review-title').textContent = state.pendingTxReview.title;
    }
    $('review-fee-value').textContent = '…';
    fetchReviewFee().catch(() => { $('review-fee-value').textContent = '—'; });
  }
```

Replace with:

```javascript
  if (name === 'send-review') {
    if (state.pendingTxReview?.title) {
      $('review-title').textContent = state.pendingTxReview.title;
    }
    $('review-fee-value').textContent = '…';
    fetchReviewFee().catch(() => { $('review-fee-value').textContent = '—'; });
    reviewSignerList = null;
    $('send-multisig-btn').classList.add('hidden');
    if (state.devSettings.multisignEnabled) probeSignerListForReview().catch(() => {});
  }
```

- [ ] **Step 3: Add probeSignerListForReview after fetchReviewFee**

In `src/popup/popup.js`, find the closing brace of `fetchReviewFee` (around line 276):

```javascript
    } catch {
      $('review-fee-value').textContent = '—';
    }
  }
}

function esc(text) {
```

Replace with:

```javascript
    } catch {
      $('review-fee-value').textContent = '—';
    }
  }
}

async function probeSignerListForReview() {
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: state.activeAccount,
      ledger_index: 'validated',
      type: 'signer_list',
    });
    const sl = (resp.result.account_objects ?? []).find(o => o.LedgerEntryType === 'SignerList');
    reviewSignerList = sl?.SignerEntries ?? [];
    if (reviewSignerList.length > 0) {
      $('send-multisig-btn').classList.remove('hidden');
    }
  } catch {
    reviewSignerList = [];
  }
}

function esc(text) {
```

- [ ] **Step 4: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add multisig signer probe on send-review entry"
```

---

## Task 4: JS — openMultisigSendView

**Files:**
- Modify: `src/popup/popup.js` — insert after `executeReviewedTx` (~line 4497), in a new `// MULTISIG DISPATCH` section

- [ ] **Step 1: Add the section and function**

In `src/popup/popup.js`, find the comment after `executeReviewedTx`:

```javascript
// ─────────────────────────────────────────────
// AUTO-REFRESH
```

Replace with:

```javascript
// ─────────────────────────────────────────────
// MULTISIG DISPATCH
// ─────────────────────────────────────────────

async function openMultisigSendView() {
  const txJson = state.pendingTxReview?.txJson;
  if (!txJson || !reviewSignerList?.length) return;

  // Navigate first so error messages are visible in the dispatch view
  hideAlert('ms-dispatch-error');
  $('ms-dispatch-confirm-btn').textContent = 'Preparing…';
  $('ms-dispatch-confirm-btn').disabled = true;
  $('ms-dispatch-confirm-btn').classList.remove('hidden');
  $('ms-dispatch-cancel-btn').classList.remove('hidden');
  $('ms-dispatch-close-btn').classList.add('hidden');
  $('ms-dispatch-summary').classList.add('hidden');
  $('ms-dispatch-tx-summary').innerHTML = '';
  $('ms-dispatch-signer-rows').innerHTML = '';
  $('ms-dispatch-fee-estimate').textContent = '—';
  showView('multisig-send');

  try {
    await ensureConnected();
    const filled = await state.client.autofill({ ...txJson });
    msDispatchTxHex = encode(filled);

    await refreshAddressNames();
    msDispatchSigners = reviewSignerList.map(e => ({
      address: e.SignerEntry.Account,
      name: resolveAddrDisplay(e.SignerEntry.Account),
    }));

    const feeDrops = parseInt(filled.Fee ?? '12', 10);
    const totalDrops = feeDrops * msDispatchSigners.length;
    const xrp = (totalDrops / 1_000_000).toFixed(6).replace(/\.?0+$/, '');
    $('ms-dispatch-fee-estimate').textContent = `~${xrp} XRP (~${totalDrops} drops)`;

    $('ms-dispatch-tx-summary').innerHTML = buildTxRows(txJson);

    $('ms-dispatch-signer-rows').innerHTML = msDispatchSigners.map((s, i) => `
      <div class="ms-dispatch-signer-row">
        <div class="ms-dispatch-signer-info">
          <div class="ms-dispatch-signer-name">${esc(s.name)}</div>
          <div class="ms-dispatch-signer-addr">${esc(truncAddr(s.address))}</div>
        </div>
        <div class="ms-dispatch-signer-status" id="ms-dispatch-status-${i}">⋯</div>
      </div>`).join('');

    $('ms-dispatch-confirm-btn').textContent = 'Confirm & Send for Multisig';
    $('ms-dispatch-confirm-btn').disabled = false;
  } catch (err) {
    showAlert('ms-dispatch-error', `Failed to prepare: ${err.message || 'Unknown error'}`);
    $('ms-dispatch-confirm-btn').textContent = 'Confirm & Send for Multisig';
    $('ms-dispatch-confirm-btn').disabled = true;
  }
}

// ─────────────────────────────────────────────
// AUTO-REFRESH
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add openMultisigSendView"
```

---

## Task 5: JS — executeMultisigDispatch

**Files:**
- Modify: `src/popup/popup.js` — insert after `openMultisigSendView`, before the `// AUTO-REFRESH` comment

- [ ] **Step 1: Add the function**

In `src/popup/popup.js`, find exactly:

```javascript
// ─────────────────────────────────────────────
// AUTO-REFRESH
```

(This is the same comment targeted in Task 4 — by now it comes after `openMultisigSendView`.)

Replace with:

```javascript
async function executeMultisigDispatch() {
  if (!msDispatchTxHex || !msDispatchSigners.length) return;

  $('ms-dispatch-confirm-btn').disabled = true;
  $('ms-dispatch-confirm-btn').textContent = 'Sending…';
  $('ms-dispatch-cancel-btn').classList.add('hidden');
  hideAlert('ms-dispatch-error');

  try {
    await ensureConnected();
  } catch (err) {
    showAlert('ms-dispatch-error', `Connection failed: ${err.message || 'Unknown error'}`);
    $('ms-dispatch-confirm-btn').disabled = false;
    $('ms-dispatch-confirm-btn').textContent = 'Confirm & Send for Multisig';
    $('ms-dispatch-cancel-btn').classList.remove('hidden');
    return;
  }

  let successCount = 0;
  let connectionLost = false;

  for (let i = 0; i < msDispatchSigners.length; i++) {
    if (connectionLost) break;
    const signer = msDispatchSigners[i];
    const statusEl = $(`ms-dispatch-status-${i}`);
    statusEl.textContent = '…';
    statusEl.className = 'ms-dispatch-signer-status';

    const credTx = {
      TransactionType: 'CredentialCreate',
      Account: state.activeAccount,
      Subject: signer.address,
      CredentialType: '4D554C5449534947',
      Memos: [{ Memo: { MemoType: '5458', MemoData: msDispatchTxHex } }],
    };

    try {
      const prepared = await state.client.autofill(credTx);
      const { tx_blob } = await signPreparedTx(prepared);
      const response = await state.client.submitAndWait(tx_blob);
      const result = response.result?.meta?.TransactionResult;
      if (result === 'tesSUCCESS') {
        statusEl.textContent = '✓ Sent';
        statusEl.className = 'ms-dispatch-signer-status success';
        successCount++;
      } else {
        statusEl.textContent = `✗ ${result}`;
        statusEl.className = 'ms-dispatch-signer-status error';
      }
    } catch (err) {
      const msg = err.message || 'Error';
      const isConnectionError = msg.toLowerCase().includes('connect') ||
        msg.toLowerCase().includes('websocket') ||
        msg.toLowerCase().includes('network');
      if (isConnectionError) {
        connectionLost = true;
        for (let j = i; j < msDispatchSigners.length; j++) {
          const el = $(`ms-dispatch-status-${j}`);
          el.textContent = '✗ Connection lost';
          el.className = 'ms-dispatch-signer-status error';
        }
        break;
      }
      statusEl.textContent = `✗ ${msg.slice(0, 28)}`;
      statusEl.className = 'ms-dispatch-signer-status error';
    }
  }

  const total = msDispatchSigners.length;
  $('ms-dispatch-summary').textContent =
    `${successCount} of ${total} credential${total === 1 ? '' : 's'} sent.`;
  $('ms-dispatch-summary').classList.remove('hidden');
  $('ms-dispatch-confirm-btn').classList.add('hidden');
  $('ms-dispatch-close-btn').classList.remove('hidden');
  refreshBalance();
}

// ─────────────────────────────────────────────
// AUTO-REFRESH
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add executeMultisigDispatch"
```

---

## Task 6: JS — event listeners + build

**Files:**
- Modify: `src/popup/popup.js` — add 4 listeners near the existing send-review listeners (~line 6634)

- [ ] **Step 1: Add event listeners**

In `src/popup/popup.js`, find:

```javascript
$('review-copy-json-btn').addEventListener('click', () => {
  const json = $('review-raw-json').textContent;
  navigator.clipboard.writeText(json).then(() => {
    $('review-copy-json-btn').textContent = 'Copied!';
    setTimeout(() => { $('review-copy-json-btn').textContent = 'Copy'; }, 1500);
  });
});
```

Replace with:

```javascript
$('review-copy-json-btn').addEventListener('click', () => {
  const json = $('review-raw-json').textContent;
  navigator.clipboard.writeText(json).then(() => {
    $('review-copy-json-btn').textContent = 'Copied!';
    setTimeout(() => { $('review-copy-json-btn').textContent = 'Copy'; }, 1500);
  });
});

$('send-multisig-btn').addEventListener('click', () => openMultisigSendView().catch(() => {}));
$('ms-dispatch-cancel-btn').addEventListener('click', () => showView('send-review'));
$('ms-dispatch-confirm-btn').addEventListener('click', () => executeMultisigDispatch().catch(() => {}));
$('ms-dispatch-close-btn').addEventListener('click', () => {
  const back = state.pendingTxReview?.backView ?? 'wallet';
  state.pendingTxReview = null;
  showView(back);
});
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: wire multisig dispatch event listeners"
```

- [ ] **Step 3: Build the extension**

```bash
npm run build
```

Expected: both `background` and `popup` compile successfully, no errors.

- [ ] **Step 4: Manual verification**

Load the extension unpacked from `src/` (or the built `dist/`). Check:

1. **Flag off:** Open any send review screen — "Send for Multisig" button must NOT appear.
2. **Flag on, no signer list:** Enable the multisign dev flag, use an account with no signer list configured. Button must NOT appear.
3. **Flag on, has signer list:** Use an account that has a SignerList on-ledger. "Send for Multisig" button appears below "Confirm & Send".
4. **Click "Send for Multisig":** `view-multisig-send` opens, showing the tx summary, the signer list with names resolved, and the fee estimate.
5. **Cancel:** Returns to send-review.
6. **Confirm:** Status indicators update per signer (⋯ → ✓ or ✗), summary line appears, Close button shows.
7. **Close:** Navigates to the original `backView`.

- [ ] **Step 5: Commit the build artefact (if dist/ is tracked)**

```bash
git status
# Only commit if dist/ is tracked in this repo
```

---

## Self-Review Notes

- `encode(filled)` returns a hex string. Used directly as `MemoData` — no additional hex-encoding needed since it's already hex.
- `MemoType: '5458'` is hex for `"TX"`, `CredentialType: '4D554C5449534947'` is hex for `"MULTISIG"` — both meet XRPL requirements for hex-encoded fields.
- `client.autofill` in the dispatch loop works correctly because `submitAndWait` waits for on-ledger validation, incrementing the account sequence before the next iteration calls autofill.
- The fee estimate uses the autofilled `Fee` from the original tx (not a CredentialCreate) as a per-tx baseline. Actual CredentialCreate fees may differ slightly, but the estimate is close enough for display.
- `send-multisig-btn` starts hidden in HTML; probe un-hides it. If the user navigates away and back to send-review, the button is re-hidden and the probe re-runs.
- `msDispatchTxHex` encodes the **autofilled** tx (with Fee/Sequence/LastLedgerSequence) — signers receiving this must sign it within the `LastLedgerSequence` window. This is by design.
