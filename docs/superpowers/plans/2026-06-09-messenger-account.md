# Messenger Account Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a "Messenger Account" card to the Multisig screen that lets the user pick a project account, stores a local link, and submits an `AccountSet` transaction setting `MessageKey` to the selected account's public key.

**Architecture:** Mirrors the existing Master Key card pattern exactly — state loaded in `loadMultisignData()`, rendered in `renderMultisignScreen()`, transaction submitted via `reviewMultisignTx()`. Three new storage helpers and one submit function slot in after `submitMasterKeyToggle`. No new views, no new modals.

**Tech Stack:** Vanilla JS, Chrome Extension APIs (`chrome.storage.local`), xrpl.js `Wallet` (already imported), HTML/CSS

---

## Files

| File | Change |
|------|--------|
| `src/popup/popup.html` | Add `ms-messenger-card` block after `ms-master-key-card` (~line 1554) |
| `src/popup/popup.css` | Add `.ms-messenger-current` rule after multisign status styles (~line 2752) |
| `src/popup/popup.js` | Add state var, 4 functions, extend 4 existing functions, add 1 event listener |

---

## Task 1: HTML card markup + CSS rule

**Files:**
- Modify: `src/popup/popup.html:1546–1554`
- Modify: `src/popup/popup.css:2752`

- [ ] **Step 1: Add the card HTML after the master key card**

In `src/popup/popup.html`, find the closing `</div>` of `ms-master-key-card` (line ~1554) and the `</div>` that closes `view-multisign` (line ~1555). Insert the new card **between** them:

```html
  <!-- ── Master Key card ── -->
  <div id="ms-master-key-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Master Key</div>
    <div class="ms-master-status-row">
      <span id="ms-master-status-dot" class="ms-status-dot"></span>
      <span id="ms-master-status-text" class="ms-status-text"></span>
    </div>
    <button id="ms-master-key-btn" class="btn btn-full ms-master-key-btn">…</button>
  </div>

  <!-- ── Messenger Account card ── -->
  <div id="ms-messenger-card" class="iou-balance-card hidden">
    <div class="iou-balance-header">Messenger Account</div>
    <div id="ms-messenger-current" class="ms-messenger-current"></div>
    <select id="ms-messenger-select" class="input-field" style="width:100%;margin-bottom:8px"></select>
    <div id="ms-messenger-error" class="alert alert-error hidden" style="margin-bottom:8px"></div>
    <button id="ms-messenger-btn" class="btn btn-full">Set Messenger Account</button>
  </div>
</div>
```

- [ ] **Step 2: Add the CSS rule**

In `src/popup/popup.css`, after line:
```css
.ms-master-key-btn.reenable:hover { background: var(--success-dim); }
```

Add:
```css
.ms-messenger-current { font-size: 11px; color: var(--text-2); margin-bottom: 8px; }
```

- [ ] **Step 3: Load the extension and verify the card is not visible**

Open the extension in Chrome (load unpacked from `src/`), navigate to any account's Multisig screen. The messenger card must **not** appear — it is still `hidden` because no JS wires it up yet. If it appears or causes a JS error, check that the HTML IDs are correct.

- [ ] **Step 4: Commit**

```bash
git add src/popup/popup.html src/popup/popup.css
git commit -m "feat: add messenger account card HTML and CSS"
```

---

## Task 2: JS helper functions

**Files:**
- Modify: `src/popup/popup.js:5841` (insert after `submitMasterKeyToggle`)

- [ ] **Step 1: Add four new functions after `submitMasterKeyToggle`**

In `src/popup/popup.js`, locate this block (lines ~5833–5841):

```javascript
function submitMasterKeyToggle() {
  const txJson = {
    TransactionType: 'AccountSet',
    Account: state.activeAccount,
    ...(msMasterKeyDisabled ? { ClearFlag: 4 } : { SetFlag: 4 }),
  };
  const msg = msMasterKeyDisabled ? 'Master key re-enabled.' : 'Master key disabled.';
  reviewMultisignTx(txJson, msg);
}

// ─────────────────────────────────────────────
// RAW TRANSACTION BUILDER
```

Replace with:

```javascript
function submitMasterKeyToggle() {
  const txJson = {
    TransactionType: 'AccountSet',
    Account: state.activeAccount,
    ...(msMasterKeyDisabled ? { ClearFlag: 4 } : { SetFlag: 4 }),
  };
  const msg = msMasterKeyDisabled ? 'Master key re-enabled.' : 'Master key disabled.';
  reviewMultisignTx(txJson, msg);
}

async function loadMessengerLink(address) {
  const key  = `messengerLink_${address}`;
  const data = await chrome.storage.local.get(key);
  return data[key] ?? null;
}

async function saveMessengerLink(address, messengerAddress) {
  await chrome.storage.local.set({ [`messengerLink_${address}`]: messengerAddress });
}

function getPublicKeyForAddress(address) {
  const wallet = getWalletForAddress(address);
  if (wallet) return wallet.publicKey;
  const kr = state.keyrings.find(k => k.type === 'ledger' && k.address === address);
  return kr?.publicKey ?? null;
}

async function submitMessengerAccountSet() {
  const messengerAddress = $('ms-messenger-select').value;
  if (!messengerAddress) {
    showAlert('ms-messenger-error', 'Please select a messenger account.');
    return;
  }
  const publicKey = getPublicKeyForAddress(messengerAddress);
  if (!publicKey) {
    showAlert('ms-messenger-error', 'Could not derive public key for selected account.');
    return;
  }
  await saveMessengerLink(state.activeAccount, messengerAddress);
  msMessengerAddress = messengerAddress;
  const txJson = {
    TransactionType: 'AccountSet',
    Account: state.activeAccount,
    MessageKey: publicKey,
  };
  reviewMultisignTx(txJson, 'Messenger key set.');
}

// ─────────────────────────────────────────────
// RAW TRANSACTION BUILDER
```

- [ ] **Step 2: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add messenger account helper functions"
```

---

## Task 3: JS lifecycle wiring

**Files:**
- Modify: `src/popup/popup.js:5553–5558` (state vars block)
- Modify: `src/popup/popup.js:5560–5568` (openMultisignView)
- Modify: `src/popup/popup.js:5571–5607` (loadMultisignData)
- Modify: `src/popup/popup.js:5610–5645` (renderMultisignScreen)

- [ ] **Step 1: Add the state variable**

In `src/popup/popup.js`, find the MULTISIGN state vars block:

```javascript
let msSignerList        = null;   // fetched SignerList object, or null if none
let msMasterKeyDisabled = false;
let msFormState         = { quorum: '', signers: [{ address: '', weight: 1 }] };
let msFormVisible       = false;  // setup form open in no-setup state
let msUpdateMode        = false;  // true when editing existing signer list
let msPickerTargetIdx   = -1;     // signer row index the picker is filling
```

Replace with:

```javascript
let msSignerList        = null;   // fetched SignerList object, or null if none
let msMasterKeyDisabled = false;
let msMessengerAddress  = null;   // locally stored messenger account for active account
let msFormState         = { quorum: '', signers: [{ address: '', weight: 1 }] };
let msFormVisible       = false;  // setup form open in no-setup state
let msUpdateMode        = false;  // true when editing existing signer list
let msPickerTargetIdx   = -1;     // signer row index the picker is filling
```

- [ ] **Step 2: Reset the card in `openMultisignView`**

Find `openMultisignView`:

```javascript
function openMultisignView() {
  msSignerList        = null;
  msMasterKeyDisabled = false;
  msFormState         = { quorum: '', signers: [{ address: '', weight: 1 }] };
  msFormVisible       = false;
  msUpdateMode        = false;
  $('ms-quorum-input').value = '';
  showView('multisign');
  loadMultisignData();
}
```

Replace with:

```javascript
function openMultisignView() {
  msSignerList        = null;
  msMasterKeyDisabled = false;
  msMessengerAddress  = null;
  msFormState         = { quorum: '', signers: [{ address: '', weight: 1 }] };
  msFormVisible       = false;
  msUpdateMode        = false;
  $('ms-quorum-input').value = '';
  $('ms-messenger-card').classList.add('hidden');
  showView('multisign');
  loadMultisignData();
}
```

- [ ] **Step 3: Hide card on load start + load link after address names**

Find the opening lines of `loadMultisignData`:

```javascript
async function loadMultisignData() {
  $('ms-loading').classList.remove('hidden');
  $('ms-load-error').classList.add('hidden');
  $('ms-no-setup-card').classList.add('hidden');
  $('ms-configured-card').classList.add('hidden');
  $('ms-form-card').classList.add('hidden');
  $('ms-master-key-card').classList.add('hidden');
```

Replace with:

```javascript
async function loadMultisignData() {
  $('ms-loading').classList.remove('hidden');
  $('ms-load-error').classList.add('hidden');
  $('ms-no-setup-card').classList.add('hidden');
  $('ms-configured-card').classList.add('hidden');
  $('ms-form-card').classList.add('hidden');
  $('ms-master-key-card').classList.add('hidden');
  $('ms-messenger-card').classList.add('hidden');
```

Then find the `await refreshAddressNames()` line in `loadMultisignData`:

```javascript
    await refreshAddressNames();
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```

Replace with:

```javascript
    await refreshAddressNames();
    msMessengerAddress = await loadMessengerLink(state.activeAccount);
    $('ms-loading').classList.add('hidden');
    renderMultisignScreen();
```

- [ ] **Step 4: Render the messenger card in `renderMultisignScreen`**

Find the end of `renderMultisignScreen` — the master key section that closes the function:

```javascript
  // ── Master Key card ──
  const dot  = $('ms-master-status-dot');
  const text = $('ms-master-status-text');
  const btn  = $('ms-master-key-btn');
  dot.className   = `ms-status-dot ${msMasterKeyDisabled ? 'disabled' : 'active'}`;
  text.textContent = msMasterKeyDisabled
    ? 'Master key is disabled'
    : 'Master key is active';
  btn.textContent = msMasterKeyDisabled ? 'Re-enable Master Key' : 'Disable Master Key';
  btn.className   = `btn btn-full ms-master-key-btn ${msMasterKeyDisabled ? 'reenable' : 'danger'}`;
  $('ms-master-key-card').classList.remove('hidden');
}
```

Replace with:

```javascript
  // ── Master Key card ──
  const dot  = $('ms-master-status-dot');
  const text = $('ms-master-status-text');
  const btn  = $('ms-master-key-btn');
  dot.className   = `ms-status-dot ${msMasterKeyDisabled ? 'disabled' : 'active'}`;
  text.textContent = msMasterKeyDisabled
    ? 'Master key is disabled'
    : 'Master key is active';
  btn.textContent = msMasterKeyDisabled ? 'Re-enable Master Key' : 'Disable Master Key';
  btn.className   = `btn btn-full ms-master-key-btn ${msMasterKeyDisabled ? 'reenable' : 'danger'}`;
  $('ms-master-key-card').classList.remove('hidden');

  // ── Messenger Account card ──
  const messengerAccounts = getProjectAccounts().filter(a => !a.isWatch);
  const messengerSelect   = $('ms-messenger-select');
  messengerSelect.innerHTML = '<option value="">— select account —</option>' +
    messengerAccounts.map(a =>
      `<option value="${esc(a.address)}">${esc(a.label)} (${esc(truncAddr(a.address))})</option>`
    ).join('');
  $('ms-messenger-current').textContent = msMessengerAddress
    ? `Current: ${resolveAddrDisplay(msMessengerAddress)} (${truncAddr(msMessengerAddress)})`
    : 'No messenger account set.';
  $('ms-messenger-card').classList.remove('hidden');
}
```

- [ ] **Step 5: Reload extension and verify card renders**

Open the extension, navigate to Multisign. After data loads:
- The "Messenger Account" card should appear below the Master Key card
- It should show "No messenger account set." (first time)
- The dropdown should list all project accounts that are not watch-only
- Selecting an option and clicking "Set Messenger Account" should do nothing yet (button not wired)

- [ ] **Step 6: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: wire messenger account card into multisign lifecycle"
```

---

## Task 4: Event listener + end-to-end verification

**Files:**
- Modify: `src/popup/popup.js:7173` (event listener block)

- [ ] **Step 1: Add the event listener**

In `src/popup/popup.js`, find:

```javascript
$('ms-master-key-btn').addEventListener('click', submitMasterKeyToggle);
```

Replace with:

```javascript
$('ms-master-key-btn').addEventListener('click', submitMasterKeyToggle);
$('ms-messenger-btn').addEventListener('click', submitMessengerAccountSet);
```

- [ ] **Step 2: Verify the full flow**

Reload the extension. Open Multisign on an account that has at least one other non-watch-only account in the project.

**Happy path:**
1. Open Multisign — card shows "No messenger account set."
2. Select an account from the dropdown
3. Click "Set Messenger Account"
4. Review card appears showing `AccountSet` transaction with a `MessageKey` field (33-byte hex)
5. Submit the transaction
6. On success, navigate back to Multisign
7. Card should now show "Current: [account name] ([truncated address])"

**Error path — no selection:**
1. Leave dropdown on "— select account —"
2. Click "Set Messenger Account"
3. Inline error "Please select a messenger account." appears

**Persistence:**
1. Set a messenger account successfully
2. Close and reopen the extension
3. Navigate to Multisign — card should still show the previously set account

- [ ] **Step 3: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: implement set messenger account on multisign screen"
```

---

## Self-Review Notes

- `getPublicKeyForAddress` covers HD, simple, and Ledger account types. Watch-only is excluded upstream by the `filter(a => !a.isWatch)` in the dropdown population, so the `null` return is a defensive fallback only.
- `saveMessengerLink` is called **before** `reviewMultisignTx` so the local link is persisted even if the user abandons the review. This is intentional — the link is a local UX association, independent of whether the on-chain tx succeeds.
- `ms-messenger-error` alert uses the same `showAlert` pattern as `ms-form-error`; no new alert infrastructure needed.
- `MessageKey` value comes from `wallet.publicKey` (xrpl.js), which is already a correctly formatted 33-byte hex string for both secp256k1 and ed25519 keys.
