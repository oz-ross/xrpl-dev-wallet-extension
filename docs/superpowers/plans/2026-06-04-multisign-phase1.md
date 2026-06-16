# Multisign Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a gated multisign management screen to the XRPL dev wallet that lets users configure a SignerList and toggle the master key on any account.

**Architecture:** All code is added inline to `popup.js` and `popup.html` (the codebase is a single-page Chrome extension with no module system). Signer form state is managed in a module-level JS object (`msFormState`) and re-rendered on every mutation, avoiding DOM scraping on submit. Transactions route through the existing `state.pendingTxReview` / `executeReviewedTx()` path that all non-payment flows already use.

**Tech Stack:** Chrome Extension MV3, xrpl.js v4.6 (already imported), vanilla JS/HTML/CSS, webpack build (`npm run build`). No test framework — verification is manual in Chrome DevTools after each build.

**Build command:** `npm run build` from the project root. Load the unpacked extension from `dist/` in `chrome://extensions`.

---

## File Map

| File | What changes |
|------|-------------|
| `src/popup/popup.html` | Add `view-multisign` view, MULTISIGN nav card in `view-wallet`, toggle in `view-settings`, picker modal |
| `src/popup/popup.js` | `multisignEnabled` in devSettings; `openMultisignView`, `loadMultisignData`, `renderMultisignScreen`, `renderMsSignerRows`, `submitSignerListSet`, `submitMasterKeyToggle`, `reviewMultisignTx`; picker modal logic; `updateWalletUI` guard |
| `src/popup/popup.css` | Styles for multisign cards, signer rows, picker modal, master key status dots |

---

## Task 1: Settings Toggle

**Files:**
- Modify: `src/popup/popup.html` — add toggle row in Developer Mode section (line ~841)
- Modify: `src/popup/popup.js` — add `multisignEnabled` to devSettings default (line 200), wire up handler and load (lines ~6661–6676)

- [ ] **Step 1: Add `multisignEnabled: false` to the devSettings default**

  In `popup.js` line 200, change:
  ```js
  devSettings: { printTxJson: false, printWC: false, lockTimeoutSecs: 0, wideMode: false, iouDecimalPrecision: 6 },
  ```
  to:
  ```js
  devSettings: { printTxJson: false, printWC: false, lockTimeoutSecs: 0, wideMode: false, iouDecimalPrecision: 6, multisignEnabled: false },
  ```

- [ ] **Step 2: Add the toggle checkbox to view-settings HTML**

  In `popup.html`, after the "Print WalletConnect logs" toggle item (after line 841, before the `<p class="form-hint">` warning), insert:
  ```html
        <div class="settings-item settings-toggle-item">
          <span class="settings-item-label">Multisign</span>
          <label class="toggle-switch">
            <input type="checkbox" id="dev-multisign-enabled" />
            <span class="toggle-slider"></span>
          </label>
        </div>
  ```

- [ ] **Step 3: Load the saved value when settings opens**

  In `popup.js`, in the block that loads devSettings into the settings UI (around line 6667–6670), add after the existing checkbox assignments:
  ```js
  $('dev-multisign-enabled').checked = state.devSettings.multisignEnabled;
  ```

- [ ] **Step 4: Wire up the change handler**

  In `popup.js`, after the `dev-print-wc` change handler (around line 6720), add:
  ```js
  $('dev-multisign-enabled').addEventListener('change', e => {
    state.devSettings.multisignEnabled = e.target.checked;
    chrome.storage.local.set({ devSettings: state.devSettings });
    updateWalletUI();
  });
  ```

- [ ] **Step 5: Build and verify**

  Run: `npm run build`

  Expected: build succeeds with no errors.

  Open extension → Settings → Developer Mode section → confirm "Multisign" toggle appears and toggling it persists across popup close/open (check `chrome.storage.local` in DevTools → Application → Storage if needed).

- [ ] **Step 6: Commit**
  ```bash
  git add src/popup/popup.html src/popup/popup.js
  git commit -m "feat: add multisignEnabled toggle to developer settings"
  ```

---

## Task 2: Main Page MULTISIGN Nav Card

**Files:**
- Modify: `src/popup/popup.html` — insert MULTISIGN card in `view-wallet` before the WalletConnect section (line ~615)
- Modify: `src/popup/popup.js` — show/hide card in `updateWalletUI()` (line ~1820); stub `openMultisignView()`

- [ ] **Step 1: Add MULTISIGN card HTML in view-wallet**

  In `popup.html`, before the `<!-- WalletConnect section -->` comment (line ~615), insert:
  ```html
      <!-- Multisign section -->
      <div id="multisign-nav-card" class="iou-balance-card multisign-nav-card hidden">
        <div class="iou-balance-header">
          <span>Multisign</span>
          <span class="multisign-nav-chevron">›</span>
        </div>
      </div>
  ```

- [ ] **Step 2: Add CSS for the nav card**

  In `popup.css`, at the end of the file, add:
  ```css
  /* ===== MULTISIGN ===== */
  .multisign-nav-card { cursor: pointer; user-select: none; }
  .multisign-nav-card:hover { border-color: var(--accent); }
  .multisign-nav-chevron { font-size: 16px; color: var(--text-3); }
  ```

- [ ] **Step 3: Show/hide the card in updateWalletUI()**

  In `popup.js`, at the end of `updateWalletUI()` (after line 1850 where `renderAccountDropdown` is called), add:
  ```js
  $('multisign-nav-card').classList.toggle('hidden', !state.devSettings.multisignEnabled);
  ```

- [ ] **Step 4: Add click handler and stub openMultisignView()**

  In `popup.js`, after the `updateWalletUI` function block, add the click handler (near other wallet-view event listeners):
  ```js
  $('multisign-nav-card').addEventListener('click', openMultisignView);
  ```

  Then add the stub function (can be placed near the end of the file, before the DOMContentLoaded or init section):
  ```js
  // ─────────────────────────────────────────────
  // MULTISIGN
  // ─────────────────────────────────────────────

  function openMultisignView() {
    showView('multisign');
  }
  ```

- [ ] **Step 5: Add a minimal view-multisign placeholder in HTML**

  In `popup.html`, before the closing `</body>` tag (or grouped with other views), add a temporary placeholder so `showView('multisign')` doesn't error:
  ```html
  <!-- ===== MULTISIGN ===== -->
  <div id="view-multisign" class="view hidden">
    <div class="view-header">
      <button id="multisign-back-btn" class="btn-icon btn-back">‹</button>
      <h2>Multisign</h2>
    </div>
  </div>
  ```

  Wire up the back button alongside the click handler added in Step 4:
  ```js
  $('multisign-back-btn').addEventListener('click', () => showView('wallet'));
  ```

- [ ] **Step 6: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  - Toggle Multisign on in Settings → MULTISIGN card appears on main page between assets and WalletConnect.
  - Toggle off → card disappears.
  - Toggle on, click the card → navigates to the blank Multisign screen with a working back button.

- [ ] **Step 7: Commit**
  ```bash
  git add src/popup/popup.html src/popup/popup.js src/popup/popup.css
  git commit -m "feat: add multisign nav card to main wallet page"
  ```

---

## Task 3: Multisign Screen HTML + CSS

Replace the placeholder view with the full HTML structure for all states of the Multisign screen.

**Files:**
- Modify: `src/popup/popup.html` — replace the placeholder `view-multisign` with the full structure
- Modify: `src/popup/popup.css` — add all multisign-specific styles

- [ ] **Step 1: Replace view-multisign with full HTML**

  Replace the placeholder `div#view-multisign` added in Task 2 with:
  ```html
  <!-- ===== MULTISIGN ===== -->
  <div id="view-multisign" class="view hidden">
    <div class="view-header">
      <button id="multisign-back-btn" class="btn-icon btn-back">‹</button>
      <h2>Multisign</h2>
    </div>

    <div id="ms-loading" class="ms-loading hidden">Loading…</div>
    <div id="ms-load-error" class="alert alert-error hidden"></div>

    <!-- ── Signer List card ── -->
    <!-- No-setup state -->
    <div id="ms-no-setup-card" class="iou-balance-card hidden">
      <div class="iou-balance-header">Signer List</div>
      <p id="ms-no-setup-msg" class="ms-empty-msg">No Multisig Setup</p>
      <button id="ms-setup-toggle-btn" class="btn btn-outline btn-full" style="margin-top:10px">
        Setup Multisig
      </button>
    </div>

    <!-- Configured state summary -->
    <div id="ms-configured-card" class="iou-balance-card hidden">
      <div class="iou-balance-header">
        <span>Signer List</span>
        <button id="ms-update-btn" class="btn btn-ghost btn-sm">Update</button>
      </div>
      <div class="ms-quorum-row">
        <span class="ms-quorum-label">Quorum Threshold</span>
        <span id="ms-quorum-display" class="ms-quorum-value">—</span>
      </div>
      <div id="ms-signer-list-display"></div>
    </div>

    <!-- Configure / Update form -->
    <div id="ms-form-card" class="iou-balance-card ms-form-card hidden">
      <div class="iou-balance-header">
        <span id="ms-form-title">Configure Signers</span>
        <button id="ms-form-cancel-btn" class="btn btn-ghost btn-sm hidden">Cancel</button>
      </div>

      <div class="ms-field-row">
        <label class="ms-field-label" for="ms-quorum-input">Quorum Threshold</label>
        <input id="ms-quorum-input" class="ms-quorum-input input-field" type="number" min="1" step="1" placeholder="e.g. 2" />
      </div>

      <div class="ms-field-label" style="margin-bottom:6px">Signers</div>
      <div id="ms-signer-rows"></div>

      <button id="ms-add-signer-btn" class="ms-add-signer-btn">+ Add Signer</button>
      <div id="ms-form-error" class="alert alert-error hidden" style="margin-bottom:8px"></div>
      <div id="ms-quorum-warn" class="alert alert-warn hidden" style="margin-bottom:8px">
        ⚠ Sum of signer weights is less than quorum threshold.
      </div>
      <button id="ms-submit-btn" class="btn btn-primary btn-full">Submit</button>
    </div>

    <!-- ── Master Key card ── -->
    <div id="ms-master-key-card" class="iou-balance-card hidden">
      <div class="iou-balance-header">Master Key</div>
      <div class="ms-master-status-row">
        <span id="ms-master-status-dot" class="ms-status-dot"></span>
        <span id="ms-master-status-text" class="ms-status-text"></span>
      </div>
      <button id="ms-master-key-btn" class="btn btn-full ms-master-key-btn">…</button>
    </div>
  </div>

  <!-- ===== MULTISIGN PICKER MODAL ===== -->
  <div id="ms-picker-modal" class="ms-picker-modal hidden">
    <div class="ms-picker-card">
      <div class="ms-picker-header">
        <span class="ms-picker-title">Select Address</span>
        <button id="ms-picker-close-btn" class="btn-icon">✕</button>
      </div>
      <input id="ms-picker-filter" class="input-field ms-picker-filter" type="text" placeholder="Filter by name or address…" />
      <div id="ms-picker-list" class="ms-picker-list"></div>
    </div>
  </div>
  ```

- [ ] **Step 2: Add CSS for the multisign screen**

  In `popup.css`, append after the `/* ===== MULTISIGN ===== */` block added in Task 2:
  ```css
  .ms-loading { text-align: center; color: var(--text-3); font-size: 13px; padding: 20px 0; }

  .ms-empty-msg { font-size: 12px; color: var(--text-3); text-align: center; padding: 8px 0 4px; }

  .ms-quorum-row {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 8px;
  }
  .ms-quorum-label { font-size: 11px; color: var(--text-3); }
  .ms-quorum-value { font-size: 16px; font-weight: 700; }

  .ms-signer-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 6px 0; border-bottom: 1px solid var(--surface-2);
  }
  .ms-signer-item:last-child { border-bottom: none; }
  .ms-signer-name { font-size: 12px; font-weight: 500; }
  .ms-signer-addr { font-family: 'SF Mono', monospace; font-size: 9px; color: var(--text-3); margin-top: 1px; }
  .ms-signer-weight-badge {
    font-size: 10px; font-weight: 600;
    background: var(--accent-dim); color: var(--accent);
    border: 1px solid rgba(99,102,241,0.2);
    border-radius: var(--radius-xs); padding: 2px 7px; flex-shrink: 0;
  }

  /* Form card */
  .ms-form-card { border-color: var(--accent); }
  .ms-field-row { margin-bottom: 10px; }
  .ms-field-label { font-size: 10px; color: var(--text-3); margin-bottom: 4px; font-weight: 500; display: block; }
  .ms-quorum-input { width: 80px; }

  /* Signer row */
  .ms-signer-row { display: flex; gap: 5px; align-items: flex-end; margin-bottom: 8px; }
  .ms-signer-addr-wrap { flex: 1; display: flex; }
  .ms-signer-addr-wrap .input-field { border-radius: var(--radius-xs) 0 0 var(--radius-xs); border-right: none; flex: 1; }
  .ms-picker-btn {
    height: 32px; width: 28px; flex-shrink: 0;
    background: var(--surface-2); border: 1px solid var(--border);
    border-radius: 0 var(--radius-xs) var(--radius-xs) 0;
    color: var(--accent); font-size: 13px;
    display: flex; align-items: center; justify-content: center; cursor: pointer;
  }
  .ms-picker-btn:hover { background: var(--accent-dim); }
  .ms-signer-weight-wrap { width: 58px; }
  .ms-remove-btn {
    width: 28px; height: 32px; flex-shrink: 0;
    background: transparent; border: 1px solid rgba(239,68,68,0.3);
    border-radius: var(--radius-xs); color: #ef4444; font-size: 13px;
    display: flex; align-items: center; justify-content: center; cursor: pointer;
    margin-bottom: 1px;
  }
  .ms-remove-btn:hover { background: rgba(239,68,68,0.08); }
  .ms-remove-btn:disabled { opacity: 0.3; cursor: default; }

  .ms-add-signer-btn {
    width: 100%; font-size: 11px; color: var(--accent);
    background: transparent; border: 1px dashed rgba(99,102,241,0.35);
    border-radius: var(--radius-xs); padding: 6px 10px;
    cursor: pointer; text-align: center; margin-bottom: 10px;
  }
  .ms-add-signer-btn:hover { background: var(--accent-dim); }

  /* Master key card */
  .ms-master-status-row { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; }
  .ms-status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .ms-status-dot.active { background: var(--success); box-shadow: 0 0 5px var(--success); }
  .ms-status-dot.disabled { background: #ef4444; box-shadow: 0 0 5px rgba(239,68,68,0.4); }
  .ms-status-text { font-size: 12px; color: var(--text-2); }
  .ms-master-key-btn.danger { border: 1px solid rgba(239,68,68,0.35); color: #ef4444; background: transparent; }
  .ms-master-key-btn.danger:hover { background: rgba(239,68,68,0.08); }
  .ms-master-key-btn.reenable { border: 1px solid rgba(16,185,129,0.35); color: var(--success); background: transparent; }
  .ms-master-key-btn.reenable:hover { background: var(--success-dim); }

  /* Picker modal */
  .ms-picker-modal {
    position: fixed; inset: 0; z-index: 200;
    background: rgba(0,0,0,0.6);
    display: flex; align-items: flex-end; justify-content: center;
  }
  .ms-picker-modal.hidden { display: none; }
  .ms-picker-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius) var(--radius) 0 0;
    width: 100%; max-height: 60vh;
    display: flex; flex-direction: column; padding: 14px 12px 0;
  }
  .ms-picker-header {
    display: flex; align-items: center; justify-content: space-between;
    margin-bottom: 10px;
  }
  .ms-picker-title { font-size: 13px; font-weight: 600; }
  .ms-picker-filter { width: 100%; margin-bottom: 8px; }
  .ms-picker-list { overflow-y: auto; flex: 1; padding-bottom: 12px; }
  .ms-picker-item {
    display: flex; flex-direction: column; gap: 2px;
    padding: 8px 10px; border-radius: var(--radius-xs); cursor: pointer;
  }
  .ms-picker-item:hover { background: var(--surface-2); }
  .ms-picker-item-name { font-size: 12px; font-weight: 500; }
  .ms-picker-item-addr { font-family: 'SF Mono', monospace; font-size: 10px; color: var(--text-3); }
  ```

- [ ] **Step 3: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  Navigate to the Multisign screen → all cards hidden (loading state visible briefly), no JS errors in console.

- [ ] **Step 4: Commit**
  ```bash
  git add src/popup/popup.html src/popup/popup.css
  git commit -m "feat: add view-multisign HTML skeleton and CSS"
  ```

---

## Task 4: Data Loading and Screen Rendering

Implement `openMultisignView()`, `loadMultisignData()`, and rendering for both SignerList states and the master key card.

**Files:**
- Modify: `src/popup/popup.js` — replace stub `openMultisignView` with full implementation

- [ ] **Step 1: Add module-level multisign state variables**

  In `popup.js`, inside the `// MULTISIGN` section added in Task 2, add before `openMultisignView`:
  ```js
  let msSignerList      = null;  // fetched SignerList object, or null if none
  let msMasterKeyDisabled = false;
  let msFormState       = { quorum: '', signers: [{ address: '', weight: 1 }] };
  let msFormVisible     = false;  // setup form open in no-setup state
  let msUpdateMode      = false;  // true when editing existing signer list
  let msPickerTargetIdx = -1;     // signer row index the picker is filling
  ```

- [ ] **Step 2: Replace the openMultisignView stub**

  Replace the stub function added in Task 2 with:
  ```js
  function openMultisignView() {
    msSignerList = null;
    msMasterKeyDisabled = false;
    msFormState  = { quorum: '', signers: [{ address: '', weight: 1 }] };
    msFormVisible = false;
    msUpdateMode  = false;
    showView('multisign');
    loadMultisignData();
  }
  ```

- [ ] **Step 3: Implement loadMultisignData()**

  Add after `openMultisignView`:
  ```js
  async function loadMultisignData() {
    $('ms-loading').classList.remove('hidden');
    $('ms-load-error').classList.add('hidden');
    $('ms-no-setup-card').classList.add('hidden');
    $('ms-configured-card').classList.add('hidden');
    $('ms-form-card').classList.add('hidden');
    $('ms-master-key-card').classList.add('hidden');

    try {
      await ensureConnected();
      const [objResp, infoResp] = await Promise.all([
        state.client.request({
          command: 'account_objects',
          account: state.activeAccount,
          ledger_index: 'validated',
        }),
        state.client.request({
          command: 'account_info',
          account: state.activeAccount,
          ledger_index: 'validated',
        }),
      ]);

      const objects = objResp.result.account_objects ?? [];
      msSignerList = objects.find(o => o.LedgerEntryType === 'SignerList') ?? null;

      const flags = infoResp.result.account_data?.Flags ?? 0;
      msMasterKeyDisabled = !!(flags & 0x00100000);

      $('ms-loading').classList.add('hidden');
      renderMultisignScreen();
    } catch (err) {
      $('ms-loading').classList.add('hidden');
      showAlert('ms-load-error', `Failed to load: ${err.message}`);
    }
  }
  ```

- [ ] **Step 4: Implement renderMultisignScreen()**

  Add after `loadMultisignData`:
  ```js
  function renderMultisignScreen() {
    // ── SignerList card ──
    if (msUpdateMode) {
      $('ms-no-setup-card').classList.add('hidden');
      $('ms-configured-card').classList.add('hidden');
      $('ms-form-title').textContent = 'Update Signers';
      $('ms-form-cancel-btn').classList.remove('hidden');
      $('ms-form-card').classList.remove('hidden');
    } else if (msSignerList) {
      $('ms-no-setup-card').classList.add('hidden');
      $('ms-form-cancel-btn').classList.add('hidden');
      $('ms-form-card').classList.add('hidden');
      renderSignerListSummary();
      $('ms-configured-card').classList.remove('hidden');
    } else {
      $('ms-configured-card').classList.add('hidden');
      $('ms-form-title').textContent = 'Configure Signers';
      $('ms-form-cancel-btn').classList.add('hidden');
      $('ms-setup-toggle-btn').textContent = msFormVisible ? '▲ Hide Setup' : 'Setup Multisig';
      $('ms-form-card').classList.toggle('hidden', !msFormVisible);
      $('ms-no-setup-card').classList.remove('hidden');
    }
    renderMsSignerRows();

    // ── Master Key card ──
    const dot  = $('ms-master-status-dot');
    const text = $('ms-master-status-text');
    const btn  = $('ms-master-key-btn');
    dot.className  = `ms-status-dot ${msMasterKeyDisabled ? 'disabled' : 'active'}`;
    text.textContent = msMasterKeyDisabled
      ? 'Master key is disabled'
      : 'Master key is active';
    btn.textContent = msMasterKeyDisabled ? 'Re-enable Master Key' : 'Disable Master Key';
    btn.className   = `btn btn-full ms-master-key-btn ${msMasterKeyDisabled ? 'reenable' : 'danger'}`;
    $('ms-master-key-card').classList.remove('hidden');
  }
  ```

- [ ] **Step 5: Implement renderSignerListSummary()**

  Add after `renderMultisignScreen`:
  ```js
  function renderSignerListSummary() {
    $('ms-quorum-display').textContent = msSignerList.SignerQuorum ?? '—';
    const entries = msSignerList.SignerEntries ?? [];
    $('ms-signer-list-display').innerHTML = entries.map(e => {
      const addr    = e.SignerEntry.Account;
      const weight  = e.SignerEntry.SignerWeight;
      const display = esc(resolveAddrDisplay(addr));
      const addrEsc = esc(addr);
      return `<div class="ms-signer-item">
        <div>
          <div class="ms-signer-name">${display}</div>
          <div class="ms-signer-addr">${addrEsc}</div>
        </div>
        <div class="ms-signer-weight-badge">w: ${weight}</div>
      </div>`;
    }).join('');
  }
  ```

- [ ] **Step 6: Wire up the Update button and Setup toggle button event listeners**

  In `popup.js`, near the other multisign event-listener block, add:
  ```js
  $('ms-update-btn').addEventListener('click', () => {
    const entries = msSignerList?.SignerEntries ?? [];
    msFormState = {
      quorum: String(msSignerList?.SignerQuorum ?? ''),
      signers: entries.map(e => ({
        address: e.SignerEntry.Account,
        weight: e.SignerEntry.SignerWeight,
      })),
    };
    if (msFormState.signers.length === 0) {
      msFormState.signers = [{ address: '', weight: 1 }];
    }
    msUpdateMode = true;
    $('ms-quorum-input').value = msFormState.quorum;
    renderMultisignScreen();
  });

  $('ms-setup-toggle-btn').addEventListener('click', () => {
    msFormVisible = !msFormVisible;
    renderMultisignScreen();
  });

  $('ms-form-cancel-btn').addEventListener('click', () => {
    msUpdateMode = false;
    msFormState  = { quorum: '', signers: [{ address: '', weight: 1 }] };
    renderMultisignScreen();
  });

  $('ms-quorum-input').addEventListener('input', e => {
    msFormState.quorum = e.target.value;
    updateMsQuorumWarning();
  });
  ```

- [ ] **Step 7: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  - Connect to devnet, navigate to Multisign screen.
  - For an account with no SignerList: "No Multisig Setup" card shows, master key card shows with correct active/disabled state.
  - For an account that has a SignerList configured: the configured summary card shows with quorum and signers.
  - Clicking Update pre-populates the form; Cancel restores the summary.
  - Clicking Setup Multisig toggles the form open/closed.

- [ ] **Step 8: Commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: implement multisign data loading and screen rendering"
  ```

---

## Task 5: Address Picker Modal

**Files:**
- Modify: `src/popup/popup.js` — add picker open/close/filter/select logic

- [ ] **Step 1: Implement openMsPickerModal()**

  Add in the `// MULTISIGN` section:
  ```js
  async function openMsPickerModal(signerIdx) {
    msPickerTargetIdx = signerIdx;
    $('ms-picker-filter').value = '';

    const accounts  = getProjectAccounts();
    const contacts  = await loadAddressBook();

    // Combine, deduplicate by address
    const seen = new Set();
    const items = [];
    for (const a of accounts) {
      if (!seen.has(a.address)) {
        seen.add(a.address);
        items.push({ name: a.label, address: a.address });
      }
    }
    for (const c of contacts) {
      if (!seen.has(c.address)) {
        seen.add(c.address);
        items.push({ name: c.name, address: c.address });
      }
    }

    const renderPickerList = (filter) => {
      const lower = filter.toLowerCase();
      const filtered = items.filter(i =>
        i.name.toLowerCase().includes(lower) || i.address.toLowerCase().includes(lower)
      );
      $('ms-picker-list').innerHTML = filtered.map(i => `
        <div class="ms-picker-item" data-address="${esc(i.address)}">
          <div class="ms-picker-item-name">${esc(i.name)}</div>
          <div class="ms-picker-item-addr">${esc(i.address)}</div>
        </div>`).join('') || '<div style="padding:10px;color:var(--text-3);font-size:12px">No matches</div>';

      $('ms-picker-list').querySelectorAll('.ms-picker-item').forEach(el => {
        el.addEventListener('click', () => {
          msFormState.signers[msPickerTargetIdx].address = el.dataset.address;
          closeMsPickerModal();
          renderMsSignerRows();
        });
      });
    };

    renderPickerList('');
    $('ms-picker-filter').oninput = e => renderPickerList(e.target.value);
    $('ms-picker-modal').classList.remove('hidden');
    $('ms-picker-filter').focus();
  }

  function closeMsPickerModal() {
    $('ms-picker-modal').classList.add('hidden');
    msPickerTargetIdx = -1;
  }
  ```

- [ ] **Step 2: Wire up picker close button and backdrop click**

  ```js
  $('ms-picker-close-btn').addEventListener('click', closeMsPickerModal);
  $('ms-picker-modal').addEventListener('click', e => {
    if (e.target === $('ms-picker-modal')) closeMsPickerModal();
  });
  ```

- [ ] **Step 3: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  The picker modal can be tested once signer rows exist (Task 6) but the build must be clean.

- [ ] **Step 4: Commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: add address picker modal for multisign signer rows"
  ```

---

## Task 6: Signer Row State and Rendering

Implement `renderMsSignerRows()` and the add/remove/input handlers for the dynamic signer rows.

**Files:**
- Modify: `src/popup/popup.js`

- [ ] **Step 1: Implement renderMsSignerRows()**

  Add in the `// MULTISIGN` section:
  ```js
  function renderMsSignerRows() {
    const container = $('ms-signer-rows');
    container.innerHTML = msFormState.signers.map((s, i) => `
      <div class="ms-signer-row" data-idx="${i}">
        <div class="ms-signer-addr-wrap">
          <input class="input-field ms-addr-input"
                 type="text"
                 placeholder="r… address"
                 value="${esc(s.address)}"
                 data-idx="${i}" />
          <button class="ms-picker-btn" data-idx="${i}" title="Pick from accounts / address book">⊞</button>
        </div>
        <div class="ms-signer-weight-wrap">
          <input class="input-field ms-weight-input"
                 type="number" min="1" step="1"
                 value="${s.weight}"
                 data-idx="${i}" />
        </div>
        <button class="ms-remove-btn" data-idx="${i}"
                ${msFormState.signers.length <= 1 ? 'disabled' : ''}>✕</button>
      </div>`).join('');

    // Address input
    container.querySelectorAll('.ms-addr-input').forEach(el => {
      el.addEventListener('input', e => {
        msFormState.signers[+e.target.dataset.idx].address = e.target.value.trim();
      });
    });
    // Weight input
    container.querySelectorAll('.ms-weight-input').forEach(el => {
      el.addEventListener('input', e => {
        const v = parseInt(e.target.value, 10);
        msFormState.signers[+e.target.dataset.idx].weight = isNaN(v) || v < 1 ? 1 : v;
        updateMsQuorumWarning();
      });
    });
    // Picker button
    container.querySelectorAll('.ms-picker-btn').forEach(el => {
      el.addEventListener('click', () => openMsPickerModal(+el.dataset.idx));
    });
    // Remove button
    container.querySelectorAll('.ms-remove-btn').forEach(el => {
      el.addEventListener('click', () => {
        const idx = +el.dataset.idx;
        msFormState.signers.splice(idx, 1);
        renderMsSignerRows();
        updateMsQuorumWarning();
      });
    });
  }
  ```

- [ ] **Step 2: Implement updateMsQuorumWarning()**

  ```js
  function updateMsQuorumWarning() {
    const quorum = parseInt($('ms-quorum-input').value, 10);
    const weightSum = msFormState.signers.reduce((s, r) => s + (parseInt(r.weight, 10) || 0), 0);
    const warn = !isNaN(quorum) && quorum > 0 && weightSum < quorum;
    $('ms-quorum-warn').classList.toggle('hidden', !warn);
  }
  ```

- [ ] **Step 3: Wire up the Add Signer button**

  ```js
  $('ms-add-signer-btn').addEventListener('click', () => {
    msFormState.signers.push({ address: '', weight: 1 });
    renderMsSignerRows();
  });
  ```

- [ ] **Step 4: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  - Open the setup form: one signer row renders with address input, picker button, weight input, ✕ button (disabled when only one row).
  - Add Signer adds a row; ✕ on a row removes it; first row ✕ is disabled when only one remains.
  - Picker button opens the modal; selecting an entry fills the address field.
  - Entering a quorum larger than sum-of-weights shows the warning.

- [ ] **Step 5: Commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: implement multisign signer row state and rendering"
  ```

---

## Task 7: SignerListSet Transaction

Validate the form, build the `SignerListSet` tx, and route it to the review screen.

**Files:**
- Modify: `src/popup/popup.js`

- [ ] **Step 1: Implement validateMsForm()**

  Add in the `// MULTISIGN` section:
  ```js
  function validateMsForm() {
    const quorum = parseInt($('ms-quorum-input').value, 10);
    if (isNaN(quorum) || quorum < 1) {
      showAlert('ms-form-error', 'Quorum must be a positive integer.');
      return false;
    }
    if (msFormState.signers.length === 0) {
      showAlert('ms-form-error', 'Add at least one signer.');
      return false;
    }
    for (const s of msFormState.signers) {
      if (!s.address || !isValidClassicAddress(s.address)) {
        showAlert('ms-form-error', `Invalid XRPL address: "${s.address || '(empty)'}"`);
        return false;
      }
      if (!Number.isInteger(s.weight) || s.weight < 1) {
        showAlert('ms-form-error', 'All signer weights must be positive integers.');
        return false;
      }
    }
    const addresses = msFormState.signers.map(s => s.address);
    if (new Set(addresses).size !== addresses.length) {
      showAlert('ms-form-error', 'Duplicate signer addresses are not allowed.');
      return false;
    }
    $('ms-form-error').classList.add('hidden');
    return true;
  }
  ```

- [ ] **Step 2: Implement reviewMultisignTx() and update showView() to handle the review title**

  `reviewMultisignTx()` stores a `title` in `pendingTxReview`. `showView()` already runs when the review screen opens — add one line there to set the title, falling back to "Review Payment" so existing payment flows are unaffected.

  In `popup.js` inside the `if (name === 'send-review')` block in `showView()` (around line 242), add after `fetchReviewFee()…`:
  ```js
  $('review-title').textContent = state.pendingTxReview?.title ?? 'Review Payment';
  ```

  Then add the `reviewMultisignTx` function:
  ```js
  function reviewMultisignTx(txJson, successMsg) {
    $('send-review-paste-warn').classList.add('hidden');
    const rows = buildTxRows(txJson);
    $('send-review-details').innerHTML = rows.join('');
    state.pendingTxReview = { txJson, backView: 'multisign', successMsg, title: 'Review Transaction' };
    showView('send-review');
  }
  ```

- [ ] **Step 3: Implement submitSignerListSet()**

  ```js
  function submitSignerListSet() {
    if (!validateMsForm()) return;
    const quorum = parseInt($('ms-quorum-input').value, 10);
    const txJson = {
      TransactionType: 'SignerListSet',
      Account: state.activeAccount,
      SignerQuorum: quorum,
      SignerEntries: msFormState.signers.map(s => ({
        SignerEntry: {
          Account: s.address,
          SignerWeight: Number(s.weight),
        },
      })),
    };
    reviewMultisignTx(txJson, 'Signer list updated!');
  }
  ```

- [ ] **Step 4: Wire up the Submit button**

  ```js
  $('ms-submit-btn').addEventListener('click', submitSignerListSet);
  ```

- [ ] **Step 5: Ensure back navigation from send-review returns to multisign**

  `executeReviewedTx()` already calls `state.pendingTxReview.backView`. The cancel button handler in `popup.js` (line ~6260) reads `backView` and calls `showView(back)`. Because we set `backView: 'multisign'`, cancel returns to the multisign screen.

  After a successful transaction, the success screen is shown by `setTxStatus('success', ...)` — the user taps Done which goes to `view-wallet`. That's the right behaviour (multisign config has changed; refreshing the screen is desirable).

  No code change needed — verify this is correct by reviewing the existing `send-review-cancel-btn` handler at line ~6259.

- [ ] **Step 6: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  - Fill in a valid quorum and at least one signer address → Submit routes to Review Transaction screen showing the SignerListSet fields and a collapsed Raw JSON section.
  - Leave address empty → error "Invalid XRPL address" appears inline.
  - Duplicate addresses → error "Duplicate signer addresses" appears.
  - Cancel on review → returns to Multisign screen.
  - Confirm on devnet → transaction succeeds and screen shows success status; returning to Multisign shows the updated signer list.

- [ ] **Step 7: Commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: implement SignerListSet transaction from multisign screen"
  ```

---

## Task 8: Master Key Toggle

Build and route the `AccountSet` transaction for disabling/re-enabling the master key.

**Files:**
- Modify: `src/popup/popup.js`

- [ ] **Step 1: Implement submitMasterKeyToggle()**

  Add in the `// MULTISIGN` section:
  ```js
  function submitMasterKeyToggle() {
    const txJson = {
      TransactionType: 'AccountSet',
      Account: state.activeAccount,
      ...(msMasterKeyDisabled ? { ClearFlag: 4 } : { SetFlag: 4 }),
    };
    const msg = msMasterKeyDisabled ? 'Master key re-enabled.' : 'Master key disabled.';
    reviewMultisignTx(txJson, msg);
  }
  ```

- [ ] **Step 2: Wire up the master key button**

  ```js
  $('ms-master-key-btn').addEventListener('click', submitMasterKeyToggle);
  ```

- [ ] **Step 3: Build and verify**

  Run: `npm run build`

  Expected: build succeeds.

  - Account with active master key → button reads "Disable Master Key" (red) → clicking routes to Review Transaction showing `AccountSet` with `SetFlag: 4`.
  - Account with disabled master key → button reads "Re-enable Master Key" (green) → clicking routes to Review Transaction showing `AccountSet` with `ClearFlag: 4`.
  - Submit on devnet → transaction succeeds; returning to Multisign shows updated master key status.

- [ ] **Step 4: Commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: implement master key toggle (AccountSet) from multisign screen"
  ```

---

## Task 9: Final Integration and Polish

Wire up any remaining loose ends and verify the full feature end-to-end.

**Files:**
- Modify: `src/popup/popup.js` — ensure `refreshAddressNames()` is called before rendering the signer list summary so names resolve correctly; reload multisign data after a successful transaction

- [ ] **Step 1: Refresh address names before rendering the summary**

  In `loadMultisignData()`, before calling `renderMultisignScreen()`, add:
  ```js
  await refreshAddressNames();
  ```

- [ ] **Step 2: Reload multisign screen after successful transaction**

  In `executeReviewedTx()` (line ~4482), after `setTxStatus('success', ...)`, the existing code calls `refreshBalance()` etc. No change needed there — the user goes to the success screen and hits Done to return to `view-wallet`.

  However, if the user navigates back to Multisign after the transaction they should see updated data. This is already handled because `openMultisignView()` resets state and calls `loadMultisignData()` on every entry. Confirm this is the case — no code change needed.

- [ ] **Step 3: Verify the full happy path end-to-end on devnet**

  Checklist:
  - [ ] Settings toggle off → MULTISIGN card absent from main page
  - [ ] Settings toggle on → MULTISIGN card present
  - [ ] Click card → Multisign screen opens, loading spinner then resolves
  - [ ] Account with no SignerList: "No Multisig Setup" + inactive master key dot
  - [ ] Setup form: add 2 signers via picker, set quorum 2, submit → Review screen → confirm → tesSUCCESS
  - [ ] Return to Multisign → configured summary shows quorum + signers with resolved names
  - [ ] Update → pre-populated form → change quorum → submit → tesSUCCESS
  - [ ] Disable Master Key → Review screen → confirm → tesSUCCESS → master key dot turns red
  - [ ] Re-enable Master Key → confirm → tesSUCCESS → master key dot turns green
  - [ ] Cancel on any review screen → returns to Multisign screen (not to wallet)
  - [ ] Toggle off Multisign in settings → MULTISIGN card disappears immediately

- [ ] **Step 4: Final commit**
  ```bash
  git add src/popup/popup.js
  git commit -m "feat: multisign phase 1 — complete integration"
  ```
