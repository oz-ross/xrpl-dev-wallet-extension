# Create MPT Issuance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the MPT section's `+` button with a dropdown (Add MPT / Create MPT), and implement a two-screen Create MPT flow that submits an `MPTokenIssuanceCreate` transaction with full XLS-89 structured metadata support.

**Architecture:** All changes are in three existing files (`popup.html`, `popup.js`, `popup.css`) — no new files. The dropdown follows the existing account/project dropdown pattern. The form → review flow mirrors the vault deposit and other existing transaction screens. `encodeMPTokenMetadata` from xrpl.js handles JSON→hex conversion.

**Tech Stack:** Vanilla JS, HTML, CSS. xrpl.js (`encodeMPTokenMetadata`, `MPTokenIssuanceCreate`). Chrome Extension Manifest v3.

**Spec:** `docs/superpowers/specs/2026-09-10-create-mpt-issuance-design.md`

## Global Constraints

- View navigation: `showView('name')` targets `id="view-{name}"`. Back buttons return to prior view.
- Dropdown close-on-outside-click: `document.addEventListener('click', handler, { capture: true, once: true })` inside `setTimeout(() => ..., 0)`.
- Transaction submission: `ensureConnected()` → `state.client.autofill(tx)` → `signWithAddress(prepared, state.activeAccount)` → `state.client.submitAndWait(tx_blob)` → check `resp.result?.meta?.TransactionResult === 'tesSUCCESS'`.
- Metadata encoding: use `encodeMPTokenMetadata` from xrpl.js — import it alongside `decodeMPTokenMetadata`. Do NOT hand-roll JSON→hex.
- Error display: `showAlert(id, message)` (sets `textContent`), `hideAlert(id)`. Never use `innerHTML` with ledger/user data.
- All DOM text from ledger/user input: `esc()` helper. Review field population via `textContent` is safe without `esc()`.
- After every code change: `NODE_OPTIONS= npm run build` must pass before moving to next step.
- **Correct flag values** (from xrpl.js source — the spec document has errors):
  - `tfMPTCanLock = 0x0002` (2)
  - `tfMPTRequireAuth = 0x0004` (4)
  - `tfMPTCanEscrow = 0x0008` (8)
  - `tfMPTCanTrade = 0x0010` (16)
  - `tfMPTCanTransfer = 0x0020` (32)
  - `tfMPTCanClawback = 0x0040` (64)
- **MaximumAmount max** is `'9223372036854775807'` (Int64.MAX from xrpl.js), not `'9999999999999999'` as the spec says.
- **TransferFee cross-validation**: xrpl.js rejects a non-zero `TransferFee` unless `tfMPTCanTransfer` (0x0020) flag is set — validate this in the form.

---

### Task 1: `+` Button Dropdown (HTML + CSS + JS)

Replace the single `+` button with a wrapper div containing the button and a small dropdown menu. Clicking `+` opens the dropdown; clicking outside closes it. The two items navigate to Add MPT (existing) and Create MPT (new).

**Files:**
- Modify: `src/popup/popup.html` (line ~672)
- Modify: `src/popup/popup.css` (after `.iou-balance-header` block, ~line 820)
- Modify: `src/popup/popup.js` (event listener section "Add MPT", ~line 7780)

**Interfaces:**
- Produces: `openMptAddDropdown()`, `closeMptAddDropdown()` — consumed by Task 2's `mpt-dropdown-create` listener.

- [ ] **Step 1: Replace button HTML in `popup.html`**

  Find this at line ~672:
  ```html
  <button id="add-mpt-btn" class="btn-icon btn-header-action" title="Add MPT">＋</button>
  ```
  Replace with:
  ```html
  <div class="mpt-add-wrapper">
    <button id="add-mpt-btn" class="btn-icon btn-header-action" title="MPT actions">＋</button>
    <div id="mpt-add-dropdown" class="mpt-add-dropdown hidden">
      <button class="mpt-add-dropdown-item" id="mpt-dropdown-add">Add MPT</button>
      <button class="mpt-add-dropdown-item" id="mpt-dropdown-create">Create MPT</button>
    </div>
  </div>
  ```

- [ ] **Step 2: Add CSS for dropdown in `popup.css`**

  After the `.iou-balance-header .btn-header-action` rule (line ~819), add:
  ```css
  /* ── MPT add dropdown ───────────────────────── */
  .mpt-add-wrapper {
    position: relative;
    display: inline-block;
  }

  .mpt-add-dropdown {
    position: absolute;
    top: calc(100% + 4px);
    right: 0;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    box-shadow: 0 4px 16px rgba(0,0,0,0.35);
    z-index: 200;
    min-width: 130px;
    padding: 4px 0;
    white-space: nowrap;
  }

  .mpt-add-dropdown-item {
    display: block;
    width: 100%;
    background: transparent;
    border: none;
    padding: 8px 14px;
    text-align: left;
    font-size: 13px;
    color: var(--text);
    font-family: inherit;
    cursor: pointer;
    transition: background var(--transition);
  }

  .mpt-add-dropdown-item:hover { background: var(--surface-2); }
  ```

- [ ] **Step 3: Update JS event listeners in `popup.js`**

  Find the "EVENT LISTENERS — Add MPT" section (~line 7780). Replace the single `$('add-mpt-btn').addEventListener('click', openAuthMpt)` line with:
  ```js
  function openMptAddDropdown() {
    $('mpt-add-dropdown').classList.remove('hidden');
    setTimeout(() => {
      document.addEventListener('click', closeMptAddDropdown, { capture: true, once: true });
    }, 0);
  }
  function closeMptAddDropdown() {
    $('mpt-add-dropdown').classList.add('hidden');
  }

  $('add-mpt-btn').addEventListener('click', e => { e.stopPropagation(); openMptAddDropdown(); });
  $('mpt-dropdown-add').addEventListener('click', () => { closeMptAddDropdown(); openAuthMpt(); });
  $('mpt-dropdown-create').addEventListener('click', () => { closeMptAddDropdown(); openCreateMptView(); });
  ```
  Note: `openCreateMptView` is implemented in Task 2 — this listener registration is fine before the function definition since event listeners fire at runtime, not parse time.

- [ ] **Step 4: Build and verify**

  ```bash
  NODE_OPTIONS= npm run build
  ```
  Expected: `compiled successfully`. Reload the extension in Chrome (`chrome://extensions` → refresh icon). Open popup, click `＋` in the MPT Balances header — dropdown shows "Add MPT" and "Create MPT". Clicking "Add MPT" opens the existing Add MPT screen. Clicking outside the dropdown closes it.

- [ ] **Step 5: Commit**

  ```bash
  git add src/popup/popup.html src/popup/popup.css src/popup/popup.js
  git commit -m "feat: replace MPT + button with Add MPT / Create MPT dropdown"
  ```

---

### Task 2: Create MPT Form View (HTML + CSS + JS)

Add the `view-create-mpt` HTML, CSS for the metadata toggle and URI rows, and all JS logic: state variables, `openCreateMptView`, URI row management, metadata mode toggling, `buildMptMetadataHex`, and `openCreateMptReview` validation.

**Files:**
- Modify: `src/popup/popup.html` (after `view-auth-mpt`, ~line 1483)
- Modify: `src/popup/popup.css` (add URI row + meta toggle styles)
- Modify: `src/popup/popup.js` (import, state vars, functions, event listeners)

**Interfaces:**
- Consumes: `showView('create-mpt')`, `showAlert`/`hideAlert`, `encodeMPTokenMetadata` (imported from xrpl).
- Produces: `_createMptPending` (object), `_createMptMetaMode` (string), `openCreateMptView()`, `buildMptMetadataHex()` — consumed by Task 3.

- [ ] **Step 1: Add `encodeMPTokenMetadata` to xrpl import in `popup.js`**

  Find line ~2 (the xrpl import):
  ```js
  import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeAccountID, decodeMPTokenMetadata, isValidClassicAddress, prepareConfidentialConvert, prepareConfidentialConvertBack, prepareConfidentialMergeInbox, prepareConfidentialSend } from 'xrpl';
  ```
  Add `encodeMPTokenMetadata` to the import list:
  ```js
  import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeAccountID, decodeMPTokenMetadata, encodeMPTokenMetadata, isValidClassicAddress, prepareConfidentialConvert, prepareConfidentialConvertBack, prepareConfidentialMergeInbox, prepareConfidentialSend } from 'xrpl';
  ```

- [ ] **Step 2: Add HTML for `view-create-mpt` in `popup.html`**

  After the closing `</div>` of `view-auth-mpt` (~line 1483), insert:
  ```html
  <!-- ===== CREATE MPT ===== -->
  <div id="view-create-mpt" class="view hidden">
    <div class="view-header">
      <button id="back-from-create-mpt-btn" class="btn-back">‹</button>
      <h2>Create MPT</h2>
    </div>

    <div class="form-group">
      <label for="create-mpt-asset-scale">Asset Scale <span class="label-optional">(0–255, default 0 = integer token)</span></label>
      <input type="number" id="create-mpt-asset-scale" min="0" max="255" value="0" />
    </div>

    <div class="form-group">
      <label for="create-mpt-max-amount">Maximum Amount <span class="label-optional">(optional — leave blank for uncapped)</span></label>
      <input type="text" id="create-mpt-max-amount" placeholder="e.g. 1000000000" autocomplete="off" spellcheck="false" />
    </div>

    <div class="form-group">
      <label for="create-mpt-transfer-fee">Transfer Fee <span class="label-optional">(optional — 0–50000 thousandths of 1%, requires Can Transfer)</span></label>
      <input type="number" id="create-mpt-transfer-fee" min="0" max="50000" placeholder="e.g. 1000 = 1%" autocomplete="off" />
    </div>

    <div class="form-group">
      <label>Flags <span class="label-optional">(immutable after creation)</span></label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-transfer" />
        <span>Can Transfer (enable peer-to-peer transfers)</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-clawback" />
        <span>Can Clawback (issuer can reclaim tokens)</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-require-auth" />
        <span>Require Auth (issuer must authorize each holder)</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-lock" />
        <span>Can Lock (issuer can freeze individual balances)</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-escrow" />
        <span>Can Escrow (allow in escrow transactions)</span>
      </label>
      <label class="checkbox-row">
        <input type="checkbox" id="create-mpt-flag-trade" />
        <span>Can Trade (allow AMM/DEX trading)</span>
      </label>
    </div>

    <div class="form-group">
      <label>Metadata <span class="label-optional">(optional)</span></label>
      <div class="create-mpt-meta-toggle">
        <button id="create-mpt-meta-structured-btn" class="create-mpt-meta-toggle-btn active">Structured</button>
        <button id="create-mpt-meta-raw-btn" class="create-mpt-meta-toggle-btn">Raw Hex</button>
      </div>

      <div id="create-mpt-meta-structured">
        <div class="form-group">
          <label for="create-mpt-ticker">Ticker <span class="label-optional">(A-Z 0-9, max 6 chars)</span></label>
          <input type="text" id="create-mpt-ticker" maxlength="6" placeholder="e.g. MYTKN" autocomplete="off" spellcheck="false" />
        </div>
        <div class="form-group">
          <label for="create-mpt-name">Name <span class="label-optional">(optional)</span></label>
          <input type="text" id="create-mpt-name" placeholder="e.g. My Token" autocomplete="off" />
        </div>
        <div class="form-group">
          <label for="create-mpt-issuer-name">Issuer Name <span class="label-optional">(optional)</span></label>
          <input type="text" id="create-mpt-issuer-name" placeholder="e.g. Acme Corp" autocomplete="off" />
        </div>
        <div class="form-group">
          <label for="create-mpt-asset-class">Asset Class <span class="label-optional">(optional)</span></label>
          <select id="create-mpt-asset-class">
            <option value="">— select —</option>
            <option value="rwa">rwa</option>
            <option value="memes">memes</option>
            <option value="wrapped">wrapped</option>
            <option value="gaming">gaming</option>
            <option value="defi">defi</option>
            <option value="other">other</option>
          </select>
        </div>
        <div id="create-mpt-asset-subclass-row" class="form-group hidden">
          <label for="create-mpt-asset-subclass">Asset Subclass <span class="label-optional">(required for rwa)</span></label>
          <select id="create-mpt-asset-subclass">
            <option value="">— select —</option>
            <option value="stablecoin">stablecoin</option>
            <option value="commodity">commodity</option>
            <option value="real_estate">real_estate</option>
            <option value="private_credit">private_credit</option>
            <option value="equity">equity</option>
            <option value="treasury">treasury</option>
            <option value="other">other</option>
          </select>
        </div>
        <div class="form-group">
          <label for="create-mpt-icon">Icon URL <span class="label-optional">(optional)</span></label>
          <input type="text" id="create-mpt-icon" placeholder="https://example.com/icon.png" autocomplete="off" />
        </div>
        <div class="form-group">
          <label for="create-mpt-desc">Description <span class="label-optional">(optional)</span></label>
          <textarea id="create-mpt-desc" placeholder="Token description…"></textarea>
        </div>
        <div class="form-group">
          <label>URIs <span class="label-optional">(optional — website, whitepaper, etc.)</span></label>
          <div id="create-mpt-uris-list"></div>
          <button id="create-mpt-add-uri-btn" class="btn btn-outline btn-full" style="margin-top:4px">+ Add URI</button>
        </div>
        <div class="form-group">
          <label for="create-mpt-additional-info">Additional Info <span class="label-optional">(optional — JSON object or plain string)</span></label>
          <textarea id="create-mpt-additional-info" placeholder='{"key": "value"}'></textarea>
        </div>
      </div>

      <div id="create-mpt-meta-raw" class="hidden">
        <div class="form-group" style="margin-top:8px">
          <label for="create-mpt-meta-hex">Metadata Hex</label>
          <textarea id="create-mpt-meta-hex" placeholder="Uppercase hex string…" style="font-family: monospace; min-height: 80px"></textarea>
        </div>
      </div>
    </div>

    <div id="create-mpt-error" class="alert alert-error hidden"></div>
    <button id="create-mpt-review-btn" class="btn btn-primary btn-full" style="margin-top:8px">Review →</button>
  </div>
  ```

- [ ] **Step 3: Add CSS for metadata toggle and URI rows in `popup.css`**

  Append near the end of the file (before the final comment/rule group), or after the `.ct-action-menu` block:
  ```css
  /* ── Create MPT form ────────────────────────── */
  .create-mpt-meta-toggle {
    display: flex;
    gap: 4px;
    margin-bottom: 12px;
  }

  .create-mpt-meta-toggle-btn {
    flex: 1;
    padding: 5px 10px;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--text-2);
    font-size: 12px;
    font-weight: 600;
    font-family: inherit;
    cursor: pointer;
    transition: background var(--transition), color var(--transition);
  }

  .create-mpt-meta-toggle-btn.active {
    background: var(--accent);
    color: #fff;
    border-color: var(--accent);
  }

  .create-mpt-uri-row {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr auto;
    gap: 6px;
    align-items: center;
    margin-bottom: 6px;
  }

  .create-mpt-uri-row input {
    min-width: 0;
  }

  .uri-remove-btn {
    background: transparent;
    border: none;
    color: var(--text-3);
    cursor: pointer;
    padding: 4px;
    font-size: 14px;
    line-height: 1;
    flex-shrink: 0;
  }

  .uri-remove-btn:hover { color: var(--danger); }
  ```

- [ ] **Step 4: Add state variables in `popup.js`**

  Near the other module-level state declarations (around line 8606 where `_ctHideTimer` etc. are declared), add:
  ```js
  let _createMptPending  = null; // { assetScale, maximumAmount, transferFee, flags, metadataHex, displayName }
  let _createMptMetaMode = 'structured'; // 'structured' | 'raw'
  ```

- [ ] **Step 5: Add `openCreateMptView()` and helper functions to `popup.js`**

  Add these functions near `openAuthMpt` (around line 4239), or in a new "// CREATE MPT" section just after it:

  ```js
  // ─────────────────────────────────────────────
  // CREATE MPT
  // ─────────────────────────────────────────────

  function openCreateMptView() {
    // Reset all fields
    $('create-mpt-asset-scale').value        = '0';
    $('create-mpt-max-amount').value         = '';
    $('create-mpt-transfer-fee').value       = '';
    $('create-mpt-flag-transfer').checked    = false;
    $('create-mpt-flag-clawback').checked    = false;
    $('create-mpt-flag-require-auth').checked = false;
    $('create-mpt-flag-lock').checked        = false;
    $('create-mpt-flag-escrow').checked      = false;
    $('create-mpt-flag-trade').checked       = false;
    $('create-mpt-ticker').value             = '';
    $('create-mpt-name').value               = '';
    $('create-mpt-issuer-name').value        = '';
    $('create-mpt-asset-class').value        = '';
    $('create-mpt-asset-subclass').value     = '';
    $('create-mpt-asset-subclass-row').classList.add('hidden');
    $('create-mpt-icon').value               = '';
    $('create-mpt-desc').value               = '';
    $('create-mpt-uris-list').innerHTML      = '';
    $('create-mpt-additional-info').value    = '';
    $('create-mpt-meta-hex').value           = '';
    hideAlert('create-mpt-error');
    // Reset metadata mode to structured
    _createMptMetaMode = 'structured';
    $('create-mpt-meta-structured').classList.remove('hidden');
    $('create-mpt-meta-raw').classList.add('hidden');
    $('create-mpt-meta-structured-btn').classList.add('active');
    $('create-mpt-meta-raw-btn').classList.remove('active');
    showView('create-mpt');
  }

  function addMptUri() {
    const list = $('create-mpt-uris-list');
    const row  = document.createElement('div');
    row.className = 'create-mpt-uri-row';
    row.innerHTML = `
      <input type="text" class="uri-field"    placeholder="URI"      autocomplete="off" />
      <input type="text" class="uri-category" placeholder="Category" autocomplete="off" />
      <input type="text" class="uri-title"    placeholder="Title"    autocomplete="off" />
      <button class="uri-remove-btn" title="Remove">✕</button>
    `;
    row.querySelector('.uri-remove-btn').addEventListener('click', () => row.remove());
    list.appendChild(row);
  }

  function switchMptMetaMode(mode) {
    if (mode === _createMptMetaMode) return;
    if (mode === 'raw') {
      // Serialize current structured state into the raw textarea before switching
      const hex = buildMptMetadataHex();
      $('create-mpt-meta-hex').value = hex ?? '';
      $('create-mpt-meta-structured').classList.add('hidden');
      $('create-mpt-meta-raw').classList.remove('hidden');
      $('create-mpt-meta-structured-btn').classList.remove('active');
      $('create-mpt-meta-raw-btn').classList.add('active');
    } else {
      // Switch back to structured — retain structured field values, don't parse raw
      $('create-mpt-meta-raw').classList.add('hidden');
      $('create-mpt-meta-structured').classList.remove('hidden');
      $('create-mpt-meta-raw-btn').classList.remove('active');
      $('create-mpt-meta-structured-btn').classList.add('active');
    }
    _createMptMetaMode = mode;
  }

  function buildMptMetadataHex() {
    if (_createMptMetaMode === 'raw') {
      return $('create-mpt-meta-hex').value.trim();
    }
    const obj = {};
    const ticker = $('create-mpt-ticker').value.trim().toUpperCase();
    if (ticker) obj.ticker = ticker;
    const name = $('create-mpt-name').value.trim();
    if (name) obj.name = name;
    const issuerName = $('create-mpt-issuer-name').value.trim();
    if (issuerName) obj.issuer_name = issuerName;
    const assetClass = $('create-mpt-asset-class').value;
    if (assetClass) obj.asset_class = assetClass;
    const assetSubclass = $('create-mpt-asset-subclass').value;
    if (assetSubclass) obj.asset_subclass = assetSubclass;
    const icon = $('create-mpt-icon').value.trim();
    if (icon) obj.icon = icon;
    const desc = $('create-mpt-desc').value.trim();
    if (desc) obj.desc = desc;
    const uriRows = $('create-mpt-uris-list').querySelectorAll('.create-mpt-uri-row');
    const uris = [];
    for (const row of uriRows) {
      const uri      = row.querySelector('.uri-field').value.trim();
      const category = row.querySelector('.uri-category').value.trim();
      const title    = row.querySelector('.uri-title').value.trim();
      if (uri || category || title) {
        uris.push({ uri, category, title });
      }
    }
    if (uris.length > 0) obj.uris = uris;
    const additionalInfoRaw = $('create-mpt-additional-info').value.trim();
    if (additionalInfoRaw) {
      try {
        obj.additional_info = JSON.parse(additionalInfoRaw);
      } catch {
        obj.additional_info = additionalInfoRaw;
      }
    }
    if (Object.keys(obj).length === 0) return '';
    try {
      return encodeMPTokenMetadata(obj);
    } catch (err) {
      showAlert('create-mpt-error', `Metadata error: ${err.message || 'Invalid metadata'}`);
      return null;
    }
  }

  function openCreateMptReview() {
    hideAlert('create-mpt-error');

    // Asset Scale
    const assetScale = parseInt($('create-mpt-asset-scale').value, 10);
    if (isNaN(assetScale) || assetScale < 0 || assetScale > 255) {
      showAlert('create-mpt-error', 'Asset Scale must be an integer 0–255.');
      return;
    }

    // Maximum Amount (optional)
    const maxAmountRaw = $('create-mpt-max-amount').value.trim();
    let maximumAmount = null;
    if (maxAmountRaw) {
      if (!/^\d+$/.test(maxAmountRaw)) {
        showAlert('create-mpt-error', 'Maximum Amount must be a positive integer.');
        return;
      }
      const maxAmt = BigInt(maxAmountRaw);
      if (maxAmt <= 0n || maxAmt > BigInt('9223372036854775807')) {
        showAlert('create-mpt-error', 'Maximum Amount must be between 1 and 9223372036854775807.');
        return;
      }
      maximumAmount = maxAmountRaw;
    }

    // Transfer Fee (optional)
    const transferFeeRaw = $('create-mpt-transfer-fee').value.trim();
    let transferFee = null;
    if (transferFeeRaw !== '') {
      transferFee = parseInt(transferFeeRaw, 10);
      if (isNaN(transferFee) || transferFee < 0 || transferFee > 50000) {
        showAlert('create-mpt-error', 'Transfer Fee must be an integer 0–50000 (thousandths of 1%).');
        return;
      }
    }

    // Flags
    let flags = 0;
    if ($('create-mpt-flag-transfer').checked)     flags |= 0x0020; // tfMPTCanTransfer
    if ($('create-mpt-flag-clawback').checked)     flags |= 0x0040; // tfMPTCanClawback
    if ($('create-mpt-flag-require-auth').checked) flags |= 0x0004; // tfMPTRequireAuth
    if ($('create-mpt-flag-lock').checked)         flags |= 0x0002; // tfMPTCanLock
    if ($('create-mpt-flag-escrow').checked)       flags |= 0x0008; // tfMPTCanEscrow
    if ($('create-mpt-flag-trade').checked)        flags |= 0x0010; // tfMPTCanTrade

    // Cross-validation: TransferFee requires tfMPTCanTransfer
    if (transferFee !== null && transferFee > 0 && !(flags & 0x0020)) {
      showAlert('create-mpt-error', 'Transfer Fee requires the "Can Transfer" flag to be enabled.');
      return;
    }

    // Metadata
    const metadataHex = buildMptMetadataHex();
    if (metadataHex === null) return; // error already shown in buildMptMetadataHex
    if (metadataHex && metadataHex.length / 2 > 1024) {
      showAlert('create-mpt-error', 'Metadata exceeds 1024 bytes.');
      return;
    }

    const ticker = $('create-mpt-ticker').value.trim().toUpperCase();
    const name   = $('create-mpt-name').value.trim();
    _createMptPending = {
      assetScale,
      maximumAmount,
      transferFee,
      flags,
      metadataHex,
      displayName: ticker || name || 'MPT',
    };

    openCreateMptReviewView();
  }
  ```

- [ ] **Step 6: Add event listeners for Create MPT form in `popup.js`**

  After the "EVENT LISTENERS — Add MPT" section, add a new section:
  ```js
  // ─────────────────────────────────────────────
  // EVENT LISTENERS — Create MPT
  // ─────────────────────────────────────────────

  $('back-from-create-mpt-btn').addEventListener('click', () => showView('wallet'));
  $('create-mpt-asset-class').addEventListener('change', () => {
    const isRwa = $('create-mpt-asset-class').value === 'rwa';
    $('create-mpt-asset-subclass-row').classList.toggle('hidden', !isRwa);
    if (!isRwa) $('create-mpt-asset-subclass').value = '';
  });
  $('create-mpt-meta-structured-btn').addEventListener('click', () => switchMptMetaMode('structured'));
  $('create-mpt-meta-raw-btn').addEventListener('click', () => switchMptMetaMode('raw'));
  $('create-mpt-add-uri-btn').addEventListener('click', addMptUri);
  $('create-mpt-review-btn').addEventListener('click', openCreateMptReview);
  ```

- [ ] **Step 7: Build and verify**

  ```bash
  NODE_OPTIONS= npm run build
  ```
  Expected: `compiled successfully`. Reload the extension. Click `＋` → "Create MPT". Verify:
  - Form renders with all fields
  - Asset Scale defaults to 0
  - Selecting "rwa" for Asset Class reveals Asset Subclass; selecting anything else hides it
  - Clicking "Structured" / "Raw Hex" toggles the metadata panels; switching to Raw Hex populates the textarea with hex if fields were filled
  - "Add URI" appends a row with 3 inputs and a remove button; clicking ✕ removes the row
  - Clicking "Review →" with Asset Scale out of range shows an error
  - Clicking "Review →" with TransferFee > 0 but "Can Transfer" unchecked shows an error
  - Clicking "Review →" with valid input stores `_createMptPending` (check in DevTools console: `window._createMptPending` won't work since it's module-scoped — verify by proceeding to review in Task 3)

- [ ] **Step 8: Commit**

  ```bash
  git add src/popup/popup.html src/popup/popup.css src/popup/popup.js
  git commit -m "feat: add Create MPT form view with XLS-89 metadata and flag selection"
  ```

---

### Task 3: Review View and Transaction Submission

Add the `view-create-mpt-review` HTML, implement `openCreateMptReviewView()` to populate it from `_createMptPending`, and implement `confirmCreateMpt()` to submit the `MPTokenIssuanceCreate` transaction.

**Files:**
- Modify: `src/popup/popup.html` (after `view-create-mpt`)
- Modify: `src/popup/popup.js` (new functions + event listeners)

**Interfaces:**
- Consumes: `_createMptPending` (from Task 2), `showView`, `showAlert`/`hideAlert`, `ensureConnected`, `state.client`, `signWithAddress`, `loadMptBalances`.
- Produces: New issuance ID shown to user on success; navigates back to wallet.

- [ ] **Step 1: Add `view-create-mpt-review` HTML in `popup.html`**

  Immediately after the closing `</div>` of `view-create-mpt`, insert:
  ```html
  <!-- ===== CREATE MPT REVIEW ===== -->
  <div id="view-create-mpt-review" class="view hidden">
    <div class="view-header">
      <button id="back-from-create-mpt-review-btn" class="btn-back">‹</button>
      <h2>Review: Create MPT</h2>
    </div>

    <div class="detail-card">
      <div class="detail-row">
        <span class="detail-label">Token</span>
        <span id="create-mpt-review-name" class="detail-value"></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Scale</span>
        <span id="create-mpt-review-scale" class="detail-value"></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Max</span>
        <span id="create-mpt-review-max" class="detail-value"></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Fee</span>
        <span id="create-mpt-review-fee" class="detail-value"></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Flags</span>
        <span id="create-mpt-review-flags" class="detail-value"></span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Metadata</span>
        <span id="create-mpt-review-meta" class="detail-value detail-break"></span>
      </div>
    </div>

    <div id="create-mpt-review-error" class="alert alert-error hidden"></div>
    <button id="create-mpt-confirm-btn" class="btn btn-primary btn-full" style="margin-top:8px">Create MPT</button>
  </div>
  ```

- [ ] **Step 2: Implement `openCreateMptReviewView()` and `confirmCreateMpt()` in `popup.js`**

  Add these functions in the CREATE MPT section (after `openCreateMptReview`):

  ```js
  function openCreateMptReviewView() {
    const p = _createMptPending;
    $('create-mpt-review-name').textContent  = p.displayName;
    $('create-mpt-review-scale').textContent = String(p.assetScale);
    $('create-mpt-review-max').textContent   = p.maximumAmount ?? 'Uncapped';
    $('create-mpt-review-fee').textContent   = p.transferFee !== null
      ? `${(p.transferFee / 1000).toFixed(3)}%`
      : 'None';

    const flagNames = [];
    if (p.flags & 0x0020) flagNames.push('Can Transfer');
    if (p.flags & 0x0040) flagNames.push('Can Clawback');
    if (p.flags & 0x0004) flagNames.push('Require Auth');
    if (p.flags & 0x0002) flagNames.push('Can Lock');
    if (p.flags & 0x0008) flagNames.push('Can Escrow');
    if (p.flags & 0x0010) flagNames.push('Can Trade');
    $('create-mpt-review-flags').textContent = flagNames.length > 0
      ? flagNames.join(', ')
      : 'None';

    if (p.metadataHex) {
      const byteLen = p.metadataHex.length / 2;
      const preview = p.metadataHex.length > 32
        ? p.metadataHex.slice(0, 32) + '…'
        : p.metadataHex;
      $('create-mpt-review-meta').textContent = `${preview} (${byteLen} bytes)`;
    } else {
      $('create-mpt-review-meta').textContent = 'None';
    }

    hideAlert('create-mpt-review-error');
    $('create-mpt-confirm-btn').disabled    = false;
    $('create-mpt-confirm-btn').textContent = 'Create MPT';
    showView('create-mpt-review');
  }

  async function confirmCreateMpt() {
    const btn = $('create-mpt-confirm-btn');
    btn.disabled    = true;
    btn.textContent = 'Creating…';
    hideAlert('create-mpt-review-error');

    try {
      await ensureConnected();
      const p  = _createMptPending;
      const tx = {
        TransactionType: 'MPTokenIssuanceCreate',
        Account: state.activeAccount,
      };
      if (p.assetScale !== 0)    tx.AssetScale     = p.assetScale;
      if (p.maximumAmount)        tx.MaximumAmount   = p.maximumAmount;
      if (p.transferFee !== null) tx.TransferFee     = p.transferFee;
      if (p.flags !== 0)          tx.Flags           = p.flags;
      if (p.metadataHex)          tx.MPTokenMetadata = p.metadataHex;

      const prepared  = await state.client.autofill(tx);
      const tx_blob   = await signWithAddress(prepared, state.activeAccount);
      const resp      = await state.client.submitAndWait(tx_blob);
      const txResult  = resp.result?.meta?.TransactionResult;

      if (txResult !== 'tesSUCCESS') {
        throw new Error(txResult ?? 'Unknown error');
      }

      const issuanceId = resp.result.meta?.mpt_issuance_id ?? '(ID unavailable)';
      const alertEl    = $('create-mpt-review-error');
      alertEl.textContent = `MPT created: ${issuanceId}`;
      alertEl.className   = 'alert alert-success';
      alertEl.classList.remove('hidden');

      setTimeout(() => {
        alertEl.className = 'alert alert-error hidden';
        showView('wallet');
        loadMptBalances();
      }, 2000);
    } catch (err) {
      showAlert('create-mpt-review-error', `Failed: ${err.message || 'Unknown error'}`);
      btn.disabled    = false;
      btn.textContent = 'Create MPT';
    }
  }
  ```

- [ ] **Step 3: Add event listeners for the review view in `popup.js`**

  In the "EVENT LISTENERS — Create MPT" section (from Task 2), add:
  ```js
  $('back-from-create-mpt-review-btn').addEventListener('click', () => showView('create-mpt'));
  $('create-mpt-confirm-btn').addEventListener('click', confirmCreateMpt);
  ```

- [ ] **Step 4: Build**

  ```bash
  NODE_OPTIONS= npm run build
  ```
  Expected: `compiled successfully`.

- [ ] **Step 5: End-to-end test in Chrome**

  Reload extension. Open popup. Click `＋` → "Create MPT". Fill the form:
  - Asset Scale: `2`
  - Maximum Amount: `1000000`
  - Transfer Fee: `500` (= 0.5%)
  - Check "Can Transfer" and "Can Clawback"
  - Ticker: `TEST`, Name: `Test Token`, Asset Class: `other`
  - Click "Review →"

  Verify review screen shows:
  - Token: `TEST`
  - Scale: `2`
  - Max: `1000000`
  - Fee: `0.500%`
  - Flags: `Can Transfer, Can Clawback`
  - Metadata: hex preview + byte count

  Click "Create MPT". Verify:
  - Button shows "Creating…" while waiting
  - On success: green success banner with issuance ID, then navigates to wallet after 2 seconds
  - New issuance appears in MPT Balances (as an "Issuer" row)
  - On failure (e.g. insufficient XRP for fee): error banner shown, button re-enabled

  Also test error paths:
  - Transfer Fee without "Can Transfer": error on form
  - Asset Scale 256: error on form
  - Max Amount 0: error on form

- [ ] **Step 6: Commit**

  ```bash
  git add src/popup/popup.html src/popup/popup.js
  git commit -m "feat: add Create MPT review screen and MPTokenIssuanceCreate submission"
  ```
