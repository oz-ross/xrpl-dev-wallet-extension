# Confidential Transfers Phase 2: MPT Holdings UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-MPT-holding confidential transfer UI: a CT state indicator + "Add Confidentiality" button for eligible holdings without confidential balances, and an expandable balance breakdown (public + spendable + inbox) for holdings that already have them.

**Architecture:** Three per-holding render states determined at `renderMptBalances` time using `state.elgamalKeys[activeAccount]` and MPToken ledger fields. State C holdings are decrypted via BSGS at render time. The convert flow uses a new view (`view-confidential-convert`) and the existing `autofill → signPreparedTx → submitAndWait` pipeline.

**Tech Stack:** `@xrplf/mpt-crypto` (already vendored), `@noble/curves/secp256k1.js` (already imported in Phase 1), `xrpl` v4.x (`state.client`), Chrome Extension MV3.

**Spec:** `docs/superpowers/specs/2026-09-08-confidential-transfers-mpt-holdings-design.md`

## Global Constraints

- Never run `git push`; run `npm run build` after every source edit — extension loads from `dist/`, not `src/`
- Hex strings (ElGamal keys, ciphertexts, blinding factors) are UPPERCASE, no `0x` prefix; this is what mpt-crypto expects and returns
- `renderMptBalances` must become `async` — its caller (`loadMptBalances`) already `await`s it via `Promise.all`, no structural change to the caller required
- Use `signPreparedTx(prepared)` + `state.client.autofill(txJson)` + `state.client.submitAndWait(tx_blob)` — the existing three-step pipeline shared by all transactions
- Fetch `Sequence` via `account_info` before building the context hash (needed before autofill since context hash must match the transaction sequence exactly)
- `showAlert('element-id', 'message')` / `hideAlert('element-id')` — exact signatures confirmed
- Only MPToken holder rows are modified (objects with `LedgerEntryType === 'MPToken'`). Issuance rows (`mpt-issuance-item`) are unchanged.
- BSGS `rangeHigh`: `BigInt(10 ** 9)` — sufficient for dev-wallet test amounts; amounts above this ceiling display as `[encrypted]`
- Working directory: `/Users/ross/Documents/Projects/tools/xrpl-dev-wallet-extension`

---

### Task 1: mpt-crypto imports + `fetchMptIssuanceInfo` extension

**Files:**
- Modify: `src/popup/popup.js`

**Interfaces:**
- Produces: `generateBlindingFactor`, `encryptAmount`, `decryptAmount`, `getConvertContextHash`, `getConvertProof` available as module-level imports; `fetchMptIssuanceInfo` return object extended with `issuerEncryptionKey` and `auditorEncryptionKey`
- Consumed by: Tasks 2 (decryptAmount) and 4 (all five functions + issuance keys)

- [ ] **Step 1: Add mpt-crypto imports**

Find the existing `import` block near the top of `src/popup/popup.js` (alongside `xrpl`, `@noble/curves/secp256k1.js`, etc.). Add:

```js
import {
  generateBlindingFactor,
  encryptAmount,
  decryptAmount,
  getConvertContextHash,
  getConvertProof,
} from '@xrplf/mpt-crypto';
```

- [ ] **Step 2: Extend `fetchMptIssuanceInfo` return value**

Find `fetchMptIssuanceInfo` (around line 2332). It does a `ledger_entry` call for `mpt_issuance` and builds a return object. The raw ledger entry result is stored in a local variable (look for something like `result.node` or `result.result.node`).

Add two fields to the returned object:

```js
issuerEncryptionKey:  result.IssuerEncryptionKey  ?? null,
auditorEncryptionKey: result.AuditorEncryptionKey ?? null,
```

These fields are already present in the raw ledger entry response when the MPT issuance has CT configured; they're simply not currently extracted.

- [ ] **Step 3: Build and verify**

```bash
npm run build
```

Expected: `compiled successfully` with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: add mpt-crypto imports and extend fetchMptIssuanceInfo with CT keys"
```

---

### Task 2: CT state rendering in `renderMptBalances`

**Files:**
- Modify: `src/popup/popup.js`

**Interfaces:**
- Consumes: `decryptAmount` import (Task 1), `issuanceMap[id].issuerEncryptionKey` and `.auditorEncryptionKey` (Task 1), `state.elgamalKeys[state.activeAccount]`
- Produces: State B rows have `.ct-add-confidentiality-btn` button and data attrs `data-issuer-enc-key`, `data-auditor-enc-key`, `data-asset-scale`; State C rows have `.ct-expand-btn` toggle and `.ct-sub-balances` section; event delegation on `#mpt-balance-list`; `openConfidentialConvertView` is called from the delegation handler (implemented as a stub if Task 4 is not yet done)

- [ ] **Step 1: Make `renderMptBalances` async**

Find `renderMptBalances` (around line 3132). Change:
```js
function renderMptBalances(regularObjects, issuanceMap, issuances) {
```
to:
```js
async function renderMptBalances(regularObjects, issuanceMap, issuances) {
```

- [ ] **Step 2: Add CT state logic to the holder row loop**

Inside `renderMptBalances`, find the loop that builds HTML for MPToken holder objects (those with `LedgerEntryType === 'MPToken'`). Before building each row's HTML, add the CT state check:

```js
const ctWalletKey = state.elgamalKeys[state.activeAccount];
const holderEncKey = obj.HolderEncryptionKey ?? null;
const info = issuanceMap[obj.MPTokenIssuanceID] ?? {};

// CT states:
// A: no wallet ElGamal key → unchanged
// B: wallet key exists, issuance has IssuerEncryptionKey, but MPToken has no HolderEncryptionKey
// C: MPToken has HolderEncryptionKey (confidential balance exists)
const ctState = !ctWalletKey
  ? 'A'
  : holderEncKey
    ? 'C'
    : info.issuerEncryptionKey
      ? 'B'
      : 'A';
```

- [ ] **Step 3: State B row rendering**

For rows where `ctState === 'B'`, append a CT button to the existing row HTML and add required data attributes to the row element. After the existing row HTML string is built (before it's inserted into the list), append inside the row div:

```html
<button class="btn-icon ct-add-confidentiality-btn" title="Add confidentiality">⛨ Add Confidentiality</button>
```

Add these data attributes to the `.mpt-balance-item` div (alongside existing `data-mpt-id`, `data-balance`, etc.):

```js
data-issuer-enc-key="${info.issuerEncryptionKey}"
data-auditor-enc-key="${info.auditorEncryptionKey ?? ''}"
data-asset-scale="${info.assetScale ?? 0}"
```

- [ ] **Step 4: State C row rendering with BSGS decryption**

For rows where `ctState === 'C'`:

```js
const RANGE_HIGH = BigInt(10 ** 9);
const privKeyHex = ctWalletKey.privKey;

const [spendable, inbox] = await Promise.all([
  obj.ConfidentialBalanceSpending
    ? decryptAmount(obj.ConfidentialBalanceSpending, privKeyHex, RANGE_HIGH).catch(() => null)
    : Promise.resolve(0n),
  obj.ConfidentialBalanceInbox
    ? decryptAmount(obj.ConfidentialBalanceInbox, privKeyHex, RANGE_HIGH).catch(() => null)
    : Promise.resolve(0n),
]);

const scale = info.assetScale ?? 0;
const divisor = scale > 0 ? 10 ** scale : 1;
const fmtRaw = (v) => v === null ? '[encrypted]' : (Number(v) / divisor).toFixed(scale);

// publicAmt is already the display string in the existing row (data-balance)
const publicRaw = parseInt(obj.MPTAmount ?? '0', 10);
const hasNull = spendable === null || inbox === null;

const totalDisplay = hasNull
  ? `~${(publicRaw / divisor + (spendable !== null ? Number(spendable) / divisor : 0) + (inbox !== null ? Number(inbox) / divisor : 0)).toFixed(scale)}`
  : ((publicRaw / divisor) + Number(spendable) / divisor + Number(inbox) / divisor).toFixed(scale);

// Sub-balances section (hidden by default):
const subBalancesHtml = `
  <div class="ct-sub-balances hidden">
    <div class="ct-sub-row">├ Public: ${(publicRaw / divisor).toFixed(scale)}</div>
    <div class="ct-sub-row">├ Confidential (spendable): ${fmtRaw(spendable)}</div>
    <div class="ct-sub-row">└ Confidential (inbox): ${fmtRaw(inbox)}</div>
  </div>`;
```

In the row HTML, replace the balance amount display with the total, prepend a `▶` toggle button, and append the sub-balances section:

```html
<button class="btn-icon ct-expand-btn" aria-expanded="false">▶</button>
<!-- existing mpt-token-info div unchanged -->
<span class="mpt-balance-amount">Total: ${totalDisplay}</span>
<!-- existing explorer link unchanged -->
${subBalancesHtml}
```

- [ ] **Step 5: Add event delegation on `#mpt-balance-list`**

After the existing event listeners for `#mpt-balance-list` (or add a new one), add:

```js
$('mpt-balance-list').addEventListener('click', (e) => {
  // Expand/collapse toggle
  const expandBtn = e.target.closest('.ct-expand-btn');
  if (expandBtn) {
    const row = expandBtn.closest('.mpt-balance-item');
    const sub = row.querySelector('.ct-sub-balances');
    const expanded = expandBtn.getAttribute('aria-expanded') === 'true';
    expandBtn.setAttribute('aria-expanded', String(!expanded));
    expandBtn.textContent = expanded ? '▶' : '▼';
    sub.classList.toggle('hidden', expanded);
    return;
  }

  // Add Confidentiality button
  const ctBtn = e.target.closest('.ct-add-confidentiality-btn');
  if (ctBtn) {
    const row = ctBtn.closest('.mpt-balance-item');
    openConfidentialConvertView(row);
    return;
  }
});
```

Note: `openConfidentialConvertView` is implemented in Task 4. If Task 4 is not yet done, add a temporary stub at the bottom of the CONFIDENTIAL TRANSFERS section:

```js
function openConfidentialConvertView(rowEl) { /* Task 4 */ }
```

- [ ] **Step 6: Add CSS for sub-row indentation**

Check `src/popup/popup.css` for a `.ct-sub-balances` or `.ct-sub-row` class. If absent, add to `src/popup/popup.css`:

```css
.ct-sub-balances {
  width: 100%;
  padding-left: 1.2rem;
  font-size: 0.82em;
  color: var(--text-secondary, #888);
}
.ct-sub-row {
  padding: 1px 0;
  font-family: monospace;
}
```

- [ ] **Step 7: Build and verify**

```bash
npm run build
```

Expected: `compiled successfully`.

- [ ] **Step 8: Commit**

```bash
git add src/popup/popup.js src/popup/popup.css
git commit -m "feat: render CT state B/C in MPT holding rows with BSGS decryption and expand toggle"
```

---

### Task 3: `view-confidential-convert` HTML

**Files:**
- Modify: `src/popup/popup.html`

**Interfaces:**
- Produces: element IDs `ct-convert-token-name`, `ct-convert-issuer`, `ct-convert-public-balance`, `ct-convert-amount`, `ct-convert-btn`, `ct-convert-error`, `back-from-ct-convert-btn`, view ID `view-confidential-convert`
- Consumed by: Task 4

- [ ] **Step 1: Add the view HTML**

In `src/popup/popup.html`, find the closing tag of `view-confidential-key` (added in Phase 1). Add the new view immediately after it:

```html
<div id="view-confidential-convert" class="view hidden">
  <div class="view-header">
    <button id="back-from-ct-convert-btn" class="btn-back">‹</button>
    <span>Add Confidentiality</span>
  </div>
  <div class="view-content">
    <div id="ct-convert-token-name" class="account-name"></div>
    <div id="ct-convert-issuer" class="account-address"></div>

    <div class="field-group">
      <label class="field-label">Public balance</label>
      <div id="ct-convert-public-balance" class="field-value"></div>
    </div>

    <div class="field-group">
      <label class="field-label" for="ct-convert-amount">Initial conversion amount</label>
      <input type="number" id="ct-convert-amount" class="text-input" value="0" min="0" step="any" />
      <p class="field-hint">Enter 0 to opt-in without converting any balance.</p>
    </div>

    <div id="ct-convert-error" class="alert alert-error hidden"></div>

    <button id="ct-convert-btn" class="btn-primary">Convert</button>
  </div>
</div>
```

Use the same CSS classes as existing views (`.view`, `.view-header`, `.btn-back`, `.view-content`, `.field-group`, `.field-label`, `.field-value`, `.text-input`, `.field-hint`, `.alert`, `.alert-error`, `.btn-primary`). Check `popup.html` for the exact class names used by similar views (e.g., `view-export-key` or `view-confidential-key`) and match their structure exactly.

- [ ] **Step 2: Build and verify**

```bash
npm run build
```

Expected: `compiled successfully`.

- [ ] **Step 3: Commit**

```bash
git add src/popup/popup.html
git commit -m "feat: add view-confidential-convert HTML for MPT CT initial conversion"
```

---

### Task 4: Convert flow JS

**Files:**
- Modify: `src/popup/popup.js`

**Interfaces:**
- Consumes: `generateBlindingFactor`, `encryptAmount`, `getConvertContextHash`, `getConvertProof` (Task 1); all 7 element IDs from `view-confidential-convert` (Task 3); `state.elgamalKeys[activeAccount]`; `state.client.request`, `state.client.autofill`, `state.client.submitAndWait`; `signPreparedTx(prepared)` (line ~989); `showAlert`, `hideAlert`, `showView`, `loadMptBalances`
- Replaces: the `openConfidentialConvertView` stub from Task 2 (or adds alongside it if no stub exists)

- [ ] **Step 1: Add module-level state variables**

At the top of the CONFIDENTIAL TRANSFERS section (alongside `let _ctHideTimer`), add:

```js
let _ctConvertIssuanceId  = null;
let _ctConvertIssuerEncKey  = null;
let _ctConvertAuditorEncKey = null;
let _ctConvertAssetScale    = 0;
```

- [ ] **Step 2: Implement `openConfidentialConvertView`**

Replace the Task 2 stub (or add if no stub exists) with the full implementation:

```js
function openConfidentialConvertView(rowEl) {
  _ctConvertIssuanceId   = rowEl.dataset.mptId;
  _ctConvertIssuerEncKey = rowEl.dataset.issuerEncKey;
  _ctConvertAuditorEncKey = rowEl.dataset.auditorEncKey || null;
  _ctConvertAssetScale   = parseInt(rowEl.dataset.assetScale ?? '0', 10);

  const display = rowEl.dataset.display ?? _ctConvertIssuanceId.slice(0, 8) + '…';
  const balance = rowEl.dataset.balance ?? '0';
  const issuerEl = rowEl.querySelector('.mpt-issuer');

  $('ct-convert-token-name').textContent = display;
  $('ct-convert-issuer').textContent = issuerEl?.textContent ?? '';
  $('ct-convert-public-balance').textContent = balance;
  $('ct-convert-amount').value = '0';
  hideAlert('ct-convert-error');
  showView('confidential-convert');
}
```

- [ ] **Step 3: Implement `confirmConfidentialConvert`**

```js
async function confirmConfidentialConvert() {
  const issuanceId = _ctConvertIssuanceId;
  const issuerEncKey = _ctConvertIssuerEncKey;
  const auditorEncKey = _ctConvertAuditorEncKey;
  const assetScale = _ctConvertAssetScale;
  const account = state.activeAccount;
  const ctKey = state.elgamalKeys[account];

  if (!issuanceId || !issuerEncKey || !ctKey) {
    showAlert('ct-convert-error', 'Missing required data. Please try again.');
    return;
  }

  const rawInput = parseFloat($('ct-convert-amount').value) || 0;
  if (rawInput < 0) {
    showAlert('ct-convert-error', 'Amount must be 0 or greater.');
    return;
  }
  const amount = BigInt(assetScale > 0
    ? Math.round(rawInput * Math.pow(10, assetScale))
    : Math.round(rawInput));

  $('ct-convert-btn').disabled = true;
  hideAlert('ct-convert-error');

  try {
    // 1. Get current sequence number for context hash
    const acctResp = await state.client.request({
      command: 'account_info',
      account,
      ledger_index: 'validated',
    });
    const sequence = acctResp.result.account_data.Sequence;

    // 2. Generate blinding factor and encrypt for all participants
    const bf = await generateBlindingFactor();
    const holderEncrypted  = await encryptAmount(amount, ctKey.pubKey, bf);
    const issuerEncrypted  = await encryptAmount(amount, issuerEncKey, bf);
    const auditorEncrypted = auditorEncKey
      ? await encryptAmount(amount, auditorEncKey, bf)
      : null;

    // 3. Compute context hash and ZK proof
    const contextHash = await getConvertContextHash(account, issuanceId, sequence);
    const zkProof = await getConvertProof(ctKey.pubKey, ctKey.privKey, contextHash);

    // 4. Build transaction
    const txJson = {
      TransactionType: 'ConfidentialMPTConvert',
      Account: account,
      MPTokenIssuanceID: issuanceId,
      MPTAmount: String(amount),
      BlindingFactor: bf,
      HolderEncryptedAmount: holderEncrypted,
      IssuerEncryptedAmount: issuerEncrypted,
      HolderEncryptionKey: ctKey.pubKey,
      ZKProof: zkProof,
      Sequence: sequence,
      ...(auditorEncrypted ? { AuditorEncryptedAmount: auditorEncrypted } : {}),
    };

    // 5. Autofill (adds Fee; Sequence already set so autofill leaves it)
    const prepared = await state.client.autofill(txJson);

    // 6. Sign and submit
    const { tx_blob } = await signPreparedTx(prepared);
    await state.client.submitAndWait(tx_blob);

    showView('wallet');
    await loadMptBalances();
  } catch (err) {
    showAlert('ct-convert-error', err.message || 'Conversion failed. Please try again.');
  } finally {
    $('ct-convert-btn').disabled = false;
  }
}
```

- [ ] **Step 4: Wire event listeners**

In the CONFIDENTIAL TRANSFERS event listener section at the bottom of popup.js:

```js
$('ct-convert-btn').addEventListener('click', () => confirmConfidentialConvert().catch(console.error));

$('back-from-ct-convert-btn').addEventListener('click', () => showView('wallet'));
```

- [ ] **Step 5: Build and verify**

```bash
npm run build
```

Expected: `compiled successfully`.

- [ ] **Step 6: Commit**

```bash
git add src/popup/popup.js
git commit -m "feat: implement openConfidentialConvertView and confirmConfidentialConvert"
```
