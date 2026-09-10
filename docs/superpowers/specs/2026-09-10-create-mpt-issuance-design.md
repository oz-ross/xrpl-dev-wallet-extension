# Create MPT Issuance — Design Spec

## Goal

Replace the single `+` button in the MPT Balances card header with a small dropdown menu giving two options — **Add MPT** (existing flow) and **Create MPT** (new). The Create MPT path leads to a two-screen flow (form → review) that submits an `MPTokenIssuanceCreate` transaction, with full XLS-89 structured metadata support.

## Scope

- `src/popup/popup.html` — dropdown HTML, new form view, new review view
- `src/popup/popup.js` — dropdown open/close, form validation, review rendering, transaction submission
- `src/popup/popup.css` — dropdown styles, URI row styles

No new files. No changes to existing Add MPT logic.

---

## Global Constraints

- Follow existing view-navigation pattern: `showView('name')` to switch, back buttons return to prior view
- Follow existing dropdown close-on-outside-click pattern (`document.addEventListener('click', ..., { capture: true, once: true })`)
- Transaction submission: `client.autofill()` → sign via `signWithAddress()` → `client.submitAndWait()` → check `meta.TransactionResult === 'tesSUCCESS'`
- Metadata encoding: use `encodeMPTokenMetadata` from xrpl.js (already imported); do not hand-roll JSON→hex
- Import `encodeMPTokenMetadata` alongside existing `decodeMPTokenMetadata` import from `'xrpl'`
- Error display: use existing `showAlert` / `hideAlert` helpers and `.alert-error` class
- All text inserted into the DOM must go through the existing `esc()` helper

---

## Part 1 — `+` Button Dropdown

### HTML change (`popup.html`)

Replace:
```html
<button id="add-mpt-btn" class="btn-icon btn-header-action" title="Add MPT">＋</button>
```

With:
```html
<div class="mpt-add-wrapper">
  <button id="add-mpt-btn" class="btn-icon btn-header-action" title="MPT actions">＋</button>
  <div id="mpt-add-dropdown" class="mpt-add-dropdown hidden">
    <button class="mpt-add-dropdown-item" id="mpt-dropdown-add">Add MPT</button>
    <button class="mpt-add-dropdown-item" id="mpt-dropdown-create">Create MPT</button>
  </div>
</div>
```

### CSS (`.mpt-add-wrapper`, `.mpt-add-dropdown`, `.mpt-add-dropdown-item`)

`.mpt-add-wrapper` — `position: relative; display: inline-block`

`.mpt-add-dropdown` — `position: absolute; top: calc(100% + 4px); right: 0; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: 0 4px 16px rgba(0,0,0,0.35); z-index: 200; min-width: 130px; padding: 4px 0; white-space: nowrap`

`.mpt-add-dropdown-item` — full-width ghost button styled like `.account-list-item` (transparent bg, padding `8px 14px`, hover `var(--surface-2)`)

### JS

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

---

## Part 2 — Create MPT Form (`view-create-mpt`)

### View structure

```
‹  Create MPT
────────────────
Asset Scale            [number 0–255, default 0]
Maximum Amount         [text, optional — leave blank for uncapped]
Transfer Fee           [number 0–50000, optional — thousandths of 1%]

Flags
  ☐ Can Transfer       (tfMPTCanTransfer)
  ☐ Can Clawback       (tfMPTCanClawback)
  ☐ Require Auth       (tfMPTRequireAuth)
  ☐ Can Lock           (tfMPTCanLock)
  ☐ Can Escrow         (tfMPTCanEscrow)
  ☐ Can Trade          (tfMPTCanTrade)

Metadata
  [Structured ▾] / [Raw Hex]   ← toggle

  — Structured mode —
  Ticker               [text, uppercase A-Z0-9, max 6]
  Name                 [text]
  Issuer Name          [text]
  Asset Class          [select: rwa / memes / wrapped / gaming / defi / other]
  Asset Subclass       [select, only shown when asset_class = rwa]
  Icon URL             [text]
  Description          [textarea]
  URIs
    [uri input] [category input] [title input] [✕]
    [uri input] [category input] [title input] [✕]
    [+ Add URI]
  Additional Info      [textarea — JSON or plain string]

  — Raw Hex mode —
  [textarea]

[error banner]
[Review →]
```

### Form IDs

| ID | Element |
|---|---|
| `view-create-mpt` | wrapper div |
| `back-from-create-mpt-btn` | back button |
| `create-mpt-asset-scale` | number input |
| `create-mpt-max-amount` | text input |
| `create-mpt-transfer-fee` | number input |
| `create-mpt-flag-transfer` | checkbox |
| `create-mpt-flag-clawback` | checkbox |
| `create-mpt-flag-require-auth` | checkbox |
| `create-mpt-flag-lock` | checkbox |
| `create-mpt-flag-escrow` | checkbox |
| `create-mpt-flag-trade` | checkbox |
| `create-mpt-meta-structured-btn` | toggle button |
| `create-mpt-meta-raw-btn` | toggle button |
| `create-mpt-meta-structured` | structured fields container |
| `create-mpt-meta-raw` | raw hex container |
| `create-mpt-ticker` | text input |
| `create-mpt-name` | text input |
| `create-mpt-issuer-name` | text input |
| `create-mpt-asset-class` | select |
| `create-mpt-asset-subclass-row` | wrapping div (hidden unless rwa) |
| `create-mpt-asset-subclass` | select |
| `create-mpt-icon` | text input |
| `create-mpt-desc` | textarea |
| `create-mpt-uris-list` | container div for dynamic URI rows |
| `create-mpt-add-uri-btn` | button |
| `create-mpt-additional-info` | textarea |
| `create-mpt-meta-hex` | raw hex textarea |
| `create-mpt-error` | error banner |
| `create-mpt-review-btn` | review button |

### Flag bits

```js
const MPT_FLAGS = {
  tfMPTCanTransfer:  0x00000008,
  tfMPTCanClawback:  0x00000010,
  tfMPTRequireAuth:  0x00000004,
  tfMPTCanLock:      0x00000002,
  tfMPTCanEscrow:    0x00000020,
  tfMPTCanTrade:     0x00000040,
};
```

### Metadata toggle behaviour

- Default: structured mode active, raw hex inactive
- Toggling structured → raw: call `buildMptMetadataHex()`, populate the raw textarea with the result (or clear if empty/all-blank)
- Toggling raw → structured: do not attempt to parse back — just switch display; structured fields retain their previous values
- Active mode button gets `.active` style; inactive does not

### Dynamic URI rows

Each URI row is a `<div class="create-mpt-uri-row">` containing three `<input>` elements (placeholder: `URI`, `Category`, `Title`) and a remove button (`✕`). Clicking `+ Add URI` appends a new row. Clicking `✕` removes that row. Minimum 0 rows.

### `buildMptMetadataHex()` — assembles metadata from form state

1. If raw hex mode is active: return the textarea value trimmed (empty string if blank)
2. Assemble a plain JS object from the structured fields, omitting any blank optional fields:
   ```js
   const obj = {};
   if (ticker) obj.ticker = ticker.toUpperCase();
   if (name)   obj.name = name;
   // ... etc
   if (uris.length > 0) obj.uris = uris;  // array of { uri, category, title }
   ```
3. If the object is completely empty: return `''`
4. Call `encodeMPTokenMetadata(obj)` — returns uppercase hex string
5. If encoding throws: show the error message in the form error banner; return `null` to signal caller to abort

### Validation (`openCreateMptReview()`)

1. `assetScale` must be integer 0–255
2. `maximumAmount` if provided: must be a positive integer string ≤ `'9999999999999999'`
3. `transferFee` if provided: must be integer 0–50000
4. Call `buildMptMetadataHex()` — if null, abort (error already shown)
5. If metadata hex is non-empty: check byte length ≤ 1024 (hex.length / 2 ≤ 1024)
6. On pass: store validated values in module-level `_createMptPending` object and navigate to review view

### `_createMptPending` shape

```js
{
  assetScale:     number,          // 0–255
  maximumAmount:  string | null,   // raw string or null
  transferFee:    number | null,   // 0–50000 or null
  flags:          number,          // bitfield
  metadataHex:    string,          // uppercase hex or ''
  displayName:    string,          // ticker or name or 'MPT' for review heading
}
```

---

## Part 3 — Review Screen (`view-create-mpt-review`)

### View structure

```
‹  Review: Create MPT
────────────────────
Token          <ticker or name or '(unnamed)'>
Asset Scale    <value>
Max Amount     <value or 'Uncapped'>
Transfer Fee   <value / 1000>% or 'None'
Flags          <comma-separated list of enabled flag names, or 'None'>
Metadata       <first 32 chars of hex>… (<N> bytes) or 'None'

[error banner]
[Create MPT]
```

### Review rendering (`openCreateMptReviewView()`)

Populate elements by ID from `_createMptPending`. The review view IDs follow the pattern `create-mpt-review-*`.

### Submission (`confirmCreateMpt()`)

```js
const tx = {
  TransactionType: 'MPTokenIssuanceCreate',
  Account: state.activeAccount,
};
if (_createMptPending.assetScale !== 0)   tx.AssetScale = _createMptPending.assetScale;
if (_createMptPending.maximumAmount)       tx.MaximumAmount = _createMptPending.maximumAmount;
if (_createMptPending.transferFee !== null) tx.TransferFee = _createMptPending.transferFee;
if (_createMptPending.flags !== 0)         tx.Flags = _createMptPending.flags;
if (_createMptPending.metadataHex)         tx.MPTokenMetadata = _createMptPending.metadataHex;
```

On `tesSUCCESS`:
- Extract `mpt_issuance_id` from `resp.result.meta`
- Show a success banner with the new issuance ID
- After 2 seconds: `showView('wallet')` and trigger `loadMptBalances()`

On failure:
- Show error in the review screen's error banner
- Re-enable the Create button

---

## Data Flow Summary

```
wallet view
  └─ MPT card header: ＋ button
       ├─ Add MPT → view-auth-mpt (unchanged)
       └─ Create MPT → view-create-mpt
                         └─ Review → view-create-mpt-review
                                       └─ MPTokenIssuanceCreate tx
                                            ├─ success → wallet (reload balances)
                                            └─ failure → error banner, stay on review
```
