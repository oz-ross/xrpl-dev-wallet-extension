# XRPL Dev Wallet

A Chrome extension wallet for the **XRPL Devnet**, built for developers. Import a family seed, check your XRP balance, and approve or reject transactions forwarded from dApps via WalletConnect — all from the browser toolbar. Intended to work with all new functionalities and transaction types.

> **⚠ Development use only.**
> Do not use mainnet accounts or any seed that controls real value.
> This extension stores your seed in the browser's session memory and is not audited for production use.

---

## Features

- Import an XRPL family seed (secret key)
- View live XRP balance on Devnet
- Connect to dApps via WalletConnect v2 (paste a `wc:` URI)
- Review, approve, or reject incoming transaction requests
- Automatically autofills, signs, submits, and monitors each transaction through to ledger validation
- Seed is held in `chrome.storage.session` — cleared when the browser closes

---

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or later
- [npm](https://www.npmjs.com/) v9 or later
- Google Chrome (or any Chromium-based browser)

---

## Installation

### 1. Clone the repository

```bash
git clone <repo-url>
cd xrpl-dev-wallet-extension
```

### 2. Install dependencies

```bash
npm install
```

### 3. Generate icons

```bash
npm run generate-icons
```

> Requires the `XRPL - Black.png` source file to be present in the parent directory (`../XRPL - Black.png` relative to the project root).

### 4. Build the extension

```bash
npm run build
```

The built extension is output to the `dist/` folder.

### 5. Load in Chrome

1. Open Chrome and navigate to `chrome://extensions`
2. Enable **Developer mode** (toggle in the top-right corner)
3. Click **Load unpacked**
4. Select the `dist/` folder

The **XRPL Dev Wallet** icon will appear in your Chrome toolbar.

---

## Development

To rebuild automatically on file changes:

```bash
npm run dev
```

Then reload the extension in `chrome://extensions` after each change (click the refresh icon on the extension card).

---

## Usage

### Importing a wallet

1. Click the extension icon in the Chrome toolbar to open the popup.
2. Enter your XRPL Devnet **family seed** (starts with `s`).
3. Click **Import Wallet**.

Your XRP balance will load automatically. The seed persists for the browser session — it is cleared when Chrome closes.

To remove the wallet from the current session, click the **✕** button in the top-right of the wallet view.

### Connecting a dApp via WalletConnect

1. In the dApp, initiate a WalletConnect connection and copy the `wc:` pairing URI.
2. In the extension popup, click **+ Connect via WalletConnect**.
3. Paste the URI and click **Connect**.
4. Review the connection request and click **Approve**.

Active sessions are listed in the popup. Click **✕** next to a session to disconnect it.

### Approving a transaction

When a connected dApp sends a transaction request:

1. The extension popup displays the transaction details (type, amount, destination, fee, etc.).
2. Click **Approve & Sign** to sign, submit, and wait for ledger validation — or **Reject** to decline.
3. The result (confirmed or failed) is shown, along with a link to the Devnet explorer.

---

## Project structure

```
xrpl-dev-wallet-extension/
├── src/
│   ├── background/
│   │   └── background.js      # Chrome service worker (badge management)
│   └── popup/
│       ├── popup.html         # Extension popup UI
│       ├── popup.css          # Styles
│       └── popup.js           # Wallet + WalletConnect logic
├── scripts/
│   └── generate-icons.js      # Builds PNG icons from the XRPL logo + tools overlay
├── icons/                     # Generated PNG icons (16, 48, 128 px)
├── dist/                      # Webpack build output — load this in Chrome
├── manifest.json              # Chrome Extension Manifest v3
├── webpack.config.js
└── package.json
```

---

## Vendored WASM — mpt-crypto (BSGS patch)

The `vendor/mpt-crypto/` directory contains a locally-built WebAssembly module for Confidential MPT (XLS-0096) cryptography. It is committed to the repository so no build toolchain is needed to use it — `npm install && npm run build` is sufficient.

### What's patched

The vendored WASM is built from [XRPLF/mpt-crypto](https://github.com/XRPLF/mpt-crypto) `main` (release 1.0.5, which includes [PR #130](https://github.com/XRPLF/mpt-crypto/pull/130): Baby-Step Giant-Step DLP solver) with an additional `src/bsgs_wasm.c` wrapper that exposes two new functions to the JS layer:

- `_mpt_bsgs_init` — builds the BSGS baby-step table (~22 MB, one-time per popup session)
- `_mpt_decrypt_amount_bsgs` — decrypts a ciphertext in O(√N) time, covering amounts up to 2^40 (~1 trillion)

The upstream [`@xrplf/mpt-crypto`](https://github.com/XRPLF/xrpl.js/tree/main/packages/mpt-crypto) JS wrapper does not yet expose these BSGS functions. Once it does, the local patch can be replaced by a standard upstream vendor refresh.

### Rebuilding the WASM

> **Do not run `scripts/setup-mpt-crypto.sh`** — it pulls from xrpl.js main and will overwrite the BSGS-enabled WASM with the upstream linear-only build.

To rebuild the WASM with BSGS from scratch (requires [Emscripten](https://emscripten.org/) 6.x):

```bash
git clone https://github.com/XRPLF/mpt-crypto.git /tmp/mpt-crypto
# Copy src/bsgs_wasm.c from this repo into /tmp/mpt-crypto/src/
# Apply the two-line patch to .github/scripts/build-wasm.sh:
#   1. Add -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF to the emcmake cmake flags
#   2. Add _mpt_bsgs_init,_mpt_decrypt_amount_bsgs to EXPORTS
#   3. Change all three `emcc "${LINK_FLAGS[@]}"` link calls to `em++`
cd /tmp/mpt-crypto
NODE_OPTIONS= bash .github/scripts/build-wasm.sh
cp emcc_out/mpt_crypto.{js,mjs,web.mjs,wasm} <repo-root>/vendor/mpt-crypto/wasm/
```

---

## Tech stack

| Library | Purpose |
|---|---|
| [xrpl.js](https://github.com/XRPLF/xrpl.js) | XRPL client — autofill, sign, submit, monitor |
| [@walletconnect/web3wallet](https://docs.walletconnect.com) | WalletConnect v2 wallet-side SDK |
| [webpack 5](https://webpack.js.org/) | Bundles ESM dependencies for the extension |
| [sharp](https://sharp.pixelplumbing.com/) | Icon generation (PNG compositing) |

---

## License

[ISC](LICENSE)
