# XRPL Dev Wallet — Security Audit

**Date:** 2026-05-26
**Scope:** Full end-to-end review of `src/popup/popup.js`, `src/background/background.js`, `src/popup/popup.html`, `manifest.json`
**Auditor:** Claude Sonnet 4.6

---

## Summary

| Severity | Count |
|----------|-------|
| HIGH     | 0     |
| MEDIUM   | 1     |
| LOW      | 2     |
| INFO     | 2     |
| **Total**| **5** |

No HIGH severity findings. One MEDIUM (M-3) is accepted as an industry-standard residual risk with a conservative default posture.

---

## Security Posture

The wallet implements a layered cryptographic architecture that meets or exceeds the standard for non-custodial browser extension wallets.

**Vault encryption** uses AES-256-GCM — authenticated encryption that simultaneously provides confidentiality and integrity, so any tampering with the ciphertext causes decryption to fail outright rather than silently producing corrupt data. The key is never derived from the password directly; it is produced by PBKDF2-SHA256 with 600,000 iterations and a 256-bit random salt, matching the OWASP 2023 recommendation for password-based key derivation and imposing a ~300 ms cost per attempt on commodity hardware. This makes offline dictionary attacks against a stolen vault blob computationally expensive. Each encryption operation uses a freshly generated 96-bit random IV, so ciphertext patterns cannot be correlated across saves even when the plaintext changes only slightly.

**Salt lifecycle** is intentionally stable within a password epoch: the salt rotates only when the user changes their password. This allows routine vault saves (key additions, account switches) to reuse the derived key without triggering a full PBKDF2 round, while ensuring that a password change immediately invalidates any previously derived key material — including any key bytes that may have been written to `chrome.storage.session`.

**Session key handling** follows the same pattern as MetaMask: the derived `CryptoKey` object's raw bytes are exported and stored in `chrome.storage.session` when auto-restore is enabled, rather than storing the raw password. This means the user's password is never written to any persistent or session store; only the 32-byte key equivalent is held, scoped to the browser session. By default, `lockTimeoutSecs` is set to `0`, meaning the key is never written to session storage at all and the user must re-enter their password on every popup open — the most conservative posture available within the extension model.

**Brute-force resistance** is provided at two levels. The PBKDF2 cost floor means each attempt takes ~300 ms regardless of lockout state. On top of this, a three-tier exponential backoff scheme tracks consecutive failures in `chrome.storage.session` (surviving popup close/reopen): 10 s lockout after 5 failures, 60 s after 10, and a permanent session lockout after 20 that requires closing the browser to reset. Wrong-password detection relies on AES-GCM's built-in authentication tag verification, which produces an `OperationError` on any incorrect key — no timing side-channel from a manual comparison.

**Message authentication** in the background service worker requires `sender.id === chrome.runtime.id` on every incoming message, preventing other extensions or web pages from injecting commands into the wallet's privileged background context.

**Input and output hardening** covers: HTML output escaping via `esc()` at all DOM write sites; trusted-HTML helpers restricted to call sites that provably escape all dynamic content; URL validation via `new URL()` before any `href` assignment; WalletConnect proposal metadata sanitised (HTTPS-only URL check, name length cap, localhost flagged); and a catch-all transaction field renderer that ensures no dApp-supplied field is silently hidden from the confirmation screen.

---

## MEDIUM Severity

### M-3 — Vault key bytes stored in `chrome.storage.session` when `lockTimeoutSecs > 0`

**File:** `src/popup/popup.js` — `persistSession()`

When `lockTimeoutSecs` is non-zero the exported raw AES-256-GCM key bytes are written to `chrome.storage.session` as a base64 string (`vaultKey`). The raw password string is never stored. The 32-byte key is cryptographically equivalent to vault access: an attacker who reads `chrome.storage.session` and the encrypted vault blob can decrypt all keyrings without knowing the password.

`chrome.storage.session` is:
- Cleared when the browser session ends (browser close or profile removal)
- Accessible to all code running in the same extension origin (popup, background service worker)
- Not encrypted at rest by Chrome

**Industry equivalence:** This is the same mechanism MetaMask uses to protect vault passwords and keys. MetaMask derives an extractable `CryptoKey` from the user's password, exports the raw bytes, and stores them in `chrome.storage.session` to support auto-restore across popup opens — identical to the approach used here. MetaMask explicitly accepts this as the correct trade-off in their published security model. The key difference is that MetaMask enables auto-restore (non-zero timeout) **by default**, whereas this wallet defaults to `lockTimeoutSecs = 0` (key never stored, password must be re-entered on each popup open), which is the more conservative posture.

The improvement over storing the raw password is that: (1) the user's password string is never exposed (no credential-reuse risk on other services), and (2) the stored key bytes are tied to the current vault salt — a password change generates a new salt, immediately invalidating the old stored key.

**`lockTimeoutSecs` defaults to `0`** (key never stored, maximum security). Changing to non-zero triggers a confirmation dialog explaining the trade-off.

**Status:** Accepted. Industry-standard residual risk for the non-zero timeout case. No further mitigation is practical without abandoning auto-restore entirely.

---

## LOW Severity

### L-1 — Auto-lock timestamp in `localStorage` survives browser restart

**File:** `src/popup/popup.js`

The `lastClosedAt` timestamp used to enforce auto-lock is written to `localStorage` on popup close (synchronously, because `chrome.storage.local.set` is async and never resolves before the popup page is destroyed). `localStorage` persists across browser restarts, unlike `chrome.storage.session`.

Practical consequence: if the browser crashes with the wallet unlocked, `lastClosedAt` retains its value. On next open, the elapsed time calculation works correctly and the lock fires as expected — so the auto-lock still functions. The concern is that any code executing in the extension popup origin (same `chrome-extension://` URL) can write any value to `lastClosedAt`, bypassing the lock timer. Web-page content scripts cannot access the extension's `localStorage` and other extensions cannot either, so the threat surface is narrow.

**Status:** Accepted. An alternative would be to send a `chrome.runtime.sendMessage` to the background on popup close and have the background record the timestamp in `chrome.storage.session` — but this is also async and may not complete before the popup tears down.

---

### L-6 — `devSettings.printTxJson` and `printWC` log sensitive data to DevTools console

**File:** `src/popup/popup.js` — multiple locations; `src/popup/popup.html` — settings section

When enabled, these flags log full transaction JSON (before signing) and WalletConnect request details to the browser console. The `TxnSignature` and `tx_blob` are redacted, but memo content, amounts, and counterparty addresses are not. The DevTools console is accessible to other extensions that attach a debugger to the popup.

**Status:** Accepted. Both flags default to `false`. The Settings screen displays a warning about the risk. This is appropriate for a dev tool. Optionally add auto-disable after a configurable session count to reduce the chance of mainnet users forgetting to disable.

---

## INFO

### I-1 — `formatCurrencyCode` decodes hex to UTF-8 without internal escaping

**File:** `src/popup/popup.js` — `formatCurrencyCode()`

Hex-encoded XRPL currency codes are decoded to UTF-8 strings. All current call sites that render the result to the DOM pass through `esc()`, so there is no current XSS path. However, the function itself returns a raw string, and a future call site that omits `esc()` would be vulnerable to DOM injection via a crafted currency code on the ledger.

**Recommended fix:** Add internal HTML-escaping inside `formatCurrencyCode()` or return a `TrustedHTML`-annotated type to make call-site escaping a type-checked requirement.

---

### I-2 — No certificate pinning for XRPL node WebSocket connections

**File:** `manifest.json` — `host_permissions`; `src/popup/popup.js` — network config

All WebSocket connections to XRPL nodes rely on standard TLS certificate validation. A MITM attacker with CA certificate access could serve modified account data or balance information. This is a standard limitation of browser-based TLS; no mitigation is practical within the extension model.

**Recommended fix:** For a production wallet, consider an intermediate proxy service with additional signing of node responses.

---

## Methodology

Static analysis of all extension source files. No dynamic analysis, fuzzing, or network interception was performed. Coverage:

- Cryptographic key management and vault encryption lifecycle
- Session and storage handling (`chrome.storage.session`, `chrome.storage.local`, `localStorage`)
- Input validation and HTML injection vectors (every `innerHTML` assignment verified)
- WalletConnect message handling, session lifecycle, transaction display completeness
- Content Security Policy configuration
- Background/popup message authentication
- Backup and restore flow integrity (import allowlist, vault format validation)
- Explorer URL construction
- Console log redaction
