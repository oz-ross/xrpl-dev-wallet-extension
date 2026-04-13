import './popup.css';
import { Client, Wallet, dropsToXrp, encodeAccountID, decodeMPTokenMetadata } from 'xrpl';
import QRCode from 'qrcode';
import { getSdkError } from '@walletconnect/utils';
import { generateMnemonic, validateMnemonic } from 'bip39';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────

const WC_PROJECT_ID = '545f3b40384efe9b93401c1dd8d0ceb0';

const NETWORKS = {
  devnet: {
    name: 'Devnet',
    wsUrl: 'wss://s.devnet.rippletest.net:51233',
    chainId: 'xrpl:2',
    explorer:        'https://devnet.xrpl.org/transactions/',
    explorerAccount: 'https://devnet.xrpl.org/accounts/',
    explorerToken:   'https://devnet.xrpl.org/token/',
    explorerMpt:     'https://devnet.xrpl.org/mpt/',
    faucet: 'https://faucet.devnet.rippletest.net/accounts',
  },
};

const XRPL_EPOCH_OFFSET = 946684800;
const AUTO_REFRESH_INTERVAL = 30_000;

// PBKDF2 parameters — matching MetaMask's browser-passworder
const PBKDF2_ITERATIONS = 600_000;
const LOCK_TIMEOUT_MS   = 10_000; // auto-lock after 10 s with popup closed
const PBKDF2_HASH      = 'SHA-256';
const KEY_LENGTH_BITS  = 256;

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────

const state = {
  /** @type {Wallet|null} */
  wallet: null,
  /** @type {Client|null} */
  client: null,
  network: 'devnet',
  /** @type {any|null} Serialised pending proposal stored by background */
  pendingProposal: null,
  /** @type {any|null} Serialised pending request stored by background */
  pendingRequest: null,
  /** @type {ReturnType<typeof setInterval>|null} */
  refreshTimer: null,

  // Multi-account
  keyrings: [],        // array of decrypted keyring objects
  activeAccount: null, // active r-address

  // Temp during setup/add flows
  flowContext: 'setup',    // 'setup' | 'add'
  pendingMnemonic: null,   // mnemonic being confirmed
  mnemonicWordCount: 12,   // 12 or 24

  // Password held in-memory during the setup flow so saveVault() can use it
  // without depending on chrome.storage.session being set first.
  _setupFlowPassword: null,

  // Address queued for removal, set before navigating to confirm view.
  pendingRemoveAddress: null,
};

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function $(id) { return document.getElementById(id); }

function showView(name) {
  for (const el of document.querySelectorAll('.view')) el.classList.add('hidden');
  $(`view-${name}`).classList.remove('hidden');
  // Close any open account dropdown
  $('account-dropdown')?.classList.add('hidden');
}

function esc(text) {
  const d = document.createElement('div');
  d.appendChild(document.createTextNode(String(text ?? '')));
  return d.innerHTML;
}

function truncAddr(addr) {
  if (!addr || addr.length < 16) return addr;
  return `${addr.slice(0, 10)}…${addr.slice(-6)}`;
}

function formatAmount(amount) {
  if (typeof amount === 'string') return `${dropsToXrp(amount)} XRP`;
  if (amount && typeof amount === 'object') return `${amount.value} ${amount.currency}`;
  return String(amount);
}

function showAlert(id, msg) {
  const el = $(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideAlert(id) { $(id).classList.add('hidden'); }

function xrplDateToLocal(xrplDate) {
  if (!xrplDate) return null;
  return new Date((xrplDate + XRPL_EPOCH_OFFSET) * 1000);
}

function togglePasswordVisibility(inputId) {
  const input = $(inputId);
  input.type = input.type === 'password' ? 'text' : 'password';
}

/**
 * Send a message to the background service worker and return the response.
 * Throws on transport error or if the background replies with ok:false.
 * @param {object} msg
 * @returns {Promise<object>}
 */
async function sendToBackground(msg, timeoutMs = 60000) {
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error('Background response timed out')), timeoutMs),
  );
  const resp = await Promise.race([chrome.runtime.sendMessage(msg), timeout]);
  if (!resp?.ok) throw new Error(resp?.error ?? 'Background error');
  return resp;
}

// ─────────────────────────────────────────────
// CRYPTO — MetaMask-compatible AES-256-GCM vault
// ─────────────────────────────────────────────

/**
 * Derive a 256-bit AES-GCM CryptoKey from a password and salt using PBKDF2-SHA256.
 * @param {string} password
 * @param {Uint8Array} salt
 * @returns {Promise<CryptoKey>}
 */
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
    keyMaterial,
    { name: 'AES-GCM', length: KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64ToBuf(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

/**
 * Encrypt a plain JS object into an opaque vault blob.
 * Vault format: { salt, iv, data } — all base64.
 * @param {string} password
 * @param {object} plainObj
 */
async function encryptVault(password, plainObj) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const enc  = new TextEncoder();
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(plainObj)),
  );
  return { salt: bufToB64(salt), iv: bufToB64(iv), data: bufToB64(ciphertext) };
}

/**
 * Decrypt a vault blob back to a JS object.
 * Throws DOMException if the password is wrong (AES-GCM auth tag mismatch).
 * @param {string} password
 * @param {{ salt: string, iv: string, data: string }} vault
 */
async function decryptVault(password, vault) {
  const salt = b64ToBuf(vault.salt);
  const iv   = b64ToBuf(vault.iv);
  const data = b64ToBuf(vault.data);
  const key  = await deriveKey(password, salt);
  const dec  = new TextDecoder();
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return JSON.parse(dec.decode(plaintext));
}

// ─────────────────────────────────────────────
// VAULT — Persist encrypted keyrings to local storage
// ─────────────────────────────────────────────

async function hasVault() {
  const { vault } = await chrome.storage.local.get('vault');
  return !!vault;
}

/**
 * Encrypt state.keyrings + state.activeAccount and persist to local storage.
 * @param {string} [passwordOverride] - if provided, use this password; otherwise
 *   fall back to the vaultPassword stored in chrome.storage.session (active session).
 */
async function saveVault(passwordOverride) {
  let password = passwordOverride;
  if (!password) {
    const { vaultPassword } = await chrome.storage.session.get('vaultPassword');
    password = vaultPassword;
  }
  if (!password) throw new Error('No vault password available — cannot save vault.');
  const payload = { keyrings: state.keyrings, activeAccount: state.activeAccount };
  const vault   = await encryptVault(password, payload);
  await chrome.storage.local.set({ vault });
  return password; // caller may need it for persistSession
}

/**
 * Decrypt vault with the given password, load keyrings into state, persist session.
 */
async function loadAndDecryptVault(password) {
  const { vault } = await chrome.storage.local.get('vault');
  if (!vault) throw new Error('No vault found.');
  const payload = await decryptVault(password, vault); // throws on bad password
  state.keyrings     = payload.keyrings ?? [];
  state.activeAccount = payload.activeAccount ?? null;
  await persistSession(password);
}

// ─────────────────────────────────────────────
// SESSION — Keep decrypted state across popup reopens
// ─────────────────────────────────────────────

async function persistSession(password) {
  await chrome.storage.session.set({
    keyrings:      state.keyrings,
    activeAccount: state.activeAccount,
    network:       state.network,
    vaultPassword: password,
  });
}

async function restoreFromSession() {
  const { keyrings, activeAccount, network, vaultPassword } =
    await chrome.storage.session.get(['keyrings', 'activeAccount', 'network', 'vaultPassword']);
  if (!keyrings || !activeAccount || !vaultPassword) return false;
  state.keyrings     = keyrings;
  state.activeAccount = activeAccount;
  state.network      = network || 'devnet';
  return true;
}

function lockWallet() {
  stopAutoRefresh();
  chrome.storage.session.clear();
  state.keyrings      = [];
  state.activeAccount = null;
  state.wallet        = null;
  state.client?.disconnect().catch(() => {});
  state.client = null;
  showView('unlock');
}

async function resetWallet() {
  if (!confirm(
    'This will permanently delete your wallet from this browser.\n\n' +
    'Make sure you have backed up all seeds and recovery phrases before continuing.\n\n' +
    'Reset wallet?',
  )) return;
  stopAutoRefresh();
  await chrome.storage.local.clear();
  await chrome.storage.session.clear();
  state.keyrings      = [];
  state.activeAccount = null;
  state.wallet        = null;
  state.client?.disconnect().catch(() => {});
  state.client = null;
  showView('setup-password');
}

// ─────────────────────────────────────────────
// KEYRINGS — HD (BIP-39) and Simple (family seed)
// ─────────────────────────────────────────────

/**
 * Derive an xrpl.js Wallet from a BIP-39 mnemonic and account index.
 * Path: m/44'/144'/{accountIndex}'/0/0
 */
function deriveHDWallet(mnemonic, accountIndex) {
  return Wallet.fromMnemonic(mnemonic, {
    mnemonicEncoding: 'bip39',
    derivationPath:   `m/44'/144'/${accountIndex}'/0/0`,
  });
}

/** Derive an xrpl.js Wallet from a family seed. */
function deriveSimpleWallet(seed) {
  return Wallet.fromSeed(seed);
}

/** Return the active Wallet object, or null if none. */
function getActiveWallet() {
  if (!state.activeAccount) return null;
  for (const kr of state.keyrings) {
    if (kr.type === 'HD') {
      const acct = kr.accounts.find(a => a.address === state.activeAccount);
      if (acct) return deriveHDWallet(kr.mnemonic, acct.accountIndex);
    } else if (kr.type === 'simple' && kr.address === state.activeAccount) {
      return deriveSimpleWallet(kr.seed);
    }
  }
  return null;
}

/** Flat list of all accounts across all keyrings. */
function getAllAccounts() {
  const out = [];
  for (let ki = 0; ki < state.keyrings.length; ki++) {
    const kr = state.keyrings[ki];
    if (kr.type === 'HD') {
      for (const acct of kr.accounts) {
        out.push({ label: acct.label, address: acct.address, keyringIndex: ki, accountIndex: acct.accountIndex });
      }
    } else if (kr.type === 'simple') {
      out.push({ label: kr.label, address: kr.address, keyringIndex: ki, accountIndex: null });
    }
  }
  return out;
}

/** Auto-generate a label for the next account. */
function nextAccountLabel() {
  return `Account ${getAllAccounts().length + 1}`;
}

/** Check whether a given address is already loaded in any keyring. */
function accountExists(address) {
  return getAllAccounts().some(a => a.address === address);
}

/** Check whether an HD keyring already has a given account index. */
function hdAccountIndexExists(keyringIndex, accountIndex) {
  const kr = state.keyrings[keyringIndex];
  return kr?.type === 'HD' && kr.accounts.some(a => a.accountIndex === accountIndex);
}

/**
 * Return metadata about what removing an account would affect.
 * Used to build the warning message before confirming removal.
 */
function getRemovalInfo(address) {
  for (let ki = 0; ki < state.keyrings.length; ki++) {
    const kr = state.keyrings[ki];
    if (kr.type === 'simple' && kr.address === address) {
      return { keyringsIdx: ki, type: 'simple', label: kr.label, phraseToo: true, siblings: 0 };
    }
    if (kr.type === 'HD') {
      const ai = kr.accounts.findIndex(a => a.address === address);
      if (ai !== -1) {
        return {
          keyringsIdx: ki,
          accountsIdx: ai,
          type: 'HD',
          label: kr.accounts[ai].label,
          phraseToo: kr.accounts.length === 1,  // last account → phrase also goes
          siblings: kr.accounts.length - 1,     // other accounts sharing the phrase
        };
      }
    }
  }
  return null;
}

/**
 * Execute the removal for state.pendingRemoveAddress.
 * Assumes the user has already confirmed.
 */
async function executeRemoveAccount() {
  const address = state.pendingRemoveAddress;
  state.pendingRemoveAddress = null;
  if (!address) return;

  const info = getRemovalInfo(address);
  if (!info) return;

  if (info.type === 'simple') {
    state.keyrings.splice(info.keyringsIdx, 1);
  } else {
    const kr = state.keyrings[info.keyringsIdx];
    kr.accounts.splice(info.accountsIdx, 1);
    if (kr.accounts.length === 0) {
      state.keyrings.splice(info.keyringsIdx, 1);
    }
  }

  // If active account was removed, switch to first remaining account.
  if (state.activeAccount === address) {
    const remaining = getAllAccounts();
    if (remaining.length > 0) {
      state.activeAccount = remaining[0].address;
      state.wallet = getActiveWallet();
    } else {
      state.activeAccount = null;
      state.wallet = null;
    }
  }

  await saveVault();
  const { vaultPassword } = await chrome.storage.session.get('vaultPassword');
  if (vaultPassword) await persistSession(vaultPassword);

  const remaining = getAllAccounts();
  if (remaining.length === 0) {
    // No accounts left — go straight to add-account flow.
    state.flowContext = 'add';
    showView('account-type');
  } else {
    updateWalletUI();
    renderManageAccountsList();
    showView('manage-accounts');
  }
}

/** Render the manage-accounts list (called each time the view is opened). */
function renderManageAccountsList() {
  const accounts = getAllAccounts();
  const list = $('manage-accounts-list');
  list.innerHTML = '';

  accounts.forEach(acct => {
    const info = getRemovalInfo(acct.address);
    const item = document.createElement('div');
    item.className = 'manage-acct-item';
    item.innerHTML = `
      <div class="manage-acct-info">
        <div class="manage-acct-label">${esc(acct.label || 'Account')}</div>
        <div class="manage-acct-addr">${truncAddr(acct.address)}</div>
      </div>
      <button class="btn btn-danger btn-sm" data-address="${esc(acct.address)}">Remove</button>
    `;
    item.querySelector('button').addEventListener('click', () => {
      state.pendingRemoveAddress = acct.address;

      // Build the warning shown on the confirm screen.
      $('remove-acct-name').textContent = acct.label || 'Account';
      $('remove-acct-addr').textContent = truncAddr(acct.address);

      let warn;
      if (info.type === 'simple') {
        warn = 'This will permanently remove the account and its secret seed from this wallet. This cannot be undone.';
      } else if (info.phraseToo) {
        warn = 'This is the only account using its recovery phrase. Removing it will also permanently delete the recovery phrase from this wallet. This cannot be undone.';
      } else {
        warn = `This will remove the account from this wallet. The recovery phrase and ${info.siblings} other account(s) derived from it will remain.`;
      }
      $('remove-acct-warning').textContent = warn;

      showView('remove-account-confirm');
    });
    list.appendChild(item);
  });
}

/**
 * Make the given address the active account, update state.wallet, update the UI.
 */
async function activateAccount(address) {
  state.activeAccount = address;
  state.wallet = getActiveWallet();
  await updateSessionActiveAccount();
  // Persist the new active account to the vault so it survives a lock/unlock.
  await saveVault().catch(err => console.warn('[activateAccount] saveVault:', err));
  updateWalletUI();
  refreshBalance();
  loadIouBalances();
  loadMptBalances();
  loadTxHistory();
}

async function updateSessionActiveAccount() {
  const { vaultPassword } = await chrome.storage.session.get('vaultPassword');
  if (vaultPassword) {
    await chrome.storage.session.set({ activeAccount: state.activeAccount });
  }
}

// ─────────────────────────────────────────────
// SETUP — Password creation
// ─────────────────────────────────────────────

async function setupPasswordContinue() {
  const password = $('setup-password').value;
  const confirm  = $('setup-password-confirm').value;
  hideAlert('setup-password-error');

  if (password.length < 8) {
    showAlert('setup-password-error', 'Password must be at least 8 characters.');
    return;
  }
  if (password !== confirm) {
    showAlert('setup-password-error', 'Passwords do not match.');
    return;
  }

  // Hold password in-memory for the duration of the setup flow.
  // finalizeAccountCreation() will write it to chrome.storage.session once
  // the vault has been successfully created.
  state._setupFlowPassword = password;
  state.flowContext = 'setup';
  $('account-type-title').textContent = 'Add First Account';
  $('type-hd-account').classList.add('hidden');
  showView('account-type');
}

// ─────────────────────────────────────────────
// ACCOUNT TYPE SELECTION
// ─────────────────────────────────────────────

function goToAddAccount() {
  state.flowContext = 'add';
  $('account-type-title').textContent = 'Add Account';
  // Show HD option if at least one HD keyring exists
  const hasHD = state.keyrings.some(kr => kr.type === 'HD');
  $('type-hd-account').classList.toggle('hidden', !hasHD);
  showView('account-type');
}

// ─────────────────────────────────────────────
// FLOW — Generated family seed
// ─────────────────────────────────────────────

function initGenSeedView() {
  hideAlert('gen-seed-error');
  $('gen-seed-backup-confirm').checked = false;
  $('gen-seed-label').value = '';

  const newWallet = Wallet.generate();
  $('generated-seed-text').textContent = newWallet.seed;
  // Store temporarily on the element so we can read it on confirm
  $('generated-seed-text').dataset.seed    = newWallet.seed;
  $('generated-seed-text').dataset.address = newWallet.address;
  showView('account-gen-seed');
}

async function confirmGenSeed() {
  hideAlert('gen-seed-error');
  if (!$('gen-seed-backup-confirm').checked) {
    showAlert('gen-seed-error', 'Please confirm you have saved the seed before continuing.');
    return;
  }

  const seed    = $('generated-seed-text').dataset.seed;
  const address = $('generated-seed-text').dataset.address;
  const label   = $('gen-seed-label').value.trim() || nextAccountLabel();

  if (accountExists(address)) {
    showAlert('gen-seed-error', 'This account is already in your wallet.');
    return;
  }

  state.keyrings.push({ type: 'simple', seed, address, label });
  state.activeAccount = address;
  await finalizeAccountCreation();
}

// ─────────────────────────────────────────────
// FLOW — Import family seed
// ─────────────────────────────────────────────

async function confirmImportSeed() {
  hideAlert('import-seed-error');
  const seed = $('import-seed-input').value.trim();
  if (!seed) {
    showAlert('import-seed-error', 'Please enter a family seed.');
    return;
  }

  let wallet;
  try {
    wallet = Wallet.fromSeed(seed);
  } catch {
    showAlert('import-seed-error', 'Invalid family seed. It should start with "s".');
    return;
  }

  if (accountExists(wallet.address)) {
    showAlert('import-seed-error', 'This account is already in your wallet.');
    return;
  }

  const label = $('import-seed-label').value.trim() || nextAccountLabel();
  state.keyrings.push({ type: 'simple', seed, address: wallet.address, label });
  state.activeAccount = wallet.address;
  await finalizeAccountCreation();
}

// ─────────────────────────────────────────────
// FLOW — Generate mnemonic
// ─────────────────────────────────────────────

function initGenMnemonicView() {
  hideAlert('gen-mnemonic-error');
  $('mnemonic-backup-confirm').checked = false;
  $('gen-mnemonic-label').value = '';
  $('gen-mnemonic-step-length').classList.remove('hidden');
  $('gen-mnemonic-step-backup').classList.add('hidden');
  state.mnemonicWordCount = 12;
  $('mnemonic-12-btn').classList.add('active-len');
  $('mnemonic-24-btn').classList.remove('active-len');
  state.pendingMnemonic = null;
  showView('account-gen-mnemonic');
}

function generateAndShowMnemonic() {
  const strength = state.mnemonicWordCount === 24 ? 256 : 128;
  const mnemonic = generateMnemonic(strength);
  state.pendingMnemonic = mnemonic;

  const words = mnemonic.split(' ');
  $('mnemonic-word-grid').innerHTML = words
    .map((w, i) => `<div class="mnemonic-word"><span class="word-num">${i + 1}</span><span class="word-text">${esc(w)}</span></div>`)
    .join('');

  $('gen-mnemonic-step-length').classList.add('hidden');
  $('gen-mnemonic-step-backup').classList.remove('hidden');
}

async function confirmMnemonicGeneration() {
  hideAlert('gen-mnemonic-error');
  if (!$('mnemonic-backup-confirm').checked) {
    showAlert('gen-mnemonic-error', 'Please confirm you have saved your recovery phrase.');
    return;
  }
  if (!state.pendingMnemonic) {
    showAlert('gen-mnemonic-error', 'No mnemonic generated. Please go back and generate one.');
    return;
  }

  let wallet;
  try {
    wallet = deriveHDWallet(state.pendingMnemonic, 0);
  } catch (err) {
    showAlert('gen-mnemonic-error', `Failed to derive wallet: ${err.message}`);
    return;
  }

  if (accountExists(wallet.address)) {
    showAlert('gen-mnemonic-error', 'This account is already in your wallet.');
    return;
  }

  const label = $('gen-mnemonic-label').value.trim() || nextAccountLabel();
  state.keyrings.push({
    type:     'HD',
    mnemonic: state.pendingMnemonic,
    accounts: [{ accountIndex: 0, address: wallet.address, label }],
  });
  state.activeAccount  = wallet.address;
  state.pendingMnemonic = null;
  await finalizeAccountCreation();
}

// ─────────────────────────────────────────────
// FLOW — Import mnemonic
// ─────────────────────────────────────────────

async function confirmImportMnemonic() {
  hideAlert('import-mnemonic-error');
  const raw      = $('import-mnemonic-input').value.trim().toLowerCase().replace(/\s+/g, ' ');
  const wordCount = raw.split(' ').length;

  if (wordCount !== 12 && wordCount !== 24) {
    showAlert('import-mnemonic-error', 'Recovery phrase must be exactly 12 or 24 words.');
    return;
  }
  if (!validateMnemonic(raw)) {
    showAlert('import-mnemonic-error', 'Invalid recovery phrase — please check the words and try again.');
    return;
  }

  let wallet;
  try {
    wallet = deriveHDWallet(raw, 0);
  } catch (err) {
    showAlert('import-mnemonic-error', `Failed to derive wallet: ${err.message}`);
    return;
  }

  if (accountExists(wallet.address)) {
    showAlert('import-mnemonic-error', 'This account is already in your wallet.');
    return;
  }

  const label = $('import-mnemonic-label').value.trim() || nextAccountLabel();
  state.keyrings.push({
    type:     'HD',
    mnemonic: raw,
    accounts: [{ accountIndex: 0, address: wallet.address, label }],
  });
  state.activeAccount = wallet.address;
  await finalizeAccountCreation();
}

// ─────────────────────────────────────────────
// FLOW — Add HD account (additional BIP-44 index)
// ─────────────────────────────────────────────

function initHdAddView() {
  hideAlert('hd-add-error');
  $('hd-account-label').value = '';
  $('hd-account-index').value = '1';
  $('hd-path-preview').textContent = '1';

  // Populate keyring selector
  const select = $('hd-keyring-select');
  select.innerHTML = '';
  state.keyrings.forEach((kr, i) => {
    if (kr.type !== 'HD') return;
    const firstLabel = kr.accounts[0]?.label ?? `HD Wallet ${i}`;
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = firstLabel;
    select.appendChild(opt);
  });

  showView('account-hd-add');
}

async function confirmHdAdd() {
  hideAlert('hd-add-error');
  const keyringIndex  = parseInt($('hd-keyring-select').value, 10);
  const accountIndex  = parseInt($('hd-account-index').value, 10);

  if (isNaN(accountIndex) || accountIndex < 0) {
    showAlert('hd-add-error', 'Account index must be a non-negative integer.');
    return;
  }
  if (hdAccountIndexExists(keyringIndex, accountIndex)) {
    showAlert('hd-add-error', `Account index ${accountIndex} already exists in this wallet.`);
    return;
  }

  const kr = state.keyrings[keyringIndex];
  let wallet;
  try {
    wallet = deriveHDWallet(kr.mnemonic, accountIndex);
  } catch (err) {
    showAlert('hd-add-error', `Failed to derive wallet: ${err.message}`);
    return;
  }

  if (accountExists(wallet.address)) {
    showAlert('hd-add-error', 'This account is already in your wallet.');
    return;
  }

  const label = $('hd-account-label').value.trim() || nextAccountLabel();
  kr.accounts.push({ accountIndex, address: wallet.address, label });
  state.activeAccount = wallet.address;
  await finalizeAccountCreation();
}

// ─────────────────────────────────────────────
// FINALIZE — Save vault + session, enter wallet
// ─────────────────────────────────────────────

async function finalizeAccountCreation() {
  try {
    // For the initial setup flow, use the in-memory password.
    // For add-account (vault already exists), fall back to the session password.
    const usedPassword = await saveVault(state._setupFlowPassword || undefined);
    state._setupFlowPassword = null; // clear immediately after use
    await persistSession(usedPassword);

    state.wallet = getActiveWallet();

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
    await initWalletConnect();
    await checkPendingWcEvent();
    startAutoRefresh();
  } catch (err) {
    console.error('[finalizeAccountCreation]', err);
    alert(`Failed to save wallet: ${err.message}`);
  }
}

// ─────────────────────────────────────────────
// UNLOCK
// ─────────────────────────────────────────────

async function unlock() {
  hideAlert('unlock-error');
  const password = $('unlock-password').value;
  if (!password) {
    showAlert('unlock-error', 'Please enter your password.');
    return;
  }

  const btn = $('unlock-btn');
  btn.disabled  = true;
  btn.textContent = 'Unlocking…';

  try {
    await loadAndDecryptVault(password);
    state.wallet  = getActiveWallet();
    state.network = 'devnet';

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
    await initWalletConnect();
    await checkPendingWcEvent();
    startAutoRefresh();

    $('unlock-password').value = '';
  } catch (err) {
    // AES-GCM auth failure → wrong password
    if (err.name === 'OperationError' || err.message?.includes('decrypt')) {
      showAlert('unlock-error', 'Incorrect password.');
    } else {
      showAlert('unlock-error', `Unlock failed: ${err.message}`);
    }
    console.error('[unlock]', err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

// ─────────────────────────────────────────────
// CHANGE PASSWORD
// ─────────────────────────────────────────────

async function changePassword() {
  hideAlert('cp-error');
  hideAlert('cp-success');

  const current = $('cp-current').value;
  const next    = $('cp-new').value;
  const confirm = $('cp-confirm').value;

  if (!current) { showAlert('cp-error', 'Enter your current password.'); return; }
  if (next.length < 8) { showAlert('cp-error', 'New password must be at least 8 characters.'); return; }
  if (next !== confirm) { showAlert('cp-error', 'New passwords do not match.'); return; }

  const btn = $('cp-save-btn');
  btn.disabled = true;
  btn.textContent = 'Updating…';

  try {
    // Verify the current password by decrypting the vault with it.
    const { vault } = await chrome.storage.local.get('vault');
    if (!vault) throw new Error('No vault found.');
    await decryptVault(current, vault); // throws OperationError if wrong

    // Re-encrypt the vault with the new password and persist.
    await saveVault(next);

    // Update the session so the new password is used from now on.
    await chrome.storage.session.set({ vaultPassword: next });

    $('cp-current').value = '';
    $('cp-new').value     = '';
    $('cp-confirm').value = '';
    showAlert('cp-success', 'Password updated successfully.');
  } catch (err) {
    if (err.name === 'OperationError' || err.message?.includes('decrypt')) {
      showAlert('cp-error', 'Current password is incorrect.');
    } else {
      showAlert('cp-error', `Failed to update password: ${err.message}`);
    }
    console.error('[changePassword]', err);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Update Password';
  }
}

// ─────────────────────────────────────────────
// WALLET UI — account switcher
// ─────────────────────────────────────────────

function updateWalletUI() {
  const addr = state.activeAccount;
  if (!addr) return;

  // Account card
  $('account-address').textContent = truncAddr(addr);
  $('account-address').title = addr;

  const net = NETWORKS[state.network];
  $('account-explorer-link').href = `${net.explorerAccount}${addr}`;

  const badge = $('network-badge');
  badge.textContent = net.name;
  badge.className = `network-badge ${state.network}`;

  // Account switcher pill
  const accounts = getAllAccounts();
  const active   = accounts.find(a => a.address === addr);
  $('switcher-label').textContent = active?.label ?? 'Account';
  $('switcher-addr').textContent  = truncAddr(addr);

  renderAccountDropdown(accounts, addr);
}

function renderAccountDropdown(accounts, activeAddr) {
  const listEl = $('account-list');
  listEl.innerHTML = accounts.map(a => `
    <button class="account-list-item ${a.address === activeAddr ? 'active-account' : ''}"
            data-address="${esc(a.address)}">
      <div class="acct-item-left">
        <span class="acct-item-label">${esc(a.label)}</span>
        <span class="acct-item-addr">${esc(truncAddr(a.address))}</span>
      </div>
      ${a.address === activeAddr ? '<span class="acct-item-check">✓</span>' : ''}
    </button>`).join('');

  listEl.querySelectorAll('.account-list-item').forEach(btn => {
    btn.addEventListener('click', async () => {
      $('account-dropdown').classList.add('hidden');
      const addr = btn.dataset.address;
      if (addr !== state.activeAccount) {
        await activateAccount(addr);
      }
    });
  });
}

// Toggle the account dropdown
$('account-switcher-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('account-dropdown').classList.toggle('hidden');
});

// Close dropdown on outside click
document.addEventListener('click', () => {
  $('account-dropdown')?.classList.add('hidden');
});

$('account-dropdown').addEventListener('click', e => e.stopPropagation());

$('add-account-dropdown-btn').addEventListener('click', () => {
  $('account-dropdown').classList.add('hidden');
  goToAddAccount();
});

// ─────────────────────────────────────────────
// WALLET — XRPL CLIENT
// ─────────────────────────────────────────────

function updateConnectionDot(status) {
  const dot = $('xrpl-connection-dot');
  if (!dot) return;
  dot.className = `connection-dot dot-${status}`;
  const labels = {
    connected:    'Connected to XRPL Devnet',
    connecting:   'Connecting to XRPL Devnet…',
    disconnected: 'Disconnected from XRPL Devnet',
  };
  dot.title = labels[status] ?? status;
}

async function connectXRPL() {
  updateConnectionDot('connecting');
  if (state.client?.isConnected()) {
    state.client.disconnect().catch(() => {});
  }
  const { wsUrl } = NETWORKS[state.network];
  state.client = new Client(wsUrl);
  state.client.on('connected',    () => updateConnectionDot('connected'));
  state.client.on('disconnected', () => updateConnectionDot('disconnected'));
  await state.client.connect();
  updateConnectionDot('connected');
}

async function ensureConnected() {
  if (!state.client?.isConnected()) await connectXRPL();
}

async function refreshBalance() {
  if (!state.wallet || !state.client) return;
  $('balance-amount').textContent = '…';
  try {
    await ensureConnected();
    const xrp = await state.client.getXrpBalance(state.wallet.address);
    $('balance-amount').textContent = `${xrp} XRP`;
  } catch (err) {
    if (err.message?.includes('Account not found') || err.data?.error === 'actNotFound') {
      $('balance-amount').textContent = '0 XRP (unfunded)';
    } else {
      $('balance-amount').textContent = 'Error';
      console.error('[balance]', err);
    }
  }
}

function formatCurrencyCode(currency) {
  if (currency.length !== 40) return currency;
  try {
    const stripped = currency.replace(/^0+/, '').replace(/0+$/, '');
    if (!stripped) return currency.slice(0, 8) + '…';
    const bytes = stripped.match(/.{2}/g) ?? [];
    const str = bytes.map(b => String.fromCharCode(parseInt(b, 16))).join('').replace(/\0/g, '').trim();
    if (str && /^[\x20-\x7E]+$/.test(str)) return str;
  } catch { /* fall through */ }
  return currency.slice(0, 8) + '…';
}

async function tryFetchAmmInfo(issuerAddress) {
  try {
    const resp = await state.client.request({
      command: 'amm_info',
      amm_account: issuerAddress,
      ledger_index: 'validated',
    });
    return resp.result.amm ?? null;
  } catch {
    return null;
  }
}

function formatPoolAsset(amount) {
  if (!amount) return '?';
  if (typeof amount === 'string') return 'XRP';
  if (amount.currency === 'XRP') return 'XRP';
  return formatCurrencyCode(amount.currency);
}

async function loadIouBalances() {
  if (!state.wallet || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_lines',
      account: state.wallet.address,
      ledger_index: 'validated',
    });
    const lines = resp.result.lines ?? [];

    const ammResults  = await Promise.all(lines.map(l => tryFetchAmmInfo(l.account)));
    const regularLines = lines.filter((_, i) => ammResults[i] === null);
    const ammLines    = lines
      .map((l, i) => ammResults[i] ? { ...l, ammInfo: ammResults[i] } : null)
      .filter(Boolean);

    renderIouBalances(regularLines);
    renderAmmBalances(ammLines);
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      renderIouBalances([]);
      renderAmmBalances([]);
    } else {
      console.error('[iou balances]', err);
    }
  }
}

function renderIouBalances(lines) {
  const card   = $('iou-balance-card');
  const listEl = $('iou-balance-list');
  const held   = lines.filter(l => parseFloat(l.balance) > 0);

  if (!held.length) { card.classList.add('hidden'); return; }

  card.classList.remove('hidden');
  const explorerToken = NETWORKS[state.network].explorerToken;
  listEl.innerHTML = held.map(line => {
    const code    = formatCurrencyCode(line.currency);
    const balance = parseFloat(line.balance).toLocaleString(undefined, { maximumFractionDigits: 6 });
    const href    = `${explorerToken}${encodeURIComponent(line.currency)}.${line.account}`;
    return `
      <a class="iou-balance-item" href="${esc(href)}" target="_blank" rel="noreferrer">
        <div class="iou-token-info">
          <span class="iou-currency">${esc(code)}</span>
          <span class="iou-issuer" title="${esc(line.account)}">${esc(truncAddr(line.account))}</span>
        </div>
        <div class="iou-balance-amount">${esc(balance)}</div>
      </a>`;
  }).join('');
}

function poolAssetShare(poolAmount, lpHeld, lpTotal) {
  if (!lpTotal || lpTotal === 0) return 0;
  const share = lpHeld / lpTotal;
  if (typeof poolAmount === 'string') return parseFloat(dropsToXrp(poolAmount)) * share;
  return parseFloat(poolAmount?.value ?? '0') * share;
}

function renderAmmBalances(lines) {
  const card   = $('amm-balance-card');
  const listEl = $('amm-balance-list');
  const held   = lines.filter(l => parseFloat(l.balance) > 0);

  if (!held.length) { card.classList.add('hidden'); return; }

  card.classList.remove('hidden');
  const explorerAccount = NETWORKS[state.network].explorerAccount;
  listEl.innerHTML = held.map(line => {
    const { ammInfo } = line;
    const label1  = formatPoolAsset(ammInfo.amount);
    const label2  = formatPoolAsset(ammInfo.amount2);
    const pool    = `${label1} / ${label2}`;
    const lpHeld  = parseFloat(line.balance);
    const lpTotal = parseFloat(ammInfo.lp_token?.value ?? '0');
    const share1  = poolAssetShare(ammInfo.amount,  lpHeld, lpTotal);
    const share2  = poolAssetShare(ammInfo.amount2, lpHeld, lpTotal);
    const fmt     = (n, dp = 6) => n.toLocaleString(undefined, { maximumFractionDigits: dp });
    const lpBal   = lpHeld.toLocaleString(undefined, { maximumFractionDigits: 6 });
    const href    = `${explorerAccount}${line.account}`;
    return `
      <a class="amm-balance-item" href="${esc(href)}" target="_blank" rel="noreferrer">
        <div class="amm-summary-row">
          <div class="amm-token-info">
            <span class="amm-pool">${esc(pool)}</span>
            <span class="amm-issuer" title="${esc(line.account)}">${esc(truncAddr(line.account))}</span>
          </div>
          <div class="amm-balance-amount">${esc(lpBal)} LP</div>
        </div>
        <div class="amm-assets-row">
          <div class="amm-asset-share">
            <span class="amm-asset-label">${esc(label1)}</span>
            <span class="amm-asset-value">${esc(fmt(share1))}</span>
          </div>
          <div class="amm-asset-share">
            <span class="amm-asset-label">${esc(label2)}</span>
            <span class="amm-asset-value">${esc(fmt(share2))}</span>
          </div>
        </div>
      </a>`;
  }).join('');
}

function issuerFromMptIssuanceId(issuanceId) {
  if (!issuanceId || issuanceId.length !== 48) return null;
  try {
    const accountIdHex = issuanceId.slice(8);
    const bytes = Buffer.from(accountIdHex, 'hex');
    return encodeAccountID(bytes);
  } catch {
    return null;
  }
}

async function fetchMptIssuanceInfo(issuanceId) {
  try {
    const resp = await state.client.request({
      command: 'ledger_entry',
      mpt_issuance: issuanceId,
      ledger_index: 'validated',
    });
    const node       = resp.result.node ?? {};
    const assetScale = node.AssetScale ?? 0;
    const issuer     = node.Issuer ?? null;
    const metadata   = node.MPTokenMetadata;
    let ticker = null;
    if (metadata) {
      const decoded = decodeMPTokenMetadata(metadata);
      ticker = (typeof decoded?.ticker === 'string' && decoded.ticker) ? decoded.ticker : null;
    }

    let vaultInfo = null;
    if (issuer) {
      try {
        const allObjs = await state.client.request({
          command: 'account_objects',
          account: issuer,
          ledger_index: 'validated',
        });
        const loanBrokers = (allObjs.result.account_objects ?? [])
          .filter(o => o.LedgerEntryType === 'LoanBroker' && o.VaultID);
        for (const lb of loanBrokers) {
          const vaultResp = await state.client.request({
            command: 'ledger_entry',
            index: lb.VaultID,
            ledger_index: 'validated',
          });
          const vault = vaultResp.result.node;
          if (vault.ShareMPTID === issuanceId) {
            vaultInfo = vault;
            break;
          }
        }
      } catch { /* vault detection failed */ }
    }

    const outstandingAmount = node.OutstandingAmount ?? '0';
    return { ticker, assetScale, outstandingAmount, vaultInfo };
  } catch {
    return { ticker: null, assetScale: 0, outstandingAmount: '0', vaultInfo: null };
  }
}

async function loadMptBalances() {
  if (!state.wallet || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: state.wallet.address,
      type: 'mptoken',
      ledger_index: 'validated',
    });
    const objects = resp.result.account_objects ?? [];
    const infos   = await Promise.all(objects.map(o => fetchMptIssuanceInfo(o.MPTokenIssuanceID)));
    const issuanceMap = new Map(objects.map((o, i) => [o.MPTokenIssuanceID, infos[i]]));

    const regularObjects = objects.filter((_, i) => !infos[i]?.vaultInfo);
    const vaultObjects   = objects.filter((_, i) =>  infos[i]?.vaultInfo);

    renderMptBalances(regularObjects, issuanceMap);
    renderVaultBalances(vaultObjects, issuanceMap);
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      renderMptBalances([]);
      renderVaultBalances([]);
    } else {
      renderMptBalances([], new Map());
      renderVaultBalances([], new Map());
      console.error('[mpt balances]', err);
    }
  }
}

function renderMptBalances(objects, issuanceMap = new Map()) {
  const card   = $('mpt-balance-card');
  const listEl = $('mpt-balance-list');
  const held   = objects.filter(o => o.LedgerEntryType === 'MPToken');

  if (!held.length) { card.classList.add('hidden'); return; }

  card.classList.remove('hidden');
  const explorerMpt = NETWORKS[state.network].explorerMpt;
  listEl.innerHTML = held.map(obj => {
    const issuanceId = obj.MPTokenIssuanceID ?? '';
    const { ticker, assetScale } = issuanceMap.get(issuanceId) ?? { ticker: null, assetScale: 0 };
    const raw         = obj.MPTAmount ? parseInt(obj.MPTAmount, 10) : 0;
    const scaled      = assetScale > 0 ? raw / Math.pow(10, assetScale) : raw;
    const amount      = scaled.toLocaleString(undefined, { maximumFractionDigits: assetScale });
    const shortId     = issuanceId.length >= 12
      ? `${issuanceId.slice(0, 8)}…${issuanceId.slice(-4)}`
      : issuanceId;
    const displayName  = ticker || shortId;
    const issuer       = issuerFromMptIssuanceId(issuanceId);
    const issuerDisplay = issuer ? truncAddr(issuer) : (issuanceId.slice(8, 16) + '…');
    const href         = `${explorerMpt}${issuanceId}`;
    return `
      <a class="mpt-balance-item" href="${esc(href)}" target="_blank" rel="noreferrer">
        <div class="mpt-token-info">
          <span class="mpt-id" title="${esc(issuanceId)}">${esc(displayName)}</span>
          <span class="mpt-issuer" title="${esc(issuer ?? issuanceId)}">${esc(issuerDisplay)}</span>
        </div>
        <div class="mpt-balance-amount">${esc(amount)}</div>
      </a>`;
  }).join('');
}

function renderVaultBalances(objects, issuanceMap = new Map()) {
  const card   = $('vault-balance-card');
  const listEl = $('vault-balance-list');
  const held   = objects.filter(o => o.LedgerEntryType === 'MPToken');

  if (!held.length) { card.classList.add('hidden'); return; }

  card.classList.remove('hidden');
  const explorerAccount = NETWORKS[state.network].explorerAccount;
  listEl.innerHTML = held.map(obj => {
    const issuanceId = obj.MPTokenIssuanceID ?? '';
    const { ticker, assetScale, outstandingAmount, vaultInfo } =
      issuanceMap.get(issuanceId) ?? { ticker: null, assetScale: 0, outstandingAmount: '0', vaultInfo: null };

    const raw         = obj.MPTAmount ? parseInt(obj.MPTAmount, 10) : 0;
    const scaled      = assetScale > 0 ? raw / Math.pow(10, assetScale) : raw;
    const totalShares = parseInt(outstandingAmount, 10) / Math.pow(10, assetScale || 1);
    const holderShare = totalShares > 0 ? scaled / totalShares : 0;
    const shares      = scaled.toLocaleString(undefined, { maximumFractionDigits: assetScale });
    const shortId     = issuanceId.length >= 12
      ? `${issuanceId.slice(0, 8)}…${issuanceId.slice(-4)}`
      : issuanceId;

    let vaultLabel = ticker || shortId;
    if (vaultInfo?.Data) {
      try {
        const decoded = Buffer.from(vaultInfo.Data, 'hex').toString('utf8').trim();
        if (decoded && /^[\x20-\x7E]+$/.test(decoded)) vaultLabel = decoded;
      } catch { /* keep existing label */ }
    }

    const issuer        = issuerFromMptIssuanceId(issuanceId);
    const issuerDisplay = issuer ? truncAddr(issuer) : (issuanceId.slice(8, 16) + '…');
    const underlying    = vaultInfo?.Asset ? formatPoolAsset(vaultInfo.Asset) : '—';
    const fmtAmt        = (v) => (parseFloat(v ?? 0) * holderShare).toLocaleString(undefined, { maximumFractionDigits: 6 });
    const available     = vaultInfo?.AssetsAvailable != null ? fmtAmt(vaultInfo.AssetsAvailable) : null;
    const total         = vaultInfo?.AssetsTotal      != null ? fmtAmt(vaultInfo.AssetsTotal)     : null;
    const href          = `${explorerAccount}${issuer ?? ''}`;

    return `
      <a class="vault-balance-item" href="${esc(href)}" target="_blank" rel="noreferrer">
        <div class="amm-summary-row">
          <div class="amm-token-info">
            <span class="vault-name" title="${esc(issuanceId)}">${esc(vaultLabel)}</span>
            <span class="amm-issuer" title="${esc(issuer ?? issuanceId)}">${esc(issuerDisplay)}</span>
          </div>
          <div class="amm-balance-amount">${esc(shares)} shares</div>
        </div>
        <div class="amm-assets-row">
          <div class="amm-asset-share">
            <span class="amm-asset-label">Underlying</span>
            <span class="amm-asset-value">${esc(underlying)}</span>
          </div>
          <div class="amm-asset-share">
            <span class="amm-asset-label">Pool share</span>
            <span class="amm-asset-value">${(holderShare * 100).toFixed(2)}%</span>
          </div>
          ${available != null ? `
          <div class="amm-asset-share">
            <span class="amm-asset-label">Available Share</span>
            <span class="amm-asset-value">${esc(available)}</span>
          </div>` : ''}
          ${total != null ? `
          <div class="amm-asset-share">
            <span class="amm-asset-label">Total Share</span>
            <span class="amm-asset-value">${esc(total)}</span>
          </div>` : ''}
        </div>
      </a>`;
  }).join('');
}

// ─────────────────────────────────────────────
// AUTO-REFRESH
// ─────────────────────────────────────────────

function startAutoRefresh() {
  stopAutoRefresh();
  state.refreshTimer = setInterval(() => {
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
  }, AUTO_REFRESH_INTERVAL);
}

function stopAutoRefresh() {
  if (state.refreshTimer) {
    clearInterval(state.refreshTimer);
    state.refreshTimer = null;
  }
}

// ─────────────────────────────────────────────
// FAUCET
// ─────────────────────────────────────────────

async function fundFromFaucet() {
  if (!state.wallet) return;
  const btn      = $('faucet-btn');
  const statusEl = $('faucet-status');
  btn.disabled = true;
  btn.textContent = '💧 Requesting…';
  statusEl.className = 'faucet-status';
  statusEl.textContent = '';
  statusEl.classList.remove('hidden');

  try {
    const resp = await fetch(NETWORKS[state.network].faucet, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ destination: state.wallet.address }),
    });
    if (!resp.ok) throw new Error(`Faucet returned HTTP ${resp.status}`);

    statusEl.textContent = '✓ Faucet request sent — balance will update shortly.';
    statusEl.className = 'faucet-status ok';

    setTimeout(async () => {
      await refreshBalance();
      await loadTxHistory();
      statusEl.textContent = '';
      statusEl.classList.add('hidden');
    }, 5000);
  } catch (err) {
    console.error('[faucet]', err);
    statusEl.textContent = `✕ Faucet failed: ${err.message}`;
    statusEl.className = 'faucet-status err';
  } finally {
    btn.disabled = false;
    btn.textContent = '💧 Faucet';
  }
}

// ─────────────────────────────────────────────
// TRANSACTION HISTORY
// ─────────────────────────────────────────────

async function loadTxHistory() {
  if (!state.wallet || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_tx',
      account: state.wallet.address,
      limit: 10,
      ledger_index_min: -1,
      ledger_index_max: -1,
    });
    renderTxHistory(resp.result.transactions ?? []);
  } catch (err) {
    const listEl = $('tx-history-list');
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      listEl.innerHTML = '<div class="tx-history-empty">Account not yet funded — no transactions.</div>';
    } else {
      listEl.innerHTML = '<div class="tx-history-empty">Could not load history.</div>';
      console.error('[tx history]', err);
    }
  }
}

function renderTxHistory(txs) {
  const listEl = $('tx-history-list');
  if (!txs.length) {
    listEl.innerHTML = '<div class="tx-history-empty">No transactions yet.</div>';
    return;
  }

  const explorer = NETWORKS[state.network].explorer;
  listEl.innerHTML = txs.map(entry => {
    const txJson  = entry.tx_json ?? entry.tx ?? {};
    const meta    = entry.meta ?? entry.metaData ?? {};
    const result  = meta.TransactionResult ?? '—';
    const success = result === 'tesSUCCESS';
    const hash    = entry.hash ?? txJson.hash ?? '—';
    const type    = txJson.TransactionType ?? '—';

    let detail = '';
    if (type === 'Payment' && txJson.Amount) {
      detail = formatAmount(txJson.Amount);
      if (txJson.Destination) detail += ` → ${truncAddr(txJson.Destination)}`;
    } else if (type === 'OfferCreate') {
      if (txJson.TakerGets && txJson.TakerPays) {
        detail = `${formatAmount(txJson.TakerGets)} / ${formatAmount(txJson.TakerPays)}`;
      }
    } else if (txJson.NFTokenID) {
      detail = truncAddr(txJson.NFTokenID);
    }

    const date    = xrplDateToLocal(txJson.date);
    const dateStr = date ? date.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : '';
    const href    = hash !== '—' ? `${explorer}${hash}` : null;
    const tag     = href ? 'a' : 'div';
    const linkAttrs = href ? ` href="${esc(href)}" target="_blank" rel="noreferrer"` : '';

    return `
      <${tag} class="tx-history-item"${linkAttrs}>
        <div class="tx-history-main">
          <span class="tx-history-type ${success ? 'success' : 'fail'}">${esc(type)}</span>
          ${detail ? `<span class="tx-history-detail">${esc(detail)}</span>` : ''}
        </div>
        <div class="tx-history-meta">
          <span class="tx-history-result ${success ? 'success' : 'fail'}">${success ? '✓' : '✕'} ${esc(result)}</span>
          <span class="tx-history-date">${esc(dateStr)}</span>
          ${hash !== '—' ? `<span class="tx-history-hash">${esc(hash.slice(0, 8))}…</span>` : ''}
        </div>
      </${tag}>`;
  }).join('');
}

// ─────────────────────────────────────────────
// WALLETCONNECT — INIT  (delegates to background)
// ─────────────────────────────────────────────

async function initWalletConnect() {
  try {
    const resp = await sendToBackground({ type: 'WC_INIT' });
    updateSessionsUI(resp.sessions);
  } catch (err) {
    console.error('[WC init]', err);
    showAlert('wc-error', `WalletConnect init failed: ${err.message}`);
  }
}

// ─────────────────────────────────────────────
// WALLETCONNECT — PAIRING
// ─────────────────────────────────────────────

async function pairUri() {
  const uri = $('wc-uri-input').value.trim();
  if (!uri) return;
  if (!uri.startsWith('wc:')) {
    showAlert('wc-error', 'Invalid WalletConnect URI. It should start with "wc:".');
    return;
  }

  hideAlert('wc-error');
  const btn = $('wc-pair-btn');
  btn.disabled = true;
  btn.textContent = 'Connecting…';

  try {
    await sendToBackground({ type: 'WC_PAIR', uri });
    $('wc-uri-input').value = '';
    $('wc-uri-group').classList.add('hidden');
    $('wc-connect-btn').classList.remove('hidden');
  } catch (err) {
    showAlert('wc-error', `Pairing failed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Connect';
  }
}

// ─────────────────────────────────────────────
// WALLETCONNECT — PENDING EVENT HANDLER
// ─────────────────────────────────────────────

/**
 * Read any pending WC event stored by the background service worker.
 * Called on popup open and after account unlock.
 */
async function checkPendingWcEvent() {
  const { wcPending } = await chrome.storage.session.get('wcPending');
  if (!wcPending) return;

  if (wcPending.type === 'proposal') {
    showWcProposal(wcPending);
  } else if (wcPending.type === 'request') {
    await showWcRequest(wcPending);
  }
}

// ─────────────────────────────────────────────
// WALLETCONNECT — SESSION PROPOSAL
// ─────────────────────────────────────────────

/**
 * @param {object} pending  Serialised proposal stored by background.
 */
function showWcProposal(pending) {
  state.pendingProposal = pending;
  const meta = pending.params.proposer.metadata;

  $('proposal-app-card').innerHTML = `
    <div class="app-icon">
      ${meta.icons?.[0]
        ? `<img src="${esc(meta.icons[0])}" alt="${esc(meta.name)}" onerror="this.replaceWith(document.createTextNode('🌐'))" />`
        : '🌐'}
    </div>
    <div>
      <div class="app-name">${esc(meta.name)}</div>
      <div class="app-url">${esc(meta.url)}</div>
    </div>
  `;

  showView('session-proposal');
}

async function approveSession() {
  if (!state.pendingProposal) return;

  const btn = $('approve-session-btn');
  btn.disabled = true;
  btn.textContent = 'Approving…';

  try {
    const chainId = NETWORKS[state.network].chainId;
    const resp = await sendToBackground({
      type: 'WC_APPROVE_SESSION',
      id:   state.pendingProposal.id,
      namespaces: {
        xrpl: {
          chains:   [chainId],
          accounts: [`${chainId}:${state.wallet.address}`],
          methods:  ['xrpl_signTransaction', 'xrpl_signTransactionFor'],
          events:   [],
        },
      },
    });
    state.pendingProposal = null;
    updateSessionsUI(resp.sessions);
    showView('wallet');
  } catch (err) {
    console.error('[approveSession]', err);
    alert('Failed to approve: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Approve';
  }
}

async function rejectSession() {
  if (!state.pendingProposal) return;
  try {
    await sendToBackground({
      type:   'WC_REJECT_SESSION',
      id:     state.pendingProposal.id,
      reason: getSdkError('USER_REJECTED'),
    });
  } catch (err) {
    console.error('[rejectSession]', err);
  }
  state.pendingProposal = null;
  showView('wallet');
}

// ─────────────────────────────────────────────
// WALLETCONNECT — SESSION REQUEST (TRANSACTION)
// ─────────────────────────────────────────────

/**
 * @param {object} pending  Serialised request stored by background.
 */
async function showWcRequest(pending) {
  // Auto-switch to the account this session was approved for.
  if (pending.address && pending.address !== state.activeAccount) {
    const accounts = getAllAccounts();
    const acct = accounts.find(a => a.address === pending.address);
    if (acct) {
      await activateAccount(pending.address);
    } else {
      // The required account is not in this wallet — show an error.
      showView('wallet');
      showAlert('wc-error', `Incoming request requires account ${truncAddr(pending.address)} which is not in this wallet.`);
      await sendToBackground({ type: 'WC_CLEAR_PENDING' });
      return;
    }
  }

  state.pendingRequest = {
    topic:  pending.topic,
    id:     pending.id,
    params: pending.params,
  };

  renderTransactionView(pending);
  showView('transaction');
}

function renderTransactionView(pending) {
  const txJson  = pending.params.request.params.tx_json;
  const appName = pending.appName ?? 'Unknown App';

  $('tx-from-app').innerHTML = `Request from <strong>${esc(appName)}</strong>`;
  $('tx-details').innerHTML  = buildTxRows(txJson);
  hideAlert('tx-warning');

  $('tx-raw-json').textContent = JSON.stringify(txJson, null, 2);
  $('tx-raw-json').classList.add('hidden');
  $('toggle-raw-btn').textContent = '▶ View raw JSON';
}

function buildTxRows(txJson) {
  const row = (label, value, cls = '') =>
    `<div class="tx-row">
       <span class="tx-label">${label}</span>
       <span class="tx-value ${cls}">${value}</span>
     </div>`;

  const rows = [];
  rows.push(row('Type', esc(txJson.TransactionType), 'tx-type'));

  if (txJson.Account)
    rows.push(row('From', `<span title="${esc(txJson.Account)}">${esc(truncAddr(txJson.Account))}</span>`, 'tx-address'));
  if (txJson.Destination)
    rows.push(row('To', `<span title="${esc(txJson.Destination)}">${esc(truncAddr(txJson.Destination))}</span>`, 'tx-address'));
  if (txJson.DestinationTag !== undefined)
    rows.push(row('Dest. Tag', esc(txJson.DestinationTag)));
  if (txJson.Amount !== undefined)
    rows.push(row('Amount', esc(formatAmount(txJson.Amount)), 'tx-amount'));
  if (txJson.SendMax !== undefined)
    rows.push(row('Send Max', esc(formatAmount(txJson.SendMax))));
  if (txJson.TakerGets !== undefined)
    rows.push(row('Sell (TakerGets)', esc(formatAmount(txJson.TakerGets))));
  if (txJson.TakerPays !== undefined)
    rows.push(row('Buy (TakerPays)', esc(formatAmount(txJson.TakerPays))));
  if (txJson.NFTokenID)
    rows.push(row('NFToken ID', `<span class="tx-address" title="${esc(txJson.NFTokenID)}">${esc(txJson.NFTokenID.slice(0, 16))}…</span>`));
  if (txJson.Fee)
    rows.push(row('Fee', esc(formatAmount(txJson.Fee)), 'tx-fee'));
  if (txJson.Memos?.length) {
    const memoText = txJson.Memos.map(m => {
      try { return Buffer.from(m.Memo?.MemoData ?? '', 'hex').toString('utf8'); }
      catch { return '(binary)'; }
    }).join(' / ');
    rows.push(row('Memo', esc(memoText)));
  }

  return rows.join('');
}

async function approveTransaction() {
  if (!state.pendingRequest) return;

  $('approve-tx-btn').disabled = true;
  $('reject-tx-btn').disabled  = true;

  const { topic, id, params } = state.pendingRequest;
  const txJson = params.request.params.tx_json;

  showView('tx-status');
  setTxStatus('pending', 'Preparing transaction…');

  try {
    await ensureConnected();

    setTxStatus('pending', 'Autofilling network fields…');
    const prepared = await state.client.autofill(txJson);

    setTxStatus('pending', 'Signing…');
    const { tx_blob, hash } = state.wallet.sign(prepared);

    setTxStatus('pending', 'Submitting to XRPL…');
    const response = await state.client.submitAndWait(tx_blob);

    const txResult = response.result?.meta?.TransactionResult;
    if (txResult !== 'tesSUCCESS') throw new Error(`Transaction failed on ledger: ${txResult}`);

    setTxStatus('success', 'Transaction validated!', hash);

    await respondWc(topic, id, { tx_json: response.result, tx_blob, hash });

    state.pendingRequest = null;
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
  } catch (err) {
    console.error('[approveTransaction]', err);
    setTxStatus('error', err.message || 'Transaction failed.');
    await respondWc(topic, id, null, { code: 5000, message: err.message });
    state.pendingRequest = null;
  }
}

async function rejectTransaction() {
  if (!state.pendingRequest) return;
  const { topic, id } = state.pendingRequest;
  state.pendingRequest = null;

  await respondWc(topic, id, null, getSdkError('USER_REJECTED'));
  showView('wallet');
  $('approve-tx-btn').disabled = false;
  $('reject-tx-btn').disabled  = false;
}

async function respondWc(topic, id, result, error) {
  try {
    const response = error
      ? { id, jsonrpc: '2.0', error }
      : { id, jsonrpc: '2.0', result };
    await sendToBackground({ type: 'WC_RESPOND', topic, response });
  } catch (err) {
    console.error('[respondWc]', err);
  }
}

// ─────────────────────────────────────────────
// WALLETCONNECT — SESSION LIST UI
// ─────────────────────────────────────────────

/**
 * @param {object} [sessions]  Pre-fetched session map.  If omitted, fetched
 *   from the background.
 */
async function updateSessionsUI(sessions) {
  if (!sessions) {
    try {
      const resp = await sendToBackground({ type: 'WC_GET_SESSIONS' });
      sessions = resp.sessions;
    } catch {
      sessions = {};
    }
  }

  const keys   = Object.keys(sessions);
  const listEl = $('wc-sessions-list');
  const dot    = $('wc-status');

  if (keys.length === 0) {
    dot.className = 'wc-status-dot wc-disconnected';
    listEl.innerHTML = '';
    return;
  }

  dot.className = 'wc-status-dot wc-connected';
  listEl.innerHTML = keys.map(topic => {
    const s    = sessions[topic];
    const meta = s.peer.metadata;
    const iconHtml = meta.icons?.[0]
      ? `<img class="session-icon" src="${esc(meta.icons[0])}" alt="${esc(meta.name)}" onerror="this.style.display='none'" />`
      : `<span class="session-icon-placeholder">🌐</span>`;

    return `
      <div class="session-item">
        <div class="session-app">
          ${iconHtml}
          <div class="session-info">
            <div class="session-name">${esc(meta.name)}</div>
            <div class="session-url">${esc(meta.url)}</div>
          </div>
        </div>
        <button class="btn-disconnect" data-topic="${esc(topic)}" title="Disconnect">✕</button>
      </div>`;
  }).join('');

  listEl.querySelectorAll('.btn-disconnect').forEach(btn => {
    btn.addEventListener('click', () => disconnectSession(btn.dataset.topic));
  });
}

async function disconnectSession(topic) {
  try {
    const resp = await sendToBackground({
      type:   'WC_DISCONNECT',
      topic,
      reason: getSdkError('USER_DISCONNECTED'),
    });
    updateSessionsUI(resp.sessions);
  } catch (err) {
    console.error('[disconnect]', err);
  }
}

// ─────────────────────────────────────────────
// TX STATUS VIEW
// ─────────────────────────────────────────────

function setTxStatus(type, message, hash) {
  const iconEl        = $('tx-status-icon');
  const titleEl       = $('tx-status-title');
  const msgEl         = $('tx-status-message');
  const hashContainer = $('tx-hash-container');
  const doneBtn       = $('tx-done-btn');

  msgEl.textContent = message;
  hashContainer.classList.add('hidden');
  doneBtn.classList.add('hidden');

  if (type === 'pending') {
    iconEl.innerHTML    = '<div class="spinner"></div>';
    titleEl.textContent = 'Processing…';
  } else if (type === 'success') {
    iconEl.innerHTML    = '<div class="status-circle success">✓</div>';
    titleEl.textContent = 'Confirmed!';
    doneBtn.classList.remove('hidden');
    if (hash) {
      const explorer = NETWORKS[state.network].explorer;
      $('tx-hash-link').textContent = `${hash.slice(0, 10)}…${hash.slice(-10)}`;
      $('tx-hash-link').href        = `${explorer}${hash}`;
      hashContainer.classList.remove('hidden');
    }
  } else if (type === 'error') {
    iconEl.innerHTML    = '<div class="status-circle error">✕</div>';
    titleEl.textContent = 'Failed';
    doneBtn.classList.remove('hidden');
  }
}

// ─────────────────────────────────────────────
// EVENT LISTENERS — Setup password view
// ─────────────────────────────────────────────

$('setup-password-btn').addEventListener('click', setupPasswordContinue);
$('setup-password-confirm').addEventListener('keypress', e => { if (e.key === 'Enter') setupPasswordContinue(); });
$('toggle-setup-password-btn').addEventListener('click', () => togglePasswordVisibility('setup-password'));
$('toggle-setup-confirm-btn').addEventListener('click', () => togglePasswordVisibility('setup-password-confirm'));

// ─────────────────────────────────────────────
// EVENT LISTENERS — Account type selection
// ─────────────────────────────────────────────

$('back-from-account-type-btn').addEventListener('click', () => {
  if (state.flowContext === 'setup') {
    showView('setup-password');
  } else {
    showView('wallet');
  }
});

$('type-gen-seed').addEventListener('click', () => initGenSeedView());
$('type-import-seed').addEventListener('click', () => {
  hideAlert('import-seed-error');
  $('import-seed-input').value = '';
  $('import-seed-label').value = '';
  showView('account-import-seed');
});
$('type-gen-mnemonic').addEventListener('click', () => initGenMnemonicView());
$('type-import-mnemonic').addEventListener('click', () => {
  hideAlert('import-mnemonic-error');
  $('import-mnemonic-input').value = '';
  $('import-mnemonic-label').value = '';
  showView('account-import-mnemonic');
});
$('type-hd-account').addEventListener('click', () => initHdAddView());

// ─────────────────────────────────────────────
// EVENT LISTENERS — Generated seed view
// ─────────────────────────────────────────────

$('back-from-gen-seed-btn').addEventListener('click', () => showView('account-type'));
$('copy-gen-seed-btn').addEventListener('click', async () => {
  const seed = $('generated-seed-text').dataset.seed;
  if (seed) await navigator.clipboard.writeText(seed).catch(() => {});
});
$('gen-seed-confirm-btn').addEventListener('click', confirmGenSeed);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Import seed view
// ─────────────────────────────────────────────

$('back-from-import-seed-btn').addEventListener('click', () => showView('account-type'));
$('toggle-import-seed-btn').addEventListener('click', () => togglePasswordVisibility('import-seed-input'));
$('import-seed-confirm-btn').addEventListener('click', confirmImportSeed);
$('import-seed-input').addEventListener('keypress', e => { if (e.key === 'Enter') confirmImportSeed(); });

// ─────────────────────────────────────────────
// EVENT LISTENERS — Generate mnemonic view
// ─────────────────────────────────────────────

$('back-from-gen-mnemonic-btn').addEventListener('click', () => {
  if (!$('gen-mnemonic-step-backup').classList.contains('hidden')) {
    // Go back to length selection within the same view
    state.pendingMnemonic = null;
    $('gen-mnemonic-step-length').classList.remove('hidden');
    $('gen-mnemonic-step-backup').classList.add('hidden');
  } else {
    showView('account-type');
  }
});

$('mnemonic-12-btn').addEventListener('click', () => {
  state.mnemonicWordCount = 12;
  $('mnemonic-12-btn').classList.add('active-len');
  $('mnemonic-24-btn').classList.remove('active-len');
});

$('mnemonic-24-btn').addEventListener('click', () => {
  state.mnemonicWordCount = 24;
  $('mnemonic-24-btn').classList.add('active-len');
  $('mnemonic-12-btn').classList.remove('active-len');
});

$('gen-mnemonic-generate-btn').addEventListener('click', generateAndShowMnemonic);

$('copy-mnemonic-btn').addEventListener('click', async () => {
  if (state.pendingMnemonic) {
    await navigator.clipboard.writeText(state.pendingMnemonic).catch(() => {});
  }
});

$('gen-mnemonic-confirm-btn').addEventListener('click', confirmMnemonicGeneration);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Import mnemonic view
// ─────────────────────────────────────────────

$('back-from-import-mnemonic-btn').addEventListener('click', () => showView('account-type'));
$('import-mnemonic-confirm-btn').addEventListener('click', confirmImportMnemonic);

// ─────────────────────────────────────────────
// EVENT LISTENERS — HD add account view
// ─────────────────────────────────────────────

$('back-from-hd-add-btn').addEventListener('click', () => showView('account-type'));
$('hd-account-index').addEventListener('input', () => {
  $('hd-path-preview').textContent = $('hd-account-index').value || '0';
});
$('hd-add-confirm-btn').addEventListener('click', confirmHdAdd);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Unlock view
// ─────────────────────────────────────────────

$('unlock-btn').addEventListener('click', unlock);
$('unlock-password').addEventListener('keypress', e => { if (e.key === 'Enter') unlock(); });
$('toggle-unlock-password-btn').addEventListener('click', () => togglePasswordVisibility('unlock-password'));
$('reset-wallet-btn').addEventListener('click', resetWallet);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Wallet view
// ─────────────────────────────────────────────

$('lock-btn').addEventListener('click', lockWallet);
$('settings-btn').addEventListener('click', () => showView('settings'));
$('back-from-settings-btn').addEventListener('click', () => showView('wallet'));
$('settings-manage-accounts-btn').addEventListener('click', () => {
  renderManageAccountsList();
  showView('manage-accounts');
});
$('back-from-manage-accounts-btn').addEventListener('click', () => showView('settings'));
$('back-from-remove-account-btn').addEventListener('click', () => showView('manage-accounts'));
$('remove-acct-cancel-btn').addEventListener('click', () => {
  state.pendingRemoveAddress = null;
  showView('manage-accounts');
});
$('remove-acct-confirm-btn').addEventListener('click', executeRemoveAccount);
$('settings-change-password-btn').addEventListener('click', () => {
  hideAlert('cp-error');
  hideAlert('cp-success');
  showView('change-password');
});
$('back-from-change-password-btn').addEventListener('click', () => showView('settings'));
$('cp-save-btn').addEventListener('click', changePassword);
$('toggle-cp-current-btn').addEventListener('click', () => togglePasswordVisibility('cp-current'));
$('toggle-cp-new-btn').addEventListener('click',     () => togglePasswordVisibility('cp-new'));
$('toggle-cp-confirm-btn').addEventListener('click', () => togglePasswordVisibility('cp-confirm'));

$('refresh-balance-btn').addEventListener('click', () => {
  $('faucet-status').textContent = '';
  $('faucet-status').classList.add('hidden');
  refreshBalance();
  loadIouBalances();
  loadMptBalances();
});

$('copy-address-btn').addEventListener('click', async () => {
  if (!state.wallet) return;
  try {
    await navigator.clipboard.writeText(state.wallet.address);
    $('copy-toast').classList.remove('hidden');
    setTimeout(() => $('copy-toast').classList.add('hidden'), 1800);
  } catch { /* clipboard permission denied */ }
});

$('qr-btn').addEventListener('click', showQr);
$('qr-close-btn').addEventListener('click', hideQr);
$('qr-modal').addEventListener('click', e => { if (e.target === $('qr-modal')) hideQr(); });

async function showQr() {
  if (!state.wallet) return;
  const addr = state.wallet.address;
  $('qr-address').textContent = addr;
  await QRCode.toCanvas($('qr-canvas'), addr, {
    width: 200,
    margin: 2,
    color: { dark: '#0f172a', light: '#f8fafc' },
  });
  $('qr-modal').classList.remove('hidden');
}

function hideQr() {
  $('qr-modal').classList.add('hidden');
}

$('faucet-btn').addEventListener('click', fundFromFaucet);
$('refresh-history-btn').addEventListener('click', loadTxHistory);

// WalletConnect
$('wc-connect-btn').addEventListener('click', () => {
  hideAlert('wc-error');
  $('wc-uri-group').classList.remove('hidden');
  $('wc-connect-btn').classList.add('hidden');
  $('wc-uri-input').focus();
});

$('wc-pair-btn').addEventListener('click', pairUri);
$('wc-uri-input').addEventListener('keypress', e => { if (e.key === 'Enter') pairUri(); });

$('wc-cancel-btn').addEventListener('click', () => {
  $('wc-uri-group').classList.add('hidden');
  $('wc-connect-btn').classList.remove('hidden');
  $('wc-uri-input').value = '';
  hideAlert('wc-error');
});

// Session proposal
$('approve-session-btn').addEventListener('click', approveSession);
$('reject-session-btn').addEventListener('click', rejectSession);
$('back-from-proposal-btn').addEventListener('click', () => rejectSession());

// Transaction review
$('approve-tx-btn').addEventListener('click', approveTransaction);
$('reject-tx-btn').addEventListener('click', rejectTransaction);

$('toggle-raw-btn').addEventListener('click', () => {
  const pre = $('tx-raw-json');
  const btn = $('toggle-raw-btn');
  const hidden = pre.classList.toggle('hidden');
  btn.textContent = hidden ? '▶ View raw JSON' : '▼ Hide raw JSON';
});

// Transaction status
$('tx-done-btn').addEventListener('click', () => {
  showView('wallet');
  $('approve-tx-btn').disabled = false;
  $('reject-tx-btn').disabled  = false;
});

// ─────────────────────────────────────────────
// BACKGROUND → POPUP  push messages
// (handles events that arrive while the popup is already open)
// ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (!state.wallet) return; // wallet locked — ignore, boot will pick up wcPending on next open

  if (message.type === 'WC_PROPOSAL') {
    showWcProposal(message.data);
  } else if (message.type === 'WC_REQUEST') {
    showWcRequest(message.data);
  } else if (message.type === 'WC_SESSIONS_CHANGED') {
    updateSessionsUI();
  }
});

// ─────────────────────────────────────────────
// EVENT LISTENERS — Setup reset (visible when vault already exists)
// ─────────────────────────────────────────────

$('setup-reset-btn').addEventListener('click', resetWallet);

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────

(async () => {
  try {
    const vaultExists = await hasVault();

    if (!vaultExists) {
      // First-time setup
      showView('setup-password');
      return;
    }

    // Vault exists — try to restore the decrypted session (popup re-opened
    // within the same browser session without the browser being closed).
    let restored = false;
    try {
      restored = await restoreFromSession();
    } catch (err) {
      console.warn('[boot] restoreFromSession error (non-fatal):', err);
    }

    if (restored) {
      // Auto-lock: if the popup was closed for >= LOCK_TIMEOUT_MS, discard
      // the session and require the password again.
      const lastClosedAt = parseInt(localStorage.getItem('lastClosedAt') || '0', 10);
      if (lastClosedAt && Date.now() - lastClosedAt >= LOCK_TIMEOUT_MS) {
        await chrome.storage.session.clear();
        showView('unlock');
        return;
      }

      state.wallet  = getActiveWallet();
      state.network = state.network || 'devnet';
      try {
        await connectXRPL();
      } catch (err) {
        console.warn('[boot] XRPL connect failed, will retry on demand:', err);
      }
      updateWalletUI();
      showView('wallet');
      refreshBalance();
      loadIouBalances();
      loadMptBalances();
      loadTxHistory();
      await initWalletConnect();
      await checkPendingWcEvent();
      startAutoRefresh();
      return;
    }

    // Vault exists but session expired → ask for password
    showView('unlock');

  } catch (err) {
    // Last-resort fallback: something went very wrong — show unlock if vault
    // exists so the user isn't stuck, otherwise fall through to setup.
    console.error('[boot] unexpected error:', err);
    try {
      const vaultExists = await hasVault();
      if (vaultExists) {
        showView('unlock');
      } else {
        showView('setup-password');
      }
    } catch {
      showView('setup-password');
    }
  }
})();

// Record the time the popup was closed so the boot sequence can enforce the
// auto-lock timeout on the next open.  localStorage is used here because it
// writes synchronously — chrome.storage.local.set() is async and the promise
// never resolves before the popup page is destroyed on close.
window.addEventListener('unload', () => {
  localStorage.setItem('lastClosedAt', Date.now());
});

// Show "reset" affordance on the setup-password view only when a vault already
// exists (e.g. user forgot password and session expired).
hasVault().then(exists => {
  if (exists) $('setup-reset-wrap').style.display = '';
}).catch(() => {});
