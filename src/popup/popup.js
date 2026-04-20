import './popup.css';
import { Client, Wallet, dropsToXrp, xrpToDrops, encodeAccountID, decodeMPTokenMetadata, isValidClassicAddress } from 'xrpl';
import xrplPkg from 'xrpl/package.json';
import QRCode from 'qrcode';
import { getSdkError } from '@walletconnect/utils';
import { generateMnemonic, validateMnemonic } from 'bip39';
import TransportWebHID from '@ledgerhq/hw-transport-webhid';
import Xrp from '@ledgerhq/hw-app-xrp';
import { encode } from 'ripple-binary-codec';
import { createHash } from 'crypto';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────

const WC_PROJECT_ID = '545f3b40384efe9b93401c1dd8d0ceb0';

const NETWORK_SERVERS = {
  // ── Devnet ──────────────────────────────────
  'devnet': {
    name: 'Ripple Devnet', group: 'devnet',
    wsUrl:           'wss://s.devnet.rippletest.net:51233',
    explorer:        'https://devnet.xrpl.org/transactions/',
    explorerAccount: 'https://devnet.xrpl.org/accounts/',
    explorerToken:   'https://devnet.xrpl.org/token/',
    explorerMpt:     'https://devnet.xrpl.org/mpt/',
    faucet:          'https://faucet.devnet.rippletest.net/accounts',
  },
  // ── Testnet ──────────────────────────────────
  'testnet': {
    name: 'Ripple Testnet', group: 'testnet',
    wsUrl:           'wss://s.altnet.rippletest.net:51233',
    explorer:        'https://testnet.xrpl.org/transactions/',
    explorerAccount: 'https://testnet.xrpl.org/accounts/',
    explorerToken:   'https://testnet.xrpl.org/token/',
    explorerMpt:     'https://testnet.xrpl.org/mpt/',
    faucet:          'https://faucet.altnet.rippletest.net/accounts',
  },
  'testnet-xrplf': {
    name: 'XRPL Foundation Testnet', group: 'testnet',
    wsUrl:           'wss://testnet.xrpl-labs.com',
    explorer:        'https://testnet.xrpl.org/transactions/',
    explorerAccount: 'https://testnet.xrpl.org/accounts/',
    explorerToken:   'https://testnet.xrpl.org/token/',
    explorerMpt:     'https://testnet.xrpl.org/mpt/',
    faucet:          null,
  },
  // ── Mainnet ──────────────────────────────────
  'mainnet-s1': {
    name: 'Ripple Mainnet (s1)', group: 'mainnet',
    wsUrl:           'wss://s1.ripple.com',
    explorer:        'https://livenet.xrpl.org/transactions/',
    explorerAccount: 'https://livenet.xrpl.org/accounts/',
    explorerToken:   'https://livenet.xrpl.org/token/',
    explorerMpt:     'https://livenet.xrpl.org/mpt/',
    faucet:          null,
  },
  'mainnet-s2': {
    name: 'Ripple Mainnet (s2)', group: 'mainnet',
    wsUrl:           'wss://s2.ripple.com',
    explorer:        'https://livenet.xrpl.org/transactions/',
    explorerAccount: 'https://livenet.xrpl.org/accounts/',
    explorerToken:   'https://livenet.xrpl.org/token/',
    explorerMpt:     'https://livenet.xrpl.org/mpt/',
    faucet:          null,
  },
  'mainnet-xrplf': {
    name: 'XRPL Foundation Mainnet', group: 'mainnet',
    wsUrl:           'wss://xrplcluster.com',
    explorer:        'https://livenet.xrpl.org/transactions/',
    explorerAccount: 'https://livenet.xrpl.org/accounts/',
    explorerToken:   'https://livenet.xrpl.org/token/',
    explorerMpt:     'https://livenet.xrpl.org/mpt/',
    faucet:          null,
  },
};

/** Return the active network config, constructing it for manual connections. */
function getNetworkConfig() {
  if (state.network === 'manual') {
    const { wsUrl = '' } = state.manualNetwork ?? {};
    const b = wsUrl ? `https://custom.xrpl.org/${wsUrl}` : '';
    return {
      name: 'Custom', group: 'custom',
      wsUrl,
      explorer:        b ? `${b}/transactions/` : '',
      explorerAccount: b ? `${b}/accounts/`     : '',
      explorerToken:   b ? `${b}/token/`        : '',
      explorerMpt:     b ? `${b}/mpt/`          : '',
      faucet:          null,
    };
  }
  return NETWORK_SERVERS[state.network] ?? NETWORK_SERVERS['devnet'];
}

const XRPL_EPOCH_OFFSET = 946684800;
const AUTO_REFRESH_INTERVAL = 30_000;

// PBKDF2 parameters — matching MetaMask's browser-passworder
const PBKDF2_ITERATIONS = 600_000;
const LOCK_TIMEOUT_MS   = 10_000; // default; overridden by devSettings.lockTimeoutSecs
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
  manualNetwork: { wsUrl: '' },
  mainnetAcknowledged: false,
  pendingNetworkChange: null,
  /** @type {any|null} Serialised pending proposal stored by background */
  pendingProposal: null,
  /** @type {any|null} Serialised pending request stored by background */
  pendingRequest: null,
  /** @type {ReturnType<typeof setInterval>|null} */
  refreshTimer: null,

  // Multi-account
  keyrings: [],        // array of decrypted keyring objects
  activeAccount: null, // active r-address

  // Projects — groupings of accounts + per-project address books
  projects: [],          // [{ id, name, accounts: [addr, ...] }]
  activeProjectId: null, // string

  // Temp during setup/add flows
  flowContext: 'setup',    // 'setup' | 'add'
  pendingMnemonic: null,   // mnemonic being confirmed
  mnemonicWordCount: 12,   // 12 or 24

  // Password held in-memory during the setup flow so saveVault() can use it
  // without depending on chrome.storage.session being set first.
  _setupFlowPassword: null,

  // Address queued for removal, set before navigating to confirm view.
  pendingRemoveAddress: null,
  pendingProjectRemoveIsDelete: false, // true = account only in this project → full wallet deletion

  // Contact being edited in the address book; null when adding a new contact.
  pendingEditContact: null,

  // Asset selected for sending; set before navigating to send-payment view.
  // { type: 'xrp'|'iou'|'mpt', displayName, balance, currency?, issuer?, mptIssuanceId?, assetScale? }
  pendingSend: null,

  // Generic tx review; set before navigating to send-review view for non-payment txs.
  // { txJson, backView, successMsg }
  pendingTxReview: null,

  // Developer settings persisted to chrome.storage.local
  devSettings: { printTxJson: false, lockTimeoutSecs: 10 },

  // Vaults fetched on the vault-deposit screen, keyed by VaultID
  fetchedVaults: new Map(),

  // Cache of address → display name built from wallet accounts + address book
  addressNames: new Map(),
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
  // Populate raw JSON panel on review screen
  if (name === 'send-review' && state.pendingTxReview?.txJson) {
    $('review-raw-json').textContent = JSON.stringify(state.pendingTxReview.txJson, null, 2);
    $('review-json-details').removeAttribute('open');
  }
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

/** Rebuild the address → name lookup from wallet accounts and address book. */
async function refreshAddressNames() {
  const map = new Map();
  for (const acct of getAllAccounts()) {
    if (acct.label) map.set(acct.address, acct.label);
  }
  const contacts = await loadAddressBook();
  for (const c of contacts) {
    if (c.name && c.address) map.set(c.address, c.name);
  }
  state.addressNames = map;
}

/** Return a human-readable label for an address, falling back to truncAddr. */
function resolveAddrDisplay(addr) {
  if (!addr) return addr;
  return state.addressNames.get(addr) ?? truncAddr(addr);
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
  const { keyrings, activeAccount, vaultPassword } =
    await chrome.storage.session.get(['keyrings', 'activeAccount', 'vaultPassword']);
  if (!keyrings || !activeAccount || !vaultPassword) return false;
  state.keyrings      = keyrings;
  state.activeAccount = activeAccount;
  // Network is NOT restored from session — loadDevSettings() already loaded it
  // from chrome.storage.local (the authoritative source).  The session copy can
  // be stale because applyNetworkChange() only writes to local storage.
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
    } else if (kr.type === 'ledger' && kr.address === state.activeAccount) {
      return null; // no local private key for hardware wallets
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
    } else if (kr.type === 'ledger') {
      out.push({ label: kr.label, address: kr.address, keyringIndex: ki, accountIndex: null, isLedger: true });
    }
  }
  return out;
}

// ─────────────────────────────────────────────
// PROJECTS
// ─────────────────────────────────────────────

function getActiveProject() {
  return state.projects.find(p => p.id === state.activeProjectId) ?? state.projects[0] ?? null;
}

/** Accounts visible in the current project (subset of all keyrings). */
function getProjectAccounts() {
  const proj = getActiveProject();
  if (!proj) return getAllAccounts();
  const set = new Set(proj.accounts);
  return getAllAccounts().filter(a => set.has(a.address));
}

async function loadProjects() {
  const { projects, activeProjectId } = await chrome.storage.local.get(['projects', 'activeProjectId']);
  state.projects       = projects       ?? [];
  state.activeProjectId = activeProjectId ?? null;
}

async function saveProjects() {
  await chrome.storage.local.set({ projects: state.projects, activeProjectId: state.activeProjectId });
}

/**
 * On first run after adding projects feature: create a Default project
 * containing all existing accounts and migrate any existing address book.
 */
async function ensureProjectsInitialized() {
  if (state.projects.length === 0) {
    const allAddrs = getAllAccounts().map(a => a.address);
    state.projects       = [{ id: 'default', name: 'Default', accounts: allAddrs }];
    state.activeProjectId = 'default';
    // Migrate global addressBook → project-scoped key
    const { addressBook } = await chrome.storage.local.get('addressBook');
    if (Array.isArray(addressBook) && addressBook.length) {
      await chrome.storage.local.set({ addressBook_default: addressBook });
    }
    await saveProjects();
  } else if (!state.activeProjectId || !state.projects.find(p => p.id === state.activeProjectId)) {
    state.activeProjectId = state.projects[0]?.id ?? null;
    await saveProjects();
  }
}

function addAccountToActiveProject(address) {
  const proj = getActiveProject();
  if (proj && !proj.accounts.includes(address)) {
    proj.accounts.push(address);
  }
}

async function switchProject(projectId) {
  state.activeProjectId = projectId;
  const proj = state.projects.find(p => p.id === projectId);
  if (proj && proj.accounts.length > 0 && !proj.accounts.includes(state.activeAccount)) {
    await activateAccount(proj.accounts[0]);
  } else {
    renderProjectSwitcher();
    updateWalletUI();
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadCredentials();
    loadTxHistory();
  }
  await saveProjects();
}

function renderProjectSwitcher() {
  const proj = getActiveProject();
  $('project-name-label').textContent = proj?.name ?? 'Default';
  const listEl = $('project-list');
  listEl.innerHTML = state.projects.map(p => `
    <button class="project-list-item ${p.id === state.activeProjectId ? 'active-project' : ''}"
            data-project-id="${esc(p.id)}">
      <span class="proj-item-name">${esc(p.name)}</span>
      ${p.id === state.activeProjectId ? '<span class="proj-item-check">✓</span>' : ''}
    </button>`).join('');
  listEl.querySelectorAll('.project-list-item').forEach(btn => {
    btn.addEventListener('click', async () => {
      $('project-dropdown').classList.add('hidden');
      const pid = btn.dataset.projectId;
      if (pid !== state.activeProjectId) await switchProject(pid);
    });
  });
}

function openNewProject() {
  $('new-project-name').value = '';
  hideAlert('new-project-error');
  showView('new-project');
}

async function createProject() {
  const name = $('new-project-name').value.trim();
  if (!name) { showAlert('new-project-error', 'Enter a project name.'); return; }
  if (state.projects.some(p => p.name.toLowerCase() === name.toLowerCase())) {
    showAlert('new-project-error', 'A project with that name already exists.');
    return;
  }
  const id = `proj_${Date.now()}`;
  state.projects.push({ id, name, accounts: [] });
  state.activeProjectId = id;
  await saveProjects();
  renderProjectSwitcher();
  updateWalletUI();
  showView('wallet');
}

function openProjectFromAccounts() {
  const currentProj = getActiveProject();
  const currentSet  = new Set(currentProj?.accounts ?? []);
  const allAccts    = getAllAccounts();

  const otherProjects = state.projects.filter(p => p.id !== state.activeProjectId);
  const listEl = $('project-from-list');
  listEl.innerHTML = '';

  // Build list of accounts from other projects not already in this project
  const rows = [];
  for (const proj of otherProjects) {
    for (const addr of proj.accounts) {
      if (!currentSet.has(addr)) {
        const acct = allAccts.find(a => a.address === addr);
        if (acct) rows.push({ proj, acct });
      }
    }
  }

  if (rows.length === 0) {
    listEl.innerHTML = '<p class="proj-from-empty">No other accounts available to add.</p>';
    showView('project-from-accounts');
    return;
  }

  // Group by project
  let lastProjId = null;
  for (const { proj, acct } of rows) {
    if (proj.id !== lastProjId) {
      const hdr = document.createElement('div');
      hdr.className = 'proj-from-header';
      hdr.textContent = proj.name;
      listEl.appendChild(hdr);
      lastProjId = proj.id;
    }
    const btn = document.createElement('button');
    btn.className = 'account-list-item';
    btn.innerHTML = `
      <div class="acct-item-left">
        <span class="acct-item-label">${esc(acct.label)}</span>
        <span class="acct-item-addr">${esc(truncAddr(acct.address))}</span>
      </div>`;
    btn.addEventListener('click', async () => {
      addAccountToActiveProject(acct.address);
      await saveProjects();
      await activateAccount(acct.address);
      showView('wallet');
    });
    listEl.appendChild(btn);
  }

  showView('project-from-accounts');
}

/** Return the ledger keyring for the active account, or null. */
function getActiveLedgerKeyring() {
  if (!state.activeAccount) return null;
  return state.keyrings.find(kr => kr.type === 'ledger' && kr.address === state.activeAccount) ?? null;
}

/** Compute XRPL transaction hash from a signed tx blob (hex). SHA-512 half with 0x54584E00 prefix. */
function computeTxHash(txBlobHex) {
  const prefix  = Buffer.from('54584E00', 'hex');
  const txBytes = Buffer.from(txBlobHex, 'hex');
  return createHash('sha512').update(Buffer.concat([prefix, txBytes])).digest('hex').slice(0, 64).toUpperCase();
}

/**
 * Sign a prepared (autofilled) transaction.
 * Uses the Ledger device if the active account is a hardware wallet,
 * otherwise uses the local software wallet.
 */
async function signPreparedTx(prepared) {
  const ledgerKr = getActiveLedgerKeyring();
  if (!ledgerKr) {
    return state.wallet.sign(prepared);
  }
  setTxStatus('pending', 'Confirm on Ledger device…');
  const txToSign = { ...prepared, SigningPubKey: ledgerKr.publicKey };
  delete txToSign.TxnSignature;
  const txBlob = encode(txToSign);
  let transport;
  try {
    transport = await TransportWebHID.create();
    const xrpApp  = new Xrp(transport);
    const sig     = await xrpApp.signTransaction(ledgerKr.derivationPath, txBlob);
    txToSign.TxnSignature = sig.toUpperCase();
    const tx_blob = encode(txToSign);
    return { tx_blob, hash: computeTxHash(tx_blob) };
  } finally {
    if (transport) await transport.close().catch(() => {});
  }
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
    if (kr.type === 'ledger' && kr.address === address) {
      return { keyringsIdx: ki, type: 'ledger', label: kr.label, phraseToo: false, siblings: 0 };
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

  if (info.type === 'simple' || info.type === 'ledger') {
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

  // Remove address from all projects
  for (const proj of state.projects) {
    proj.accounts = proj.accounts.filter(a => a !== address);
  }
  await saveProjects();

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

/** Render the manage-accounts list — shows only accounts in the current project. */
function renderManageAccountsList() {
  const proj     = getActiveProject();
  const accounts = getProjectAccounts();
  const list     = $('manage-accounts-list');
  list.innerHTML = '';

  $('manage-accounts-project-name').textContent = proj?.name ?? 'Default';

  if (accounts.length === 0) {
    list.innerHTML = '<p class="proj-from-empty">No accounts in this project.</p>';
    return;
  }

  accounts.forEach(acct => {
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
      openProjectRemoveConfirm(acct.address);
    });
    list.appendChild(item);
  });
}

/** Open the remove-confirm view with project-aware messaging. */
function openProjectRemoveConfirm(address) {
  const acct = getAllAccounts().find(a => a.address === address);
  const info = getRemovalInfo(address);
  const proj = getActiveProject();

  // Is this account referenced in any other project?
  const inOtherProject = state.projects.some(
    p => p.id !== state.activeProjectId && p.accounts.includes(address)
  );

  state.pendingRemoveAddress      = address;
  state.pendingProjectRemoveIsDelete = !inOtherProject;

  $('remove-acct-name').textContent = acct?.label || 'Account';
  $('remove-acct-addr').textContent = truncAddr(address);
  $('remove-acct-title').textContent = inOtherProject ? 'Remove from Project' : 'Remove Account';

  let warn;
  if (inOtherProject) {
    warn = `This will remove the account from the "${proj?.name ?? 'current'}" project. It will remain accessible in other projects.`;
  } else if (info?.type === 'ledger') {
    warn = 'This account is not in any other project. Removing it will permanently delete it from this wallet. Your Ledger device and funds are not affected.';
  } else if (info?.type === 'simple') {
    warn = 'This account is not in any other project. Removing it will permanently delete the account and its secret seed from this wallet. This cannot be undone.';
  } else if (info?.phraseToo) {
    warn = 'This account is not in any other project. This is the only account using its recovery phrase — removing it will also permanently delete the recovery phrase. This cannot be undone.';
  } else {
    warn = `This account is not in any other project. Removing it will delete it from this wallet. The recovery phrase and ${info?.siblings} other account(s) derived from it will remain.`;
  }
  $('remove-acct-warning').textContent = warn;

  // Show or hide the deletion checkbox
  const needsCheck = !inOtherProject;
  const checkRow = $('remove-acct-delete-check-row');
  checkRow.classList.toggle('hidden', !needsCheck);
  $('remove-acct-delete-checkbox').checked = false;
  const confirmBtn = $('remove-acct-confirm-btn');
  confirmBtn.textContent = inOtherProject ? 'Remove from Project' : 'Delete Account';
  confirmBtn.disabled = needsCheck; // disabled until checkbox is ticked

  showView('remove-account-confirm');
}

/** Execute the pending project-remove action. */
async function executeProjectRemove() {
  const address  = state.pendingRemoveAddress;
  const isDelete = state.pendingProjectRemoveIsDelete;
  state.pendingRemoveAddress         = null;
  state.pendingProjectRemoveIsDelete = false;
  if (!address) return;

  if (!isDelete) {
    // Just remove from current project — keep keyring and other projects intact.
    const proj = getActiveProject();
    if (proj) {
      proj.accounts = proj.accounts.filter(a => a !== address);
      await saveProjects();
    }
    // If active account was the removed one, switch to another in the project.
    if (state.activeAccount === address) {
      const remaining = getProjectAccounts();
      const next = remaining.find(a => a.address !== address);
      if (next) {
        await activateAccount(next.address);
      } else {
        // No accounts left in project — fall through to manage list.
        state.activeAccount = getAllAccounts()[0]?.address ?? null;
        state.wallet = getActiveWallet();
      }
    }
    updateWalletUI();
    renderManageAccountsList();
    showView('manage-accounts');
    return;
  }

  // Full deletion path — same as the original executeRemoveAccount.
  const info = getRemovalInfo(address);
  if (!info) return;

  if (info.type === 'simple' || info.type === 'ledger') {
    state.keyrings.splice(info.keyringsIdx, 1);
  } else {
    const kr = state.keyrings[info.keyringsIdx];
    kr.accounts.splice(info.accountsIdx, 1);
    if (kr.accounts.length === 0) state.keyrings.splice(info.keyringsIdx, 1);
  }

  if (state.activeAccount === address) {
    const remaining = getAllAccounts();
    state.activeAccount = remaining[0]?.address ?? null;
    state.wallet = getActiveWallet();
  }

  // Remove from all projects.
  for (const proj of state.projects) {
    proj.accounts = proj.accounts.filter(a => a !== address);
  }
  await saveProjects();

  await saveVault();
  const { vaultPassword } = await chrome.storage.session.get('vaultPassword');
  if (vaultPassword) await persistSession(vaultPassword);

  const remaining = getAllAccounts();
  if (remaining.length === 0) {
    state.flowContext = 'add';
    showView('account-type');
  } else {
    updateWalletUI();
    renderManageAccountsList();
    showView('manage-accounts');
  }
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
  refreshAddressNames();
  updateWalletUI();
  refreshBalance();
  loadIouBalances();
  loadMptBalances();
  loadCredentials();
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

    // Register the new account with the active project (init project first if needed)
    await ensureProjectsInitialized();
    addAccountToActiveProject(state.activeAccount);
    await saveProjects();

    state.wallet = getActiveWallet();

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    refreshAddressNames();
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadCredentials();
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
    state.network = state.network || 'devnet';
    await ensureProjectsInitialized();

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    refreshAddressNames();
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadCredentials();
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
// ADDRESS BOOK
// ─────────────────────────────────────────────

async function loadAddressBook() {
  const key  = `addressBook_${state.activeProjectId ?? 'default'}`;
  const data = await chrome.storage.local.get(key);
  return data[key] ?? [];
}

async function saveAddressBook(entries) {
  const key = `addressBook_${state.activeProjectId ?? 'default'}`;
  await chrome.storage.local.set({ [key]: entries });
}

async function renderAddressBook() {
  const contacts = await loadAddressBook();
  const list = $('address-book-list');
  list.innerHTML = '';

  if (contacts.length === 0) {
    list.innerHTML = '<p class="type-hint" style="text-align:center;margin-top:16px">No contacts yet.</p>';
    return;
  }

  contacts.forEach(contact => {
    const item = document.createElement('div');
    item.className = 'ab-item';
    item.innerHTML = `
      <div class="ab-info">
        <div class="ab-name">${esc(contact.name)}</div>
        <div class="ab-addr">${truncAddr(contact.address)}</div>
        ${contact.tag != null ? `<div class="ab-tag">Tag: ${esc(String(contact.tag))}</div>` : ''}
      </div>
      <div class="ab-actions">
        <button class="btn-icon ab-copy-btn" title="Copy address" data-address="${esc(contact.address)}">⧉</button>
        <button class="btn-icon ab-edit-btn" title="Edit" data-id="${contact.id}">✎</button>
        <button class="btn-icon ab-delete-btn" title="Delete" data-id="${contact.id}">✕</button>
      </div>
    `;

    item.querySelector('.ab-copy-btn').addEventListener('click', async e => {
      try {
        await navigator.clipboard.writeText(e.currentTarget.dataset.address);
        e.currentTarget.textContent = '✓';
        setTimeout(() => { e.currentTarget.textContent = '⧉'; }, 1500);
      } catch { /* clipboard permission denied */ }
    });

    item.querySelector('.ab-edit-btn').addEventListener('click', async () => {
      const all = await loadAddressBook();
      state.pendingEditContact = all.find(c => c.id === contact.id) ?? null;
      openAddressBookEdit();
    });

    item.querySelector('.ab-delete-btn').addEventListener('click', async () => {
      if (!confirm(`Remove "${contact.name}" from your address book?`)) return;
      const all = await loadAddressBook();
      await saveAddressBook(all.filter(c => c.id !== contact.id));
      refreshAddressNames();
      await renderAddressBook();
    });

    list.appendChild(item);
  });
}

function openAddressBookEdit() {
  const c = state.pendingEditContact;
  $('address-book-edit-title').textContent = c ? 'Edit Contact' : 'Add Contact';
  $('contact-name').value    = c?.name    ?? '';
  $('contact-address').value = c?.address ?? '';
  $('contact-tag').value     = c?.tag != null ? String(c.tag) : '';
  hideAlert('contact-error');
  showView('address-book-edit');
}

async function saveContact() {
  hideAlert('contact-error');

  const name    = $('contact-name').value.trim();
  const address = $('contact-address').value.trim();
  const rawTag  = $('contact-tag').value.trim();

  if (!name)    { showAlert('contact-error', 'Name is required.'); return; }
  if (!address) { showAlert('contact-error', 'Address is required.'); return; }
  if (!isValidClassicAddress(address)) {
    showAlert('contact-error', 'Invalid XRPL address — must start with r and be 25–34 characters.');
    return;
  }

  let tag = null;
  if (rawTag !== '') {
    const n = parseInt(rawTag, 10);
    if (!Number.isInteger(n) || n < 0 || n > 4_294_967_295) {
      showAlert('contact-error', 'Destination tag must be a whole number between 0 and 4294967295.');
      return;
    }
    tag = n;
  }

  const all = await loadAddressBook();

  if (state.pendingEditContact) {
    const idx = all.findIndex(c => c.id === state.pendingEditContact.id);
    if (idx !== -1) all[idx] = { ...all[idx], name, address, tag };
  } else {
    all.push({ id: Date.now(), name, address, tag });
  }

  await saveAddressBook(all);
  refreshAddressNames();
  state.pendingEditContact = null;
  await renderAddressBook();
  showView('address-book');
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

  const net = getNetworkConfig();
  $('account-explorer-link').href = `${net.explorerAccount}${addr}`;

  const badge = $('network-badge');
  badge.textContent = net.name;
  badge.className = `network-badge ${net.group}`;

  $('faucet-btn').classList.toggle('hidden', !net.faucet);

  // Project switcher
  renderProjectSwitcher();

  // Account switcher pill
  const accounts = getAllAccounts();
  const active   = accounts.find(a => a.address === addr);
  $('switcher-label').textContent = active?.label ?? 'Account';
  $('switcher-addr').textContent  = truncAddr(addr);

  renderAccountDropdown(accounts, addr);
}

function renderAccountDropdown(accounts, activeAddr) {
  // Only show accounts belonging to the active project
  const projAccts = getProjectAccounts();
  const activeSet = new Set(projAccts.map(a => a.address));

  const listEl = $('account-list');
  listEl.innerHTML = projAccts.map(a => `
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

  // Show "from another project" only if other projects have accounts not in this project
  const currentSet = new Set(getActiveProject()?.accounts ?? []);
  const hasOthers  = state.projects.some(p =>
    p.id !== state.activeProjectId && p.accounts.some(a => !currentSet.has(a))
  );
  $('add-from-project-btn').classList.toggle('hidden', !hasOthers);
}

// Toggle the account dropdown
$('account-switcher-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('account-dropdown').classList.toggle('hidden');
});

// Close dropdowns on outside click
document.addEventListener('click', () => {
  $('account-dropdown')?.classList.add('hidden');
  $('project-dropdown')?.classList.add('hidden');
});

$('account-dropdown').addEventListener('click', e => e.stopPropagation());

$('add-account-dropdown-btn').addEventListener('click', () => {
  $('account-dropdown').classList.add('hidden');
  goToAddAccount();
});

$('add-from-project-btn').addEventListener('click', () => {
  $('account-dropdown').classList.add('hidden');
  openProjectFromAccounts();
});

// Project switcher
$('project-switcher-btn').addEventListener('click', (e) => {
  e.stopPropagation();
  $('account-dropdown').classList.add('hidden');
  $('project-dropdown').classList.toggle('hidden');
});
$('project-dropdown').addEventListener('click', e => e.stopPropagation());
$('new-project-dropdown-btn').addEventListener('click', () => {
  $('project-dropdown').classList.add('hidden');
  openNewProject();
});

// New project view
$('create-project-btn').addEventListener('click', createProject);
$('new-project-name').addEventListener('keypress', e => { if (e.key === 'Enter') createProject(); });
$('back-from-new-project-btn').addEventListener('click', () => showView('wallet'));

// Project-from-accounts view
$('back-from-project-from-btn').addEventListener('click', () => showView('wallet'));

// ─────────────────────────────────────────────
// WALLET — XRPL CLIENT
// ─────────────────────────────────────────────

function updateConnectionDot(status) {
  const dot = $('xrpl-connection-dot');
  if (!dot) return;
  dot.className = `connection-dot dot-${status}`;
  const netName = getNetworkConfig().name;
  const labels = {
    connected:    `Connected to ${netName}`,
    connecting:   `Connecting to ${netName}…`,
    disconnected: `Disconnected from ${netName}`,
  };
  dot.title = labels[status] ?? status;
}

async function connectXRPL() {
  updateConnectionDot('connecting');
  if (state.client?.isConnected()) {
    state.client.disconnect().catch(() => {});
  }
  const { wsUrl } = getNetworkConfig();
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
  if (!state.activeAccount || !state.client) return;
  $('balance-amount').textContent = '…';
  try {
    await ensureConnected();
    const xrp = await state.client.getXrpBalance(state.activeAccount);
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
  if (!state.activeAccount || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_lines',
      account: state.activeAccount,
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
  const listEl = $('iou-balance-list');

  if (!lines.length) { listEl.innerHTML = ''; return; }
  const explorerToken = getNetworkConfig().explorerToken;
  listEl.innerHTML = lines.map(line => {
    const code    = formatCurrencyCode(line.currency);
    const balance = parseFloat(line.balance).toLocaleString(undefined, { maximumFractionDigits: 6 });
    const href    = `${explorerToken}${encodeURIComponent(line.currency)}.${line.account}`;
    return `
      <div class="iou-balance-item"
           data-send-type="iou"
           data-currency="${esc(line.currency)}"
           data-issuer="${esc(line.account)}"
           data-balance="${esc(balance)}"
           data-display="${esc(code)}">
        <div class="iou-token-info">
          <span class="iou-currency">${esc(code)}</span>
          <span class="iou-issuer" title="${esc(line.account)}">${esc(resolveAddrDisplay(line.account))}</span>
        </div>
        <div class="iou-balance-amount">${esc(balance)}</div>
        <a class="token-explorer-link" href="${esc(href)}" target="_blank" rel="noreferrer" title="View on explorer">↗</a>
      </div>`;
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

  card.classList.remove('hidden');
  if (!held.length) { listEl.innerHTML = ''; return; }

  const explorerAccount = getNetworkConfig().explorerAccount;
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
      <div class="amm-balance-item"
           data-send-type="amm"
           data-display="${esc(pool)}"
           data-balance="${esc(lpBal)}"
           data-currency="${esc(line.currency)}"
           data-issuer="${esc(line.account)}"
           data-asset1="${encodeURIComponent(JSON.stringify(ammInfo.amount))}"
           data-asset2="${encodeURIComponent(JSON.stringify(ammInfo.amount2))}"
           data-label1="${esc(label1)}"
           data-label2="${esc(label2)}">
        <div class="amm-summary-row">
          <div class="amm-token-info">
            <span class="amm-pool">${esc(pool)}</span>
            <span class="amm-issuer" title="${esc(line.account)}">${esc(resolveAddrDisplay(line.account))}</span>
          </div>
          <div class="amm-balance-amount">${esc(lpBal)} LP</div>
          <a class="token-explorer-link" href="${esc(href)}" target="_blank" rel="noreferrer" title="View on explorer">↗</a>
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
      </div>`;
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
        const issuerObjects = allObjs.result.account_objects ?? [];

        // Check for direct Vault objects on the issuer's account whose
        // ShareMPTID matches this issuance.
        const directVault = issuerObjects
          .find(o => o.LedgerEntryType === 'Vault' && o.ShareMPTID === issuanceId);
        if (directVault) {
          vaultInfo = { ...directVault, vaultId: directVault.index };
        } else {
          // Fallback: LoanBroker objects that carry a VaultID pointer.
          const loanBrokers = issuerObjects
            .filter(o => o.LedgerEntryType === 'LoanBroker' && o.VaultID);
          for (const lb of loanBrokers) {
            const vaultResp = await state.client.request({
              command: 'ledger_entry',
              index: lb.VaultID,
              ledger_index: 'validated',
            });
            const vault = vaultResp.result.node;
            if (vault.ShareMPTID === issuanceId) {
              vaultInfo = { ...vault, vaultId: lb.VaultID };
              break;
            }
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
  if (!state.activeAccount || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: state.activeAccount,
      ledger_index: 'validated',
    });
    const allObjects = resp.result.account_objects ?? [];
    const objects = allObjects.filter(o => o.LedgerEntryType === 'MPToken');

    // Build a lookup of ShareMPTID → Vault for vaults owned by this account.
    // This handles the case where the vault owner also holds the share tokens
    // and the issuer's account has no LoanBroker objects to link them.
    const vaultByShareMPT = new Map(
      allObjects
        .filter(o => o.LedgerEntryType === 'Vault' && o.ShareMPTID)
        .map(o => [o.ShareMPTID, { ...o, vaultId: o.index }])
    );

    const infos = await Promise.all(objects.map(async o => {
      const info = await fetchMptIssuanceInfo(o.MPTokenIssuanceID);
      // If the issuer-side lookup found no vault link, check if this account
      // owns a Vault whose ShareMPTID matches.
      if (!info.vaultInfo) {
        const ownedVault = vaultByShareMPT.get(o.MPTokenIssuanceID);
        if (ownedVault) info.vaultInfo = ownedVault;
      }
      return info;
    }));
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

// ─── Credentials ────────────────────────────────────────────────────────────

const LSF_ACCEPTED = 0x00010000;

function hexToUtf8(hex) {
  try {
    return Buffer.from(hex, 'hex').toString('utf8');
  } catch { return hex; }
}

async function loadCredentials() {
  if (!state.activeAccount || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: state.activeAccount,
      ledger_index: 'validated',
    });
    const creds = (resp.result.account_objects ?? [])
      .filter(o => o.LedgerEntryType === 'Credential');
    renderCredentials(creds);
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      renderCredentials([]);
    } else {
      console.error('[credentials]', err);
    }
  }
}

function renderCredentials(creds) {
  const card   = $('credential-card');
  const listEl = $('credential-list');

  if (!creds.length) {
    card.classList.add('hidden');
    listEl.innerHTML = '';
    return;
  }

  card.classList.remove('hidden');
  listEl.innerHTML = creds.map((c, i) => {
    const typeHex    = c.CredentialType ?? '';
    const typeLabel  = hexToUtf8(typeHex) || typeHex.slice(0, 16);
    const issuer     = c.Issuer ?? '';
    const accepted   = !!(c.Flags & LSF_ACCEPTED);
    const statusLabel = accepted ? 'Accepted' : 'Pending';
    const statusClass = accepted ? 'cred-status-accepted' : 'cred-status-pending';
    return `
      <div class="credential-item" data-cred-index="${i}">
        <div class="cred-info">
          <span class="cred-type">${esc(typeLabel)}</span>
          <span class="cred-issuer" title="${esc(issuer)}">${esc(resolveAddrDisplay(issuer))}</span>
        </div>
        <span class="cred-status ${statusClass}">${statusLabel}</span>
      </div>`;
  }).join('');

  // Store credentials on the element for click access
  listEl._credentials = creds;
}

function openCredentialDetail(cred) {
  const typeHex   = cred.CredentialType ?? '';
  const typeLabel = hexToUtf8(typeHex) || typeHex.slice(0, 16);
  const issuer    = cred.Issuer ?? '';
  const accepted  = !!(cred.Flags & LSF_ACCEPTED);
  const uriHex    = cred.URI ?? '';
  const expiration = cred.Expiration;

  $('cred-detail-type').textContent    = typeLabel;
  $('cred-detail-issuer').textContent  = resolveAddrDisplay(issuer);
  $('cred-detail-issuer').title        = issuer;
  $('cred-detail-status').textContent  = accepted ? 'Accepted' : 'Pending';
  $('cred-detail-status').className    = 'detail-value ' + (accepted ? 'cred-status-accepted' : 'cred-status-pending');

  if (uriHex) {
    const uriDecoded = hexToUtf8(uriHex);
    $('cred-detail-uri').textContent = uriDecoded;
    $('cred-detail-uri-row').classList.remove('hidden');
  } else {
    $('cred-detail-uri-row').classList.add('hidden');
  }

  if (expiration != null) {
    const dt = xrplDateToLocal(expiration);
    $('cred-detail-expiry').textContent = dt ? dt.toLocaleString() : String(expiration);
    $('cred-detail-expiry-row').classList.remove('hidden');
  } else {
    $('cred-detail-expiry-row').classList.add('hidden');
  }

  $('cred-detail-error').classList.add('hidden');

  const acceptBtn = $('cred-accept-btn');
  if (!accepted) {
    acceptBtn.classList.remove('hidden');
    acceptBtn.disabled = false;
    acceptBtn.onclick = () => acceptCredential(cred);
  } else {
    acceptBtn.classList.add('hidden');
  }

  showView('credential-detail');
}

function acceptCredential(cred) {
  const row = (label, value, cls = '') =>
    `<div class="tx-row"><span class="tx-label">${label}</span><span class="tx-value ${cls}">${value}</span></div>`;

  const typeLabel = hexToUtf8(cred.CredentialType ?? '') || (cred.CredentialType ?? '').slice(0, 16);
  const issuer    = cred.Issuer ?? '';

  const txJson = {
    TransactionType: 'CredentialAccept',
    Account: state.activeAccount,
    Issuer: issuer,
    CredentialType: cred.CredentialType,
  };

  $('send-review-details').innerHTML = [
    row('Type', 'CredentialAccept', 'tx-type'),
    row('Credential', esc(typeLabel)),
    row('Issuer', `<span title="${esc(issuer)}">${esc(resolveAddrDisplay(issuer))}</span>`, 'tx-address'),
  ].join('');

  $('review-title').textContent = 'Accept Credential';
  state.pendingTxReview = { txJson, backView: 'credential-detail', successMsg: 'Credential accepted!' };
  showView('send-review');
}

function renderMptBalances(objects, issuanceMap = new Map()) {
  const listEl = $('mpt-balance-list');
  const held   = objects.filter(o => o.LedgerEntryType === 'MPToken');

  if (!held.length) { listEl.innerHTML = ''; return; }
  const explorerMpt = getNetworkConfig().explorerMpt;
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
    const issuerDisplay = issuer ? resolveAddrDisplay(issuer) : (issuanceId.slice(8, 16) + '…');
    const href         = `${explorerMpt}${issuanceId}`;
    return `
      <div class="mpt-balance-item"
           data-send-type="mpt"
           data-mpt-id="${esc(issuanceId)}"
           data-asset-scale="${assetScale}"
           data-balance="${esc(amount)}"
           data-display="${esc(displayName)}">
        <div class="mpt-token-info">
          <span class="mpt-id" title="${esc(issuanceId)}">${esc(displayName)}</span>
          <span class="mpt-issuer" title="${esc(issuer ?? issuanceId)}">${esc(issuerDisplay)}</span>
        </div>
        <div class="mpt-balance-amount">${esc(amount)}</div>
        <a class="token-explorer-link" href="${esc(href)}" target="_blank" rel="noreferrer" title="View on explorer">↗</a>
      </div>`;
  }).join('');
}

function renderVaultBalances(objects, issuanceMap = new Map()) {
  const card   = $('vault-balance-card');
  const listEl = $('vault-balance-list');
  const held   = objects.filter(o => o.LedgerEntryType === 'MPToken');

  card.classList.remove('hidden');
  if (!held.length) { listEl.innerHTML = ''; return; }

  const explorerAccount = getNetworkConfig().explorerAccount;
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
    const issuerDisplay = issuer ? resolveAddrDisplay(issuer) : (issuanceId.slice(8, 16) + '…');
    const underlying    = vaultInfo?.Asset ? formatPoolAsset(vaultInfo.Asset) : '—';
    const fmtAmt        = (v) => (parseFloat(v ?? 0) * holderShare).toLocaleString(undefined, { maximumFractionDigits: 6 });
    const available     = vaultInfo?.AssetsAvailable != null ? fmtAmt(vaultInfo.AssetsAvailable) : null;
    const total         = vaultInfo?.AssetsTotal      != null ? fmtAmt(vaultInfo.AssetsTotal)     : null;
    const href          = `${explorerAccount}${issuer ?? ''}`;

    return `
      <div class="vault-balance-item"
           data-send-type="vault"
           data-display="${esc(vaultLabel)}"
           data-balance="${esc(shares)}"
           data-mpt-id="${esc(issuanceId)}"
           data-asset-scale="${assetScale}"
           data-vault-id="${esc(vaultInfo?.vaultId ?? '')}"
           data-vault-asset="${encodeURIComponent(JSON.stringify(vaultInfo?.Asset ?? null))}"
           data-underlying-label="${esc(underlying)}">
        <div class="amm-summary-row">
          <div class="amm-token-info">
            <span class="vault-name" title="${esc(issuanceId)}">${esc(vaultLabel)}</span>
            <span class="amm-issuer" title="${esc(issuer ?? issuanceId)}">${esc(issuerDisplay)}</span>
          </div>
          <div class="amm-balance-amount">${esc(shares)} shares</div>
          <a class="token-explorer-link" href="${esc(href)}" target="_blank" rel="noreferrer" title="View on explorer">↗</a>
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
      </div>`;
  }).join('');
}

// ─────────────────────────────────────────────
// SHARED ADDRESS PICKER HELPERS
// ─────────────────────────────────────────────

/** Populate a <select> with My Accounts (excl. active), Address Book, and a manual entry option. */
async function populateAddressPicker(selectEl) {
  selectEl.innerHTML = '';

  const myAccounts = getAllAccounts().filter(a => a.address !== state.activeAccount);
  if (myAccounts.length > 0) {
    const grp = document.createElement('optgroup');
    grp.label = 'My Accounts';
    for (const acct of myAccounts) {
      const opt = document.createElement('option');
      opt.value = `acct:${acct.address}`;
      opt.textContent = `${acct.label || 'Account'} — ${truncAddr(acct.address)}`;
      grp.appendChild(opt);
    }
    selectEl.appendChild(grp);
  }

  const contacts = await loadAddressBook();
  if (contacts.length > 0) {
    const grp = document.createElement('optgroup');
    grp.label = 'Address Book';
    for (const contact of contacts) {
      const opt = document.createElement('option');
      opt.value = `book:${contact.address}:${contact.tag ?? ''}`;
      opt.textContent = `${contact.name} — ${truncAddr(contact.address)}`;
      grp.appendChild(opt);
    }
    selectEl.appendChild(grp);
  }

  const manualOpt = document.createElement('option');
  manualOpt.value = '__manual__';
  manualOpt.textContent = 'Enter address manually…';
  selectEl.appendChild(manualOpt);

  if (myAccounts.length === 0 && contacts.length === 0) selectEl.value = '__manual__';
}

/** Show/hide the manual address input based on select value. Returns tag value if address-book entry. */
function handlePickerChange(selectEl, manualGroupEl, tagInputEl) {
  const val = selectEl.value;
  if (val === '__manual__') {
    manualGroupEl.classList.remove('hidden');
  } else {
    manualGroupEl.classList.add('hidden');
    if (tagInputEl) tagInputEl.value = val.startsWith('book:') ? (val.split(':')[2] || '') : '';
  }
}

/** Resolve the address from a picker select + manual input pair. */
function getPickerAddress(selectEl, manualInputEl) {
  const val = selectEl.value;
  if (val === '__manual__') return manualInputEl?.value.trim() ?? '';
  if (val.startsWith('acct:')) return val.slice(5);
  if (val.startsWith('book:')) return val.split(':')[1];
  return '';
}

// ─────────────────────────────────────────────
// SEND PAYMENT
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// VAULT DEPOSIT / WITHDRAW
// ─────────────────────────────────────────────

function openVaultDW() {
  const { pendingSend } = state;
  if (!pendingSend || pendingSend.type !== 'vault') return;
  $('vault-dw-section').classList.remove('hidden');
  $('amm-deposit-section').classList.add('hidden');
  $('vault-dw-shares').textContent = `${pendingSend.balance} shares`;
  $('vault-dw-amount').value = '';
  $('vault-dw-error').classList.add('hidden');
  switchVaultDWMode('deposit');
}

function switchVaultDWMode(mode) {
  const isDeposit = mode === 'deposit';
  if (state.pendingSend) {
    state.pendingSend.dwMode = mode;
    if (!isDeposit) state.pendingSend.withdrawBy = 'asset';
  }
  $('vault-deposit-mode-btn').classList.toggle('vault-dw-tab-active', isDeposit);
  $('vault-withdraw-mode-btn').classList.toggle('vault-dw-tab-active', !isDeposit);
  $('vault-withdraw-by-group').classList.toggle('hidden', isDeposit);
  $('vault-withdraw-by-asset-btn').classList.add('vault-dw-tab-active');
  $('vault-withdraw-by-shares-btn').classList.remove('vault-dw-tab-active');
  const asset = state.pendingSend?.underlyingLabel ?? '';
  $('vault-dw-amount-label').textContent = isDeposit
    ? `Amount to deposit (${asset})`
    : `Amount to withdraw (${asset})`;
  $('vault-dw-amount').value = '';
  $('vault-dw-error').classList.add('hidden');
}

function switchWithdrawBy(by) {
  const byAsset = by === 'asset';
  if (state.pendingSend) state.pendingSend.withdrawBy = by;
  $('vault-withdraw-by-asset-btn').classList.toggle('vault-dw-tab-active', byAsset);
  $('vault-withdraw-by-shares-btn').classList.toggle('vault-dw-tab-active', !byAsset);
  const asset = state.pendingSend?.underlyingLabel ?? '';
  $('vault-dw-amount-label').textContent = byAsset
    ? `Amount to withdraw (${asset})`
    : 'Amount to withdraw (shares)';
  $('vault-dw-amount').value = '';
  $('vault-dw-error').classList.add('hidden');
}

function reviewVaultDW() {
  const { pendingSend } = state;
  if (!pendingSend) return;

  $('vault-dw-error').classList.add('hidden');

  const amountStr = $('vault-dw-amount').value.trim();
  const amountNum = parseFloat(amountStr);
  if (!amountStr || isNaN(amountNum) || amountNum <= 0) {
    showAlert('vault-dw-error', 'Enter a valid amount greater than zero.');
    return;
  }

  const { vaultId, vaultAsset, dwMode, withdrawBy, underlyingLabel, mptIssuanceId, assetScale } = pendingSend;
  if (!vaultId) {
    showAlert('vault-dw-error', 'Vault ID not available for this position.');
    return;
  }

  // For withdraw-by-shares, Amount is the share MPT token amount
  let txAmount;
  let amountDisplayLabel;
  if (dwMode === 'withdraw' && withdrawBy === 'shares') {
    const scale = assetScale ?? 0;
    const raw = scale > 0 ? Math.round(amountNum * Math.pow(10, scale)) : Math.round(amountNum);
    txAmount = { mpt_issuance_id: mptIssuanceId, value: String(raw) };
    amountDisplayLabel = 'shares';
  } else {
    // Deposit, or withdraw specifying underlying asset amount
    if (!vaultAsset || typeof vaultAsset === 'string') {
      txAmount = xrpToDrops(amountStr);
    } else if (vaultAsset.currency) {
      txAmount = { currency: vaultAsset.currency, issuer: vaultAsset.issuer, value: amountStr };
    } else if (vaultAsset.mpt_issuance_id) {
      const scale = assetScale ?? 0;
      const raw = scale > 0 ? Math.round(amountNum * Math.pow(10, scale)) : Math.round(amountNum);
      txAmount = { mpt_issuance_id: vaultAsset.mpt_issuance_id, value: String(raw) };
    } else {
      txAmount = xrpToDrops(amountStr);
    }
    amountDisplayLabel = underlyingLabel;
  }

  const txType = dwMode === 'deposit' ? 'VaultDeposit' : 'VaultWithdraw';
  const txJson = {
    TransactionType: txType,
    Account: state.activeAccount,
    VaultID: vaultId,
    Amount: txAmount,
  };

  const row = (label, value, cls = '') =>
    `<div class="tx-row">
       <span class="tx-label">${label}</span>
       <span class="tx-value ${cls}">${value}</span>
     </div>`;

  const rows = [];
  rows.push(row('Type', dwMode === 'deposit' ? 'Vault Deposit' : 'Vault Withdraw', 'tx-type'));
  rows.push(row('Vault', esc(pendingSend.displayName)));
  rows.push(row('Amount', esc(`${amountStr} ${amountDisplayLabel}`), 'tx-amount'));

  $('send-review-details').innerHTML = rows.join('');
  $('review-title').textContent = dwMode === 'deposit' ? 'Review Deposit' : 'Review Withdraw';

  state.pendingTxReview = {
    txJson,
    backView: 'send-payment',
    successMsg: dwMode === 'deposit' ? 'Deposit confirmed!' : 'Withdrawal confirmed!',
  };

  showView('send-review');
}

// ─────────────────────────────────────────────
// AMM DEPOSIT
// ─────────────────────────────────────────────

/** Return the current account balance of a pool asset (string=XRP drops, object=IOU). */
async function fetchAmmAssetBalance(asset) {
  await ensureConnected();
  if (typeof asset === 'string') {
    // XRP — asset value is drops
    const resp = await state.client.request({
      command: 'account_info',
      account: state.activeAccount,
      ledger_index: 'validated',
    });
    const xrp = parseFloat(dropsToXrp(resp.result.account_data.Balance));
    return xrp.toLocaleString(undefined, { maximumFractionDigits: 6 });
  } else {
    // IOU
    const resp = await state.client.request({
      command: 'account_lines',
      account: state.activeAccount,
      peer: asset.issuer,
      ledger_index: 'validated',
    });
    const line = (resp.result.lines ?? [])
      .find(l => l.currency === asset.currency && l.account === asset.issuer);
    if (!line) return '0';
    const n = parseFloat(line.balance);
    return n.toLocaleString(undefined, { maximumFractionDigits: 6 });
  }
}

function openAmmDeposit() {
  const { pendingSend } = state;
  if (!pendingSend || pendingSend.type !== 'amm') return;

  $('amm-deposit-section').classList.remove('hidden');
  $('vault-dw-section').classList.add('hidden');

  const { label1, label2, balance } = pendingSend;

  // Deposit labels
  $('amm-dep-label1').textContent       = label1;
  $('amm-dep-label2').textContent       = label2;
  $('amm-dep-amount1-label').textContent = `${label1} amount`;
  $('amm-dep-amount2-label').textContent = `${label2} amount`;
  $('amm-dep-asset1-btn').textContent   = label1;
  $('amm-dep-asset2-btn').textContent   = label2;
  $('amm-dep-eprice-label').textContent = `Effective price limit (${label1} per LP token)`;

  // Withdraw labels
  $('amm-wdw-asset1-btn').textContent   = label1;
  $('amm-wdw-asset2-btn').textContent   = label2;
  $('amm-wdw-amount2-label').textContent = `${label2} amount`;
  $('amm-wdw-lp-bal').textContent       = balance;

  // Reset deposit inputs
  $('amm-dep-amount1').value = '';
  $('amm-dep-amount2').value = '';
  $('amm-dep-lptoken').value = '';
  $('amm-dep-maxamt').value  = '';
  $('amm-dep-eprice').value  = '';
  $('amm-dep-error').classList.add('hidden');
  $('amm-dep-mode').value    = 'two-asset';
  pendingSend.ammDepAsset    = 1;

  // Reset withdraw inputs
  $('amm-wdw-amount1').value = '';
  $('amm-wdw-amount2').value = '';
  $('amm-wdw-lptoken').value = '';
  $('amm-wdw-eprice').value  = '';
  $('amm-wdw-error').classList.add('hidden');
  $('amm-wdw-mode').value    = 'lp-token';
  pendingSend.ammWdwAsset    = 1;

  switchAmmMode('deposit');
  updateAmmDepFields();
  updateAmmWdwFields();

  // Fetch current asset balances asynchronously
  $('amm-dep-bal1').textContent = '…';
  $('amm-dep-bal2').textContent = '…';
  Promise.all([
    fetchAmmAssetBalance(pendingSend.asset1),
    fetchAmmAssetBalance(pendingSend.asset2),
  ]).then(([b1, b2]) => {
    $('amm-dep-bal1').textContent = b1;
    $('amm-dep-bal2').textContent = b2;
  }).catch(() => {
    $('amm-dep-bal1').textContent = '—';
    $('amm-dep-bal2').textContent = '—';
  });
}

function switchAmmMode(mode) {
  const isDeposit = mode === 'deposit';
  $('amm-dep-sub').classList.toggle('hidden', !isDeposit);
  $('amm-wdw-sub').classList.toggle('hidden', isDeposit);
  $('amm-mode-deposit-btn').classList.toggle('vault-dw-tab-active', isDeposit);
  $('amm-mode-withdraw-btn').classList.toggle('vault-dw-tab-active', !isDeposit);
}

function updateAmmDepFields() {
  const mode  = $('amm-dep-mode').value;
  const asset = state.pendingSend?.ammDepAsset ?? 1;

  const showBothAssets = mode === 'two-asset';
  const isOneAsset     = mode === 'one-asset' || mode === 'one-asset-lp' || mode === 'one-asset-limit';
  const hasLp          = mode === 'two-asset-lp' || mode === 'one-asset-lp';
  const hasEPrice      = mode === 'one-asset-limit';
  // lpOnly: no amount input — ledger determines asset amounts from LPTokenOut
  const lpOnly         = mode === 'two-asset-lp' || mode === 'one-asset-lp';

  const hasMaxAmt = mode === 'one-asset-lp';

  $('amm-dep-asset-group').classList.toggle('hidden', !isOneAsset);
  $('amm-dep-amount1-group').classList.toggle('hidden', lpOnly || (isOneAsset && asset !== 1));
  $('amm-dep-amount2-group').classList.toggle('hidden', lpOnly || (showBothAssets ? false : asset !== 2));
  $('amm-dep-lptoken-group').classList.toggle('hidden', !hasLp);
  $('amm-dep-maxamt-group').classList.toggle('hidden', !hasMaxAmt);
  $('amm-dep-eprice-group').classList.toggle('hidden', !hasEPrice);

  if (showBothAssets) $('amm-dep-amount2-group').classList.remove('hidden');

  if (hasMaxAmt) {
    const lbl = asset === 1 ? state.pendingSend?.label1 : state.pendingSend?.label2;
    $('amm-dep-maxamt-label').textContent = `Maximum ${lbl ?? 'asset'} amount`;
  }
}

function updateAmmWdwFields() {
  const mode  = $('amm-wdw-mode').value;
  const asset = state.pendingSend?.ammWdwAsset ?? 1;
  const { label1, label2 } = state.pendingSend ?? {};

  const isOneAsset = ['one-asset-all', 'single-asset', 'one-asset-lp', 'one-asset-limit'].includes(mode);
  const isTwoAsset = mode === 'two-asset';
  const hasAmount  = ['single-asset', 'one-asset-lp', 'one-asset-limit'].includes(mode);
  const hasLpIn    = mode === 'lp-token' || mode === 'one-asset-lp';
  const hasEPrice  = mode === 'one-asset-limit';

  $('amm-wdw-asset-group').classList.toggle('hidden', !isOneAsset);
  $('amm-wdw-amount1-group').classList.toggle('hidden', !hasAmount && !isTwoAsset);
  $('amm-wdw-amount2-group').classList.toggle('hidden', !isTwoAsset);
  $('amm-wdw-lptoken-group').classList.toggle('hidden', !hasLpIn);
  $('amm-wdw-eprice-group').classList.toggle('hidden', !hasEPrice);

  if (isTwoAsset) {
    $('amm-wdw-amount1-label').textContent = `${label1 ?? 'Asset 1'} amount`;
  } else if (hasAmount) {
    const lbl = asset === 1 ? (label1 ?? 'Asset 1') : (label2 ?? 'Asset 2');
    $('amm-wdw-amount1-label').textContent = `${lbl} amount`;
    $('amm-wdw-eprice-label').textContent  = `Effective price limit (${lbl} per LP token)`;
  }
}

function reviewAmmDeposit() {
  const { pendingSend } = state;
  if (!pendingSend || pendingSend.type !== 'amm') return;

  $('amm-dep-error').classList.add('hidden');

  const mode  = $('amm-dep-mode').value;
  const asset = pendingSend.ammDepAsset ?? 1;
  const { asset1, asset2, currency: lpCurrency, issuer: lpIssuer, label1, label2 } = pendingSend;

  const showBothAssets = mode === 'two-asset';
  const isOneAsset     = mode === 'one-asset' || mode === 'one-asset-lp' || mode === 'one-asset-limit';
  const hasLp          = mode === 'two-asset-lp' || mode === 'one-asset-lp';
  const hasEPrice      = mode === 'one-asset-limit';
  const lpOnly         = mode === 'two-asset-lp' || mode === 'one-asset-lp';

  // Build XRPL Amount field from user input + pool asset type
  const buildAmt = (poolAsset, str) =>
    typeof poolAsset === 'string' ? xrpToDrops(str) : { currency: poolAsset.currency, issuer: poolAsset.issuer, value: str };

  // Build Asset spec (no value) for AMMDeposit Asset / Asset2 fields
  const assetSpec = (poolAsset) =>
    typeof poolAsset === 'string' ? { currency: 'XRP' } : { currency: poolAsset.currency, issuer: poolAsset.issuer };

  const row = (label, value, cls = '') =>
    `<div class="tx-row"><span class="tx-label">${label}</span><span class="tx-value ${cls}">${value}</span></div>`;

  const rows = [
    row('Type', 'AMMDeposit', 'tx-type'),
    row('Pool', esc(`${label1} / ${label2}`)),
  ];

  const txJson = {
    TransactionType: 'AMMDeposit',
    Account: state.activeAccount,
    Asset: assetSpec(asset1),
    Asset2: assetSpec(asset2),
  };

  // Explicit Flags required — ledger uses these to determine deposit mode
  const modeFlags = {
    'two-asset':       0x00100000,
    'two-asset-lp':    0x00010000,
    'one-asset':       0x00080000,
    'one-asset-lp':    0x00200000,
    'one-asset-limit': 0x00400000,
  };
  txJson.Flags = modeFlags[mode] ?? 0x00100000;

  // Amount (asset1, for two-asset or one-asset modes — not for two-asset-lp)
  if (!lpOnly && (showBothAssets || (isOneAsset && asset === 1))) {
    const s = $('amm-dep-amount1').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-dep-error', `Enter a valid ${label1} amount.`); return; }
    txJson.Amount = buildAmt(asset1, s);
    rows.push(row(label1, s));
  }

  // Amount2 (asset2, for two-asset or one-asset modes — not for two-asset-lp)
  if (!lpOnly && (showBothAssets || (isOneAsset && asset === 2))) {
    const s = $('amm-dep-amount2').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-dep-error', `Enter a valid ${label2} amount.`); return; }
    txJson.Amount2 = buildAmt(asset2, s);
    rows.push(row(label2, s));
  }

  // one-asset-lp: Amount always refers to Asset; if asset2 is selected, swap Asset/Asset2
  if (mode === 'one-asset-lp') {
    const s = $('amm-dep-maxamt').value.trim();
    const n = parseFloat(s);
    const lbl = asset === 1 ? label1 : label2;
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-dep-error', `Enter a valid maximum ${lbl} amount.`); return; }
    if (asset === 2) {
      txJson.Asset  = assetSpec(asset2);
      txJson.Asset2 = assetSpec(asset1);
    }
    txJson.Amount = buildAmt(asset === 1 ? asset1 : asset2, s);
    rows.push(row(`Max ${lbl}`, s));
  }

  // LPTokenOut
  if (hasLp) {
    const s = $('amm-dep-lptoken').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-dep-error', 'Enter a valid LP token amount.'); return; }
    txJson.LPTokenOut = { currency: lpCurrency, issuer: lpIssuer, value: s };
    rows.push(row('LP Tokens out', s));
  }

  // EPrice
  if (hasEPrice) {
    const s = $('amm-dep-eprice').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-dep-error', 'Enter a valid effective price.'); return; }
    txJson.EPrice = buildAmt(asset === 1 ? asset1 : asset2, s);
    rows.push(row('Effective price', s));
  }

  $('send-review-details').innerHTML = rows.join('');
  $('review-title').textContent = 'Review AMM Deposit';
  state.pendingTxReview = { txJson, backView: 'send-payment', successMsg: 'AMM deposit submitted!' };
  showView('send-review');
}

function reviewAmmWithdraw() {
  const { pendingSend } = state;
  if (!pendingSend || pendingSend.type !== 'amm') return;

  $('amm-wdw-error').classList.add('hidden');

  const mode  = $('amm-wdw-mode').value;
  const asset = pendingSend.ammWdwAsset ?? 1;
  const { asset1, asset2, currency: lpCurrency, issuer: lpIssuer, label1, label2 } = pendingSend;

  const isOneAsset = ['one-asset-all', 'single-asset', 'one-asset-lp', 'one-asset-limit'].includes(mode);
  const isTwoAsset = mode === 'two-asset';
  const hasAmount  = ['single-asset', 'one-asset-lp', 'one-asset-limit'].includes(mode);
  const hasLpIn    = mode === 'lp-token' || mode === 'one-asset-lp';
  const hasEPrice  = mode === 'one-asset-limit';

  const buildAmt = (poolAsset, str) =>
    typeof poolAsset === 'string' ? xrpToDrops(str) : { currency: poolAsset.currency, issuer: poolAsset.issuer, value: str };
  const assetSpec = (poolAsset) =>
    typeof poolAsset === 'string' ? { currency: 'XRP' } : { currency: poolAsset.currency, issuer: poolAsset.issuer };
  const row = (label, value, cls = '') =>
    `<div class="tx-row"><span class="tx-label">${label}</span><span class="tx-value ${cls}">${value}</span></div>`;

  const assetLbl = asset === 1 ? label1 : label2;
  const rows = [
    row('Type', 'AMMWithdraw', 'tx-type'),
    row('Pool', esc(`${label1} / ${label2}`)),
  ];

  // For single-asset modes, swap Asset/Asset2 when asset2 is selected so Amount always maps to Asset
  const txJson = {
    TransactionType: 'AMMWithdraw',
    Account: state.activeAccount,
    Asset:  (isOneAsset && asset === 2) ? assetSpec(asset2) : assetSpec(asset1),
    Asset2: (isOneAsset && asset === 2) ? assetSpec(asset1) : assetSpec(asset2),
  };

  const modeFlags = {
    'lp-token':        0x00010000,
    'withdraw-all':    0x00020000,
    'one-asset-all':   0x00040000,
    'single-asset':    0x00080000,
    'two-asset':       0x00100000,
    'one-asset-lp':    0x00200000,
    'one-asset-limit': 0x00400000,
  };
  txJson.Flags = modeFlags[mode] ?? 0x00010000;

  // Single-asset amount (always Amount, not Amount2, due to swap)
  if (hasAmount) {
    const s = $('amm-wdw-amount1').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-wdw-error', `Enter a valid ${assetLbl} amount.`); return; }
    txJson.Amount = buildAmt(asset === 1 ? asset1 : asset2, s);
    rows.push(row(assetLbl, s));
  }

  // Two-asset: Amount + Amount2
  if (isTwoAsset) {
    const s1 = $('amm-wdw-amount1').value.trim();
    const n1 = parseFloat(s1);
    if (!s1 || isNaN(n1) || n1 <= 0) { showAlert('amm-wdw-error', `Enter a valid ${label1} amount.`); return; }
    txJson.Amount = buildAmt(asset1, s1);
    rows.push(row(label1, s1));

    const s2 = $('amm-wdw-amount2').value.trim();
    const n2 = parseFloat(s2);
    if (!s2 || isNaN(n2) || n2 <= 0) { showAlert('amm-wdw-error', `Enter a valid ${label2} amount.`); return; }
    txJson.Amount2 = buildAmt(asset2, s2);
    rows.push(row(label2, s2));
  }

  // LPTokenIn
  if (hasLpIn) {
    const s = $('amm-wdw-lptoken').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-wdw-error', 'Enter a valid LP token amount.'); return; }
    txJson.LPTokenIn = { currency: lpCurrency, issuer: lpIssuer, value: s };
    rows.push(row('LP Tokens in', s));
  }

  // EPrice
  if (hasEPrice) {
    const s = $('amm-wdw-eprice').value.trim();
    const n = parseFloat(s);
    if (!s || isNaN(n) || n <= 0) { showAlert('amm-wdw-error', 'Enter a valid effective price.'); return; }
    txJson.EPrice = buildAmt(asset === 1 ? asset1 : asset2, s);
    rows.push(row('Effective price', s));
  }

  $('send-review-details').innerHTML = rows.join('');
  $('review-title').textContent = 'Review AMM Withdrawal';
  state.pendingTxReview = { txJson, backView: 'send-payment', successMsg: 'AMM withdrawal submitted!' };
  showView('send-review');
}

function switchSendTab(tab) {
  const isTransfer = tab === 'transfer';
  $('send-tab-transfer-panel').classList.toggle('hidden', !isTransfer);
  $('send-tab-deposit-panel').classList.toggle('hidden', isTransfer);
  $('send-tab-transfer-btn').classList.toggle('send-tab-active', isTransfer);
  $('send-tab-deposit-btn').classList.toggle('send-tab-active', !isTransfer);
}

async function openSendPayment(type, data) {
  state.pendingSend = { type, ...data };

  $('send-title').textContent = type === 'vault' ? data.displayName : `Send ${data.displayName}`;
  $('send-available-balance').textContent = `${data.balance} ${data.displayName}`;
  $('send-amount-label').textContent = `Amount (${data.displayName})`;
  $('send-amount').value   = '';
  $('send-dest-tag').value = '';
  $('send-error').classList.add('hidden');

  switchSendTab(type === 'amm' || type === 'vault' ? 'deposit' : 'transfer');
  if (type === 'vault') openVaultDW();
  else if (type === 'amm') openAmmDeposit();

  await populateSendDestination();
  showView('send-payment');
}

async function populateSendDestination() {
  await populateAddressPicker($('send-destination-select'));
  handleSendDestChange();
}

function handleSendDestChange() {
  handlePickerChange(
    $('send-destination-select'),
    $('send-manual-group'),
    $('send-dest-tag'),
  );
  // Don't wipe a tag the user already typed
}

function resolveSendDestination() {
  return getPickerAddress($('send-destination-select'), $('send-manual-address'));
}

function reviewSendPayment() {
  const { pendingSend } = state;
  if (!pendingSend) return;

  $('send-error').classList.add('hidden');

  const destAddress = resolveSendDestination();
  if (!destAddress || !isValidClassicAddress(destAddress)) {
    showAlert('send-error', 'Invalid destination address.');
    return;
  }

  const amountStr = $('send-amount').value.trim();
  const amountNum = parseFloat(amountStr);
  if (!amountStr || isNaN(amountNum) || amountNum <= 0) {
    showAlert('send-error', 'Enter a valid amount greater than zero.');
    return;
  }

  const destTagStr = $('send-dest-tag').value.trim();

  const row = (label, value, cls = '') =>
    `<div class="tx-row">
       <span class="tx-label">${label}</span>
       <span class="tx-value ${cls}">${value}</span>
     </div>`;

  const rows = [];
  rows.push(row('Type', 'Payment', 'tx-type'));
  rows.push(row('From', `<span title="${esc(state.activeAccount)}">${esc(truncAddr(state.activeAccount))}</span>`, 'tx-address'));
  rows.push(row('To', `<span title="${esc(destAddress)}">${esc(truncAddr(destAddress))}</span>`, 'tx-address'));
  if (destTagStr) rows.push(row('Dest. Tag', esc(destTagStr)));
  rows.push(row('Amount', esc(`${amountStr} ${pendingSend.displayName}`), 'tx-amount'));

  $('send-review-details').innerHTML = rows.join('');
  $('review-title').textContent = 'Review Payment';
  showView('send-review');
}

async function executeSendPayment() {
  const { pendingSend } = state;
  if (!pendingSend) return;

  const destAddress = resolveSendDestination();
  const amountStr   = $('send-amount').value.trim();
  const amountNum   = parseFloat(amountStr);
  const destTagStr  = $('send-dest-tag').value.trim();

  // Build Amount field
  let txAmount;
  if (pendingSend.type === 'xrp') {
    txAmount = xrpToDrops(amountStr);
  } else if (pendingSend.type === 'iou') {
    txAmount = { currency: pendingSend.currency, issuer: pendingSend.issuer, value: amountStr };
  } else if (pendingSend.type === 'mpt') {
    const scale = pendingSend.assetScale ?? 0;
    const raw = scale > 0 ? Math.round(amountNum * Math.pow(10, scale)) : Math.round(amountNum);
    txAmount = { mpt_issuance_id: pendingSend.mptIssuanceId, value: String(raw) };
  } else if (pendingSend.type === 'amm') {
    txAmount = { currency: pendingSend.currency, issuer: pendingSend.issuer, value: amountStr };
  } else if (pendingSend.type === 'vault') {
    const scale = pendingSend.assetScale ?? 0;
    const raw = scale > 0 ? Math.round(amountNum * Math.pow(10, scale)) : Math.round(amountNum);
    txAmount = { mpt_issuance_id: pendingSend.mptIssuanceId, value: String(raw) };
  }

  const txJson = {
    TransactionType: 'Payment',
    Account: state.activeAccount,
    Destination: destAddress,
    Amount: txAmount,
  };
  if (destTagStr) txJson.DestinationTag = parseInt(destTagStr, 10);

  showView('tx-status');
  setTxStatus('pending', 'Preparing…');

  try {
    await ensureConnected();
    setTxStatus('pending', 'Autofilling network fields…');
    const prepared = await state.client.autofill(txJson);
    setTxStatus('pending', 'Signing…');
    if (state.devSettings.printTxJson) console.log('[tx json]', prepared);
    const { tx_blob, hash } = await signPreparedTx(prepared);
    setTxStatus('pending', 'Submitting to XRPL…');
    const response = await state.client.submitAndWait(tx_blob);
    const txResult = response.result?.meta?.TransactionResult;
    if (txResult !== 'tesSUCCESS') throw new Error(`Transaction failed: ${txResult}`);
    setTxStatus('success', 'Payment sent!', hash);
    state.pendingSend = null;
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadCredentials();
    loadTxHistory();
  } catch (err) {
    console.error('[sendPayment]', err);
    setTxStatus('error', err.message || 'Payment failed.');
  }
}

// ─────────────────────────────────────────────
// ADD TRUST LINE (IOU)
// ─────────────────────────────────────────────

async function openTrustIou() {
  $('trust-currency').value = '';
  $('trust-limit').value    = '';
  $('trust-error').classList.add('hidden');
  await populateAddressPicker($('trust-issuer-select'));
  handlePickerChange($('trust-issuer-select'), $('trust-manual-group'));
  showView('trust-iou');
}

function reviewTrustSet() {
  $('trust-error').classList.add('hidden');

  const issuer = getPickerAddress($('trust-issuer-select'), $('trust-manual-address'));
  if (!issuer || !isValidClassicAddress(issuer)) {
    showAlert('trust-error', 'Invalid issuer address.');
    return;
  }

  const currency = $('trust-currency').value.trim().toUpperCase();
  if (!currency) { showAlert('trust-error', 'Enter a currency code.'); return; }
  const is3Char = /^[A-Z0-9]{3}$/.test(currency) && currency !== 'XRP';
  const isHex   = /^[0-9A-F]{40}$/.test(currency);
  if (!is3Char && !isHex) {
    showAlert('trust-error', 'Currency must be 3 alphanumeric chars (e.g. USD) or 40 hex chars.');
    return;
  }

  const limitStr = $('trust-limit').value.trim() || '1000000000000';

  const txJson = {
    TransactionType: 'TrustSet',
    Account: state.activeAccount,
    LimitAmount: { currency, issuer, value: limitStr },
  };

  const row = (label, value, cls = '') =>
    `<div class="tx-row"><span class="tx-label">${label}</span><span class="tx-value ${cls}">${value}</span></div>`;

  $('send-review-details').innerHTML = [
    row('Type', 'TrustSet', 'tx-type'),
    row('Currency', esc(currency)),
    row('Issuer', `<span title="${esc(issuer)}">${esc(truncAddr(issuer))}</span>`, 'tx-address'),
    row('Limit', esc(parseFloat(limitStr).toLocaleString())),
  ].join('');

  $('review-title').textContent = 'Review Trust Line';
  state.pendingTxReview = { txJson, backView: 'trust-iou', successMsg: 'Trust line established!' };
  showView('send-review');
}

// ─────────────────────────────────────────────
// ADD MPT (MPTokenAuthorize)
// ─────────────────────────────────────────────

async function openAuthMpt() {
  $('mpt-error').classList.add('hidden');
  $('mpt-issuance-group').classList.add('hidden');
  $('mpt-manual-id-group').classList.add('hidden');
  await populateAddressPicker($('mpt-issuer-select'));
  handlePickerChange($('mpt-issuer-select'), $('mpt-manual-group'));
  showView('auth-mpt');
}

async function fetchAndPopulateMpts() {
  $('mpt-error').classList.add('hidden');

  const issuer = getPickerAddress($('mpt-issuer-select'), $('mpt-manual-address'));
  if (!issuer || !isValidClassicAddress(issuer)) {
    showAlert('mpt-error', 'Invalid issuer address.');
    return;
  }

  const btn = $('mpt-fetch-btn');
  btn.disabled    = true;
  btn.textContent = 'Fetching…';

  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: issuer,
      ledger_index: 'validated',
    });
    const issuances = (resp.result.account_objects ?? [])
      .filter(o => o.LedgerEntryType === 'MPTokenIssuance');

    const sel = $('mpt-issuance-select');
    sel.innerHTML = '';

    for (const obj of issuances) {
      const id = obj.MPTokenIssuanceID ?? obj.mpt_issuance_id ?? obj.index ?? '';
      let label = id.length >= 12 ? `${id.slice(0, 8)}…${id.slice(-4)}` : id;
      if (obj.MPTokenMetadata) {
        try {
          const decoded = decodeMPTokenMetadata(obj.MPTokenMetadata);
          const ticker = (typeof decoded?.ticker === 'string' && decoded.ticker) ? decoded.ticker : null;
          if (ticker) label = `${ticker} (${label})`;
        } catch { /* keep short id */ }
      }
      const opt = document.createElement('option');
      opt.value = id;
      opt.textContent = label;
      sel.appendChild(opt);
    }

    const manualOpt = document.createElement('option');
    manualOpt.value = '__manual__';
    manualOpt.textContent = 'Enter ID manually…';
    sel.appendChild(manualOpt);

    $('mpt-issuance-group').classList.remove('hidden');
    $('mpt-manual-id-group').classList.add('hidden');
    handleMptIssuanceChange();

    if (issuances.length === 0) {
      showAlert('mpt-error', 'No MPT issuances found for this issuer.');
    }
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      showAlert('mpt-error', 'Issuer account not found on the ledger.');
    } else {
      showAlert('mpt-error', `Fetch failed: ${err.message}`);
    }
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Fetch MPTs from Issuer';
  }
}

function handleMptIssuanceChange() {
  const val = $('mpt-issuance-select').value;
  $('mpt-manual-id-group').classList.toggle('hidden', val !== '__manual__');
}

function reviewMptAuthorize() {
  $('mpt-error').classList.add('hidden');

  const issuanceGroup = $('mpt-issuance-group');
  let issuanceId;

  if (issuanceGroup.classList.contains('hidden')) {
    // User hasn't fetched yet — require manual ID
    issuanceId = $('mpt-manual-id').value.trim().toUpperCase();
    if (!issuanceId) {
      showAlert('mpt-error', 'Fetch MPTs first or enter an Issuance ID manually.');
      $('mpt-manual-id-group').classList.remove('hidden');
      return;
    }
  } else {
    const selVal = $('mpt-issuance-select').value;
    issuanceId = selVal === '__manual__' ? $('mpt-manual-id').value.trim().toUpperCase() : selVal;
  }

  if (!/^[0-9A-F]{48}$/i.test(issuanceId)) {
    showAlert('mpt-error', 'Issuance ID must be a 48-character hex string.');
    return;
  }

  const txJson = {
    TransactionType: 'MPTokenAuthorize',
    Account: state.activeAccount,
    MPTokenIssuanceID: issuanceId.toUpperCase(),
  };

  const shortId = `${issuanceId.slice(0, 8)}…${issuanceId.slice(-4)}`;
  const issuer  = issuerFromMptIssuanceId(issuanceId) ?? '—';

  const row = (label, value, cls = '') =>
    `<div class="tx-row"><span class="tx-label">${label}</span><span class="tx-value ${cls}">${value}</span></div>`;

  $('send-review-details').innerHTML = [
    row('Type', 'MPTokenAuthorize', 'tx-type'),
    row('Issuance ID', `<span title="${esc(issuanceId)}">${esc(shortId)}</span>`, 'tx-address'),
    row('Issuer', `<span title="${esc(issuer)}">${esc(truncAddr(issuer))}</span>`, 'tx-address'),
  ].join('');

  $('review-title').textContent = 'Review MPT Authorization';
  state.pendingTxReview = { txJson, backView: 'auth-mpt', successMsg: 'MPT authorization submitted!' };
  showView('send-review');
}

// ─────────────────────────────────────────────
// VAULT DEPOSIT (onboarding — new vault position)
// ─────────────────────────────────────────────

async function openVaultDeposit() {
  $('vault-deposit-error').classList.add('hidden');
  $('vault-select-group').classList.add('hidden');
  $('vault-deposit-amount-group').classList.add('hidden');
  $('vault-deposit-review-btn').classList.add('hidden');
  $('vault-deposit-amount').value = '';
  state.fetchedVaults = new Map();
  await populateAddressPicker($('vault-owner-select'));
  handlePickerChange($('vault-owner-select'), $('vault-owner-manual-group'));
  showView('vault-deposit');
}

async function fetchAndPopulateVaults() {
  $('vault-deposit-error').classList.add('hidden');

  const owner = getPickerAddress($('vault-owner-select'), $('vault-owner-manual-address'));
  if (!owner || !isValidClassicAddress(owner)) {
    showAlert('vault-deposit-error', 'Invalid vault owner address.');
    return;
  }

  const btn = $('vault-fetch-btn');
  btn.disabled    = true;
  btn.textContent = 'Fetching…';

  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_objects',
      account: owner,
      ledger_index: 'validated',
    });
    const objects = resp.result.account_objects ?? [];

    // Vaults owned by this account appear as Vault-type objects; their own
    // ledger index is the vault ID.
    const directVaults = objects
      .filter(o => o.LedgerEntryType === 'Vault')
      .map(o => ({ vaultId: o.index ?? o.VaultID, vault: o }));

    // Fallback: some devnet builds link vaults via LoanBroker objects which
    // carry a VaultID field; fetch the actual vault node separately.
    const loanBrokers = objects
      .filter(o => o.LedgerEntryType === 'LoanBroker' && o.VaultID);
    const lbVaults = [];
    for (const lb of loanBrokers) {
      try {
        const vaultResp = await state.client.request({
          command: 'ledger_entry',
          index: lb.VaultID,
          ledger_index: 'validated',
        });
        lbVaults.push({ vaultId: lb.VaultID, vault: vaultResp.result.node });
      } catch { /* skip unavailable vaults */ }
    }

    // Merge, preferring direct Vault entries; deduplicate by vaultId.
    const seen = new Set();
    const vaults = [];
    for (const v of [...directVaults, ...lbVaults]) {
      if (v.vaultId && !seen.has(v.vaultId)) {
        seen.add(v.vaultId);
        vaults.push(v);
      }
    }

    const sel = $('vault-select');
    sel.innerHTML = '';
    state.fetchedVaults = new Map();

    for (const { vaultId, vault } of vaults) {
      let name = vaultId.length >= 12 ? `${vaultId.slice(0, 8)}…${vaultId.slice(-4)}` : vaultId;
      if (vault.Data) {
        try {
          const decoded = Buffer.from(vault.Data, 'hex').toString('utf8').trim();
          if (decoded && /^[\x20-\x7E]+$/.test(decoded)) name = decoded;
        } catch { /* keep id */ }
      }
      const assetLabel = vault.Asset ? formatPoolAsset(vault.Asset) : '?';
      const opt = document.createElement('option');
      opt.value = vaultId;
      opt.textContent = `${name} (${assetLabel})`;
      sel.appendChild(opt);
      state.fetchedVaults.set(vaultId, { name, asset: vault.Asset, assetLabel });
    }

    if (vaults.length === 0) {
      showAlert('vault-deposit-error', 'No vaults found for this owner.');
    } else {
      $('vault-select-group').classList.remove('hidden');
      $('vault-deposit-amount-group').classList.remove('hidden');
      $('vault-deposit-review-btn').classList.remove('hidden');
      updateVaultDepositAmountLabel();
    }
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      showAlert('vault-deposit-error', 'Owner account not found on the ledger.');
    } else {
      showAlert('vault-deposit-error', `Fetch failed: ${err.message}`);
    }
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Fetch Vaults';
  }
}

function updateVaultDepositAmountLabel() {
  const vaultId = $('vault-select').value;
  const info = state.fetchedVaults.get(vaultId);
  $('vault-deposit-amount-label').textContent = info?.assetLabel
    ? `Amount to deposit (${info.assetLabel})`
    : 'Amount to deposit';
}

function reviewNewVaultDeposit() {
  $('vault-deposit-error').classList.add('hidden');

  const vaultId = $('vault-select').value;
  if (!vaultId) {
    showAlert('vault-deposit-error', 'Select a vault.');
    return;
  }

  const amountStr = $('vault-deposit-amount').value.trim();
  const amountNum = parseFloat(amountStr);
  if (!amountStr || isNaN(amountNum) || amountNum <= 0) {
    showAlert('vault-deposit-error', 'Enter a valid amount greater than zero.');
    return;
  }

  const info = state.fetchedVaults.get(vaultId);
  const asset = info?.asset ?? null;

  let txAmount;
  if (!asset || typeof asset === 'string') {
    txAmount = xrpToDrops(amountStr);
  } else if (asset.currency) {
    txAmount = { currency: asset.currency, issuer: asset.issuer, value: amountStr };
  } else if (asset.mpt_issuance_id) {
    txAmount = { mpt_issuance_id: asset.mpt_issuance_id, value: amountStr };
  } else {
    txAmount = xrpToDrops(amountStr);
  }

  const txJson = {
    TransactionType: 'VaultDeposit',
    Account: state.activeAccount,
    VaultID: vaultId,
    Amount: txAmount,
  };

  const row = (label, value, cls = '') =>
    `<div class="tx-row">
       <span class="tx-label">${label}</span>
       <span class="tx-value ${cls}">${value}</span>
     </div>`;

  const rows = [];
  rows.push(row('Type', 'Vault Deposit', 'tx-type'));
  rows.push(row('Vault', esc(info?.name ?? vaultId)));
  rows.push(row('Amount', esc(`${amountStr} ${info?.assetLabel ?? ''}`), 'tx-amount'));

  $('send-review-details').innerHTML = rows.join('');
  $('review-title').textContent = 'Review Deposit';
  state.pendingTxReview = {
    txJson,
    backView: 'vault-deposit',
    successMsg: 'Vault deposit confirmed!',
  };
  showView('send-review');
}

// ─────────────────────────────────────────────
// GENERIC TX REVIEW EXECUTION
// ─────────────────────────────────────────────

async function executeReviewedTx() {
  const review = state.pendingTxReview;
  if (!review) return;
  state.pendingTxReview = null;

  showView('tx-status');
  setTxStatus('pending', 'Preparing…');

  try {
    await ensureConnected();
    setTxStatus('pending', 'Autofilling network fields…');
    const prepared = await state.client.autofill(review.txJson);
    setTxStatus('pending', 'Signing…');
    if (state.devSettings.printTxJson) console.log('[tx json]', prepared);
    const { tx_blob, hash } = await signPreparedTx(prepared);
    setTxStatus('pending', 'Submitting to XRPL…');
    const response = await state.client.submitAndWait(tx_blob);
    const txResult = response.result?.meta?.TransactionResult;
    if (txResult !== 'tesSUCCESS') throw new Error(`Transaction failed: ${txResult}`);
    setTxStatus('success', review.successMsg || 'Transaction confirmed!', hash);
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadCredentials();
    loadTxHistory();
  } catch (err) {
    console.error('[executeReviewedTx]', err);
    setTxStatus('error', err.message || 'Transaction failed.');
  }
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
    loadCredentials();
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
  if (!state.activeAccount) return;
  const btn      = $('faucet-btn');
  const statusEl = $('faucet-status');
  btn.disabled = true;
  btn.textContent = '💧 Requesting…';
  statusEl.className = 'faucet-status';
  statusEl.textContent = '';
  statusEl.classList.remove('hidden');

  try {
    const resp = await fetch(getNetworkConfig().faucet, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ destination: state.activeAccount }),
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
  if (!state.activeAccount || !state.client) return;
  try {
    await ensureConnected();
    const resp = await state.client.request({
      command: 'account_tx',
      account: state.activeAccount,
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

  const explorer = getNetworkConfig().explorer;
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
      if (txJson.Destination) detail += ` → ${resolveAddrDisplay(txJson.Destination)}`;
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
    const chainId = getNetworkConfig().chainId;
    const resp = await sendToBackground({
      type: 'WC_APPROVE_SESSION',
      id:   state.pendingProposal.id,
      namespaces: {
        xrpl: {
          chains:   [chainId],
          accounts: [`${chainId}:${state.activeAccount}`],
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
    if (state.devSettings.printTxJson) console.log('[tx json]', prepared);
    const { tx_blob, hash } = await signPreparedTx(prepared);

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
    loadCredentials();
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
      const explorer = getNetworkConfig().explorer;
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
$('type-ledger').addEventListener('click', openLedgerImport);

// ─────────────────────────────────────────────
// LEDGER HARDWARE WALLET
// ─────────────────────────────────────────────

function openLedgerImport() {
  $('ledger-account-index').value = '0';
  $('ledger-path-preview').textContent = '0';
  $('ledger-connect-btn').disabled = false;
  $('ledger-connect-btn').textContent = 'Connect & Import';
  $('ledger-connect-btn').classList.remove('hidden');
  $('ledger-error').classList.add('hidden');
  $('ledger-retry-group').classList.add('hidden');
  showView('ledger-import');
}

async function connectLedgerDevice() {
  const idx = parseInt($('ledger-account-index').value, 10);
  if (isNaN(idx) || idx < 0) {
    showAlert('ledger-error', 'Enter a valid account index (0 or higher).');
    return;
  }

  // Chrome extension popups close the instant the OS device-picker opens,
  // causing requestDevice() to return empty ("Access denied").  The fix is to
  // run the WebHID call from a regular browser tab, which does NOT close on
  // focus loss.  If we are currently in the popup, open a tab and hand off.
  const inTab = new URLSearchParams(window.location.search).has('ledger');
  if (!inTab) {
    await chrome.storage.session.set({ _ledgerTabIdx: idx });
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?ledger=1' });
    window.close();
    return;
  }

  const btn = $('ledger-connect-btn');
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  $('ledger-error').classList.add('hidden');

  let transport;
  try {
    transport = await TransportWebHID.create();
    const xrpApp = new Xrp(transport);
    const path = `44'/144'/${idx}'/0/0`;
    btn.textContent = 'Confirm on device…';
    const result = await xrpApp.getAddress(path, true);

    if (accountExists(result.address)) {
      showAlert('ledger-error', 'This account is already in your wallet.');
      btn.disabled = false;
      btn.textContent = 'Connect & Import';
      return;
    }

    const label = idx > 0 ? `Ledger Account ${idx}` : 'Ledger Account';
    state.keyrings.push({ type: 'ledger', address: result.address, publicKey: result.publicKey, derivationPath: path, label });
    state.activeAccount = result.address;
    state.wallet        = null;

    const usedPassword = await saveVault(state._setupFlowPassword ?? undefined);
    state._setupFlowPassword = null;
    await persistSession(usedPassword);

    // Register with active project
    await ensureProjectsInitialized();
    addAccountToActiveProject(result.address);
    await saveProjects();

    // Tab mode: close this tab — the user's popup will show the new account next open.
    window.close();
  } catch (err) {
    const msg = err.message || String(err);
    let friendlyMsg;
    if (msg.includes('0x650f')) {
      friendlyMsg = 'Please open the XRP application on your device.';
    } else if (msg.includes('0x6511') || err.name === 'LockedDeviceError' || msg.toLowerCase().includes('locked')) {
      friendlyMsg = 'Please unlock your device and ensure the XRP application is open.';
    } else {
      friendlyMsg = `Ledger error: ${msg}`;
    }
    showAlert('ledger-error', friendlyMsg);
    if (friendlyMsg !== `Ledger error: ${msg}`) {
      // actionable error — show retry/cancel instead of re-enabling connect
      btn.classList.add('hidden');
      $('ledger-retry-group').classList.remove('hidden');
    } else {
      btn.disabled = false;
      btn.textContent = 'Connect & Import';
    }
  } finally {
    if (transport) await transport.close().catch(() => {});
  }
}

$('back-from-ledger-btn').addEventListener('click', () => showView('account-type'));
$('ledger-account-index').addEventListener('input', () => {
  const v = parseInt($('ledger-account-index').value, 10);
  $('ledger-path-preview').textContent = isNaN(v) || v < 0 ? '?' : v;
});
$('ledger-connect-btn').addEventListener('click', connectLedgerDevice);
$('ledger-retry-btn').addEventListener('click', () => {
  $('ledger-retry-group').classList.add('hidden');
  $('ledger-connect-btn').classList.remove('hidden');
  $('ledger-connect-btn').disabled = false;
  $('ledger-connect-btn').textContent = 'Connect & Import';
  $('ledger-error').classList.add('hidden');
  connectLedgerDevice();
});
$('ledger-cancel-btn').addEventListener('click', () => {
  const inTab = new URLSearchParams(window.location.search).has('ledger');
  if (inTab) { window.close(); } else { showView('account-type'); }
});

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
$('settings-about-btn').addEventListener('click', () => {
  $('about-version').textContent      = chrome.runtime.getManifest().version;
  $('about-xrpl-version').textContent = xrplPkg.version;
  showView('about');
});
$('back-from-about-btn').addEventListener('click', () => showView('settings'));
$('settings-manage-accounts-btn').addEventListener('click', () => {
  renderManageAccountsList();
  showView('manage-accounts');
});
$('settings-address-book-btn').addEventListener('click', async () => {
  await renderAddressBook();
  showView('address-book');
});
$('back-from-address-book-btn').addEventListener('click', () => showView('settings'));
$('add-contact-btn').addEventListener('click', () => {
  state.pendingEditContact = null;
  openAddressBookEdit();
});
$('back-from-address-book-edit-btn').addEventListener('click', async () => {
  state.pendingEditContact = null;
  await renderAddressBook();
  showView('address-book');
});
$('contact-save-btn').addEventListener('click', saveContact);
$('back-from-manage-accounts-btn').addEventListener('click', () => showView('settings'));
$('back-from-remove-account-btn').addEventListener('click', () => showView('manage-accounts'));
$('remove-acct-cancel-btn').addEventListener('click', () => {
  state.pendingRemoveAddress         = null;
  state.pendingProjectRemoveIsDelete = false;
  showView('manage-accounts');
});
$('remove-acct-delete-checkbox').addEventListener('change', (e) => {
  $('remove-acct-confirm-btn').disabled = !e.target.checked;
});
$('remove-acct-confirm-btn').addEventListener('click', executeProjectRemove);
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
  loadCredentials();
});

$('copy-address-btn').addEventListener('click', async () => {
  if (!state.activeAccount) return;
  try {
    await navigator.clipboard.writeText(state.activeAccount);
    $('copy-toast').classList.remove('hidden');
    setTimeout(() => $('copy-toast').classList.add('hidden'), 1800);
  } catch { /* clipboard permission denied */ }
});

$('qr-btn').addEventListener('click', showQr);
$('qr-close-btn').addEventListener('click', hideQr);
$('qr-modal').addEventListener('click', e => { if (e.target === $('qr-modal')) hideQr(); });

async function showQr() {
  if (!state.activeAccount) return;
  const addr = state.activeAccount;
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
// EVENT LISTENERS — Send payment
// ─────────────────────────────────────────────

$('send-xrp-btn').addEventListener('click', () => {
  const balText = $('balance-amount').textContent;
  const balance = balText.replace(' XRP', '').replace('(unfunded)', '').trim() || '0';
  openSendPayment('xrp', { displayName: 'XRP', balance });
});

$('iou-balance-list').addEventListener('click', (e) => {
  if (e.target.closest('.token-explorer-link')) return;
  const item = e.target.closest('[data-send-type]');
  if (!item) return;
  openSendPayment('iou', {
    displayName: item.dataset.display,
    balance:     item.dataset.balance,
    currency:    item.dataset.currency,
    issuer:      item.dataset.issuer,
  });
});

$('mpt-balance-list').addEventListener('click', (e) => {
  if (e.target.closest('.token-explorer-link')) return;
  const item = e.target.closest('[data-send-type]');
  if (!item) return;
  openSendPayment('mpt', {
    displayName:    item.dataset.display,
    balance:        item.dataset.balance,
    mptIssuanceId:  item.dataset.mptId,
    assetScale:     parseInt(item.dataset.assetScale, 10) || 0,
  });
});

$('amm-balance-list').addEventListener('click', (e) => {
  if (e.target.closest('.token-explorer-link')) return;
  const item = e.target.closest('[data-send-type]');
  if (!item) return;
  openSendPayment('amm', {
    displayName: item.dataset.display,
    balance:     item.dataset.balance,
    currency:    item.dataset.currency,  // LP token currency
    issuer:      item.dataset.issuer,    // LP token issuer (= AMM account)
    asset1:      JSON.parse(decodeURIComponent(item.dataset.asset1 || 'null')),
    asset2:      JSON.parse(decodeURIComponent(item.dataset.asset2 || 'null')),
    label1:      item.dataset.label1,
    label2:      item.dataset.label2,
  });
});

$('vault-balance-list').addEventListener('click', (e) => {
  if (e.target.closest('.token-explorer-link')) return;
  const item = e.target.closest('[data-send-type]');
  if (!item) return;
  openSendPayment('vault', {
    displayName:     item.dataset.display,
    balance:         item.dataset.balance,
    mptIssuanceId:   item.dataset.mptId,
    assetScale:      parseInt(item.dataset.assetScale, 10) || 0,
    vaultId:         item.dataset.vaultId,
    vaultAsset:      JSON.parse(decodeURIComponent(item.dataset.vaultAsset || 'null')),
    underlyingLabel: item.dataset.underlyingLabel,
  });
});

$('send-tab-transfer-btn').addEventListener('click', () => switchSendTab('transfer'));
$('send-tab-deposit-btn').addEventListener('click', () => switchSendTab('deposit'));

// AMM deposit
$('amm-dep-mode').addEventListener('change', updateAmmDepFields);

$('amm-dep-asset1-btn').addEventListener('click', () => {
  if (!state.pendingSend) return;
  state.pendingSend.ammDepAsset = 1;
  $('amm-dep-asset1-btn').classList.add('vault-dw-tab-active');
  $('amm-dep-asset2-btn').classList.remove('vault-dw-tab-active');
  const { label1 } = state.pendingSend;
  $('amm-dep-eprice-label').textContent = `Effective price limit (${label1} per LP token)`;
  updateAmmDepFields();
});

$('amm-dep-asset2-btn').addEventListener('click', () => {
  if (!state.pendingSend) return;
  state.pendingSend.ammDepAsset = 2;
  $('amm-dep-asset2-btn').classList.add('vault-dw-tab-active');
  $('amm-dep-asset1-btn').classList.remove('vault-dw-tab-active');
  const { label2 } = state.pendingSend;
  $('amm-dep-eprice-label').textContent = `Effective price limit (${label2} per LP token)`;
  updateAmmDepFields();
});

$('amm-dep-review-btn').addEventListener('click', reviewAmmDeposit);

// AMM deposit/withdraw mode tabs
$('amm-mode-deposit-btn').addEventListener('click', () => switchAmmMode('deposit'));
$('amm-mode-withdraw-btn').addEventListener('click', () => switchAmmMode('withdraw'));

// AMM withdraw
$('amm-wdw-mode').addEventListener('change', updateAmmWdwFields);

$('amm-wdw-asset1-btn').addEventListener('click', () => {
  if (!state.pendingSend) return;
  state.pendingSend.ammWdwAsset = 1;
  $('amm-wdw-asset1-btn').classList.add('vault-dw-tab-active');
  $('amm-wdw-asset2-btn').classList.remove('vault-dw-tab-active');
  updateAmmWdwFields();
});

$('amm-wdw-asset2-btn').addEventListener('click', () => {
  if (!state.pendingSend) return;
  state.pendingSend.ammWdwAsset = 2;
  $('amm-wdw-asset2-btn').classList.add('vault-dw-tab-active');
  $('amm-wdw-asset1-btn').classList.remove('vault-dw-tab-active');
  updateAmmWdwFields();
});

$('amm-wdw-review-btn').addEventListener('click', reviewAmmWithdraw);

$('vault-deposit-mode-btn').addEventListener('click', () => switchVaultDWMode('deposit'));
$('vault-withdraw-mode-btn').addEventListener('click', () => switchVaultDWMode('withdraw'));
$('vault-withdraw-by-asset-btn').addEventListener('click', () => switchWithdrawBy('asset'));
$('vault-withdraw-by-shares-btn').addEventListener('click', () => switchWithdrawBy('shares'));
$('vault-dw-review-btn').addEventListener('click', reviewVaultDW);

$('send-destination-select').addEventListener('change', handleSendDestChange);

$('back-from-send-btn').addEventListener('click', () => showView('wallet'));

$('send-confirm-btn').addEventListener('click', reviewSendPayment);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Add trust line (IOU)
// ─────────────────────────────────────────────

$('add-iou-btn').addEventListener('click', openTrustIou);

$('back-from-trust-iou-btn').addEventListener('click', () => showView('wallet'));

$('trust-issuer-select').addEventListener('change', () =>
  handlePickerChange($('trust-issuer-select'), $('trust-manual-group')));

$('trust-review-btn').addEventListener('click', reviewTrustSet);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Add MPT
// ─────────────────────────────────────────────

$('add-mpt-btn').addEventListener('click', openAuthMpt);

$('back-from-auth-mpt-btn').addEventListener('click', () => showView('wallet'));

$('mpt-issuer-select').addEventListener('change', () =>
  handlePickerChange($('mpt-issuer-select'), $('mpt-manual-group')));

$('mpt-fetch-btn').addEventListener('click', fetchAndPopulateMpts);

$('mpt-issuance-select').addEventListener('change', handleMptIssuanceChange);

$('mpt-review-btn').addEventListener('click', reviewMptAuthorize);

// ─────────────────────────────────────────────
// EVENT LISTENERS — Vault deposit (onboarding)
// ─────────────────────────────────────────────

$('add-vault-btn').addEventListener('click', openVaultDeposit);

$('back-from-vault-deposit-btn').addEventListener('click', () => showView('wallet'));

$('back-from-credential-btn').addEventListener('click', () => showView('wallet'));

$('credential-list').addEventListener('click', e => {
  const item = e.target.closest('.credential-item');
  if (!item) return;
  const idx  = parseInt(item.dataset.credIndex, 10);
  const cred = $('credential-list')._credentials?.[idx];
  if (cred) openCredentialDetail(cred);
});

$('vault-owner-select').addEventListener('change', () =>
  handlePickerChange($('vault-owner-select'), $('vault-owner-manual-group')));

$('vault-fetch-btn').addEventListener('click', fetchAndPopulateVaults);

$('vault-select').addEventListener('change', updateVaultDepositAmountLabel);

$('vault-deposit-review-btn').addEventListener('click', reviewNewVaultDeposit);

$('send-review-cancel-btn').addEventListener('click', () => {
  const back = state.pendingTxReview?.backView ?? 'send-payment';
  state.pendingTxReview = null;
  showView(back);
  if (back === 'send-payment' && (state.pendingSend?.type === 'vault' || state.pendingSend?.type === 'amm')) {
    switchSendTab('deposit');
  }
});

$('send-review-submit-btn').addEventListener('click', () => {
  if (state.pendingTxReview) executeReviewedTx();
  else executeSendPayment();
});

$('review-copy-json-btn').addEventListener('click', () => {
  const json = $('review-raw-json').textContent;
  navigator.clipboard.writeText(json).then(() => {
    $('review-copy-json-btn').textContent = 'Copied!';
    setTimeout(() => { $('review-copy-json-btn').textContent = 'Copy'; }, 1500);
  });
});

// ─────────────────────────────────────────────
// BACKGROUND → POPUP  push messages
// (handles events that arrive while the popup is already open)
// ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message) => {
  if (!state.activeAccount) return; // wallet locked — ignore, boot will pick up wcPending on next open

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
// BACKUP & RESTORE
// ─────────────────────────────────────────────

async function downloadBackup() {
  const data = await chrome.storage.local.get(null);
  const backup = {
    _meta: {
      app:     'xrpl-dev-wallet',
      version: chrome.runtime.getManifest().version,
      date:    new Date().toISOString(),
    },
    data,
  };
  const json = JSON.stringify(backup, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const date = new Date().toISOString().slice(0, 10);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `xrpl-wallet-backup-${date}.xrplbak`;
  a.click();
  URL.revokeObjectURL(url);
}

// Holds the parsed backup data awaiting confirmation.
let _pendingRestoreData = null;
let _restoreBackTarget  = 'unlock'; // 'unlock' | 'setup-password'

function openRestoreBackup() {
  _pendingRestoreData = null;
  _restoreBackTarget  = 'unlock';
  $('backup-file-input').value = '';
  $('backup-drop-label').textContent = 'Click to choose file, or drag & drop';
  $('backup-drop-zone').classList.remove('backup-drop-ready');
  hideAlert('restore-backup-status');
  $('restore-backup-confirm-btn').classList.add('hidden');
  showView('restore-backup');
}

function handleBackupFile(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    try {
      const parsed = JSON.parse(e.target.result);
      // Accept either raw storage dump or wrapped backup format.
      const data = parsed._meta ? parsed.data : parsed;
      if (!data?.vault) throw new Error('No encrypted vault found in file.');
      _pendingRestoreData = data;
      $('backup-drop-label').textContent = `✓ ${file.name}`;
      $('backup-drop-zone').classList.add('backup-drop-ready');
      $('restore-backup-confirm-btn').classList.remove('hidden');
      hideAlert('restore-backup-status');
    } catch (err) {
      _pendingRestoreData = null;
      $('restore-backup-confirm-btn').classList.add('hidden');
      $('backup-drop-zone').classList.remove('backup-drop-ready');
      showAlert('restore-backup-status', `Invalid backup file: ${err.message}`);
      $('restore-backup-status').className = 'alert alert-error';
    }
  };
  reader.readAsText(file);
}

async function confirmRestoreBackup() {
  if (!_pendingRestoreData) return;
  try {
    await chrome.storage.local.clear();
    await chrome.storage.local.set(_pendingRestoreData);
    await chrome.storage.session.clear();
    _pendingRestoreData = null;
    // Reload dev settings and projects from the restored data.
    await loadDevSettings();
    await loadProjects();
    showAlert('restore-backup-status', 'Backup restored. Enter your password to unlock.');
    $('restore-backup-status').className = 'alert alert-success';
    $('restore-backup-confirm-btn').classList.add('hidden');
    // Navigate to unlock after a short pause so the user reads the message.
    setTimeout(() => showView('unlock'), 1200);
  } catch (err) {
    showAlert('restore-backup-status', `Restore failed: ${err.message}`);
    $('restore-backup-status').className = 'alert alert-error';
  }
}

// Backup drop-zone interactions
$('backup-drop-zone').addEventListener('click', () => $('backup-file-input').click());
$('backup-file-input').addEventListener('change', (e) => handleBackupFile(e.target.files[0]));
$('backup-drop-zone').addEventListener('dragover', (e) => { e.preventDefault(); $('backup-drop-zone').classList.add('backup-drop-hover'); });
$('backup-drop-zone').addEventListener('dragleave', () => $('backup-drop-zone').classList.remove('backup-drop-hover'));
$('backup-drop-zone').addEventListener('drop', (e) => {
  e.preventDefault();
  $('backup-drop-zone').classList.remove('backup-drop-hover');
  handleBackupFile(e.dataTransfer.files[0]);
});
$('restore-backup-confirm-btn').addEventListener('click', confirmRestoreBackup);
$('back-from-restore-backup-btn').addEventListener('click', () => {
  _pendingRestoreData = null;
  showView(_restoreBackTarget);
});
$('settings-backup-btn').addEventListener('click', downloadBackup);
$('restore-backup-link-btn').addEventListener('click', () => { _restoreBackTarget = 'unlock'; openRestoreBackup(); });
$('setup-restore-backup-btn').addEventListener('click', () => { _restoreBackTarget = 'setup-password'; openRestoreBackup(); });

// ─────────────────────────────────────────────
// DEVELOPER SETTINGS
// ─────────────────────────────────────────────

async function loadDevSettings() {
  const { devSettings, networkSettings } = await chrome.storage.local.get(['devSettings', 'networkSettings']);
  if (devSettings) state.devSettings = { ...state.devSettings, ...devSettings };
  if (networkSettings) {
    state.network       = networkSettings.network       ?? state.network;
    state.manualNetwork = networkSettings.manualNetwork ?? state.manualNetwork;
  }
  $('dev-print-tx-json').checked = state.devSettings.printTxJson;
  $('lock-timeout-secs').value   = state.devSettings.lockTimeoutSecs;
  populateNetworkSelector();
}

async function saveDevSettings() {
  await chrome.storage.local.set({ devSettings: state.devSettings });
}

async function saveNetworkSettings() {
  await chrome.storage.local.set({
    networkSettings: { network: state.network, manualNetwork: state.manualNetwork },
  });
}

function populateNetworkSelector() {
  $('network-select').value = state.network;
  const isManual = state.network === 'manual';
  $('network-manual-group').classList.toggle('hidden', !isManual);
  if (isManual) {
    $('network-manual-ws').value = state.manualNetwork.wsUrl ?? '';
  }
}

async function applyNetworkChange() {
  if (!isMainnetNetwork(state.network)) state.mainnetAcknowledged = false;
  await saveNetworkSettings();
  if (state.client) {
    state.client.disconnect().catch(() => {});
    state.client = null;
  }
  if (state.activeAccount) {
    updateConnectionDot('disconnected');
    await connectXRPL();
    activateAccount(state.activeAccount);
  }
}

$('dev-print-tx-json').addEventListener('change', async (e) => {
  state.devSettings.printTxJson = e.target.checked;
  await saveDevSettings();
});

$('lock-timeout-secs').addEventListener('change', async (e) => {
  const val = parseInt(e.target.value, 10);
  state.devSettings.lockTimeoutSecs = isNaN(val) || val < 0 ? 10 : val;
  e.target.value = state.devSettings.lockTimeoutSecs;
  await saveDevSettings();
});

function isMainnetNetwork(networkId) {
  const cfg = networkId === 'manual'
    ? { group: 'custom' }
    : (NETWORK_SERVERS[networkId] ?? { group: '' });
  return cfg.group === 'mainnet';
}

function maybeApplyNetworkChange(networkId, manualNetwork) {
  if (isMainnetNetwork(networkId) && !state.mainnetAcknowledged) {
    state.pendingNetworkChange = { network: networkId, manualNetwork };
    $('mainnet-warning-checkbox').checked = false;
    $('mainnet-warning-accept-btn').disabled = true;
    showView('mainnet-warning');
  } else {
    state.network = networkId;
    if (manualNetwork) state.manualNetwork = manualNetwork;
    applyNetworkChange();
  }
}

$('network-select').addEventListener('change', async (e) => {
  const selected = e.target.value;
  const isManual = selected === 'manual';
  $('network-manual-group').classList.toggle('hidden', !isManual);
  if (!isManual) maybeApplyNetworkChange(selected, null);
});

$('network-manual-apply-btn').addEventListener('click', async () => {
  const ws = $('network-manual-ws').value.trim();
  if (!ws) { alert('Please enter a WebSocket URL.'); return; }
  maybeApplyNetworkChange('manual', { wsUrl: ws });
});

$('mainnet-warning-checkbox').addEventListener('change', (e) => {
  $('mainnet-warning-accept-btn').disabled = !e.target.checked;
});

$('mainnet-warning-accept-btn').addEventListener('click', async () => {
  state.mainnetAcknowledged = true;
  const { network, manualNetwork } = state.pendingNetworkChange;
  state.pendingNetworkChange = null;
  state.network = network;
  if (manualNetwork) state.manualNetwork = manualNetwork;
  populateNetworkSelector();
  await applyNetworkChange();
  showView('settings');
});

$('mainnet-warning-reject-btn').addEventListener('click', () => {
  state.pendingNetworkChange = null;
  populateNetworkSelector();
  showView('settings');
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────

(async () => {
  try {
    await loadDevSettings();
    await loadProjects();
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
      // Auto-lock: if the popup was closed for >= the configured timeout, discard
      // the session and require the password again.
      const lockTimeoutMs = state.devSettings.lockTimeoutSecs * 1000;
      const lastClosedAt = parseInt(localStorage.getItem('lastClosedAt') || '0', 10);
      if (lastClosedAt && lockTimeoutMs > 0 && Date.now() - lastClosedAt >= lockTimeoutMs) {
        await chrome.storage.session.clear();
        showView('unlock');
        return;
      }

      state.wallet  = getActiveWallet();
      state.network = state.network || 'devnet';
      await ensureProjectsInitialized();
      try {
        await connectXRPL();
      } catch (err) {
        console.warn('[boot] XRPL connect failed, will retry on demand:', err);
      }
      // Tab opened to handle Ledger HID (popup closes when device picker appears).
      if (new URLSearchParams(window.location.search).has('ledger')) {
        const { _ledgerTabIdx } = await chrome.storage.session.get('_ledgerTabIdx');
        await chrome.storage.session.remove('_ledgerTabIdx');
        $('ledger-account-index').value = _ledgerTabIdx ?? 0;
        $('ledger-path-preview').textContent = _ledgerTabIdx ?? 0;
        $('ledger-connect-btn').disabled = false;
        $('ledger-connect-btn').textContent = 'Connect & Import';
        $('ledger-connect-btn').classList.remove('hidden');
        $('ledger-error').classList.add('hidden');
        $('ledger-retry-group').classList.add('hidden');
        showView('ledger-import');
        return;
      }

      updateWalletUI();
      showView('wallet');
      refreshBalance();
      loadIouBalances();
      loadMptBalances();
      loadCredentials();
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
