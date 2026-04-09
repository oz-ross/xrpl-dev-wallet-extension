import './popup.css';
import { Client, Wallet, dropsToXrp } from 'xrpl';
import { Core } from '@walletconnect/core';
import { Web3Wallet } from '@walletconnect/web3wallet';
import { getSdkError } from '@walletconnect/utils';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────

/**
 * Get your free Project ID at https://cloud.walletconnect.com
 * Replace this placeholder before building.
 */
const WC_PROJECT_ID = '545f3b40384efe9b93401c1dd8d0ceb0';

const NETWORKS = {
  devnet: {
    name: 'Devnet',
    wsUrl: 'wss://s.devnet.rippletest.net:51233',
    chainId: 'xrpl:2',
    explorer: 'https://devnet.xrpl.org/transactions/',
  },
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────

const state = {
  /** @type {Wallet|null} */
  wallet: null,
  /** @type {Client|null} */
  client: null,
  /** @type {import('@walletconnect/web3wallet').Web3Wallet|null} */
  web3wallet: null,
  /** @type {'mainnet'|'testnet'} */
  network: 'devnet',
  /** @type {any|null} WalletConnect session proposal */
  pendingProposal: null,
  /** @type {any|null} WalletConnect session_request event */
  pendingRequest: null,
};

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function $(id) { return document.getElementById(id); }

function showView(name) {
  for (const el of document.querySelectorAll('.view')) {
    el.classList.add('hidden');
  }
  $(`view-${name}`).classList.remove('hidden');
}

/** Escape HTML to prevent XSS when rendering external data */
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
  if (typeof amount === 'string') {
    return `${dropsToXrp(amount)} XRP`;
  }
  if (amount && typeof amount === 'object') {
    return `${amount.value} ${amount.currency}`;
  }
  return String(amount);
}

function showAlert(id, msg) {
  const el = $(id);
  el.textContent = msg;
  el.classList.remove('hidden');
}

function hideAlert(id) {
  $(id).classList.add('hidden');
}

// ─────────────────────────────────────────────
// WALLET — IMPORT & RESTORE
// ─────────────────────────────────────────────

async function importWallet() {
  const seed = $('seed-input').value.trim();
  const network = 'devnet';

  hideAlert('import-error');

  if (!seed) {
    showAlert('import-error', 'Please enter your seed phrase or family seed.');
    return;
  }

  const btn = $('import-btn');
  btn.disabled = true;
  btn.textContent = 'Importing…';

  try {
    const wallet = Wallet.fromSeed(seed);

    // Persist in session storage (clears when browser closes, not on popup close)
    await chrome.storage.session.set({
      walletSeed: seed,
      walletAddress: wallet.address,
      network,
    });

    state.wallet = wallet;
    state.network = network;

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    // Non-blocking: fetch balance and init WC
    refreshBalance();
    initWalletConnect();

  } catch (err) {
    showAlert('import-error', `Invalid seed: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Import Wallet';
  }
}

async function restoreSession() {
  const { walletSeed, network } = await chrome.storage.session.get(['walletSeed', 'network']);
  if (!walletSeed) return false;

  try {
    state.wallet = Wallet.fromSeed(walletSeed);
    state.network = network || 'mainnet';
    await connectXRPL();
    updateWalletUI();
    showView('wallet');
    refreshBalance();
    await initWalletConnect();
    return true;
  } catch {
    await chrome.storage.session.clear();
    return false;
  }
}

function logout() {
  if (!confirm('Remove wallet from this session?\nYou will need to re-import your seed.')) return;
  chrome.storage.session.clear();
  state.wallet = null;
  state.web3wallet = null;
  state.client?.disconnect().catch(() => {});
  state.client = null;
  showView('import');
  $('seed-input').value = '';
}

// ─────────────────────────────────────────────
// WALLET — XRPL CLIENT
// ─────────────────────────────────────────────

async function connectXRPL() {
  if (state.client?.isConnected()) {
    state.client.disconnect().catch(() => {});
  }
  const { wsUrl } = NETWORKS[state.network];
  state.client = new Client(wsUrl);
  await state.client.connect();
}

async function ensureConnected() {
  if (!state.client?.isConnected()) {
    await connectXRPL();
  }
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

function updateWalletUI() {
  const addr = state.wallet.address;
  $('account-address').textContent = truncAddr(addr);
  $('account-address').title = addr;

  const badge = $('network-badge');
  const net = NETWORKS[state.network];
  badge.textContent = net.name;
  badge.className = `network-badge ${state.network}`;
}

// ─────────────────────────────────────────────
// WALLETCONNECT — INIT
// ─────────────────────────────────────────────

async function initWalletConnect() {
  if (state.web3wallet) {
    // Re-attach listeners in case popup was closed and reopened
    attachWcListeners();
    updateSessionsUI();
    return;
  }

  if (!WC_PROJECT_ID || WC_PROJECT_ID === 'YOUR_WALLETCONNECT_PROJECT_ID') {
    showAlert('wc-error', 'WalletConnect Project ID not configured. See src/popup/popup.js.');
    return;
  }

  try {
    const core = new Core({ projectId: WC_PROJECT_ID });

    state.web3wallet = await Web3Wallet.init({
      core,
      metadata: {
        name: 'XRPL Wallet',
        description: 'XRPL Chrome Extension Wallet',
        url: 'https://xrpl-wallet.example.com',
        icons: [],
      },
    });

    attachWcListeners();
    updateSessionsUI();
  } catch (err) {
    console.error('[WC init]', err);
    showAlert('wc-error', `WalletConnect init failed: ${err.message}`);
  }
}

function attachWcListeners() {
  const wc = state.web3wallet;
  // Remove existing listeners to avoid duplicates on popup reopen
  wc.removeAllListeners?.('session_proposal');
  wc.removeAllListeners?.('session_request');
  wc.removeAllListeners?.('session_delete');

  wc.on('session_proposal', onSessionProposal);
  wc.on('session_request', onSessionRequest);
  wc.on('session_delete', () => updateSessionsUI());
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
    await state.web3wallet.core.pairing.pair({ uri });
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
// WALLETCONNECT — SESSION PROPOSAL
// ─────────────────────────────────────────────

function onSessionProposal(proposal) {
  state.pendingProposal = proposal;
  const meta = proposal.params.proposer.metadata;

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
    await state.web3wallet.approveSession({
      id: state.pendingProposal.id,
      namespaces: {
        xrpl: {
          chains: [chainId],
          accounts: [`${chainId}:${state.wallet.address}`],
          methods: ['xrpl_signTransaction', 'xrpl_signTransactionFor'],
          events: [],
        },
      },
    });
    state.pendingProposal = null;
    updateSessionsUI();
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
    await state.web3wallet.rejectSession({
      id: state.pendingProposal.id,
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

function onSessionRequest(event) {
  const { method } = event.params.request;

  if (method === 'xrpl_signTransaction' || method === 'xrpl_signTransactionFor') {
    state.pendingRequest = event;
    renderTransactionView(event);
    showView('transaction');
  } else {
    // Unsupported — reject immediately
    respondWc(event.topic, event.id, null, getSdkError('UNSUPPORTED_METHODS'));
  }
}

function renderTransactionView(event) {
  const txJson = event.params.request.params.tx_json;
  const sessions = state.web3wallet.getActiveSessions();
  const session = sessions[event.topic];
  const appName = session?.peer?.metadata?.name ?? 'Unknown App';

  $('tx-from-app').innerHTML = `Request from <strong>${esc(appName)}</strong>`;
  $('tx-details').innerHTML = buildTxRows(txJson);
  hideAlert('tx-warning');
}

function buildTxRows(txJson) {
  const rows = [];

  const row = (label, value, cls = '') =>
    `<div class="tx-row">
       <span class="tx-label">${label}</span>
       <span class="tx-value ${cls}">${value}</span>
     </div>`;

  rows.push(row('Type', esc(txJson.TransactionType), 'tx-type'));

  if (txJson.Account) {
    rows.push(row('From', `<span title="${esc(txJson.Account)}">${esc(truncAddr(txJson.Account))}</span>`, 'tx-address'));
  }

  if (txJson.Destination) {
    rows.push(row('To', `<span title="${esc(txJson.Destination)}">${esc(truncAddr(txJson.Destination))}</span>`, 'tx-address'));
  }

  if (txJson.DestinationTag !== undefined) {
    rows.push(row('Dest. Tag', esc(txJson.DestinationTag)));
  }

  if (txJson.Amount !== undefined) {
    rows.push(row('Amount', esc(formatAmount(txJson.Amount)), 'tx-amount'));
  }

  if (txJson.SendMax !== undefined) {
    rows.push(row('Send Max', esc(formatAmount(txJson.SendMax))));
  }

  // DEX offer fields
  if (txJson.TakerGets !== undefined) {
    rows.push(row('Sell (TakerGets)', esc(formatAmount(txJson.TakerGets))));
  }
  if (txJson.TakerPays !== undefined) {
    rows.push(row('Buy (TakerPays)', esc(formatAmount(txJson.TakerPays))));
  }

  // NFT fields
  if (txJson.NFTokenID) {
    rows.push(row('NFToken ID', `<span class="tx-address" title="${esc(txJson.NFTokenID)}">${esc(txJson.NFTokenID.slice(0, 16))}…</span>`));
  }

  if (txJson.Fee) {
    rows.push(row('Fee', esc(formatAmount(txJson.Fee)), 'tx-fee'));
  }

  if (txJson.Memos?.length) {
    const memoText = txJson.Memos.map(m => {
      try {
        return Buffer.from(m.Memo?.MemoData ?? '', 'hex').toString('utf8');
      } catch { return '(binary)'; }
    }).join(' / ');
    rows.push(row('Memo', esc(memoText)));
  }

  return rows.join('');
}

async function approveTransaction() {
  if (!state.pendingRequest) return;

  $('approve-tx-btn').disabled = true;
  $('reject-tx-btn').disabled = true;

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
    if (txResult !== 'tesSUCCESS') {
      throw new Error(`Transaction failed on ledger: ${txResult}`);
    }

    setTxStatus('success', 'Transaction validated!', hash);

    await respondWc(topic, id, {
      tx_json: response.result,
      tx_blob,
      hash,
    });

    state.pendingRequest = null;
    refreshBalance();

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
  $('reject-tx-btn').disabled = false;
}

/** Send a JSON-RPC response back to the connected dApp via WalletConnect. */
async function respondWc(topic, id, result, error) {
  if (!state.web3wallet) return;
  try {
    const response = error
      ? { id, jsonrpc: '2.0', error }
      : { id, jsonrpc: '2.0', result };
    await state.web3wallet.respondSessionRequest({ topic, response });
  } catch (err) {
    console.error('[respondWc]', err);
  }
}

// ─────────────────────────────────────────────
// WALLETCONNECT — SESSION LIST UI
// ─────────────────────────────────────────────

function updateSessionsUI() {
  if (!state.web3wallet) return;

  const sessions = state.web3wallet.getActiveSessions();
  const keys = Object.keys(sessions);
  const listEl = $('wc-sessions-list');
  const dot = $('wc-status');

  if (keys.length === 0) {
    dot.className = 'wc-status-dot wc-disconnected';
    listEl.innerHTML = '';
    return;
  }

  dot.className = 'wc-status-dot wc-connected';

  listEl.innerHTML = keys.map(topic => {
    const s = sessions[topic];
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
      </div>
    `;
  }).join('');

  listEl.querySelectorAll('.btn-disconnect').forEach(btn => {
    btn.addEventListener('click', () => disconnectSession(btn.dataset.topic));
  });
}

async function disconnectSession(topic) {
  try {
    await state.web3wallet.disconnectSession({
      topic,
      reason: getSdkError('USER_DISCONNECTED'),
    });
    updateSessionsUI();
  } catch (err) {
    console.error('[disconnect]', err);
  }
}

// ─────────────────────────────────────────────
// TX STATUS VIEW
// ─────────────────────────────────────────────

function setTxStatus(type, message, hash) {
  const iconEl = $('tx-status-icon');
  const titleEl = $('tx-status-title');
  const msgEl = $('tx-status-message');
  const hashContainer = $('tx-hash-container');
  const doneBtn = $('tx-done-btn');

  msgEl.textContent = message;
  hashContainer.classList.add('hidden');
  doneBtn.classList.add('hidden');

  if (type === 'pending') {
    iconEl.innerHTML = '<div class="spinner"></div>';
    titleEl.textContent = 'Processing…';
  } else if (type === 'success') {
    iconEl.innerHTML = '<div class="status-circle success">✓</div>';
    titleEl.textContent = 'Confirmed!';
    doneBtn.classList.remove('hidden');

    if (hash) {
      const explorer = NETWORKS[state.network].explorer;
      $('tx-hash-link').textContent = `${hash.slice(0, 10)}…${hash.slice(-10)}`;
      $('tx-hash-link').href = `${explorer}${hash}`;
      hashContainer.classList.remove('hidden');
    }
  } else if (type === 'error') {
    iconEl.innerHTML = '<div class="status-circle error">✕</div>';
    titleEl.textContent = 'Failed';
    doneBtn.classList.remove('hidden');
  }
}

// ─────────────────────────────────────────────
// EVENT LISTENERS
// ─────────────────────────────────────────────

// Import view
$('import-btn').addEventListener('click', importWallet);
$('seed-input').addEventListener('keypress', e => { if (e.key === 'Enter') importWallet(); });
$('toggle-seed-btn').addEventListener('click', () => {
  const input = $('seed-input');
  input.type = input.type === 'password' ? 'text' : 'password';
});

// Wallet view
$('logout-btn').addEventListener('click', logout);
$('refresh-balance-btn').addEventListener('click', refreshBalance);
$('copy-address-btn').addEventListener('click', async () => {
  if (!state.wallet) return;
  try {
    await navigator.clipboard.writeText(state.wallet.address);
    $('copy-toast').classList.remove('hidden');
    setTimeout(() => $('copy-toast').classList.add('hidden'), 1800);
  } catch {
    /* clipboard permission denied */
  }
});

// WalletConnect controls
$('wc-connect-btn').addEventListener('click', () => {
  if (!state.web3wallet) {
    showAlert('wc-error', 'WalletConnect is not initialized. Check Project ID configuration.');
    return;
  }
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
$('back-from-proposal-btn').addEventListener('click', async () => {
  await rejectSession();
});

// Transaction review
$('approve-tx-btn').addEventListener('click', approveTransaction);
$('reject-tx-btn').addEventListener('click', rejectTransaction);

// Transaction status
$('tx-done-btn').addEventListener('click', () => {
  showView('wallet');
  $('approve-tx-btn').disabled = false;
  $('reject-tx-btn').disabled = false;
});

// ─────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────

(async () => {
  const restored = await restoreSession();
  if (!restored) {
    showView('import');
  }
})();
