import './popup.css';
import { Client, Wallet, dropsToXrp, encodeAccountID, decodeMPTokenMetadata } from 'xrpl';
import QRCode from 'qrcode';
import { Core } from '@walletconnect/core';
import { Web3Wallet } from '@walletconnect/web3wallet';
import { getSdkError } from '@walletconnect/utils';

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

// XRPL epoch offset (seconds between Unix epoch and XRPL epoch)
const XRPL_EPOCH_OFFSET = 946684800;

const AUTO_REFRESH_INTERVAL = 30_000; // ms

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
  network: 'devnet',
  /** @type {any|null} */
  pendingProposal: null,
  /** @type {any|null} */
  pendingRequest: null,
  /** @type {ReturnType<typeof setInterval>|null} */
  refreshTimer: null,
};

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function $(id) { return document.getElementById(id); }

function showView(name) {
  for (const el of document.querySelectorAll('.view')) el.classList.add('hidden');
  $(`view-${name}`).classList.remove('hidden');
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

// ─────────────────────────────────────────────
// WALLET — IMPORT & RESTORE
// ─────────────────────────────────────────────

async function importWallet() {
  const seed = $('seed-input').value.trim();
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

    await chrome.storage.session.set({
      walletSeed: seed,
      walletAddress: wallet.address,
      network: 'devnet',
    });

    state.wallet = wallet;
    state.network = 'devnet';

    await connectXRPL();
    updateWalletUI();
    showView('wallet');

    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
    initWalletConnect();
    startAutoRefresh();

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
    state.network = network || 'devnet';
    await connectXRPL();
    updateWalletUI();
    showView('wallet');
    refreshBalance();
    loadIouBalances();
    loadMptBalances();
    loadTxHistory();
    await initWalletConnect();
    startAutoRefresh();
    return true;
  } catch {
    await chrome.storage.session.clear();
    return false;
  }
}

function logout() {
  if (!confirm('Remove wallet from this session?\nYou will need to re-import your seed.')) return;
  stopAutoRefresh();
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

// Decode a 40-char hex currency code to a human-readable string where possible
function formatCurrencyCode(currency) {
  if (currency.length !== 40) return currency; // standard 3-char code passes through unchanged
  // Try to decode as ASCII (strip leading/trailing zero padding)
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
  if (typeof amount === 'string') return 'XRP'; // drops string = XRP
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

    // Check every issuer for AMM status in parallel
    const ammResults = await Promise.all(lines.map(l => tryFetchAmmInfo(l.account)));
    const regularLines = lines.filter((_, i) => ammResults[i] === null);
    const ammLines     = lines
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

  // Only show lines where we hold a positive balance
  const held = lines.filter(l => parseFloat(l.balance) > 0);

  if (!held.length) {
    card.classList.add('hidden');
    return;
  }

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

  const held = lines.filter(l => parseFloat(l.balance) > 0);

  if (!held.length) {
    card.classList.add('hidden');
    return;
  }

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

// Derive the XRPL classic address from an MPTokenIssuanceID.
// The issuance ID is 48 hex chars: [8 hex seq][40 hex accountID]
function issuerFromMptIssuanceId(issuanceId) {
  if (!issuanceId || issuanceId.length !== 48) return null;
  try {
    const accountIdHex = issuanceId.slice(8); // last 40 hex chars = 20 bytes
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
    const node = resp.result.node ?? {};
    const assetScale = node.AssetScale ?? 0;
    const metadata = node.MPTokenMetadata;
    let ticker = null;
    if (metadata) {
      const decoded = decodeMPTokenMetadata(metadata);
      ticker = (typeof decoded?.ticker === 'string' && decoded.ticker) ? decoded.ticker : null;
    }
    return { ticker, assetScale };
  } catch {
    return { ticker: null, assetScale: 0 };
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

    // Fetch issuance info (ticker + asset scale) for all MPTs in parallel
    const infos = await Promise.all(objects.map(o => fetchMptIssuanceInfo(o.MPTokenIssuanceID)));
    const issuanceMap = new Map(objects.map((o, i) => [o.MPTokenIssuanceID, infos[i]]));

    renderMptBalances(objects, issuanceMap);
  } catch (err) {
    if (err.data?.error === 'actNotFound' || err.message?.includes('Account not found')) {
      renderMptBalances([]);
    } else {
      // MPTs may not be supported on all nodes; fail silently
      renderMptBalances([], new Map());
      console.error('[mpt balances]', err);
    }
  }
}

function renderMptBalances(objects, issuanceMap = new Map()) {
  const card   = $('mpt-balance-card');
  const listEl = $('mpt-balance-list');

  const held = objects.filter(o => o.LedgerEntryType === 'MPToken');

  if (!held.length) {
    card.classList.add('hidden');
    return;
  }

  card.classList.remove('hidden');
  const explorerMpt = NETWORKS[state.network].explorerMpt;
  listEl.innerHTML = held.map(obj => {
    const issuanceId = obj.MPTokenIssuanceID ?? '';
    const { ticker, assetScale } = issuanceMap.get(issuanceId) ?? { ticker: null, assetScale: 0 };
    const raw        = obj.MPTAmount ? parseInt(obj.MPTAmount, 10) : 0;
    const scaled     = assetScale > 0 ? raw / Math.pow(10, assetScale) : raw;
    const amount     = scaled.toLocaleString(undefined, { maximumFractionDigits: assetScale });
    const shortId    = issuanceId.length >= 12
      ? `${issuanceId.slice(0, 8)}…${issuanceId.slice(-4)}`
      : issuanceId;
    const displayName = ticker || shortId;
    const issuer      = issuerFromMptIssuanceId(issuanceId);
    const issuerDisplay = issuer ? truncAddr(issuer) : (issuanceId.slice(8, 16) + '…');
    const href        = `${explorerMpt}${issuanceId}`;

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

function updateWalletUI() {
  const addr = state.wallet.address;
  $('account-address').textContent = truncAddr(addr);
  $('account-address').title = addr;

  const net = NETWORKS[state.network];
  $('account-explorer-link').href = `${net.explorerAccount}${addr}`;

  const badge = $('network-badge');
  badge.textContent = net.name;
  badge.className = `network-badge ${state.network}`;
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
  const btn = $('faucet-btn');
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

    // The faucet takes a few seconds to settle; clear the status once updated
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
    // xrpl.js v4 shape: { tx_json, meta, validated }
    const txJson = entry.tx_json ?? entry.tx ?? {};
    const meta   = entry.meta ?? entry.metaData ?? {};
    const result = meta.TransactionResult ?? '—';
    const success = result === 'tesSUCCESS';
    const hash = entry.hash ?? txJson.hash ?? '—';
    const type = txJson.TransactionType ?? '—';

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

    const date = xrplDateToLocal(txJson.date);
    const dateStr = date ? date.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' }) : '';
    const href = hash !== '—' ? `${explorer}${hash}` : null;
    const tag  = href ? `a` : `div`;
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
// WALLETCONNECT — INIT
// ─────────────────────────────────────────────

async function initWalletConnect() {
  if (state.web3wallet) {
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
        name: 'XRPL Dev Wallet',
        description: 'XRPL Devnet Chrome Extension Wallet — for development use only',
        url: 'https://github.com/oz-ross/xrpl-dev-wallet-extension',
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
  wc.removeAllListeners?.('session_proposal');
  wc.removeAllListeners?.('session_request');
  wc.removeAllListeners?.('session_delete');

  wc.on('session_proposal', onSessionProposal);
  wc.on('session_request',  onSessionRequest);
  wc.on('session_delete',   () => updateSessionsUI());
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
          chains:   [chainId],
          accounts: [`${chainId}:${state.wallet.address}`],
          methods:  ['xrpl_signTransaction', 'xrpl_signTransactionFor'],
          events:   [],
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
    respondWc(event.topic, event.id, null, getSdkError('UNSUPPORTED_METHODS'));
  }
}

function renderTransactionView(event) {
  const txJson = event.params.request.params.tx_json;
  const sessions = state.web3wallet.getActiveSessions();
  const session  = sessions[event.topic];
  const appName  = session?.peer?.metadata?.name ?? 'Unknown App';

  $('tx-from-app').innerHTML = `Request from <strong>${esc(appName)}</strong>`;
  $('tx-details').innerHTML  = buildTxRows(txJson);
  hideAlert('tx-warning');

  // Populate raw JSON but keep it hidden
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
  const keys     = Object.keys(sessions);
  const listEl   = $('wc-sessions-list');
  const dot      = $('wc-status');

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
  const iconEl        = $('tx-status-icon');
  const titleEl       = $('tx-status-title');
  const msgEl         = $('tx-status-message');
  const hashContainer = $('tx-hash-container');
  const doneBtn       = $('tx-done-btn');

  msgEl.textContent = message;
  hashContainer.classList.add('hidden');
  doneBtn.classList.add('hidden');

  if (type === 'pending') {
    iconEl.innerHTML   = '<div class="spinner"></div>';
    titleEl.textContent = 'Processing…';
  } else if (type === 'success') {
    iconEl.innerHTML   = '<div class="status-circle success">✓</div>';
    titleEl.textContent = 'Confirmed!';
    doneBtn.classList.remove('hidden');
    if (hash) {
      const explorer = NETWORKS[state.network].explorer;
      $('tx-hash-link').textContent = `${hash.slice(0, 10)}…${hash.slice(-10)}`;
      $('tx-hash-link').href        = `${explorer}${hash}`;
      hashContainer.classList.remove('hidden');
    }
  } else if (type === 'error') {
    iconEl.innerHTML   = '<div class="status-circle error">✕</div>';
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
  input.type  = input.type === 'password' ? 'text' : 'password';
});

// Wallet view
$('logout-btn').addEventListener('click', logout);
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
  if (!state.web3wallet) {
    showAlert('wc-error', 'WalletConnect is not initialised. Check Project ID configuration.');
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
// BOOT
// ─────────────────────────────────────────────

(async () => {
  const restored = await restoreSession();
  if (!restored) showView('import');
})();
