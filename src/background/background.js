/**
 * Background service worker.
 *
 * Owns the WalletConnect Web3Wallet instance so events are received even when
 * the popup is closed.  When a session proposal or transaction request arrives
 * the pending event is stored in chrome.storage.session, the extension badge
 * is updated, and chrome.action.openPopup() is called so the popup can handle
 * the user interaction.
 *
 * The popup communicates with this worker via chrome.runtime.sendMessage.
 */

import { Core } from '@walletconnect/core';
import { Web3Wallet } from '@walletconnect/web3wallet';
import { getSdkError } from '@walletconnect/utils';

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────

const WC_PROJECT_ID = '545f3b40384efe9b93401c1dd8d0ceb0';

const WC_METADATA = {
  name: 'XRPL Dev Wallet',
  description: 'XRPL Devnet Chrome Extension Wallet — for development use only',
  url: 'https://github.com/oz-ross/xrpl-dev-wallet-extension',
  icons: [],
};

// ─────────────────────────────────────────────
// STATE
// ─────────────────────────────────────────────

/** @type {import('@walletconnect/web3wallet').Web3Wallet|null} */
let web3wallet = null;
let initPromise = null;

// ─────────────────────────────────────────────
// WALLETCONNECT — INIT
// ─────────────────────────────────────────────

async function initWalletConnect() {
  if (web3wallet) return web3wallet;
  if (initPromise) return initPromise;

  initPromise = (async () => {
    console.log('[bg] WC init: creating Core…');
    const core = new Core({ projectId: WC_PROJECT_ID });

    // Do NOT race against a timeout here — if the relay handshake is slow,
    // a timeout would clear initPromise while Web3Wallet.init() is still
    // running, causing a second Core to be created on the next call and
    // triggering the "already initialized" warning.  The popup-level timeout
    // on sendToBackground() is the safety net for the user-facing side.
    console.log('[bg] WC init: calling Web3Wallet.init…');
    web3wallet = await Web3Wallet.init({ core, metadata: WC_METADATA });
    console.log('[bg] WC init: complete');

    // Replace any stale listeners (service worker may restart and re-run this)
    web3wallet.removeAllListeners?.('session_proposal');
    web3wallet.removeAllListeners?.('session_request');
    web3wallet.removeAllListeners?.('session_delete');

    web3wallet.on('session_proposal', onSessionProposal);
    web3wallet.on('session_request',  onSessionRequest);
    web3wallet.on('session_delete',   onSessionDelete);

    return web3wallet;
  })().catch(err => {
    console.error('[bg] WC init failed:', err);
    initPromise = null;
    throw err;
  });

  return initPromise;
}

// ─────────────────────────────────────────────
// WALLETCONNECT — EVENT HANDLERS
// ─────────────────────────────────────────────

async function onSessionProposal(proposal) {
  // Serialise only the fields the popup needs (live SDK objects aren't
  // JSON-safe and can't cross the message boundary).
  const pending = {
    type:   'proposal',
    id:     proposal.id,
    params: {
      id:        proposal.params.id,
      proposer:  { metadata: proposal.params.proposer.metadata },
      requiredNamespaces: proposal.params.requiredNamespaces ?? {},
    },
  };

  await chrome.storage.session.set({ wcPending: pending });
  setBadge(1);
  // Notify the popup if it is already open; also try to open it.
  chrome.runtime.sendMessage({ type: 'WC_PROPOSAL', data: pending }).catch(() => {});
  await tryOpenPopup();
}

async function onSessionRequest(event) {
  const { method } = event.params.request;

  // Reject unsupported methods immediately — no need to bother the user.
  if (method !== 'xrpl_signTransaction' && method !== 'xrpl_signTransactionFor') {
    await web3wallet.respondSessionRequest({
      topic:    event.topic,
      response: { id: event.id, jsonrpc: '2.0', error: getSdkError('UNSUPPORTED_METHODS') },
    });
    return;
  }

  const sessions = web3wallet.getActiveSessions();
  const session  = sessions[event.topic];
  const address  = extractAddressFromSession(session);

  const pending = {
    type:    'request',
    topic:   event.topic,
    id:      event.id,
    params:  event.params,          // { request: { method, params: { tx_json } }, chainId }
    address,                        // r-address the session was approved for
    appName: session?.peer?.metadata?.name ?? 'Unknown App',
  };

  await chrome.storage.session.set({ wcPending: pending });
  setBadge(1);
  chrome.runtime.sendMessage({ type: 'WC_REQUEST', data: pending }).catch(() => {});
  await tryOpenPopup();
}

async function onSessionDelete() {
  // If the deleted session had a pending request, clear it.
  const { wcPending } = await chrome.storage.session.get('wcPending');
  if (wcPending?.type === 'request') {
    await chrome.storage.session.set({ wcPending: null });
    setBadge(0);
  }
  chrome.runtime.sendMessage({ type: 'WC_SESSIONS_CHANGED' }).catch(() => {});
}

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

/**
 * Extract the r-address from the first account listed in the xrpl namespace.
 * Account entries have the form  "xrpl:2:rXXXXXXXXXXXXXXXX".
 */
function extractAddressFromSession(session) {
  const accounts = session?.namespaces?.xrpl?.accounts ?? [];
  if (!accounts.length) return null;
  const parts = accounts[0].split(':');
  return parts.length >= 3 ? parts[2] : null;
}

function setBadge(count) {
  chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
  if (count > 0) chrome.action.setBadgeBackgroundColor({ color: '#6366f1' });
}

/**
 * Attempt to programmatically open the extension popup (Chrome 127+).
 * Falls back to a system notification so the user is still informed.
 */
async function tryOpenPopup() {
  try {
    await chrome.action.openPopup();
  } catch {
    chrome.notifications.create('wc-pending', {
      type:               'basic',
      iconUrl:            'icons/icon48.png',
      title:              'XRPL Dev Wallet',
      message:            'New WalletConnect request — click to review',
      requireInteraction: true,
    });
  }
}

// ─────────────────────────────────────────────
// MESSAGE API  (popup → background)
// ─────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then(sendResponse)
    .catch(err => {
      console.error('[bg] message handler error:', err);
      sendResponse({ ok: false, error: err.message });
    });
  return true; // keep the channel open for async response
});

async function handleMessage(msg) {
  switch (msg.type) {

    case 'WC_INIT': {
      const wc = await initWalletConnect();
      return { ok: true, sessions: wc.getActiveSessions() };
    }

    case 'WC_PAIR': {
      const wc = await initWalletConnect();
      // Fire-and-forget: pair() can take several seconds to connect to the
      // relay.  The session_proposal event arrives asynchronously regardless,
      // so there is no need to await here — returning immediately prevents the
      // popup message channel from timing out.
      wc.core.pairing.pair({ uri: msg.uri }).catch(err => {
        console.error('[bg] WC pairing error:', err);
      });
      return { ok: true };
    }

    case 'WC_GET_SESSIONS': {
      const sessions = web3wallet?.getActiveSessions() ?? {};
      return { ok: true, sessions };
    }

    case 'WC_APPROVE_SESSION': {
      const wc = await initWalletConnect();
      await wc.approveSession({ id: msg.id, namespaces: msg.namespaces });
      await chrome.storage.session.set({ wcPending: null });
      setBadge(0);
      return { ok: true, sessions: wc.getActiveSessions() };
    }

    case 'WC_REJECT_SESSION': {
      const wc = await initWalletConnect();
      await wc.rejectSession({ id: msg.id, reason: msg.reason });
      await chrome.storage.session.set({ wcPending: null });
      setBadge(0);
      return { ok: true };
    }

    case 'WC_DISCONNECT': {
      const wc = await initWalletConnect();
      await wc.disconnectSession({ topic: msg.topic, reason: msg.reason });
      return { ok: true, sessions: wc.getActiveSessions() };
    }

    case 'WC_RESPOND': {
      const wc = await initWalletConnect();
      await wc.respondSessionRequest({ topic: msg.topic, response: msg.response });
      await chrome.storage.session.set({ wcPending: null });
      setBadge(0);
      return { ok: true };
    }

    case 'WC_CLEAR_PENDING': {
      await chrome.storage.session.set({ wcPending: null });
      setBadge(0);
      return { ok: true };
    }

    case 'UPDATE_BADGE': {
      setBadge(msg.count ?? 0);
      return { ok: true };
    }

    default:
      return { ok: false, error: `Unknown message type: ${msg.type}` };
  }
}

// ─────────────────────────────────────────────
// LIFECYCLE
// ─────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(() => {
  console.log('[XRPL Wallet] Extension installed/updated');
  initWalletConnect().catch(err => console.error('[bg] WC init on install:', err));
});

// Open popup when notification is clicked (fallback path)
chrome.notifications.onClicked.addListener(() => {
  chrome.action.openPopup().catch(() => {});
  chrome.notifications.clear('wc-pending');
});

// Eagerly initialize on every service worker start so sessions are restored
// from the WalletConnect SDK's internal IndexedDB store and the event
// listeners are attached before any request could arrive.
initWalletConnect().catch(err => console.error('[bg] WC init on startup:', err));
