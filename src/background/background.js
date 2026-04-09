/**
 * Background service worker.
 * Handles extension lifecycle and badge management.
 * WalletConnect sessions are managed in the popup while it's open.
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log('[XRPL Wallet] Extension installed');
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'UPDATE_BADGE') {
    const count = message.count || 0;
    chrome.action.setBadgeText({ text: count > 0 ? count.toString() : '' });
    if (count > 0) {
      chrome.action.setBadgeBackgroundColor({ color: '#6366f1' });
    }
    sendResponse({ ok: true });
  }
  return true;
});
