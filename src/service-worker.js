/**
 * Prompt Injection Sniffer - MV3 service worker.
 *
 * The worker is evicted whenever the browser feels like it, so it holds no
 * state in module scope. Everything lives in chrome.storage.local, keyed by
 * `tab_{tabId}`, and the badge is always written with an explicit tabId.
 */

const KEY_PREFIX = 'tab_';

const BADGE = {
  safe: { text: '', color: '#1f8f4e' },
  low: { text: '!', color: '#c8951a' },
  medium: { text: '!!', color: '#d1691f' },
  high: { text: '!!!', color: '#cc2b3d' }
};

function keyFor(tabId) {
  return `${KEY_PREFIX}${tabId}`;
}

async function setBadge(tabId, level) {
  const badge = BADGE[level] || BADGE.safe;
  try {
    await chrome.action.setBadgeText({ tabId, text: badge.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
  } catch (err) {
    // Tab closed between the scan and the badge write. Nothing to do.
  }
}

async function clearBadge(tabId) {
  try {
    await chrome.action.setBadgeText({ tabId, text: '' });
  } catch (err) {
    // Same as above - the tab is gone.
  }
}

async function storeResult(tabId, result) {
  await chrome.storage.local.set({ [keyFor(tabId)]: { ...result, tabId } });
  await setBadge(tabId, result.level);
}

async function clearTab(tabId) {
  await chrome.storage.local.remove(keyFor(tabId));
  await clearBadge(tabId);
}

/** Drop stored results for tabs that no longer exist (browser restart, crash). */
async function pruneOrphans() {
  const [stored, tabs] = await Promise.all([
    chrome.storage.local.get(null),
    chrome.tabs.query({})
  ]);
  const live = new Set(tabs.map((t) => keyFor(t.id)));
  const stale = Object.keys(stored).filter((k) => k.startsWith(KEY_PREFIX) && !live.has(k));
  if (stale.length > 0) await chrome.storage.local.remove(stale);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'SCAN_RESULT') return undefined;

  const tabId = sender.tab && sender.tab.id;
  if (typeof tabId !== 'number') return undefined;

  (async () => {
    await storeResult(tabId, message.result);
    sendResponse({ ok: true });
  })();

  return true; // response is delivered asynchronously
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.status === 'loading') await clearTab(tabId);
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  await chrome.storage.local.remove(keyFor(tabId));
});

chrome.runtime.onStartup.addListener(async () => {
  await pruneOrphans();
});

chrome.runtime.onInstalled.addListener(async () => {
  await pruneOrphans();
});
