/**
 * Sneppard Sniffer - popup.
 *
 * Reads whatever the content script last stored for the active tab and renders
 * it. No inline handlers, no innerHTML with page-derived strings: every piece
 * of scanned text is inserted as a text node.
 */

const LEVEL_COPY = {
  safe: 'No threats detected on this page.',
  low: 'Something mildly suspicious turned up.',
  medium: 'This page contains text that looks aimed at an AI assistant.',
  high: 'This page is actively trying to give instructions to an AI assistant.'
};

const VECTOR_COPY = {
  hidden_css: 'hidden by CSS',
  offscreen: 'off-screen',
  comment: 'HTML comment',
  attribute: 'attribute',
  meta: 'meta tag',
  unicode: 'invisible characters',
  homoglyph: 'disguised characters',
  template: 'inert container',
  visible: 'visible text'
};

const RESCAN_TIMEOUT_MS = 3000;
const RESCAN_POLL_MS = 150;

const els = {
  status: document.getElementById('status'),
  level: document.getElementById('status-level'),
  summary: document.getElementById('status-summary'),
  host: document.getElementById('status-host'),
  vectors: document.getElementById('vectors'),
  empty: document.getElementById('empty'),
  notice: document.getElementById('notice'),
  findings: document.getElementById('findings'),
  rescan: document.getElementById('rescan')
};

function summaryFor(result) {
  if (result.level === 'error') {
    return 'The scanner could not finish on this page.';
  }
  if (result.level === 'safe' || result.findingCount === 0) return LEVEL_COPY.safe;
  const n = result.findingCount;
  const noun = n === 1 ? 'suspicious pattern' : 'suspicious patterns';
  return `${n} ${noun} found. ${LEVEL_COPY[result.level] || ''}`.trim();
}

function hostFor(result) {
  try {
    return new URL(result.url).hostname;
  } catch (err) {
    return result.url || '';
  }
}

function findingLevel(score) {
  if (score >= 15) return 'high';
  if (score >= 6) return 'medium';
  return 'low';
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function metaLine(label, value) {
  const p = el('p', 'finding__meta');
  p.append(el('b', null, `${label} `), document.createTextNode(value));
  return p;
}

function renderFinding(finding) {
  const li = el('li', `finding finding--${findingLevel(finding.score)}`);

  const head = el('div', 'finding__head');
  head.append(
    el('span', 'finding__type', finding.typeLabel),
    el('span', 'finding__element', finding.element),
    el('span', 'finding__score', `+${finding.score}`)
  );

  li.append(head, el('p', 'finding__quote', finding.preview));

  if (finding.keywords && finding.keywords.length > 0) {
    li.append(metaLine('matched', finding.keywords.join(', ')));
  }
  if (finding.flags && finding.flags.length > 0) {
    li.append(metaLine('concealed by', finding.flags.join(', ')));
  }

  return li;
}

function setStatus(level, levelText, summary, host) {
  els.status.className = `status status--${level}`;
  els.level.textContent = levelText;
  els.summary.textContent = summary;
  els.host.textContent = host || '';
}

function showNotice(text) {
  if (!text) {
    els.notice.hidden = true;
    els.notice.textContent = '';
    return;
  }
  els.notice.textContent = text;
  els.notice.hidden = false;
}

/** One-line coverage breakdown: which vectors fired, and how often. */
function showVectors(result) {
  const counts = result && result.vectors ? result.vectors : null;
  const entries = counts ? Object.entries(counts) : [];
  if (entries.length === 0) {
    els.vectors.hidden = true;
    els.vectors.textContent = '';
    return;
  }
  els.vectors.textContent = entries
    .sort((a, b) => b[1] - a[1])
    .map(([vector, n]) => `${VECTOR_COPY[vector] || vector} ×${n}`)
    .join('  ·  ');
  els.vectors.hidden = false;
}

function render(result) {
  els.findings.replaceChildren();

  if (!result) {
    setStatus(
      'unknown',
      'NO DATA',
      'This page has not been scanned. Browser pages and the Chrome Web Store cannot be scanned.',
      ''
    );
    els.empty.hidden = true;
    showVectors(null);
    showNotice(null);
    return;
  }

  const levelText = result.level === 'error' ? 'ERROR' : result.level.toUpperCase();
  setStatus(result.level, levelText, summaryFor(result), hostFor(result));

  const hasFindings = result.findings && result.findings.length > 0;
  els.empty.hidden = hasFindings || result.level === 'error';
  showVectors(result);

  if (result.level === 'error') {
    showNotice(result.error ? `Scanner error: ${result.error}` : 'Scanner error.');
  } else if (result.truncated) {
    showNotice(
      `Showing the ${result.findings.length} highest-scoring of ${result.findingCount} findings.`
    );
  } else {
    showNotice(null);
  }

  if (!hasFindings) return;

  const frame = document.createDocumentFragment();
  for (const finding of result.findings) frame.append(renderFinding(finding));
  els.findings.append(frame);
}

async function activeTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function readResult(tabId) {
  const key = `tab_${tabId}`;
  const stored = await chrome.storage.local.get(key);
  return stored[key] || null;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function rescan() {
  const tab = await activeTab();
  if (!tab || typeof tab.id !== 'number') return;

  const before = await readResult(tab.id);
  const previousStamp = before ? before.scannedAt : 0;

  els.rescan.disabled = true;
  els.rescan.textContent = 'SCANNING…';

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      files: ['src/detector.js']
    });

    const deadline = Date.now() + RESCAN_TIMEOUT_MS;
    let result = null;
    while (Date.now() < deadline) {
      await sleep(RESCAN_POLL_MS);
      const candidate = await readResult(tab.id);
      if (candidate && candidate.scannedAt > previousStamp) {
        result = candidate;
        break;
      }
    }

    render(result || before);
    if (!result) showNotice('Re-scan timed out. The page may still be loading.');
  } catch (err) {
    render(before);
    showNotice(
      'This page cannot be scanned. Chrome blocks extensions on browser and Web Store pages.'
    );
  } finally {
    els.rescan.disabled = false;
    els.rescan.textContent = 'RE-SCAN PAGE';
  }
}

async function init() {
  els.rescan.addEventListener('click', rescan);

  const tab = await activeTab();
  if (!tab || typeof tab.id !== 'number') {
    render(null);
    return;
  }
  render(await readResult(tab.id));
}

init();
