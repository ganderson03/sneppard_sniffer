/**
 * Prompt Injection Sniffer - content script / detector
 *
 * Read-only scanner. It never modifies the page. It walks the live DOM looking
 * for text that reads like an instruction aimed at an AI assistant, then checks
 * whether that text was deliberately concealed from human eyes (hidden CSS,
 * off-screen positioning, comment nodes, attributes, meta tags).
 *
 * Design note: a finding always requires at least one keyword match. A hidden
 * element on its own is not evidence of anything - the whole web hides things
 * with display:none. Concealment raises the score of text that already looks
 * like an injection attempt.
 */

(() => {
  'use strict';

  // Re-injection via chrome.scripting.executeScript lands in the same isolated
  // world, so a second run would double up observers. Reuse the first instance.
  if (window.__PROMPT_INJECTION_SNIFFER__) {
    window.__PROMPT_INJECTION_SNIFFER__.rescan('manual');
    return;
  }

  const MAX_ELEMENTS = 6000;
  const MAX_TEXT_LEN = 4000;
  const MIN_TEXT_LEN = 8;
  const MAX_FINDINGS = 40;
  const PREVIEW_LEN = 120;
  const MUTATION_DEBOUNCE_MS = 1200;
  const ANCESTOR_DEPTH = 10;
  const RAF_BATCH_THRESHOLD = 20;

  const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'CANVAS']);

  /**
   * Weighted injection heuristics. `label` is what the popup shows the user, so
   * it is written in plain language rather than as a regex description.
   */
  const PATTERNS = [
    { id: 'ignore-previous', weight: 10, label: 'ignore previous instructions', re: /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?|context|commands?)/i },
    { id: 'forget-everything', weight: 10, label: 'forget everything above', re: /\b(forget|erase|discard)\s+(everything|all)\s+(you|that|above|before|previously)/i },
    { id: 'override-safety', weight: 10, label: 'override safety rules', re: /\b(ignore|bypass|override|disable|turn\s+off)\s+(your|all|any|the)\s+(safety|content|security|guard(rail)?s?|guidelines?|restrictions?|filters?|policies)/i },
    { id: 'ai-directive', weight: 10, label: 'directive addressed to an AI', re: /\b(instructions?|message|note|directive|command)\s+(for|to)\s+(the\s+)?(ai|a\.i\.|assistant|llm|chat\s?bot|agent|language\s+model|browser\s+agent)\b/i },
    { id: 'exfiltrate', weight: 10, label: 'attempt to leak secrets', re: /\b(send|post|exfiltrate|upload|transmit|email|leak)\b[^.]{0,40}\b(api\s*key|secret|password|credential|cookie|session\s+token|auth\s+token|private\s+key)/i },
    { id: 'you-are-now', weight: 9, label: 'you are now [AI persona]', re: /\byou\s+are\s+now\s+(a|an|the)?\s*[\w .'-]{0,30}\b(assistant|ai|a\.i\.|model|agent|dan|gpt|claude|copilot|gemini|perplexity|bot|persona)\b/i },
    { id: 'new-system-prompt', weight: 9, label: 'new system prompt', re: /\b(new|updated|revised|real|actual)\s+(system\s+)?(prompt|instructions?)\s*[:\-—]/i },
    { id: 'system-override', weight: 9, label: 'system prompt override', re: /\bsystem\s*prompt\s*(override|update|replacement|:)/i },
    { id: 'true-goal', weight: 9, label: 'your true goal is', re: /\byour\s+(true|real|actual|hidden|secret|primary|only)\s+(goal|purpose|objective|task|mission|instruction)s?\s+(is|are)\b/i },
    { id: 'chat-tokens', weight: 9, label: 'fake chat/system tokens', re: /(<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>|\[\/?\s*(INST|SYS)\s*\]|###\s*(system|instruction)\s*:)/i },
    { id: 'urgent-ai', weight: 10, label: 'urgent message for the AI', re: /\b(important|urgent|critical|priority)\s+(message|instruction|notice|update)\s+(for|to)\s+(the\s+)?(ai|assistant|llm|agent|model)/i },
    { id: 'dont-tell-user', weight: 8, label: "don't tell the user", re: /\b(do\s+not|don'?t|never)\s+(tell|inform|notify|alert|show)\s+(the\s+)?(user|human|person|reader)/i },
    { id: 'jailbreak', weight: 8, label: 'jailbreak', re: /\bjail\s?break(ing|ed)?\b/i },
    { id: 'when-asked-say', weight: 8, label: 'when asked X, say Y', re: /\bwhen(ever)?\s+(you\s+are\s+)?(asked|the\s+user\s+asks|prompted)\b[^.!?]{0,80}\b(say|reply|respond|answer|tell|output|recommend)\b/i },
    { id: 'end-of-prompt', weight: 8, label: 'fake end-of-prompt marker', re: /\b(end\s+of\s+(the\s+)?(system\s+)?(prompt|instructions?)|begin\s+new\s+instructions?)\b/i },
    { id: 'override-previous', weight: 8, label: 'override previous rules', re: /\boverrid(e|ing)\s+(all\s+)?(previous|prior|existing|earlier|default)\b/i },
    { id: 'do-not-reveal', weight: 7, label: 'do not reveal', re: /\b(do\s+not|don'?t|never)\s+(reveal|disclose|mention|repeat|summari[sz]e|quote|display)\b/i },
    { id: 'system-bracket', weight: 7, label: 'fake [system] block', re: /\[\s*(system|admin|developer|root)\s*\]\s*[:\-]?/i },
    { id: 'must-comply', weight: 7, label: 'you must comply', re: /\byou\s+(must|shall|have\s+to)\s+(now\s+)?(comply|obey|follow|execute|perform|do)\b/i },
    { id: 'dan', weight: 6, label: 'DAN prompt', re: /\bDAN\b(?!\w)/ },
    { id: 'developer-mode', weight: 6, label: 'developer mode', re: /\bdeveloper\s+mode\s+(enabled|on|activated)\b/i },
    { id: 'pretend', weight: 6, label: 'pretend to be', re: /\bpretend\s+(to\s+be|that\s+you|you\s+are)\b/i },
    { id: 'respond-only-with', weight: 6, label: 'respond only with', re: /\b(reply|respond|answer|output|say)\s+only\s+(with|the\s+following)\b/i },
    { id: 'navigate-to', weight: 6, label: 'instructs AI to visit a URL', re: /\b(navigate|browse|go|redirect)\s+to\s+https?:\/\//i },
    { id: 'act-as', weight: 5, label: 'act as', re: /\bact\s+as\s+(a|an|the|if)\b/i },
    { id: 'roleplay', weight: 5, label: 'roleplay as', re: /\brole\s?play\s+as\b/i },
    { id: 'from-now-on', weight: 5, label: 'from now on', re: /\bfrom\s+now\s+on\s*[,:]/i }
  ];

  const ATTRIBUTES = ['alt', 'aria-label', 'title', 'placeholder', 'data-tooltip'];

  const TYPE_LABELS = {
    hidden: 'Hidden element',
    offscreen: 'Off-screen element',
    comment: 'HTML comment',
    attribute: 'Attribute injection',
    meta: 'Meta tag',
    visible: 'Visible text'
  };

  const FLAG_LABELS = {
    'display:none': 'display:none',
    'visibility:hidden': 'visibility:hidden',
    'opacity<0.05': 'near-zero opacity',
    'font-size<2px': 'micro font size',
    'color=background': 'text colour matches background',
    'transparent-text': 'transparent text',
    'height:0': 'zero height',
    'width:0': 'zero width',
    'clip:rect(0,0,0,0)': 'clipped to nothing',
    'clip-path:inset(100%)': 'clip-path hides content',
    'zero-size': 'renders at zero size',
    'not-rendered': 'never painted',
    'text-indent-offscreen': 'text indented off-screen',
    'offscreen-left': 'positioned far off-screen (left)',
    'offscreen-top': 'positioned far off-screen (top)'
  };

  // ---------------------------------------------------------------- utilities

  function matchPatterns(text) {
    const hits = [];
    let score = 0;
    for (const p of PATTERNS) {
      if (p.re.test(text)) {
        hits.push({ id: p.id, label: p.label, weight: p.weight });
        score += p.weight;
      }
    }
    return { hits, score };
  }

  function normalise(text) {
    return text
      .replace(/[​-‏‪-‮⁠﻿]/g, '') // zero-width / bidi
      .replace(/\s+/g, ' ')
      .trim();
  }

  function preview(text) {
    return text.length > PREVIEW_LEN ? text.slice(0, PREVIEW_LEN - 1) + '…' : text;
  }

  function describe(el) {
    if (!el || !el.tagName) return '<unknown>';
    const tag = el.tagName.toLowerCase();
    if (el.id) return `<${tag}#${el.id}>`;
    const cls = (el.getAttribute('class') || '').trim().split(/\s+/)[0];
    return cls ? `<${tag}.${cls}>` : `<${tag}>`;
  }

  function parseColor(value) {
    if (!value) return null;
    const m = value.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const parts = m[1].split(/[,\s/]+/).filter(Boolean).map(Number);
    if (parts.length < 3 || parts.some(Number.isNaN)) return null;
    return { r: parts[0], g: parts[1], b: parts[2], a: parts.length > 3 ? parts[3] : 1 };
  }

  function effectiveBackground(el) {
    let node = el;
    let depth = 0;
    while (node && node.nodeType === 1 && depth < 20) {
      const c = parseColor(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0.05) return c;
      node = node.parentElement;
      depth += 1;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }

  function colorDistance(a, b) {
    return Math.abs(a.r - b.r) + Math.abs(a.g - b.g) + Math.abs(a.b - b.b);
  }

  /**
   * Collect concealment flags for an element and its ancestors. Ancestors
   * matter because `display:none` on a wrapper does not show up in the computed
   * style of the child that actually holds the text.
   */
  function concealmentFlags(el) {
    const flags = new Set();
    let node = el;
    let depth = 0;

    while (node && node.nodeType === 1 && depth < ANCESTOR_DEPTH) {
      const cs = getComputedStyle(node);

      if (cs.display === 'none') flags.add('display:none');
      if (cs.visibility === 'hidden' || cs.visibility === 'collapse') flags.add('visibility:hidden');

      const opacity = parseFloat(cs.opacity);
      if (!Number.isNaN(opacity) && opacity < 0.05) flags.add('opacity<0.05');

      const fontSize = parseFloat(cs.fontSize);
      if (!Number.isNaN(fontSize) && fontSize < 2) flags.add('font-size<2px');

      if (cs.clip === 'rect(0px, 0px, 0px, 0px)') flags.add('clip:rect(0,0,0,0)');
      if (/inset\(\s*100%/.test(cs.clipPath)) flags.add('clip-path:inset(100%)');

      const h = parseFloat(cs.height);
      const w = parseFloat(cs.width);
      if (cs.overflow === 'hidden' && h === 0) flags.add('height:0');
      if (cs.overflow === 'hidden' && w === 0) flags.add('width:0');

      const indent = parseFloat(cs.textIndent);
      if (!Number.isNaN(indent) && indent <= -1000) flags.add('text-indent-offscreen');

      if (node === el) {
        const color = parseColor(cs.color);
        if (color) {
          if (color.a < 0.05) {
            flags.add('transparent-text');
          } else if (colorDistance(color, effectiveBackground(node)) <= 24) {
            flags.add('color=background');
          }
        }
      }

      node = node.parentElement;
      depth += 1;
    }

    const rect = el.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) flags.add('zero-size');
    if (el.getClientRects().length === 0 && !flags.has('display:none')) flags.add('not-rendered');

    return flags;
  }

  function offscreenFlags(el) {
    const flags = new Set();
    let node = el;
    let depth = 0;

    while (node && node.nodeType === 1 && depth < ANCESTOR_DEPTH) {
      const cs = getComputedStyle(node);
      if (cs.position === 'absolute' || cs.position === 'fixed') {
        const left = parseFloat(cs.left);
        const top = parseFloat(cs.top);
        if (!Number.isNaN(left) && left < -500) flags.add('offscreen-left');
        if (!Number.isNaN(top) && top < -500) flags.add('offscreen-top');
      }
      node = node.parentElement;
      depth += 1;
    }

    const rect = el.getBoundingClientRect();
    if (rect.right < -500) flags.add('offscreen-left');
    if (rect.bottom < -500) flags.add('offscreen-top');

    return flags;
  }

  function ownText(el) {
    let text = '';
    for (const node of el.childNodes) {
      if (node.nodeType === 3) text += node.nodeValue;
    }
    return text;
  }

  // ------------------------------------------------------------------ scanner

  function collectTextCandidates() {
    const candidates = [];
    const all = document.body ? document.body.querySelectorAll('*') : [];
    const limit = Math.min(all.length, MAX_ELEMENTS);

    for (let i = 0; i < limit; i += 1) {
      const el = all[i];
      if (SKIP_TAGS.has(el.tagName)) continue;
      const text = normalise(ownText(el));
      if (text.length < MIN_TEXT_LEN || text.length > MAX_TEXT_LEN) continue;
      const { hits, score } = matchPatterns(text);
      if (hits.length === 0) continue;
      candidates.push({ el, text, hits, score });
    }
    return candidates;
  }

  /** Style reads for keyword-matched elements. Layout-thrashing, so it is kept
   *  in one pass and, above the batch threshold, deferred to an animation frame. */
  function classifyCandidates(candidates) {
    const findings = [];

    for (const c of candidates) {
      const hidden = concealmentFlags(c.el);
      const offscreen = offscreenFlags(c.el);
      const flags = [...hidden, ...offscreen];

      let type = 'visible';
      if (hidden.size > 0) type = 'hidden';
      else if (offscreen.size > 0) type = 'offscreen';

      // Plainly visible page text that merely discusses these phrases is not an
      // attack - a security blog would light up like a christmas tree. Only
      // report visible text when the wording is unambiguously an AI directive.
      if (type === 'visible' && !c.hits.some((h) => h.weight >= 9)) continue;

      findings.push(buildFinding(type, c.text, c.hits, c.score, flags, describe(c.el)));
    }

    return findings;
  }

  function scanComments() {
    const findings = [];
    const walker = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    let node = walker.nextNode();

    while (node) {
      const text = normalise(node.nodeValue || '');
      if (text.length >= MIN_TEXT_LEN && text.length <= MAX_TEXT_LEN) {
        const { hits, score } = matchPatterns(text);
        if (hits.length > 0) {
          const owner = node.parentElement;
          findings.push(
            buildFinding('comment', text, hits, score, ['html-comment'], `<!-- --> in ${describe(owner)}`)
          );
        }
      }
      node = walker.nextNode();
    }
    return findings;
  }

  function scanAttributes() {
    const findings = [];
    const selector = ATTRIBUTES.map((a) => `[${a}]`).join(',');
    const nodes = document.querySelectorAll(selector);

    for (let i = 0; i < nodes.length && i < MAX_ELEMENTS; i += 1) {
      const el = nodes[i];
      for (const attr of ATTRIBUTES) {
        const raw = el.getAttribute(attr);
        if (!raw) continue;
        const text = normalise(raw);
        if (text.length < MIN_TEXT_LEN || text.length > MAX_TEXT_LEN) continue;
        const { hits, score } = matchPatterns(text);
        if (hits.length === 0) continue;
        findings.push(buildFinding('attribute', text, hits, score, [`${attr} attribute`], describe(el)));
      }
    }
    return findings;
  }

  function scanMeta() {
    const findings = [];
    for (const meta of document.querySelectorAll('meta[content]')) {
      const text = normalise(meta.getAttribute('content') || '');
      if (text.length < MIN_TEXT_LEN || text.length > MAX_TEXT_LEN) continue;
      const { hits, score } = matchPatterns(text);
      if (hits.length === 0) continue;
      const name = meta.getAttribute('name') || meta.getAttribute('property') || 'meta';
      findings.push(buildFinding('meta', text, hits, score, ['meta content'], `<meta name="${name}">`));
    }
    return findings;
  }

  function buildFinding(type, text, hits, keywordScore, flags, element) {
    const cssFlags = flags.filter((f) => FLAG_LABELS[f]);
    const score = keywordScore + cssFlags.length * 3;
    return {
      type,
      typeLabel: TYPE_LABELS[type] || type,
      element,
      preview: preview(text),
      keywords: hits.map((h) => h.label),
      flags: flags.map((f) => FLAG_LABELS[f] || f),
      score
    };
  }

  function dedupe(findings) {
    const seen = new Set();
    const out = [];
    for (const f of findings) {
      const key = `${f.type}|${f.element}|${f.preview}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(f);
    }
    return out;
  }

  function levelFor(score) {
    if (score <= 0) return 'safe';
    if (score <= 5) return 'low';
    if (score <= 14) return 'medium';
    return 'high';
  }

  function buildResult(findings, reason) {
    const ranked = dedupe(findings).sort((a, b) => b.score - a.score);
    const trimmed = ranked.slice(0, MAX_FINDINGS);
    const total = ranked.reduce((sum, f) => sum + f.score, 0);

    return {
      level: levelFor(total),
      score: total,
      findingCount: ranked.length,
      truncated: ranked.length > trimmed.length,
      findings: trimmed,
      url: location.href,
      title: document.title || location.hostname,
      scannedAt: Date.now(),
      reason
    };
  }

  async function send(result) {
    try {
      await chrome.runtime.sendMessage({ type: 'SCAN_RESULT', result });
    } catch (err) {
      // The service worker may be asleep or the extension reloaded mid-scan.
      // Nothing to recover here - the next scan will report again.
    }
  }

  let scanning = false;

  async function scan(reason) {
    if (scanning || !document.body) return;
    scanning = true;
    try {
      const candidates = collectTextCandidates();

      // Style reads over many elements are batched into a single animation
      // frame so the page's own rendering is not interleaved with our layout
      // queries.
      const classified =
        candidates.length > RAF_BATCH_THRESHOLD
          ? await new Promise((resolve) => {
              requestAnimationFrame(() => resolve(classifyCandidates(candidates)));
            })
          : classifyCandidates(candidates);

      const findings = [...classified, ...scanComments(), ...scanAttributes(), ...scanMeta()];
      await send(buildResult(findings, reason));
    } finally {
      scanning = false;
    }
  }

  // --------------------------------------------------------------- lifecycle

  let debounceTimer = null;

  function scheduleScan(reason) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      scan(reason);
    }, MUTATION_DEBOUNCE_MS);
  }

  function significantMutation(records) {
    for (const r of records) {
      if (r.type === 'attributes') return true;
      if (r.addedNodes.length > 0) return true;
      if (r.type === 'characterData') return true;
    }
    return false;
  }

  const observer = new MutationObserver((records) => {
    if (significantMutation(records)) scheduleScan('mutation');
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true,
    attributes: true,
    attributeFilter: ['style', 'class', 'hidden', ...ATTRIBUTES]
  });

  window.__PROMPT_INJECTION_SNIFFER__ = {
    rescan: (reason) => scan(reason || 'manual')
  };

  scan('load');
})();
