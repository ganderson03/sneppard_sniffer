/**
 * Sneppard Sniffer - content script / detector
 *
 * Read-only scanner. It never modifies the page. It walks the live DOM looking
 * for text that reads like an instruction aimed at an AI assistant, then checks
 * whether that text was deliberately concealed from human eyes (hidden CSS,
 * off-screen positioning, comment nodes, attributes, meta tags, inert
 * containers, invisible Unicode, mixed-script homoglyphs).
 *
 * Two rules hold everywhere except the Unicode vector:
 *   1. A finding always requires a keyword hit. A hidden element on its own is
 *      not evidence of anything - the whole web hides things with display:none.
 *   2. Plainly visible text is only reported when it trips a weight >= 9
 *      pattern, so an article about prompt injection does not light up.
 *
 * The Unicode vector is the deliberate exception: runs of zero-width or Unicode
 * tag characters in body text are almost never legitimate, so they are reported
 * on their own.
 */

(() => {
  'use strict';

  // Re-injection via chrome.scripting.executeScript lands in the same isolated
  // world, so a second run would double up observers. Reuse the first instance.
  if (window.__SNEPPARD_SNIFFER__) {
    window.__SNEPPARD_SNIFFER__.rescan('manual');
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

  // Scoring
  const FLAG_BONUS = 3;
  const MAX_SCORED_FLAGS = 4; // one element cannot dominate on concealment alone
  const FINDING_SCORE_CAP = 30;
  const A11Y_FACTOR = 0.5;
  const UNICODE_WEIGHT = 9;
  const HOMOGLYPH_WEIGHT = 6;
  const DENSITY_FLOOR = 3; // findings beyond this start applying the multiplier
  const DENSITY_STEP = 0.05;
  const DENSITY_MAX = 1.5;
  const COLOR_MATCH_THRESHOLD = 28; // redmean perceptual distance

  const SKIP_TAGS = new Set([
    'SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE', 'SVG', 'CANVAS',
    'OPTION', 'OPTGROUP', 'SELECT', 'DATALIST'
  ]);

  // Accessibility utility classes. Screen-reader-only text is legitimately
  // invisible, but attackers do hide behind the convention, so findings on
  // these elements are halved rather than dropped.
  const A11Y_CLASS = /(^|[\s_-])(sr[-_]?only|visually[-_]?hidden|visuallyhidden|screen[-_]?reader[-_]?text|a11y[-_]?hidden|hidden[-_]?visually|assistive[-_]?text)([\s_-]|$)/i;

  // Zero-width, word-joiner, BOM, and the Unicode tag block (U+E0000-U+E007F)
  // used to smuggle ASCII text that renders as nothing at all.
  const INVISIBLE_CHARS = /[​-‍⁠﻿]|[\u{E0000}-\u{E007F}]/gu;
  const INVISIBLE_RUN = /(?:[​-‍⁠﻿]{3,})|(?:[\u{E0000}-\u{E007F}]{3,})/u;
  const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
  const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g;

  const LATIN = /[A-Za-z]/;
  const CYRILLIC = /[Ѐ-ӿ]/;
  const GREEK = /[Ͱ-Ͽ]/;

  // Lookalikes used to slip keyword filters. Folding these before matching is
  // what makes the homoglyph vector work at all - the raw text would never hit
  // an ASCII pattern.
  const CONFUSABLES = {
    'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm',
    'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't',
    'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
    'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ѡ': 'w',
    'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M',
    'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
    'У': 'Y', 'Х': 'X', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J',
    'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
    'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'γ': 'y',
    'ς': 's', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z',
    'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
    'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X'
  };
  const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'g');

  const VECTORS = {
    hidden_css: 'Hidden element',
    offscreen: 'Off-screen element',
    comment: 'HTML comment',
    attribute: 'Attribute injection',
    meta: 'Meta tag',
    unicode: 'Invisible characters',
    homoglyph: 'Disguised characters',
    template: 'Inert container',
    visible: 'Visible text'
  };

  const FLAG_LABELS = {
    'display:none': 'display:none',
    'visibility:hidden': 'visibility:hidden',
    'opacity<0.05': 'near-zero opacity',
    'font-size<2px': 'micro font size',
    'color=background': 'text colour matches its background',
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

  const ATTRIBUTES = ['alt', 'aria-label', 'title', 'placeholder'];

  // Framing that marks visible text as writing *about* injection rather than an
  // attempt at it. Only ever applied to plainly visible text - concealment
  // always wins, because nobody hides a worked example.
  const EXPLANATORY = /\b(for example|for instance|such as|e\.g\.|i\.e\.|phrases? like|words? like|text like|things like|looks? like this|known as|called|referred to as|example of|demonstrat(e|es|ing|ion)|attackers?|adversar(y|ial)|malicious|prompt injection|injection attack)\b/i;
  const QUOTE_CONTAINERS = 'blockquote, q, code, pre, samp, kbd, figure, cite, .quote, .example';
  const QUOTED_SPAN = /["“”'‘’«»][^"“”'‘’«»]{5,}["“”'‘’«»]/g;

  // ------------------------------------------------------------ pattern load

  let patterns = null;

  async function loadPatterns() {
    if (patterns) return patterns;
    const mod = await import(chrome.runtime.getURL('src/patterns.js'));
    patterns = mod.PATTERNS;
    return patterns;
  }

  // ---------------------------------------------------------------- utilities

  function stripInvisible(text) {
    return text.replace(INVISIBLE_CHARS, '').replace(BIDI_CONTROLS, '');
  }

  function normalise(text) {
    return stripInvisible(text).replace(/\s+/g, ' ').trim();
  }

  /** Fold Cyrillic/Greek lookalikes to Latin so disguised keywords still match. */
  function fold(text) {
    return text.replace(CONFUSABLE_RE, (ch) => CONFUSABLES[ch] || ch);
  }

  function isMixedScript(text) {
    return LATIN.test(text) && (CYRILLIC.test(text) || GREEK.test(text));
  }

  function matchPatterns(text) {
    const folded = fold(text);
    const hits = [];
    let score = 0;
    for (const p of patterns) {
      if (p.re.test(folded)) {
        hits.push({ id: p.id, label: p.label, weight: p.weight });
        score += p.weight;
      }
    }
    return { hits, score };
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

  /** Nearest ancestor background that is actually opaque enough to see. */
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

  /**
   * Redmean colour distance - a cheap perceptual approximation that behaves far
   * better than raw RGB difference near the extremes. Comparing against the
   * resolved ancestor background catches white-on-white, black-on-black and
   * every off-brand pairing in between, rather than two hardcoded colours.
   */
  function perceptualDistance(a, b) {
    const rm = (a.r + b.r) / 2;
    const dr = a.r - b.r;
    const dg = a.g - b.g;
    const db = a.b - b.b;
    return Math.sqrt((2 + rm / 256) * dr * dr + 4 * dg * dg + (2 + (255 - rm) / 256) * db * db);
  }

  function isA11yUtility(el) {
    let node = el;
    let depth = 0;
    while (node && node.nodeType === 1 && depth < ANCESTOR_DEPTH) {
      const cls = node.getAttribute('class');
      if (cls && A11Y_CLASS.test(cls)) return true;
      node = node.parentElement;
      depth += 1;
    }
    return false;
  }

  /**
   * True when visible text is discussing injection rather than attempting it:
   * sitting in a quotation/code container, framed by explanatory language, or
   * only tripping strong patterns inside quotation marks.
   */
  function isExplanatory(el, text) {
    if (EXPLANATORY.test(text)) return true;
    if (el && el.closest && el.closest(QUOTE_CONTAINERS)) return true;
    const unquoted = text.replace(QUOTED_SPAN, ' ');
    if (unquoted !== text) {
      const { hits } = matchPatterns(unquoted);
      if (!hits.some((h) => h.weight >= 9)) return true;
    }
    return false;
  }

  /** Content the page hides by design, where hiding carries no signal. */
  function isLegitimatelyHidden(el) {
    if (!el || !el.closest) return false;
    return Boolean(el.closest('details:not([open]), select, option, optgroup, datalist'));
  }

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
          } else if (perceptualDistance(color, effectiveBackground(node)) < COLOR_MATCH_THRESHOLD) {
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

  // ------------------------------------------------------------------ finding

  function buildFinding(opts) {
    const cssFlags = opts.flags.filter((f) => FLAG_LABELS[f]);
    const otherFlags = opts.flags.filter((f) => !FLAG_LABELS[f]);
    const scoredFlags = Math.min(cssFlags.length, MAX_SCORED_FLAGS);

    let score = Math.min(opts.keywordScore + scoredFlags * FLAG_BONUS, FINDING_SCORE_CAP);
    if (opts.a11y) score = Math.round(score * A11Y_FACTOR);

    const flags = [...cssFlags.map((f) => FLAG_LABELS[f]), ...otherFlags];
    if (cssFlags.length > MAX_SCORED_FLAGS) {
      flags.push(`+${cssFlags.length - MAX_SCORED_FLAGS} more, not scored`);
    }
    if (opts.a11y) flags.push('accessibility utility class — score halved');

    return {
      vector: opts.vector,
      typeLabel: VECTORS[opts.vector] || opts.vector,
      element: opts.element,
      preview: preview(opts.text),
      keywords: opts.hits.map((h) => h.label),
      flags,
      score
    };
  }

  // ------------------------------------------------------------------ vectors

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
      if (isLegitimatelyHidden(el)) continue;
      candidates.push({ el, text, hits, score });
    }
    return candidates;
  }

  /** Style reads for keyword-matched elements. Layout-thrashing, so kept to one
   *  pass and, above the batch threshold, deferred to an animation frame. */
  function classifyCandidates(candidates) {
    const findings = [];

    for (const c of candidates) {
      const hidden = concealmentFlags(c.el);
      const offscreen = offscreenFlags(c.el);
      const flags = [...hidden, ...offscreen];
      const hits = [...c.hits];
      let keywordScore = c.score;

      const mixed = isMixedScript(c.text);
      if (mixed) {
        hits.push({
          id: 'homoglyph',
          label: 'Latin mixed with Cyrillic/Greek lookalikes',
          weight: HOMOGLYPH_WEIGHT
        });
        keywordScore += HOMOGLYPH_WEIGHT;
        flags.push('disguised with lookalike characters');
      }

      let vector = 'visible';
      if (hidden.size > 0) vector = 'hidden_css';
      else if (offscreen.size > 0) vector = 'offscreen';
      else if (mixed) vector = 'homoglyph';

      // Rule 2: visible text needs an unambiguous pattern, and must not read as
      // an article explaining what an injection looks like.
      if (vector === 'visible') {
        if (!hits.some((h) => h.weight >= 9)) continue;
        if (isExplanatory(c.el, c.text)) continue;
      }

      findings.push(
        buildFinding({
          vector,
          text: c.text,
          hits,
          keywordScore,
          flags,
          element: describe(c.el),
          a11y: isA11yUtility(c.el)
        })
      );
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
          findings.push(
            buildFinding({
              vector: 'comment',
              text,
              hits,
              keywordScore: score,
              flags: ['hidden in an HTML comment'],
              element: `<!-- --> in ${describe(node.parentElement)}`,
              a11y: false
            })
          );
        }
      }
      node = walker.nextNode();
    }
    return findings;
  }

  function scanAttributes() {
    const findings = [];
    const nodes = document.querySelectorAll('*');
    const limit = Math.min(nodes.length, MAX_ELEMENTS);

    for (let i = 0; i < limit; i += 1) {
      const el = nodes[i];
      if (!el.attributes || el.attributes.length === 0) continue;

      for (const attr of el.attributes) {
        const named = ATTRIBUTES.includes(attr.name);
        const isData = attr.name.startsWith('data-');
        if (!named && !isData) continue;

        const text = normalise(attr.value || '');
        if (text.length < MIN_TEXT_LEN || text.length > MAX_TEXT_LEN) continue;
        const { hits, score } = matchPatterns(text);
        if (hits.length === 0) continue;

        findings.push(
          buildFinding({
            vector: 'attribute',
            text,
            hits,
            keywordScore: score,
            flags: [`${attr.name} attribute`],
            element: describe(el),
            a11y: isA11yUtility(el)
          })
        );
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
      findings.push(
        buildFinding({
          vector: 'meta',
          text,
          hits,
          keywordScore: score,
          flags: ['meta content'],
          element: `<meta name="${name}">`,
          a11y: false
        })
      );
    }
    return findings;
  }

  /**
   * <template>, <noscript> and unslotted <slot> fallback content is never shown
   * to a human in a normal browser, but it sits in the markup where scrapers
   * and some AI page readers will happily pick it up.
   */
  function scanInertContainers() {
    const findings = [];

    const sources = [];
    for (const el of document.querySelectorAll('template')) {
      sources.push({
        el,
        text: el.content ? el.content.textContent || '' : '',
        note: 'inside a <template>, never rendered'
      });
    }
    for (const el of document.querySelectorAll('noscript')) {
      sources.push({
        el,
        text: el.textContent || '',
        note: 'inside <noscript>, not shown when scripts run'
      });
    }
    for (const el of document.querySelectorAll('slot')) {
      const assigned = el.assignedNodes ? el.assignedNodes() : [];
      sources.push({
        el,
        text: assigned.length > 0 ? '' : el.textContent || '',
        note: 'unused <slot> fallback content'
      });
    }

    for (const src of sources) {
      const text = normalise(src.text);
      if (text.length < MIN_TEXT_LEN || text.length > MAX_TEXT_LEN) continue;
      const { hits, score } = matchPatterns(text);
      if (hits.length === 0) continue;
      findings.push(
        buildFinding({
          vector: 'template',
          text,
          hits,
          keywordScore: score,
          flags: [src.note],
          element: describe(src.el),
          a11y: false
        })
      );
    }
    return findings;
  }

  /** Decode Unicode tag characters (U+E0000 block) back to the ASCII they carry. */
  function decodeTagChars(text) {
    let out = '';
    for (const ch of text) {
      const cp = ch.codePointAt(0);
      if (cp >= 0xe0000 && cp <= 0xe007f) {
        const ascii = cp - 0xe0000;
        if (ascii >= 0x20 && ascii <= 0x7e) out += String.fromCharCode(ascii);
      }
    }
    return out;
  }

  /**
   * The one vector that does not need a keyword hit. A run of zero-width or tag
   * characters in body text has essentially no legitimate use, and tag-character
   * smuggling renders as literally nothing.
   */
  function scanInvisibleUnicode() {
    const findings = [];
    if (!document.body) return findings;

    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = new Set();
    let node = walker.nextNode();

    while (node) {
      const raw = node.nodeValue || '';
      const parent = node.parentElement;

      if (raw && parent && !SKIP_TAGS.has(parent.tagName) && INVISIBLE_RUN.test(raw)) {
        const invisible = raw.match(INVISIBLE_CHARS) || [];
        const smuggled = raw.match(TAG_CHARS) ? decodeTagChars(raw) : '';
        const visible = normalise(raw);
        const element = describe(parent);
        const key = `${element}|${visible}`;

        if (!seen.has(key)) {
          seen.add(key);

          const text = smuggled
            ? `${invisible.length} invisible characters decode to: "${smuggled}"`
            : `${invisible.length} invisible characters hidden in: "${visible || '(no visible text)'}"`;

          const hits = [
            {
              id: 'invisible-unicode',
              label: smuggled
                ? 'Unicode tag characters carrying hidden text'
                : 'run of zero-width characters',
              weight: UNICODE_WEIGHT
            }
          ];

          // If the smuggled payload itself reads like an injection, that is
          // worth more than the concealment alone.
          const inner = smuggled ? matchPatterns(smuggled) : { hits: [], score: 0 };

          findings.push(
            buildFinding({
              vector: 'unicode',
              text,
              hits: [...hits, ...inner.hits],
              keywordScore: UNICODE_WEIGHT + inner.score,
              flags: ['invisible to human readers'],
              element,
              a11y: false
            })
          );
        }
      }
      node = walker.nextNode();
    }
    return findings;
  }

  // ------------------------------------------------------------------ scoring

  function dedupe(findings) {
    const seen = new Set();
    const out = [];
    for (const f of findings) {
      const key = `${f.vector}|${f.element}|${f.preview}`;
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

  /** Many small findings across a page are worse than one. Deliberately mild. */
  function densityMultiplier(count) {
    if (count <= DENSITY_FLOOR) return 1;
    return Math.min(DENSITY_MAX, 1 + (count - DENSITY_FLOOR) * DENSITY_STEP);
  }

  function buildResult(findings, reason) {
    const ranked = dedupe(findings).sort((a, b) => b.score - a.score);
    const trimmed = ranked.slice(0, MAX_FINDINGS);

    const raw = ranked.reduce((sum, f) => sum + f.score, 0);
    const multiplier = densityMultiplier(ranked.length);
    const total = Math.round(raw * multiplier);

    const vectors = {};
    for (const f of ranked) vectors[f.vector] = (vectors[f.vector] || 0) + 1;

    return {
      level: levelFor(total),
      score: total,
      rawScore: raw,
      density: Number(multiplier.toFixed(2)),
      findingCount: ranked.length,
      truncated: ranked.length > trimmed.length,
      vectors,
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

  // ----------------------------------------------------------------- lifecycle

  let scanning = false;

  async function scan(reason) {
    if (scanning || !document.body) return;
    scanning = true;
    try {
      await loadPatterns();

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

      const findings = [
        ...classified,
        ...scanComments(),
        ...scanAttributes(),
        ...scanMeta(),
        ...scanInertContainers(),
        ...scanInvisibleUnicode()
      ];

      await send(buildResult(findings, reason));
    } catch (err) {
      // Never fail silently: a scanner that reports "safe" because it crashed
      // is worse than no scanner at all.
      await send({
        level: 'error',
        score: 0,
        findingCount: 0,
        findings: [],
        vectors: {},
        error: String((err && err.message) || err),
        url: location.href,
        title: document.title || location.hostname,
        scannedAt: Date.now(),
        reason
      });
    } finally {
      scanning = false;
    }
  }

  let debounceTimer = null;

  function scheduleScan(reason) {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      scan(reason);
    }, MUTATION_DEBOUNCE_MS);
  }

  /** Only added content matters. Attribute churn - class toggles, ARIA state,
   *  framework bookkeeping - fires constantly and told us nothing. */
  function addedContent(records) {
    for (const r of records) {
      if (r.type === 'characterData') return true;
      for (const node of r.addedNodes) {
        if (node.nodeType === 1 || node.nodeType === 3 || node.nodeType === 8) return true;
      }
    }
    return false;
  }

  const observer = new MutationObserver((records) => {
    if (addedContent(records)) scheduleScan('mutation');
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    characterData: true
  });

  window.__SNEPPARD_SNIFFER__ = {
    rescan: (reason) => scan(reason || 'manual')
  };

  scan('load');
})();
