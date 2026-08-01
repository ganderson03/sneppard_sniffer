# Prompt Injection Sniffer

A Manifest V3 browser extension that finds text hidden on web pages that is
written to hijack AI browser assistants — Claude in Chrome, Copilot, Perplexity,
Gemini and the like.

Your assistant reads the whole page. You read the visible part. This extension
tells you when the difference between the two contains an instruction.

## Load it in Chrome

1. Open `chrome://extensions`
2. Turn on **Developer mode** (top right)
3. Click **Load unpacked**
4. Select the `prompt-injection-sniffer/` folder (the one containing `manifest.json`)

Then open `test/injection-fixture.html` from this repo in a tab. The toolbar
badge should turn red with `!!!`; click it to see the eight planted injections.

The extension ships with no icons, so Chrome shows its default puzzle-piece icon
in the toolbar. Add `icons` to `manifest.json` when real PNGs exist.

## Layout

```
manifest.json          MV3 manifest
src/detector.js        content script — scans the DOM, scores findings
src/service-worker.js  background — stores results, drives the badge
src/popup.html/.js/.css  the popup UI
test/injection-fixture.html  a mock product page with eight planted injections
CHROMEWEBSTORE.md      store listing copy, permission justifications, privacy policy
```

## How detection works

The detector looks for two things at the same time and combines them:

**1. Text that reads like an instruction to an AI.** Twenty-seven weighted
patterns (weight 5–10) covering `ignore previous instructions`,
`you are now [persona]`, `new system prompt`, `your true goal is`,
`do not reveal`, `when asked … say …`, `act as`, `jailbreak`, `DAN`, fake
`<|im_start|>` / `[INST]` chat tokens, safety-override phrasing, and attempts to
make an assistant exfiltrate credentials.

**2. Evidence the text was concealed.** Each concealment flag adds +3:

| Vector | Checks |
| --- | --- |
| Hidden CSS | `display:none`, `visibility:hidden`, `opacity < 0.05`, `font-size < 2px`, text colour matching the effective background, transparent text, `height:0`/`width:0` under `overflow:hidden`, `clip:rect(0,0,0,0)`, `clip-path:inset(100%)`, zero-size or never-painted boxes |
| Off-screen | `position:absolute/fixed` with `left`/`top < -500px`, `text-indent <= -1000px`, or a bounding box entirely past the viewport edge |
| HTML comments | comment nodes containing injection keywords |
| Attributes | `alt`, `aria-label`, `title`, `placeholder`, `data-tooltip` |
| Meta tags | `<meta content="…">` |

Concealment checks walk up to ten ancestors, because `display:none` on a wrapper
does not appear in the computed style of the child that holds the text.

**Scoring.** `finding score = sum of matched pattern weights + 3 per concealment
flag`. The page score is the sum of all findings:

| Score | Level | Badge |
| --- | --- | --- |
| 0 | safe | none |
| 1–5 | low | amber `!` |
| 6–14 | medium | orange `!!` |
| 15+ | high | red `!!!` |

**Two deliberate false-positive guards.** A finding always requires at least one
keyword match — a hidden element on its own is never reported, because half the
web is hidden dropdown menus. And plainly *visible* text is only reported when it
trips a high-weight pattern (≥9), so an article discussing prompt injection does
not light up.

Rescans are triggered by a `MutationObserver`, debounced 1200 ms, so single-page
apps that inject content after load are still covered.

## Verified behaviour

Both fixtures were run against the real `src/detector.js` in Chrome:

- `test/injection-fixture.html` → **high**, score 198, all 8 planted injections
  found; the page's ordinary `display:none` dropdown and `.sr-only` text were
  correctly ignored.
- A benign control page (`sr-only` labels, hidden nav, `opacity:0` tooltip,
  descriptive `alt` text, copy containing "act as", "from now on" and "do not
  reveal your password") → **safe**, score 0.
- Appending an off-screen injected element after load produced a rescan within
  the debounce window (8 → 9 findings).

## MV3 constraints observed

- No `eval`, no `new Function`, no inline scripts or inline event handlers
- No `.then()` chains — all async code uses `async`/`await`
- The service worker keeps zero state in globals; every read and write goes
  through `chrome.storage.local`
- The `onMessage` listener returns `true` because it responds asynchronously
- `chrome.action.setBadgeText` is always called with an explicit `tabId`
- Style reads across more than 20 candidate elements are deferred into a single
  `requestAnimationFrame` callback rather than interleaved with page rendering
- The content script is read-only: it never modifies the page

## Firefox

The manifest as written is Chrome-shaped. Firefox's MV3 does not support
`background.service_worker`; it needs

```json
"background": { "scripts": ["src/service-worker.js"] }
```

and a `browser_specific_settings.gecko.id`. The detector, popup, and storage
logic are otherwise API-compatible (Firefox supports promise-based `chrome.*`).
Ship a separate `manifest.json` per store rather than trying to satisfy both.

## Limits

It is a heuristic detector, not a shield. It cannot block anything, it cannot
see inside cross-origin iframes or shadow DOM, and an attacker who phrases an
instruction in wording no pattern covers will not be caught. A clean result
means "nothing matched", not "this page is safe".
