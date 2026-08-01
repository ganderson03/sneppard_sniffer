/**
 * Sneppard Sniffer - weighted injection patterns.
 *
 * Kept separate from the detection logic so the list can be tuned without
 * touching how scanning works. Loaded by src/detector.js as an ES module via
 * dynamic import, so there is no build step: edit this file, reload the
 * extension, done.
 *
 * Each entry:
 *   id     - stable slug, used for dedupe and future telemetry-free tuning
 *   weight - 5 to 10. Anything scoring >= 9 is treated as unambiguous enough
 *            to report even when the text is plainly visible on the page.
 *   label  - shown to the user in the popup, so write it in plain language
 *   re     - matched against normalised, confusable-folded text
 */

export const PATTERNS = [
  { id: 'ignore-previous', weight: 10, label: 'ignore previous instructions', re: /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?|context|commands?)/i },
  { id: 'forget-everything', weight: 10, label: 'forget everything above', re: /\b(forget|erase|discard)\s+(everything|all)\s+(you|that|above|before|previously)/i },
  { id: 'override-safety', weight: 10, label: 'override safety rules', re: /\b(ignore|bypass|override|disable|turn\s+off)\s+(your|all|any|the)\s+(safety|content|security|guard(rail)?s?|guidelines?|restrictions?|filters?|policies)/i },
  { id: 'ai-directive', weight: 10, label: 'directive addressed to an AI', re: /\b(instructions?|message|note|directive|command)\s+(for|to)\s+(the\s+)?(ai|a\.i\.|assistant|llm|chat\s?bot|agent|language\s+model|browser\s+agent)\b/i },
  { id: 'exfiltrate', weight: 10, label: 'attempt to leak secrets', re: /\b(send|post|exfiltrate|upload|transmit|email|leak)\b[^.]{0,40}\b(api\s*key|secret|password|credential|cookie|session\s+token|auth\s+token|private\s+key)/i },
  { id: 'urgent-ai', weight: 10, label: 'urgent message for the AI', re: /\b(important|urgent|critical|priority)\s+(message|instruction|notice|update)\s+(for|to)\s+(the\s+)?(ai|assistant|llm|agent|model)/i },
  { id: 'you-are-now', weight: 9, label: 'you are now [AI persona]', re: /\byou\s+are\s+now\s+(a|an|the)?\s*[\w .'-]{0,30}\b(assistant|ai|a\.i\.|model|agent|dan|gpt|claude|copilot|gemini|perplexity|bot|persona)\b/i },
  { id: 'new-system-prompt', weight: 9, label: 'new system prompt', re: /\b(new|updated|revised|real|actual)\s+(system\s+)?(prompt|instructions?)\s*[:\-—]/i },
  { id: 'system-override', weight: 9, label: 'system prompt override', re: /\bsystem\s*prompt\s*(override|update|replacement|:)/i },
  { id: 'true-goal', weight: 9, label: 'your true goal is', re: /\byour\s+(true|real|actual|hidden|secret|primary|only)\s+(goal|purpose|objective|task|mission|instruction)s?\s+(is|are)\b/i },
  { id: 'chat-tokens', weight: 9, label: 'fake chat/system tokens', re: /(<\|?\s*(im_start|im_end|system|endoftext)\s*\|?>|\[\/?\s*(INST|SYS)\s*\]|###\s*(system|instruction)\s*:)/i },
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

export default PATTERNS;
