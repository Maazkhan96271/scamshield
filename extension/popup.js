/**
 * ScamShield browser extension — on-device scam-risk analysis.
 *
 * This popup bundles the same weighted rule engine as the web app
 * (src/lib/scam.ts), self-contained so the extension has zero network
 * dependencies: nothing you analyze ever leaves the browser.
 */

/* ------------------------------------------------------------------ */
/* Rule engine (shared logic with src/lib/scam.ts)                     */
/* ------------------------------------------------------------------ */

const RULES = [
  // Urgency & pressure
  { category: "urgency", weight: 18, pattern: /\burgent(?:ly)?\b|asap|immediately|right now|act now|time[- ]sensitive/i, title: "Urgency pressure", inference: "Urgent framing is used to push people into acting before verifying." },
  { category: "urgency", weight: 20, pattern: /\b(?:within|in)\s+\d+\s*(?:minutes?|mins?|hours?|hrs?)\b|\b\d+\s*(?:minutes?|mins?|hours?)\s*(?:left|remaining|to (?:avoid|prevent))\b|\bexpire[sd]?\b.{0,20}\b(?:account|card|offer)\b|\blast (?:warning|notice|chance)\b|final (?:warning|notice|reminder)\b|account will be (?:closed|blocked|suspended|deactivated)/i, title: "Countdown / closure threat", inference: "Countdowns and closure threats are classic pressure tactics in phishing messages." },
  { category: "urgency", weight: 14, pattern: /\bdon'?t (?:hesitate|delay|wait)\b|no time to (?:lose|waste)|every (?:minute|second) counts/i, title: "Hurry reinforcement", inference: "Reinforced urgency stacks pressure on top of deadlines — common in scam scripts." },

  // Authority impersonation
  { category: "authority", weight: 16, pattern: /\b(?:bank|banking)\s+(?:security|fraud|compliance|support|team)\b|\bsecurity (?:team|department|alert|center)\b|\bfraud (?:team|department|prevention)\b/i, title: "Claims a security/fraud team", inference: "Real institutions rarely message first about fraud; impersonating their security teams is a common phishing pattern." },
  { category: "authority", weight: 14, pattern: /\b(?:irs|hmrc|income tax|tax (?:office|department|refund))\b/i, title: "Tax authority reference", inference: "Tax agencies contact by post, not SMS/email with links — this reference frequently appears in scams." },
  { category: "authority", weight: 15, pattern: /\b(?:police|cia|fbi|interpol|customs|immigration)\b.{0,40}\b(?:case|file|warrant|arrest|notice)\b/i, title: "Law-enforcement threat", inference: "Messages claiming police action aim to frighten recipients into complying quickly." },

  // Credentials
  { category: "credentials", weight: 30, pattern: /\b(?:otp|one[- ]time (?:password|code)|verification code|security code|pin|passcode)\b/i, title: "Asks for an OTP/PIN/code", inference: "No legitimate service asks you to share one-time codes — this is a credential-harvesting indicator." },
  { category: "credentials", weight: 25, pattern: /\bpasswords?\b.{0,30}\b(?:send|share|provide|confirm|enter (?:your|the))\b|\bsend|share|confirm\b.{0,30}\bpasswords?\b/i, title: "Password request", inference: "Requests to share passwords are always unsafe — services never need your actual password." },
  { category: "credentials", weight: 22, pattern: /\b(?:cvv|cvc|card number|card details|bank (?:account|details)|account number|routing number|ssn|social security|national insurance)\b/i, title: "Sensitive financial info request", inference: "Asking for card or account details over message channels is a hallmark of financial fraud." },
  { category: "credentials", weight: 20, pattern: /\b(?:verify|confirm|update|validate|restore)\b.{0,40}\b(?:your )?(?:account|identity|details|information|kyc)\b/i, title: "Verification request", inference: "'Verify your account' links are the standard phishing call-to-action." },

  // Payments
  { category: "payment", weight: 28, pattern: /\bgift ?cards?\b|\b(?:itunes|google play|steam)\s*cards?\b/i, title: "Gift-card payment", inference: "Gift cards are the most common scam payment rail because they're untraceable." },
  { category: "payment", weight: 25, pattern: /\b(?:bitcoin|btc|ethereum|eth|usdt|crypto(?:currency)?|wallet address)\b/i, title: "Cryptocurrency request", inference: "Crypto payments are irreversible — a strong indicator of fraudulent requests." },
  { category: "payment", weight: 22, pattern: /\b(?:send|transfer|wire|pay|deposit)\b.{0,40}\b(?:money|funds?|\$|€|£|₹|usd|eur|gbp|inr)\b|\b(?:fee|charge|payment)\b.{0,25}\b(?:require[sd]?|need(?:ed)?|must|pending)\b/i, title: "Money transfer request", inference: "Unsolicited requests to send money or pay a 'fee' match advance-fee fraud patterns." },
  { category: "payment", weight: 18, pattern: /\b(?:unclaimed|pending|awaiting)\b.{0,30}\b(?:refund|payment|invoice|transaction)\b|\bdouble (?:charge|payment)\b/i, title: "Refund/charge bait", inference: "Fake refund notifications trick people into 'correcting' payment details." },

  // Links
  { category: "links", weight: 20, pattern: /https?:\/\/[^\s]+|www\.[^\s]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\.[a-z]{2,}\/?\S*/gi, title: "Contains a link", inference: "Links in unexpected messages should be treated as untrusted; type the official address instead.", every: true },
  { category: "links", weight: 15, pattern: /\b(?:bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl|ow\.ly|buff\.ly|rebrand\.ly)\/\S+/i, title: "Shortened URL", inference: "Link shorteners hide the true destination — a common way to disguise malicious sites." },

  // Prize / opportunity / delivery / tech support / secrecy / attachments / software / tone
  { category: "prize", weight: 24, pattern: /\b(?:congratulations|you(?:'ve)? (?:won|been selected)|winner|lottery|prize|lucky draw|raffle)\b/i, title: "Prize/lottery claim", inference: "Unexpected prize claims are a long-established scam format." },
  { category: "opportunity", weight: 20, pattern: /\b(?:earn|make)\s*(?:\$|€|£|₹)?\s*\d+[,\d]*\s*(?:per|a|\/)\s*(?:day|week|month|hour)\b|\bguaranteed (?:income|profit|returns?)\b|\b(?:double|triple) your (?:money|investment|bitcoin)\b/i, title: "Too-good-to-be-true offer", inference: "Guaranteed high returns are the core promise of investment scams." },
  { category: "delivery", weight: 16, pattern: /\b(?:package|parcel|shipment|delivery|courier)\b.{0,40}\b(?:fee|customs|charge|reschedul|failed|held|pay)\b/i, title: "Delivery fee trick", inference: "Fake 'your parcel is held, pay a small fee' texts are a widespread smishing pattern." },
  { category: "techsupport", weight: 20, pattern: /\b(?:virus|malware|infected|hacked|compromised)\b.{0,40}\b(?:device|computer|phone|account)\b|\bcall (?:this|the following) number\b/i, title: "Fake tech-support warning", inference: "Scare warnings about infections push victims into calling attacker-controlled numbers." },
  { category: "secrecy", weight: 22, pattern: /\b(?:don'?t|do not|keep this|not to)\b.{0,25}\b(?:tell|inform|share|discuss|mention)\b.{0,25}\b(?:anyone|anybody|them|others?|colleagues?|bank)\b|confidential (?:matter|transaction)/i, title: "Requests secrecy", inference: "Legitimate organizations never ask you to hide the conversation — secrecy requests signal manipulation." },
  { category: "attachments", weight: 20, pattern: /\.(?:zip|rar|7z|exe|scr|bat|cmd|js|vbs|apk|dmg|iso|docm|xlsm)\b/i, title: "Suspicious attachment type", inference: "Executables, scripts and macro-enabled documents are common malware carriers." },
  { category: "software", weight: 22, pattern: /\b(?:install|download)\b.{0,35}\b(?:app|software|program|update|tool|extension|apk)\b|\b(?:anydesk|teamviewer|remote[- ]?desktop)\b/i, title: "Software install / remote access request", inference: "Urging software installs or remote-desktop tools gives attackers direct access to your device." },
  { category: "tone", weight: 8, pattern: /!{3,}|\b(?:FREE|WINNER|URGENT|ATTENTION)\b/ , title: "Aggressive formatting", inference: "ALL-CAPS shouting and stacked exclamation marks are typical of mass scam templates." },
];

function scoreText(text) {
  const flags = [];
  let score = 0;
  for (const rule of RULES) {
    const m = rule.pattern.exec(text);
    if (!m) continue;
    rule.pattern.lastIndex = 0;
    const evidence = (m[0] || "").trim().slice(0, 120);
    flags.push({ title: rule.title, category: rule.category, weight: rule.weight, evidence, inference: rule.inference });
    score += rule.weight;
  }
  const risk = score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";
  const indicatorCount = flags.length;
  const confidence = Math.max(25, Math.min(90, 35 + indicatorCount * 7 + (risk === "HIGH" ? 10 : 0)));
  return { risk_level: risk, confidence, signals: flags };
}

/* ------------------------------------------------------------------ */
/* Popup wiring                                                        */
/* ------------------------------------------------------------------ */

const $ = (id) => document.getElementById(id);
const resultBox = $("result");

$("grab").addEventListener("click", async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const [res] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => String(window.getSelection?.() ?? ""),
    });
    const sel = (res?.result ?? "").trim();
    if (sel) {
      $("text").value = sel.slice(0, 8000);
      $("empty").hidden = true;
    }
  } catch {
    /* restricted page — ignore */
  }
});

$("analyze").addEventListener("click", () => {
  const text = $("text").value.trim();
  resultBox.hidden = true;
  $("empty").hidden = true;
  if (!text) {
    resultBox.hidden = false;
    resultBox.innerHTML = `<p class="muted">Paste a message or grab the page selection first.</p>`;
    return;
  }

  const r = scoreText(text);
  chrome.storage?.local?.set({ lastScan: { text: text.slice(0, 500), at: Date.now(), risk: r.risk_level } });

  const items = r.signals
    .map(
      (f) => `<li><b>${escapeHtml(f.title)}</b><span class="ev">observed: ${escapeHtml(f.evidence || "—")}</span><span class="inf">${escapeHtml(f.inference)}</span></li>`,
    )
    .join("");

  resultBox.hidden = false;
  resultBox.innerHTML = `
    <div class="verdict">
      <div class="risk ${r.risk_level}">${riskEmoji(r.risk_level)} ${r.risk} RISK</div>
      <div class="count">${r.signals.length} risk indicator${r.signals.length === 1 ? "" : "s"} detected · confidence in verdict: ${confidenceWord(r.confidence)}</div>
      ${r.signals.length ? `<ul>${items}</ul>` : `<p class="muted">No known scam indicators found. That is not a guarantee — stay cautious with links and payment requests.</p>`}
      <p class="note">Indicators are not proof. Verify claims through official channels before acting.</p>
    </div>`;
});

function riskEmoji(level) {
  return { HIGH: "🚨", MEDIUM: "⚠️", LOW: "✅" }[level] ?? "";
}

function confidenceWord(c) {
  return c >= 70 ? "High" : c >= 45 ? "Medium" : "Low";
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}
