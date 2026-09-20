export type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

export type MessageKind = "email" | "sms" | "whatsapp" | "payment";

export const MESSAGE_KINDS: { value: MessageKind; label: string }[] = [
  { value: "email", label: "Email" },
  { value: "sms", label: "SMS" },
  { value: "whatsapp", label: "WhatsApp" },
  { value: "payment", label: "Payment request" },
];

export type AnalysisMode = "text" | "url" | "image";

export type AnalyzePayload =
  | { mode: "text"; content: string; kind: MessageKind }
  | { mode: "url"; url: string }
  | { mode: "image"; imageDataUrl: string };

export const MAX_URL_LENGTH = 2048;
export const MAX_IMAGE_BYTES = 5 * 1024 * 1024;

export type FlagCategory =
  | "urgency"
  | "authority"
  | "credentials"
  | "payment"
  | "links"
  | "prize"
  | "opportunity"
  | "delivery"
  | "techsupport"
  | "secrecy"
  | "attachments"
  | "software"
  | "tone";

export interface ScamFlag {
  title: string;
  /** Observed evidence — the exact wording/pattern found in the input. */
  evidence: string;
  /** Inference — what this indicator suggests, hedged. */
  inference: string;
  weight: number;
  category: FlagCategory;
}

export type SignalSeverity = "high" | "medium" | "low";

/** Maps an indicator's weight to a display severity. */
export function signalSeverity(weight: number): SignalSeverity {
  return weight >= 20 ? "high" : weight >= 10 ? "medium" : "low";
}

/** An exact phrase from the analyzed text that triggered an indicator. */
export interface Highlight {
  text: string;
  category: FlagCategory;
  severity: SignalSeverity;
}

export interface AnalysisResult {
  risk_level: RiskLevel;
  /** 0–100 — how confident the engine is in this verdict (never 95+: no certainty claims). */
  confidence: number;
  signals: ScamFlag[];
  /** Exact phrases in the analyzed text that triggered indicators — powers the UI highlighter. */
  highlights: Highlight[];
  explanation: string;
  recommended_actions: string[];
  extracted_urls: string[];
  /** Organization the message claims to be from, if detectable. */
  claimed_organization: string | null;
  /** Who produced the verdict. */
  source: "heuristic" | "ai";
  note?: string;
  scanned_url?: string;
  page_title?: string;
  /** Vision model's transcription of a screenshot, when available. */
  extracted_text?: string;
}

export const MAX_CONTENT_LENGTH = 8000;

/** Shape the AI is asked to return — AnalysisResult plus the vision model's text transcription. */
interface AiVerdictJson extends Partial<AnalysisResult> {
  extracted_text?: string;
}

const CATEGORY_LABEL: Record<FlagCategory, string> = {
  urgency: "urgency & threats",
  authority: "authority impersonation",
  credentials: "credential & financial info requests",
  payment: "suspicious payment requests",
  links: "suspicious URLs",
  prize: "suspicious rewards/prizes",
  opportunity: "too-good-to-be-true offers",
  delivery: "delivery fee tricks",
  techsupport: "fake tech support",
  secrecy: "secrecy & bypassing procedures",
  attachments: "unexpected attachments",
  software: "software installation requests",
  tone: "spelling/formatting anomalies",
};

/* ------------------------------------------------------------------ */
/* Claimed-organization detection                                      */
/* ------------------------------------------------------------------ */

const OFFICIAL_DOMAINS: { brand: RegExp; domain: string; name: string }[] = [
  { brand: /paypal/i, domain: "paypal.com", name: "PayPal" },
  { brand: /apple|icloud|itunes/i, domain: "apple.com", name: "Apple" },
  { brand: /amazon/i, domain: "amazon.com", name: "Amazon" },
  { brand: /netflix/i, domain: "netflix.com", name: "Netflix" },
  { brand: /microsoft|outlook|office365/i, domain: "microsoft.com", name: "Microsoft" },
  { brand: /whatsapp/i, domain: "whatsapp.com", name: "WhatsApp" },
  { brand: /wellsfargo/i, domain: "wellsfargo.com", name: "Wells Fargo" },
  { brand: /hsbc/i, domain: "hsbc.com", name: "HSBC" },
  { brand: /revolut/i, domain: "revolut.com", name: "Revolut" },
  { brand: /binance/i, domain: "binance.com", name: "Binance" },
  { brand: /royal ?mail/i, domain: "royalmail.com", name: "Royal Mail" },
];

const EXTRA_ORGS: { pattern: RegExp; name: string }[] = [
  { pattern: /\bUSPS\b/, name: "USPS" },
  { pattern: /\bFedEx\b/, name: "FedEx" },
  { pattern: /\bDHL\b/, name: "DHL" },
  { pattern: /\bUPS\b/, name: "UPS" },
  { pattern: /\bHMRC\b/, name: "HMRC" },
  { pattern: /\bIRS\b/, name: "IRS" },
  { pattern: /\bebay\b/i, name: "eBay" },
  { pattern: /\bcoinbase\b/i, name: "Coinbase" },
  { pattern: /\bgoogle\b/i, name: "Google" },
  { pattern: /\btelegram\b/i, name: "Telegram" },
];

function detectClaimedOrganization(text: string, host?: string): string | null {
  if (host) {
    for (const { brand, name } of OFFICIAL_DOMAINS) {
      if (brand.test(host)) return name;
    }
  }
  for (const { brand, name } of OFFICIAL_DOMAINS) {
    if (brand.test(text)) return name;
  }
  for (const { pattern, name } of EXTRA_ORGS) {
    if (pattern.test(text)) return name;
  }
  const suffix =
    /\b([A-Z][A-Za-z&.'-]{2,}(?: [A-Z][A-Za-z&.'-]{2,}){0,2})\s+(?:Security Team|Support Team|Customer (?:Care|Service|Support)|Fraud (?:Team|Department)|Bank)\b/.exec(
      text,
    );
  if (suffix) {
    const org = suffix[1].trim();
    return org.length >= 2 ? org : null;
  }
  return null;
}

/* ================================================================== */
/* RULE ENGINE                                                         */
/*                                                                     */
/* Named detectors, each returning indicators with observed evidence   */
/* (quoted from the input) and hedged inference. Runs on every scan;   */
/* verdicts are later merged with the AI analysis (see mergeVerdicts). */
/* ================================================================== */

interface Rule {
  category: FlagCategory;
  weight: number;
  pattern: RegExp;
  title: string;
  /** What the indicator suggests (inference — hedged). */
  inference: string;
}

/* --- URGENCY DETECTOR ---------------------------------------------- */
const URGENCY_RULES: Rule[] = [
  {
    category: "urgency",
    weight: 18,
    pattern: /\b(urgent|immediately|act now|right away|last warning|last chance|final (warning|notice)|time[- ]sensitive|don'?t (delay|wait)|expires? (today|in \d+)|within \d+ ?(minutes?|mins?|hours?|days?)|\d+ ?(minutes?|mins?|hours?|days?) (or|before))\b/i,
    title: "Urgency or pressure phrases",
    inference: "Pressure to act fast is a classic tactic to stop careful review or checking with someone.",
  },
  {
    category: "urgency",
    weight: 20,
    pattern: /\b(account (will be|is|has been) (suspended|closed|locked|deactivated|blocked|limited)|suspension|permanently (closed|disabled)|legal action|warrant|arre?st|unusual (activity|login)|suspicious (activity|login))\b/i,
    title: "Threat of consequences",
    inference: "Threats to close accounts or take legal action push people into clicking or paying before verifying anything.",
  },
];

/* --- SENSITIVE INFORMATION DETECTOR --------------------------------- */
const SENSITIVE_INFO_RULES: Rule[] = [
  {
    category: "credentials",
    weight: 15,
    pattern: /\b(otp|one[- ]time (?:code|password|pin)|upi(?:\s+pin)?|\bpin\b|password|cvv|cvc|card number|bank account(?:\s+(?:number|details))?|security code|verification code|sort code|iban|social security number|ssn|mother'?s maiden name)\b/i,
    title: "References sensitive credentials",
    inference: "Mentions of OTPs, PINs, passwords, CVV or bank/card details are common in credential-harvesting attempts.",
  },
  {
    category: "credentials",
    weight: 30,
    pattern: /\b(confirm|verify|enter|provide|share)\s+(your\s+)?(identity|password|details|account|card(?:\s+number)?|pin|otp|banking|billing\s+details)\b/i,
    title: "Asks you to hand over credentials or financial details",
    inference: "No legitimate service asks for one-time codes, passwords or card details over email, SMS or chat.",
  },
];

/* --- PAYMENT DETECTOR ------------------------------------------------ */
const PAYMENT_RULES: Rule[] = [
  {
    category: "payment",
    weight: 25,
    pattern: /\b(?:send|sent)\s+(?:money|funds|cash|\$|£|€|\d)|\bpay\s+now\b|\bmake\s+a\s+payment\b|\bpay\s+(?:the\s+)?(?:fee|amount|invoice|balance)\b|(?:money|bank)\s+transfer|wire\s+transfer|western\s+union|money\s?gram|\bzelle\b|\bcash\s?app\b|transfer\s+(?:money|funds|the\s+amount|\d)|deposit\s+(?:money|funds|the\s+amount|\d|now|today)|security\s+deposit|fee\s+of|(?:processing|handling|service|activation|release|customs|delivery|registration|clearance|unlock|admin)\s+fee|gift\s+card|(?:itunes|google\s+play|steam)\s+card|crypto(?:currency)?|bitcoin|\bbtc\b|usdt|ethereum/i,
    title: "Payment demand or transfer request",
    inference: "Payment demands — especially via gift cards, crypto or wire transfer — are hard to reverse and common in fraud.",
  },
];

/* --- OTHER DETECTORS -------------------------------------------------- */
const GENERAL_RULES: Rule[] = [
  // Impersonation / authority
  {
    category: "authority",
    weight: 12,
    pattern: /\b(security team|fraud (team|department)|compliance (team|department)|customer (care|support) (team|centre|center)|account manager|head ?office|police|federal|revenue|customs officer|regulator)\b/i,
    title: "Claims to be an official body",
    inference: "Real institutions rarely open sensitive conversations by text or chat; this may be impersonation.",
  },
  // Prizes / too-good-to-be-true
  {
    category: "prize",
    weight: 14,
    pattern: /\b(you('ve| have)? won|congratulations.{0,20}(won|selected)|lottery|jackpot|prize|lucky (draw|winner)|claim your|you('ve| have)? been (selected|chosen)|free (gift|iphone|money)|inheritance)\b/i,
    title: "Prize or windfall you never entered for",
    inference: "Real prizes never require fees or bank details to claim; unsolicited winnings are commonly bait.",
  },
  {
    category: "opportunity",
    weight: 12,
    pattern: /\b(work from home|earn(ing)? (\$|£|€)\s?\d+[,\dkK]? ?(a|per|\/)? ?(day|week|hour)|guaranteed (return|profit|income)|double your (money|crypto|investment)|investment opportunity|trading (signals|tips)|financial freedom|passive income|paid in (btc|crypto|bitcoin))\b/i,
    title: "Too-good-to-be-true offer",
    inference: "Guaranteed profits and high pay for little effort are the core pitch of investment and job scams.",
  },
  // Delivery
  {
    category: "delivery",
    weight: 10,
    pattern: /\b(parcel|package|delivery (failed|attempt|on hold)|reschedule (delivery|your parcel)|redelivery|shipping fee|usps|fedex|dhl|royal mail|ups delivery|customs (charge|hold)|missed (delivery|you))\b/i,
    title: "Delivery problem that needs a payment",
    inference: "Fake 'missed delivery' texts are widespread; couriers bill through their official app, never via a link in a text.",
  },
  // Fake tech support
  {
    category: "techsupport",
    weight: 12,
    pattern: /\b(virus (detected|found)|your (computer|device|pc) (is|has been) (infected|compromised|at risk)|microsoft (support|security)|license (expired|expires)|renew (your )?(subscription|licence|license))\b/i,
    title: "Fake security or support warning",
    inference: "Warnings about viruses or expiring licences are used to sell fake fixes or gain trust before remote access.",
  },
  // Install software
  {
    category: "software",
    weight: 14,
    pattern: /\b(install (the|this|our) (app|software|program|update)|download (the|this|our) (app|software|program)|\.exe\b|\.apk\b|\.dmg\b|remote (access|session|desktop)|allow access to (your )?(computer|device)|teamviewer|anydesk)\b/i,
    title: "Requests to install software or grant access",
    inference: "Installing apps from links or granting remote access can hand scammers control of the device.",
  },
  // Secrecy / bypassing procedures
  {
    category: "secrecy",
    weight: 14,
    pattern: /\b(don'?t tell|do not tell|keep this (secret|confidential)|confidentiality|don'?t (mention|discuss|talk) (to|with|about)|don'?t inform|keep (this )?between|between us)\b/i,
    title: "Pressure to keep communication secret",
    inference: "Isolating the target from family, bank staff or advisors is a hallmark of ongoing fraud — legitimate organizations never demand secrecy.",
  },
  {
    category: "secrecy",
    weight: 12,
    pattern: /\b(bypass|skip (the |your )?(verification|security|checks?)|use (this )?(direct|special) (link|line|code)|agent (can|will) (help|override)|manually (approve|process)|fast[- ]track)\b/i,
    title: "Asks to bypass normal procedures",
    inference: "Requests to skip standard security steps or use 'special' channels suggest the sender is avoiding checks that would expose the fraud.",
  },
  // Attachments
  {
    category: "attachments",
    weight: 12,
    pattern: /\b(attachment|attached (file|document|invoice|receipt)|open the (attached|attachment)|\.zip\b|\.rar\b|\.js\b|\.docm\b|invoice attached|see attached|document (is )?attached)\b/i,
    title: "Unexpected attachment",
    inference: "Unexpected attachments — especially archives or documents with macros — are a common malware delivery route.",
  },
  // Spelling / formatting anomalies
  {
    category: "tone",
    weight: 6,
    pattern: /[A-Z]{5,}/,
    title: "SHOUTING CAPITALS",
    inference: "Blocks of capital letters are a common visual pressure tactic in scam messages.",
  },
  {
    category: "tone",
    weight: 4,
    pattern: /!{3,}/,
    title: "Excessive punctuation",
    inference: "Strings of exclamation marks ('!!!') are used to fake excitement or urgency.",
  },
];

const RULES: Rule[] = [...URGENCY_RULES, ...SENSITIVE_INFO_RULES, ...PAYMENT_RULES, ...GENERAL_RULES];

/* --- LINK DETECTOR (uses a real URL parser per extracted link) ------- */

const SHORTENERS = /(bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|goo\.gl|ow\.ly|buff\.ly|rebrand\.ly|shorturl\.at|tiny\.cc|shorte\.st|cli\.gs)/i;

const RISKY_TLDS = /\.(xyz|top|click|link|loan|rest|icu|cyou|shop|buzz|monster|quest|sbs|fit|beauty|hair|makeup|mom)\b/i;

const URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi;
// Catches scheme-less links common in smishing (e.g. "bit.ly/abc123", "festival-tickets.top/pay").
const BARE_DOMAIN_REGEX = /\b(?:[a-z0-9-]+\.)+(?:com|net|org|co|io|ly|ru|su|cn|xyz|top|info|biz|online|site|click|link|shop|us|uk|me|cc|app|dev|icu|cyou)\b(?:\/[^\s<>"')\]]*)?/gi;

const URL_KEYWORD_REGEX = /\b(login|log-?in|signin|sign-?in|verify|verification|secure|security|account|update|confirm|billing|invoice|payment|wallet|unlock|refund|bonus|gift|recover|suspended|limited|support|bank|banking|ebanking)\b/gi;

function countUrlKeywords(s: string): number {
  const m = s.match(URL_KEYWORD_REGEX);
  return m ? new Set(m.map((w) => w.toLowerCase())).size : 0;
}

function snippet(text: string, max = 120): string {
  const s = text.replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 1)}…` : s;
}

function extractLinks(text: string): string[] {
  const found: string[] = [];
  const seen = new Set<string>();
  const push = (m: string) => {
    const clean = m.replace(/[.,;:!?]+$/, "");
    const key = clean.replace(/^(?:https?:\/\/)?(?:www\.)?/i, "").toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      found.push(clean);
    }
  };
  for (const m of text.match(URL_REGEX) ?? []) push(m);
  for (const m of text.match(BARE_DOMAIN_REGEX) ?? []) push(m);
  return found.slice(0, 10);
}

function hostnameOf(url: string): string {
  try {
    const withProto = url.startsWith("http") ? url : `http://${url}`;
    return new URL(withProto).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/** Parses a single URL with `new URL()` and returns shape-based indicators. */
function analyzeUrlShape(rawUrl: string): { normalized: string; host: string; flags: ScamFlag[] } {
  let normalized = rawUrl.trim();
  if (!/^https?:\/\//i.test(normalized)) normalized = `https://${normalized}`;

  const parsed = new URL(normalized); // throws on invalid input
  const host = parsed.hostname.toLowerCase();
  const bareHost = host.replace(/^www\./, "");
  const flags: ScamFlag[] = [];
  const push = (weight: number, title: string, evidence: string, inference: string) =>
    flags.push({ title, evidence, inference, weight, category: "links" });

  if (parsed.protocol === "http:") {
    push(10, "Link is not encrypted (http://)", bareHost, "Anything typed on an unencrypted page can be intercepted. Legitimate sign-in pages always use https.");
  }
  if (SHORTENERS.test(bareHost)) {
    push(10, "Shortened URL hides the real destination", bareHost, "URL shorteners conceal where the link actually leads.");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(bareHost)) {
    push(14, "Address is a raw IP number", bareHost, "Real services don't serve their website from a bare IP address.");
  }
  if (bareHost.includes("xn--")) {
    push(14, "Look-alike (punycode) domain", bareHost, "The domain uses encoded characters that can imitate letters like 'a' or 'o' — a classic phishing trick.");
  }
  if (RISKY_TLDS.test(bareHost)) {
    push(8, "Suspicious domain extension", bareHost, "This domain extension is heavily abused in phishing campaigns.");
  }
  let brandMismatch = false;
  for (const { brand, domain } of OFFICIAL_DOMAINS) {
    if (brand.test(bareHost) && !bareHost.endsWith(`.${domain}`) && bareHost !== domain) {
      brandMismatch = true;
      push(20, "Brand name doesn't match the domain", bareHost, `The address contains "${domain.split(".")[0]}" but is not an official "${domain}" domain — a hallmark of brand impersonation.`);
      break;
    }
  }
  const kwCount = countUrlKeywords(`${bareHost}${parsed.pathname}`);
  if (kwCount > 0) {
    push(Math.min(20, kwCount * 7), "Credential keywords in the address", bareHost, "Words like 'bank', 'login', 'verify' or 'account' inside URLs lend fake credibility.");
  }
  if ((bareHost.split(".")[0].match(/-/g) ?? []).length >= 2) {
    push(10, "Hyphen-stuffed domain", bareHost, "Long hyphenated chains like 'bank-security-login' imitate trusted institutions.");
  }
  if (brandMismatch && kwCount > 0) {
    push(25, "Classic phishing URL pattern", bareHost, "An impersonated brand combined with credential keywords is the signature of a fake sign-in page.");
  }
  if ((bareHost.match(/\./g) ?? []).length >= 3) {
    push(8, "Deeply nested subdomains", bareHost, "Many subdomain levels are often used to bury the real destination at the end.");
  }

  return { normalized: parsed.toString(), host: bareHost, flags };
}

function linkFlags(text: string, links: string[]): ScamFlag[] {
  const flags: ScamFlag[] = [];
  let budget = 28; // cap total weight from link-shape rules

  // LINK DETECTOR — parse every extracted URL and collect its shape indicators.
  for (const link of links) {
    let shape: ReturnType<typeof analyzeUrlShape>;
    try {
      shape = analyzeUrlShape(link);
    } catch {
      continue;
    }
    for (const f of shape.flags) {
      if (budget <= 0) break;
      const w = Math.min(f.weight, budget);
      budget -= w;
      flags.push({ ...f, weight: w });
    }
  }

  if (links.length === 0 && /\b(click (here|the link)|tap (here|the link)|open (this|the) link|login here|sign in here|verify here)\b/i.test(text)) {
    const m = /\b(click (here|the link)|tap (here|the link)|open (this|the) link|login here|sign in here|verify here)\b/i.exec(text);
    flags.push({
      title: "Asks you to click without a visible destination",
      evidence: snippet(m?.[0] ?? ""),
      inference: "The message pushes toward links while hiding where they lead.",
      weight: 8,
      category: "links",
    });
  }

  // Explicit verify/sign-in instruction in the text (with or without a visible link).
  const verify = /\b(verify|confirm|sign ?in|log ?in|unlock|validate|update)\s+(here|below|at|now|your (account|identity|details|password))/i.exec(text);
  if (verify) {
    flags.push({
      title: "Directs you to verify or sign in via the message",
      evidence: snippet(verify[0]),
      inference: "Legitimate services ask you to sign in via their app or by typing the address yourself — not through links in unsolicited messages.",
      weight: 12,
      category: "links",
    });
  }

  return flags;
}

function confidenceFor(risk: RiskLevel, signalCount: number, maxWeight: number): number {
  const signalBonus = Math.min(6, signalCount * 1.5);
  const seriousBonus = maxWeight >= 25 ? 6 : maxWeight >= 14 ? 3 : 0;
  let conf: number;
  if (risk === "HIGH") conf = 72 + signalBonus + seriousBonus;
  else if (risk === "MEDIUM") conf = 50 + signalBonus * 0.5 + seriousBonus * 0.5;
  else conf = 78 + (signalCount === 0 ? 6 : 0);
  return Math.round(Math.max(40, Math.min(95, conf))); // never 95+ — no certainty claims
}

/** Qualitative band for display — we never show a bare number that could read as a fraud probability. */
export function confidenceBand(confidence: number): "High" | "Moderate" | "Low" {
  if (confidence >= 75) return "High";
  if (confidence >= 55) return "Moderate";
  return "Low";
}

/* --- Highlight extraction — "show me exactly what triggered this" ---- */

function containsPhrase(text: string, phrase: string): boolean {
  if (text.toLowerCase().includes(phrase.toLowerCase())) return true;
  const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, "\\$&").replace(/\s+/g, "\\s+");
  return new RegExp(escaped, "i").test(text);
}

/** Maps rule-detected evidence back to exact phrases in the analyzed text. */
function buildHighlights(text: string, signals: ScamFlag[], extras: Highlight[] = []): Highlight[] {
  const out: Highlight[] = [];
  const seen = new Set<string>();
  const tryAdd = (raw: string, category: FlagCategory, severity: SignalSeverity) => {
    const phrase = raw.trim();
    if (phrase.length < 3 || phrase.length > 120 || phrase.endsWith("…")) return;
    const key = `${phrase.toLowerCase()}|${category}`;
    if (seen.has(key) || !containsPhrase(text, phrase)) return;
    seen.add(key);
    out.push({ text: phrase, category, severity });
  };
  for (const s of signals) {
    tryAdd(
      s.evidence.replace(/^[“”"']+/, "").replace(/[“”"']+$/, ""),
      s.category,
      signalSeverity(s.weight),
    );
  }
  for (const h of extras) tryAdd(h.text, h.category, h.severity);
  return out.slice(0, 14);
}

export function analyzeHeuristics(content: string, kind: MessageKind): AnalysisResult {
  const text = content;
  const flags: ScamFlag[] = [];

  const extraHighlights: Highlight[] = [];
  for (const rule of RULES) {
    const m = rule.pattern.exec(text);
    if (!m) continue;
    flags.push({
      title: rule.title,
      evidence: `“${snippet(m[0])}”`,
      inference: rule.inference,
      weight: rule.weight,
      category: rule.category,
    });
    // Later matches of the same rule feed the highlighter only — they never add score.
    const global = new RegExp(
      rule.pattern.source,
      rule.pattern.flags.includes("g") ? rule.pattern.flags : `${rule.pattern.flags}g`,
    );
    const seenPhrases = new Set<string>([m[0].trim().toLowerCase()]);
    let extra = 0;
    for (const g of text.matchAll(global)) {
      if (extra >= 2) break;
      const phrase = g[0].trim();
      if (!phrase || seenPhrases.has(phrase.toLowerCase())) continue;
      seenPhrases.add(phrase.toLowerCase());
      extraHighlights.push({ text: phrase, category: rule.category, severity: signalSeverity(rule.weight) });
      extra += 1;
    }
  }

  const extracted_urls = extractLinks(text);
  flags.push(...linkFlags(text, extracted_urls));

  let score = flags.reduce((sum, f) => sum + f.weight, 0);

  // Irreversible-payment demands are extra alarming outside formal invoices.
  const hasPaymentFlag = flags.some((f) => f.category === "payment");
  if (kind === "payment" && hasPaymentFlag) score += 14;
  if ((kind === "sms" || kind === "whatsapp") && hasPaymentFlag) score += 6;
  // Short messages (SMS/WhatsApp) carry proportionally more signal per red flag.
  if ((kind === "sms" || kind === "whatsapp") && flags.length > 0) score *= 1.25;

  score = Math.max(0, Math.min(100, Math.round(score)));

  const risk_level: RiskLevel = score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";
  const signals = [...flags].sort((a, b) => b.weight - a.weight);
  const topCategory = signals[0]?.category;

  const explanation =
    risk_level === "HIGH"
      ? topCategory
        ? `Multiple strong hallmarks of a scam built on ${CATEGORY_LABEL[topCategory]}. Do not act on this message.`
        : "Multiple strong scam hallmarks detected. Do not act on this message."
      : risk_level === "MEDIUM"
        ? topCategory
          ? `Some indicators of a possible scam built on ${CATEGORY_LABEL[topCategory]}. Verify before you act.`
          : "Some indicators detected. Verify through an official channel before you act."
        : signals.length > 0
          ? "A few minor indicators, but nothing decisive. Stay alert and trust your instincts."
          : "No scam-associated indicators found — but new scams appear daily, so stay alert.";

  const recommended_actions = buildRecommendations(signals, kind, risk_level);
  const claimed_organization = detectClaimedOrganization(text);
  const maxWeight = signals[0]?.weight ?? 0;

  return {
    risk_level,
    confidence: confidenceFor(risk_level, signals.length, maxWeight),
    explanation,
    signals,
    highlights: buildHighlights(text, signals, extraHighlights),
    extracted_urls,
    recommended_actions,
    claimed_organization,
    source: "heuristic",
  };
}

const CATEGORY_ADVICE: Record<FlagCategory, string> = {
  urgency: "Slow down. Nothing legitimate collapses in 24 hours — take the time to verify independently.",
  authority: "Contact the organisation yourself via its official app or the number on your card/official website — never via details in this message.",
  credentials: "Never share codes, passwords or card details. Nobody legitimate will ever ask for a one-time code.",
  payment: "Do not pay, especially by gift card, crypto or wire. If you already paid, contact your bank immediately and ask about a recall or chargeback.",
  links: "Don't click the link. If the message claims to be from a service you use, open that service's app or type its address yourself.",
  prize: "Ignore it. Real prizes never require payment, fees or your bank details to claim.",
  opportunity: "Be sceptical of guaranteed returns or easy money — check who is behind it with an independent search.",
  delivery: "Track the parcel in the courier's official app instead of paying anything from a text or email link.",
  techsupport: "Don't call the number or grant remote access. If worried, contact the software maker through its official site.",
  secrecy: "Break the secrecy: tell someone you trust. Fraud works best in isolation.",
  attachments: "Don't open unexpected attachments — delete them if you don't recognize the sender.",
  software: "Never install software or grant remote access at someone's request from a message or call.",
  tone: "Read the message again calmly — pressure and sloppy formatting are manipulation tools, not signs of importance.",
};

function buildRecommendations(signals: ScamFlag[], kind: MessageKind, risk: RiskLevel): string[] {
  const advice: string[] = [];
  const seen = new Set<FlagCategory>();

  for (const signal of signals) {
    if (seen.has(signal.category)) continue;
    seen.add(signal.category);
    advice.push(CATEGORY_ADVICE[signal.category]);
  }

  if (advice.length === 0) {
    advice.push("Forward suspicious texts to your carrier's scam-reporting number (e.g. 7726) and delete them.");
  }

  if (kind === "payment" || signals.some((f) => f.category === "payment")) {
    advice.push("Verify any invoice or payment request by calling the company on a number you find independently.");
  }
  if (kind === "whatsapp" || kind === "sms") {
    advice.push("If it claims to be someone you know, call them on their usual number to confirm — accounts do get hijacked.");
  }

  advice.push(
    risk === "LOW"
      ? "ScamShield can't guarantee safety — if something feels off, stop and check with someone you trust."
      : "Independently verify important claims through official channels before acting on anything here.",
  );

  return advice.slice(0, 6);
}

/* ================================================================== */
/* RISK ANALYSIS — merge rule engine + AI verdicts                     */
/*                                                                     */
/*   INPUT ──► [ RULE ENGINE ─┬─ AI ] ──► RISK ANALYSIS ──► RESULT     */
/*                                                                     */
/* Both verdicts are computed on every scan (AI only when a key is     */
/* configured); the more cautious risk level wins, signals are         */
/* de-duplicated and confidence is averaged with an agreement bonus.   */
/* ================================================================== */

const RISK_ORDER: RiskLevel[] = ["LOW", "MEDIUM", "HIGH"];

function mergeVerdicts(rules: AnalysisResult, ai: AnalysisResult): AnalysisResult {
  const risk_level =
    RISK_ORDER.indexOf(ai.risk_level) >= RISK_ORDER.indexOf(rules.risk_level) ? ai.risk_level : rules.risk_level;
  const elevated = RISK_ORDER.indexOf(risk_level) > RISK_ORDER.indexOf(ai.risk_level);

  const seen = new Set<string>();
  const signals = [...ai.signals, ...rules.signals]
    .filter((s) => {
      const key = s.title.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 12);

  const agree = ai.risk_level === rules.risk_level;
  const confidence = Math.max(5, Math.min(95, Math.round((ai.confidence + rules.confidence) / 2) + (agree ? 4 : -6)));

  return {
    risk_level,
    confidence,
    signals,
    highlights: rules.highlights,
    explanation: elevated ? rules.explanation : ai.explanation?.trim() ? ai.explanation : rules.explanation,
    recommended_actions: [...new Set([...ai.recommended_actions, ...rules.recommended_actions])].slice(0, 6),
    extracted_urls: [...new Set([...ai.extracted_urls, ...rules.extracted_urls])].slice(0, 10),
    claimed_organization: ai.claimed_organization ?? rules.claimed_organization,
    source: "ai",
    scanned_url: rules.scanned_url ?? ai.scanned_url,
    page_title: rules.page_title ?? ai.page_title,
    extracted_text: ai.extracted_text ?? rules.extracted_text,
    note: elevated
      ? "The rule engine found stronger indicators than the AI did — the more cautious level is shown."
      : agree
        ? undefined
        : "AI and rule-engine verdicts differed — the more cautious level is shown.",
  };
}

/* --- AI analysis (Novita) — activates when NOVITA_API_KEY is set ----- */

const AI_SYSTEM_PROMPT = `You are ScamShield, a scam-risk analysis assistant.

Analyze the supplied message, URL, or extracted screenshot text.

Your task is NOT to determine with certainty whether something is a scam. Instead, identify observable indicators associated with scams.

Look for:
- impersonation
- urgency or threats
- requests for passwords, OTPs, PINs or financial information
- suspicious payment requests
- suspicious URLs
- domain/brand mismatch
- unusual sender information
- requests to bypass normal procedures
- unexpected attachments
- suspicious rewards/prizes
- pressure to keep communication secret
- spelling/formatting anomalies when relevant
- requests to install software
- cryptocurrency/payment requests

Respond ONLY with a JSON object in exactly this shape:
{
  "risk_level": "HIGH" | "MEDIUM" | "LOW",
  "confidence": 0-100,
  "explanation": "one or two plain sentences explaining the verdict",
  "signals": [{ "title": "short indicator name", "evidence": "the exact wording or pattern observed in the input (quote it)", "inference": "what this indicator suggests — hedged language", "weight": 1-20, "category": "urgency|authority|credentials|payment|links|prize|opportunity|delivery|techsupport|secrecy|attachments|software|tone" }],
  "recommended_actions": ["concrete recommended safety action", "..."],
  "extracted_urls": ["URLs found in or referred to by the input"],
  "claimed_organization": "organization the input claims to be from, or null if unclear",
  "extracted_text": "for screenshots only: all readable text from the image, otherwise omit this field"
}

Rules:
- Assign risk_level based on the number and seriousness of observable indicators.
- Do not invent facts that aren't present. Each signal's "evidence" must be quoted from the input; put reasoning in "inference".
- Clearly distinguish observed evidence from inference.
- Never claim certainty that something is fraudulent: use hedged language and keep confidence at or below 95.
- Always recommend independently verifying important claims through official channels.
- If the input is benign, return risk_level "LOW" with an empty signals array.`;

async function callNovitaText(
  user: string,
  apiKey: string,
): Promise<AiVerdictJson> {
  const res = await fetch("https://api.novita.ai/v3/openai/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "meta-llama/llama-3.3-70b-instruct",
      messages: [
        { role: "system", content: AI_SYSTEM_PROMPT },
        { role: "user", content: user },
      ],
      response_format: { type: "json_object" },
      temperature: 0.2,
      max_tokens: 1400,
    }),
    signal: AbortSignal.timeout(25_000),
  });

  if (!res.ok) throw new Error(`AI provider responded ${res.status}`);

  const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const raw = data.choices?.[0]?.message?.content;
  if (!raw) throw new Error("Empty AI response");

  return JSON.parse(raw) as AiVerdictJson;
}

function mapAiResult(parsed: AiVerdictJson, fallback: AnalysisResult): AnalysisResult {
  const risk_level =
    parsed.risk_level === "HIGH" || parsed.risk_level === "MEDIUM" || parsed.risk_level === "LOW"
      ? parsed.risk_level
      : fallback.risk_level;
  const confidence =
    typeof parsed.confidence === "number"
      ? Math.max(0, Math.min(95, Math.round(parsed.confidence))) // never 95+ — no certainty claims
      : fallback.confidence;
  const signals = Array.isArray(parsed.signals)
    ? parsed.signals
        .filter((f): f is ScamFlag => !!f && typeof f.title === "string")
        .map((f) => ({
          title: f.title,
          evidence: typeof f.evidence === "string" ? f.evidence : "",
          inference: typeof f.inference === "string" ? f.inference : "",
          weight: typeof f.weight === "number" ? Math.max(1, Math.min(20, f.weight)) : 5,
          category: (CATEGORY_LABEL[f.category as FlagCategory] ? f.category : "tone") as FlagCategory,
        }))
        .filter((f) => f.evidence || f.inference)
        .sort((a, b) => b.weight - a.weight)
    : fallback.signals;

  const aiUrls =
    Array.isArray(parsed.extracted_urls)
      ? parsed.extracted_urls.filter((u): u is string => typeof u === "string").slice(0, 10)
      : [];
  const extracted_urls = [...new Set([...fallback.extracted_urls, ...aiUrls])];

  const claimed_organization =
    typeof parsed.claimed_organization === "string" && parsed.claimed_organization.trim()
      ? parsed.claimed_organization.trim()
      : fallback.claimed_organization;

  return {
    ...fallback,
    risk_level,
    confidence,
    explanation:
      typeof parsed.explanation === "string" && parsed.explanation.trim() ? parsed.explanation.trim() : fallback.explanation,
    signals,
    extracted_urls,
    recommended_actions:
      Array.isArray(parsed.recommended_actions) && parsed.recommended_actions.length > 0
        ? parsed.recommended_actions.filter((r): r is string => typeof r === "string").slice(0, 6)
        : fallback.recommended_actions,
    claimed_organization,
    source: "ai",
  };
}

/* --- Text mode: RULE ENGINE + AI in parallel paths ------------------- */

export async function analyzeMessage(content: string, kind: MessageKind): Promise<AnalysisResult> {
  const rules = analyzeHeuristics(content, kind);
  const apiKey = process.env.NOVITA_API_KEY;

  if (!apiKey) return rules;

  try {
    const aiParsed = await callNovitaText(`Message type: ${kind}\n\nMessage:\n${content}`, apiKey);
    const aiResult = mapAiResult(aiParsed, rules);
    return mergeVerdicts(rules, aiResult);
  } catch {
    return { ...rules, note: "AI analysis was unavailable — rule-engine verdict shown instead." };
  }
}

/* --- URL mode: link forensics + fetched-page inspection + AI ---------- */

interface FetchedPage {
  ok: boolean;
  finalUrl: string;
  title?: string;
  text: string;
  hasPasswordInput: boolean;
}

async function fetchPage(url: string): Promise<FetchedPage> {
  const res = await fetch(url, {
    headers: { "User-Agent": "Mozilla/5.0 (compatible; ScamShieldBot/1.0)" },
    redirect: "follow",
    signal: AbortSignal.timeout(10_000),
  });
  const contentType = res.headers.get("content-type") ?? "";
  const html = contentType.includes("html") ? (await res.text()).slice(0, 600_000) : "";
  const title = /<title[^>]*>([\s\S]*?)<\/title>/i.exec(html)?.[1]?.replace(/\s+/g, " ").trim();
  const text = html
    .replace(/<(script|style|noscript)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;|&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 4000);
  return {
    ok: res.ok,
    finalUrl: res.url || url,
    title,
    text,
    hasPasswordInput: /<input[^>]+type=["']?password/i.test(html),
  };
}

export async function analyzeUrlMessage(rawUrl: string): Promise<AnalysisResult> {
  let shape: ReturnType<typeof analyzeUrlShape>;
  try {
    shape = analyzeUrlShape(rawUrl);
  } catch {
    throw new Error("That doesn't look like a valid URL.");
  }

  const flags = [...shape.flags];
  let page: FetchedPage | null = null;
  try {
    page = await fetchPage(shape.normalized);
  } catch {
    page = null;
  }

  if (page) {
    if (page.hasPasswordInput) {
      flags.push({
        title: "Page asks for a password",
        evidence: `A password field was observed on the page at ${shape.host}`,
        inference: "Combined with the other indicators, this matches how fake sign-in pages harvest credentials.",
        weight: 14,
        category: "credentials",
      });
    }
    if (page.text.length >= 80) {
      const pageResult = analyzeHeuristics(page.text, "email");
      const seen = new Set(flags.map((f) => f.title));
      for (const f of pageResult.signals) {
        if (!seen.has(f.title)) {
          seen.add(f.title);
          flags.push(f);
        }
      }
    }
  }

  const score = Math.max(0, Math.min(100, flags.reduce((s, f) => s + f.weight, 0)));
  const risk_level: RiskLevel = score >= 60 ? "HIGH" : score >= 30 ? "MEDIUM" : "LOW";
  const signals = [...flags].sort((a, b) => b.weight - a.weight).slice(0, 10);
  const where = page ? `on the page at ${shape.host}` : "in this link";
  const explanation =
    risk_level === "HIGH"
      ? `Serious indicators ${where}. Do not sign in or enter any personal details here.`
      : risk_level === "MEDIUM"
        ? `Some indicators ${where}. If you visit it, don't sign in or share any information.`
        : `No strong scam-associated indicators ${where}. Still, only enter credentials if you're certain of the domain.`;

  const recommended_actions = buildRecommendations(signals, "email", risk_level);
  if (!recommended_actions.some((r) => /type|open that service|official app/i.test(r))) {
    recommended_actions.unshift("Instead of following the link, open the service by typing its official address yourself or using its app.");
  }

  const rules: AnalysisResult = {
    risk_level,
    confidence: confidenceFor(risk_level, signals.length, signals[0]?.weight ?? 0),
    explanation,
    signals,
    highlights: buildHighlights(shape.normalized, signals),
    extracted_urls: [shape.normalized],
    recommended_actions: recommended_actions.slice(0, 6),
    claimed_organization: detectClaimedOrganization(page?.text ?? "", shape.host),
    source: "heuristic",
    scanned_url: shape.normalized,
    page_title: page?.title,
    note: page ? undefined : "Couldn't fetch the page (site down, blocked or not HTML) — verdict is based on the link itself.",
  };

  // Feed the link + fetched page content to the AI and merge with the rule verdict.
  const apiKey = process.env.NOVITA_API_KEY;
  if (apiKey) {
    try {
      const context = `The user scanned this link: ${shape.normalized}\n\n${
        page
          ? `ScamShield fetched the page (title: ${page.title ?? "unknown"}). Page content:\n${page.text.slice(0, 2500)}`
          : "The page could not be fetched — analyze the link itself."
      }`;
      const aiParsed = await callNovitaText(context, apiKey);
      const aiResult = mapAiResult(aiParsed, rules);
      return mergeVerdicts(rules, aiResult);
    } catch {
      // fall through to rules-only result
    }
  }

  return rules;
}

/* --- Screenshot mode: AI vision, then rules re-run on extracted text -- */

export async function analyzeImage(dataUrl: string): Promise<AnalysisResult> {
  const apiKey = process.env.NOVITA_API_KEY;
  if (!apiKey) {
    throw new Error("Screenshot analysis uses AI vision — add NOVITA_API_KEY in your Freebuff Keys/API keys settings and try again. Text and link scanning work without any key.");
  }

  const res = await fetch("https://api.novita.ai/v3/openai/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "qwen/qwen-2.5-vl-72b-instruct",
      messages: [
        { role: "system", content: AI_SYSTEM_PROMPT },
        {
          role: "user",
          content: [
            { type: "text", text: "This is a screenshot of a message, email, chat or payment request. Analyze it for scam indicators, transcribe its text, and respond with the JSON verdict." },
            { type: "image_url", image_url: { url: dataUrl } },
          ],
        },
      ],
      temperature: 0.2,
      max_tokens: 1400,
    }),
    signal: AbortSignal.timeout(40_000),
  });

  if (!res.ok) throw new Error(`The AI vision service returned an error (${res.status}). Please try again.`);

  const data = (await res.json()) as { choices?: { message?: { content?: string } }[] };
  const raw = data.choices?.[0]?.message?.content;
  if (!raw) throw new Error("The AI vision service returned an empty result. Please try again.");

  let parsed: AiVerdictJson;
  try {
    parsed = JSON.parse(raw) as AiVerdictJson;
  } catch {
    throw new Error("The AI vision service returned an unreadable verdict. Please try again.");
  }

  const fallback: AnalysisResult = {
    risk_level: "LOW",
    confidence: 0,
    explanation: "No verdict could be read from the screenshot.",
    signals: [],
    highlights: [],
    extracted_urls: [],
    recommended_actions: [
      "Don't act on the message until you've verified it through an official channel.",
      "If it asks for payment, codes or logins, treat it as suspicious until proven otherwise.",
    ],
    claimed_organization: null,
    source: "ai",
  };
  const extractedText = typeof parsed.extracted_text === "string" ? parsed.extracted_text.trim() : "";
  const aiResult = { ...mapAiResult(parsed, fallback), extracted_text: extractedText || undefined };

  // RULE ENGINE pass: re-run detectors on the text the vision model extracted.
  if (extractedText.length >= 40) {
    const rules = analyzeHeuristics(extractedText.slice(0, 4000), "email");
    return mergeVerdicts(rules, aiResult);
  }

  return aiResult;
}
