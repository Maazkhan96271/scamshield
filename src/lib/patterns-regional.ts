import type { Rule } from "./scam";

/**
 * Regional scam pattern packs — scam vocabularies that don't appear in
 * English-language rule sets but dominate specific regions. These merge
 * into the global rule engine; every rule keeps the same evidence/inference
 * discipline as the core rules.
 */

export const REGIONAL_RULES: Rule[] = [
  /* ---------- South Asia: UPI / KYC / LPG (India, Pakistan, Bangladesh) ---------- */
  {
    category: "payment",
    weight: 22,
    pattern: /\b(?:upi|gpay|google\s?pay|phonepe|paytm|bhim)\s*(?:ki|me|se)?\s*(?:id|se|number)?\s*(?:bhij|kij|send|bhej|transfer|kare?|kar(?:o|na|do)|chahiye|dek?hna?)\b|\bsend\s+(?:the\s+)?(?:money|amount|payment)\s+(?:on|to|via)\s+(?:upi|gpay|google\s?pay|phonepe|paytm)\b|\bupi\s+(?:id|number)\s+(?:do|dedo|send|bhejo|share)\s+kare?/i,
    title: "UPI payment request (South Asia)",
    inference:
      "UPI scams (fake KYC expiry, reward transfers, 'send 1 rupee to verify') dominate South Asian payment fraud; any unsolicited UPI request deserves verification.",
  },
  {
    category: "credentials",
    weight: 25,
    pattern: /\b(?:kyc|e[- ]?kyc|re[- ]?kyc)\b.{0,40}\b(?:expire|expired|expiry|update|verify|suspend|suspend|invalid|pending|complete|confirm)\b|\b(?:update|complete|verify)\b.{0,30}\b(?:kyc|e[- ]?kyc)\b/i,
    title: "Fake KYC expiry or update demand",
    inference:
      "Fake 'KYC expiring' messages are the most widespread banking scam in South Asia — banks never suspend accounts for KYC via SMS links.",
  },
  {
    category: "delivery",
    weight: 14,
    pattern: /\b(?:lpg|indane|hp|bharat)\s*(?:gas)?\s*(?:subsidy|connection|cylinder|booking)\b.{0,40}\b(?:expire|update|link|aadhaar|bank)\b|\baadhaar\b.{0,30}\b(?:update|link|verify|suspend|re[- ]?kyc)\b/i,
    title: "LPG subsidy / Aadhaar bait",
    inference:
      "Fake LPG-subsidy expiry and Aadhaar-linking texts redirect to credential-harvesting clones of government portals.",
  },

  /* ---------- West Africa: ECOWAS / inheritance / consignment ---------- */
  {
    category: "opportunity",
    weight: 16,
    pattern: /\b(?:consignment|diplomatic\s+(?:bag|immunity|courier)|atm\s+card|master\s?card.{0,30}(?:deliver|courier|agent)|abidjan|lome|lagos|dakar|accra|ouagadougou|cotonou)\b|\b(?:deceased|late)\s+(?:customer|investor|engineer|contractor)\b.{0,60}\b(?:inheritance|next of kin|fund)\b|\b(?:beneficiary|next of kin)\b.{0,40}\b(?:fund|consignment|box|trunk)\b/i,
    title: "Inheritance / consignment fraud narrative",
    inference:
      "Long-running advance-fee stories (inheritance, ATM consignment, diplomatic bags) are designed to extract 'release fees' — always a scam shape.",
  },
  {
    category: "secrecy",
    weight: 14,
    pattern: /\b(?:eco ?w|ecowas|central bank of nigeria|cbn|efcc)\b.{0,60}\b(?:compensation|fund|release|approve|transfer)\b|\bgod\s?(?:bless|forbid)\b.{0,30}\b(?:transfer|help)\b|\bdo\s?n[o']?t\s+(?:let|tell)\s+(?:anybody|anyone|them|the\s+bank)\b/i,
    title: "Official-sounding fund release",
    inference:
      "Impersonation of West African central banks or ECOWAS with secrecy demands ('don't tell the bank') is a hallmark of advance-fee fraud.",
  },

  /* ---------- LATAM: paquetería / bancos ---------- */
  {
    category: "delivery",
    weight: 14,
    pattern: /\b(?:paquete|paqueter[ií]a|encomienda|aduana)\b.{0,40}\b(?:retenido|detenido|aduanal|impuesto|pagar|liberar)\b|\b(?:estafeta|dhl|mexpost|correos)\b.{0,40}\b(?:rastrear|seguimiento|pago|link)\b/i,
    title: "Fake parcel / customs hold (LATAM)",
    inference:
      "Fake 'paquete retenido en aduana' texts are the most common smishing format across Spanish-speaking countries.",
  },
  {
    category: "authority",
    weight: 18,
    pattern: /\b(?:banco|tarjeta)\b.{0,40}\b(?:bloquead[oa]|suspendid[oa]|clave\s+digital|token\s+caducad[oa]|sinpe|movil?\s+pagado)\b|\bcuenta\s+(?:bloqueada|suspendida)\b.{0,30}\b(?:verificar|reactivar)\b/i,
    title: "Bank account blocked (LATAM)",
    inference:
      "'Su cuenta fue bloqueada' texts push to cloned banking portals to harvest credentials — banks ask you to use the app instead.",
  },

  /* ---------- China / Traditional Chinese ---------- */
  {
    category: "authority",
    weight: 20,
    pattern: /(?:银行卡|账户|账号)(?:被)?(?:冻结|停用|异常|锁定)|(?:涉嫌|涉及)(?:洗钱|犯罪)|(?:公安|网警|银监会)/,
    title: "Bank frozen / police investigation claim (CN)",
    inference:
      "'Your bank card is frozen, you are under investigation' scripts impersonating police are the dominant phone/text scam in Chinese-speaking regions.",
  },
  {
    category: "opportunity",
    weight: 16,
    pattern: /(?:刷单|兼职|点赞|返利|佣金)|(?:投资|博彩)(?:群|平台|导师)/,
    title: "Task-brushing or job rebate scam (CN)",
    inference:
      "'Brush orders for commission' and investment-group pitches are mass-market scams; victims pay upfront and are never repaid.",
  },
];
