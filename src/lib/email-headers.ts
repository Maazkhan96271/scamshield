import type { ScamFlag } from "./scam";

/**
 * Email header analysis — extracts authentication signals (SPF, DKIM, DMARC),
 * alignment problems (Reply-To ≠ From), and odd routing from raw RFC-822
 * headers (paste the .eml header block or the whole email).
 *
 * Language is deliberately hedged: headers are evidence, not proof.
 */

export interface EmailHeaderAnalysis {
  from: string | null;
  fromDomain: string | null;
  replyTo: string | null;
  replyToDomain: string | null;
  returnPathDomain: string | null;
  spf: "pass" | "fail" | "softfail" | "none" | "unknown";
  dkim: "pass" | "fail" | "softfail" | "none" | "unknown";
  dmarc: "pass" | "fail" | "softfail" | "none" | "unknown";
  flags: ScamFlag[];
}

function domainOf(addr: string | null): string | null {
  if (!addr) return null;
  const m = /@([A-Za-z0-9.-]+)/.exec(addr);
  return m ? m[1].toLowerCase().replace(/^www\./, "") : null;
}

function extractAddr(value: string | null): string | null {
  if (!value) return null;
  const angled = /<([^>]+)>/.exec(value);
  const raw = angled ? angled[1] : value.trim();
  return /@/.test(raw) ? raw.trim() : null;
}

function authValue(headers: string, mechanism: string): EmailHeaderAnalysis["spf" | "dkim" | "dmarc"] {
  const re = new RegExp(`${mechanism}\\s*=\\s*(pass|fail|softfail|none|neutral|temperror|permerror)`, "i");
  const m = re.exec(headers);
  if (!m) return "unknown";
  const v = m[1].toLowerCase();
  if (v === "pass") return "pass";
  if (v === "softfail" || v === "neutral" || v.includes("error")) return "softfail";
  if (v === "none") return "none";
  return "fail";
}

export function analyzeEmailHeaders(raw: string): EmailHeaderAnalysis {
  // Only look at the header block: everything before the first blank line.
  const headerBlock = raw.split(/\r?\n\r?\n/)[0] ?? raw;
  const lower = headerBlock.toLowerCase();

  const fromLine = /(^|\n)from:\s*([^\n]+)/i.exec(headerBlock)?.[2]?.trim() ?? null;
  const replyToLine = /(^|\n)reply-to:\s*([^\n]+)/i.exec(headerBlock)?.[2]?.trim() ?? null;
  const returnPathLine = /(^|\n)return-path:\s*([^\n]+)/i.exec(headerBlock)?.[2]?.trim() ?? null;

  const from = extractAddr(fromLine);
  const replyTo = extractAddr(replyToLine);
  const fromDomain = domainOf(from);
  const replyToDomain = domainOf(replyTo);
  const returnPathDomain = domainOf(returnPathLine);

  const spf = authValue(lower, "spf");
  const dkim = authValue(lower, "dkim");
  const dmarc = authValue(lower, "dmarc");

  const flags: ScamFlag[] = [];

  // Reply-To hijack: the highest-value header signal in business email compromise.
  if (replyToDomain && fromDomain && replyToDomain !== fromDomain) {
    flags.push({
      title: "Replies are diverted to a different domain",
      evidence: `From: ${fromDomain} · Reply-To: ${replyToDomain}`,
      inference:
        "Reply-To pointing somewhere other than the sender's own domain is the signature of business email compromise — replies would reach the attacker, not the supposed sender.",
      weight: 25,
      category: "authority",
    });
  }

  // Authentication failures.
  if (spf === "fail" || spf === "softfail") {
    flags.push({
      title: `SPF check ${spf === "fail" ? "failed" : "soft-failed"}`,
      evidence: `Authentication-Results reports spf=${spf}`,
      inference:
        "The sending server is not authorized by the claimed sender's domain — common in spoofed or unsolicited mail, though some small servers misconfigure it.",
      weight: spf === "fail" ? 18 : 10,
      category: "authority",
    });
  }
  if (dmarc === "fail") {
    flags.push({
      title: "DMARC check failed",
      evidence: "Authentication-Results reports dmarc=fail",
      inference:
        "The message does not align with the domain's published anti-spoofing policy — a strong indicator of impersonation.",
      weight: 20,
      category: "authority",
    });
  }
  if (dkim === "fail") {
    flags.push({
      title: "DKIM signature failed",
      evidence: "Authentication-Results reports dkim=fail",
      inference:
        "The message was modified in transit or the signature is forged — treat the content with suspicion.",
      weight: 14,
      category: "tone",
    });
  }

  // Display-name / domain mismatch: "PayPal <billing@random.xyz>".
  if (fromLine && fromDomain) {
    const displayMatch = /^"?([^"<]+)"?\s*</.exec(fromLine);
    if (displayMatch) {
      const displayName = displayMatch[1].trim().toLowerCase();
      const brandRoot = fromDomain.split(".")[0];
      if (brandRoot.length >= 4 && displayName.length >= 4 && !displayName.includes(brandRoot) && !brandRoot.includes(displayName.split(" ")[0])) {
        const officialBrand = /paypal|apple|amazon|netflix|microsoft|google|whatsapp|hsbc|binance|coinbase/i.test(displayName);
        if (officialBrand) {
          flags.push({
            title: "Sender name doesn't match the sending domain",
            evidence: `${displayMatch[1].trim()} <${fromDomain}>`,
            inference:
              "A familiar display name paired with an unrelated sending domain is a classic impersonation technique.",
            weight: 20,
            category: "authority",
          });
        }
      }
    }
  }

  // Free-mail used to impersonate an organization (very common in gift-card/CEO fraud).
  if (fromDomain && /paypal|apple|amazon|netflix|microsoft|hsbc|binance|coinbase/i.test(fromLine ?? "") && /\b(gmail|yahoo|hotmail|outlook|aol|proton|mail\.ru|yandex)\./i.test(fromDomain)) {
    flags.push({
      title: "Brand name on a free email service",
      evidence: fromDomain,
      inference:
        "Real companies send from their own domains — a brand name on gmail/yahoo/outlook is usually impersonation.",
      weight: 22,
      category: "authority",
    });
  }

  return {
    from,
    fromDomain,
    replyTo,
    replyToDomain,
    returnPathDomain,
    spf,
    dkim,
    dmarc,
    flags,
  };
}
