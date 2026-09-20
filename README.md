<div align="center">

# 🛡️ ScamShield

**Analyze suspicious messages before you act.**

A free, open-source scam-risk analyzer for emails, SMS, WhatsApp forwards, payment requests,
QR codes, screenshots, and raw email headers. ScamShield flags risk, shows its evidence, and
recommends safe next steps — **without ever claiming certainty**.

[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=nextdotjs&logoColor=white)](https://nextjs.org)
[![React](https://img.shields.io/badge/React-19-149ECA?logo=react&logoColor=white)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)](https://typescriptlang.org)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-4-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com)
[![PWA](https://img.shields.io/badge/PWA-installable-5A0FC8?logo=pwa&logoColor=white)](#-install-as-an-app)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

</div>

---

## ✨ Why ScamShield is different

| | Typical "AI scam checkers" | ScamShield |
|---|---|---|
| Verdict source | One opaque LLM call | **Deterministic rule engine + LLM, merged** — the more cautious verdict wins |
| Explanation | "This looks suspicious" | Every flag shows **Observed evidence** (quoted from your text) vs **Inference** (hedged) |
| Certainty claims | "97% scam probability" | Qualitative bands — *"High risk indicators detected"*, never fake statistics |
| Transparency | Black box | 🔍 **"What triggered the warning"** — the exact suspicious phrases are highlighted in your original message |
| Privacy | Often logs inputs | Scan history is **AES-256-GCM encrypted on your device only** (non-extractable key in IndexedDB) |
| Regional coverage | English-only patterns | **Regional pattern packs** for UPI/KYC, ECOWAS, LATAM, and CN scam vocabularies |
| Install experience | Desktop website only | **Installable PWA** — offline-capable, lives on your home screen, accepts shares from your messaging app |
| Ecosystem | Website only | **Browser extension** that runs the same rule engine on-device |

## 🔍 What it checks

ScamShield runs a weighted **rule engine** over every scan across 13 indicator categories:

- ⏰ **Urgency & pressure** — countdowns, "final warnings", account-closure threats
- 🎭 **Authority impersonation** — fake banks, couriers, tax offices, "security teams"
- 🔐 **Credential harvesting** — OTP, PIN, password, CVV, and bank-detail requests
- 💳 **Payment traps** — gift cards, crypto, wire transfers, surprise "fees"
- 🔗 **Suspicious links** — parsed with a real URL parser: shorteners, look-alike domains, brand mismatch (`paypal` ≠ `paypal.com`), punycode, raw IPs, hyphen-stuffed hosts, credential keywords, risky TLDs, `http://`
- 📦 **Delivery tricks**, 🎁 **prize bait**, 💰 **too-good-to-be-true offers**, 🖥️ **fake tech support**, 🤫 **secrecy pressure**, 📎 **unexpected attachments**, ⬇️ **software-install requests**, ✍️ **formatting anomalies**, **spoofed sender IDs**

Each rule contributes an observed-evidence quote and a hedged inference to the final report.
Internal score (0–100) maps to **LOW / MEDIUM / HIGH** risk bands.

### 🌍 Regional pattern packs

Scam vocabularies differ by region, so the engine merges dedicated packs for:

- **South Asia** — UPI/KYC expiry scams, LPG-subsidy and Aadhaar bait
- **West Africa (ECOWAS)** — inheritance, consignment, and customs-fee formats
- **LATAM** — delivery holds and bank "security checks"
- **China** — impersonation of official channels with uncommon phrasings

### 📧 Email header analysis

Paste raw `.eml` headers (or a whole email) and ScamShield extracts **SPF / DKIM / DMARC**
authentication results, detects **Reply-To domain mismatch** (the signature of business email
compromise), free-mail brand impersonation, and odd routing — each as evidence + inference.

## 🧠 The analysis pipeline

```
              INPUT  (message · link · QR · screenshot · email headers)
                │
       ┌────────┼──────────┐
       ▼        ▼          ▼
 RULE ENGINE  EMAIL       LLM (optional)     ← Novita API key enables AI mode
 deterministic HEADER      vision + reason     (rule engine always runs)
 weighted      FORENSICS   JSON verdict
 rules + regional packs
       │        │           │
       └────────┴─────┬─────┘
                      ▼
               RISK ANALYSIS            ← more cautious verdict wins;
                      ▼                    signals de-duplicated; confidence
                   RESULT                  averaged with agreement bonus
```

- **Without an API key**: the rule engine alone still delivers a complete verdict.
- **With `NOVITA_API_KEY`**: an LLM (and for screenshots, a vision model) analyzes the input in
  parallel; verdicts are merged, and if the two disagree, the more cautious level is shown with a note.

### The killer feature: show me exactly what triggered this

Every scan highlights the precise phrases that raised the alarm in your original text:

> URGENT! Your bank **account is suspended**. **Verify here**:
> https://`bank-security-login.example.com`

…with a severity-colored legend (🔴 high · 🟠 medium · 🔵 low) mapping each mark to its indicator —
so the analysis is transparent instead of a mysterious "AI says HIGH".

## 🚀 Features

- **Five input modes** — paste message text (email/SMS/WhatsApp/payment), analyze a URL
  (fetched server-side, never opened in your browser), **decode QR codes entirely client-side**
  (quishing protection), drop a screenshot (AI vision transcription + rule-engine re-scan), or
  **paste raw email headers** for SPF/DKIM/DMARC + Reply-To forensics
- **🔍 Trigger highlighting** — see exactly which words and links caused the verdict
- **Observable vs inferred** — every indicator separates quoted evidence from hedged inference
- **🧭 Community reports** — crowd-sourced scam flags for domains and phone numbers, folded into
  URL analysis with time-decayed counts; reporting sends only the domain/number and a verdict
  word — never your message
- **Encrypted local history** — last 50 scans stored with AES-256-GCM in your browser; per-entry
  delete, clear-all, plus **passphrase-encrypted backup export/import** (PBKDF2 + AES-256-GCM)
  so you can move history between devices without any cloud copy
- **Installable PWA** — offline-capable app shell, home-screen icon, app shortcuts
- **Share-target** — on Android, share any suspicious SMS straight into ScamShield from your
  messaging app
- **Shareable verdicts** — copy or share a compact, honest summary of any scan
- **Browser extension** — same rule engine, on-device, with one-click "grab selection" from any
  web page (see [`extension/`](extension/README.md))
- **Safe next steps** — every verdict ends with concrete, category-specific recommendations
  (never "just be careful")

## 📲 Install as an app

1. Open ScamShield in Chrome/Edge (desktop or Android) — an **Install app** button appears in the nav.
2. On **iOS Safari**: tap Share → **Add to Home Screen**.
3. On **Android**: you can also use your messaging app's **Share → ScamShield** to scan texts in one tap.

## 🧩 Browser extension

The [`extension/`](extension) folder contains a Chrome/Edge MV3 extension that bundles the same
rule engine with **zero network access** — ideal for checking text right where you read it.

```bash
# Load it in three steps
# 1. chrome://extensions  2. Enable Developer mode  3. Load unpacked → select extension/
```

## 🛠️ Tech stack

- **Next.js 16** (App Router) · **React 19** · **TypeScript 5**
- **Tailwind CSS 4** with a custom dark security-console theme
- **jsQR** for fully client-side QR decoding — images never leave the browser
- **Web Crypto API** — `AES-256-GCM` with non-extractable keys (history) and PBKDF2-derived
  keys (backup export/import)
- **Novita AI** (optional) for LLM/vision analysis — the rule engine works without it
- **PWA**: `manifest.webmanifest` + custom service worker (app-shell precache,
  stale-while-revalidate for assets, network-only for verdict API calls)
- **Chrome MV3 extension** — self-contained popup sharing the core rule engine

## ⚡ Getting started

```bash
git clone https://github.com/Maazkhan96271/scamshield.git
cd scamshield
bun install        # or npm install
bun run dev        # or npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Optional: enable AI analysis

Set `NOVITA_API_KEY` in your environment (`.env.local` or your host's env settings). Without it,
ScamShield runs in rule-engine-only mode — every core feature still works.

## 📁 Project structure

```
src/
├── app/
│   ├── page.tsx               # Landing page
│   ├── analyze/page.tsx       # Scanner + results + community reports (the core experience)
│   ├── history/page.tsx       # Encrypted on-device history + encrypted backup/restore
│   ├── share/page.tsx         # PWA share-target handler
│   ├── api/analyze/route.ts   # Analysis API endpoint
│   ├── api/community/…        # Community report feed (GET) + report (POST)
│   ├── icon.svg               # Shield app icon
│   └── layout.tsx             # Metadata, manifest, theme
├── components/
│   ├── InstallPwaButton.tsx   # beforeinstallprompt install control
│   ├── PwaProviders.tsx       # Service-worker registration
│   ├── QrChecker.tsx          # Client-side QR decoder
│   └── EmailHeaderChecker.tsx # .eml header forensics card
└── lib/
    ├── scam.ts                # Rule engine, URL forensics, AI merge pipeline
    ├── patterns-regional.ts   # Regional scam pattern packs (SA / ECOWAS / LATAM / CN)
    ├── email-headers.ts       # SPF/DKIM/DMARC + Reply-To analysis
    ├── community.ts           # Privacy-preserving report registry (time-decayed, capped)
    ├── history.ts             # AES-GCM encrypted IndexedDB history
    └── history-backup.ts      # Passphrase-encrypted backup export/import
extension/                     # Chrome/Edge MV3 extension (same rule engine, on-device)
scripts/gen-icons.ts           # Regenerates PWA/app icons from the shield SVG
```

## 🔐 Privacy principles

1. **No accounts.** No sign-up, no tracking, no profiles.
2. **History never leaves the device.** It's encrypted with a key your browser generates and
   cannot export; clearing browser data destroys it by design.
3. **Backups are end-to-end encrypted.** The export file is unreadable without your passphrase —
   even we couldn't open it. The passphrase is never stored or transmitted.
4. **QR images are never uploaded.** Decoding happens in your browser; only the decoded string
   is analyzed.
5. **Community reports carry no message content.** Only the domain/number and a verdict word —
   counts decay over time and the registry is size-capped.
6. **URL checks are performed server-side** — the link is fetched by the API (sandboxed, never
   executed) so your browser never touches the destination.
7. **Honest language.** Verdicts are guidance, not guarantees. Confidence describes our certainty
   in the verdict — never a probability that something is fraud.

## 🗺️ Roadmap

- [x] Community scam-report feed (crowd-sourced indicators)
- [x] Email header (.eml) analysis
- [x] Multi-language scam pattern packs
- [x] Browser extension using the same rule engine
- [x] Encrypted history backup (passphrase-based export/import)
- [ ] Deployable report backend (Redis/Postgres) behind the same API shape
- [ ] i18n UI translations (the pattern packs already cover regional vocabularies)
- [ ] Extension store publishing

## 🤝 Contributing

Issues and pull requests are welcome! The rule engine lives in
[`src/lib/scam.ts`](src/lib/scam.ts) — adding a detector is a great first contribution:

```ts
{
  category: "payment",
  weight: 25,
  pattern: /\bsome\s+suspicious\s+phrase\b/i,
  title: "What the indicator is called",
  inference: "Why this pattern matters — in hedged language.",
}
```

Regional contributions belong in [`src/lib/patterns-regional.ts`](src/lib/patterns-regional.ts).

## 📜 Disclaimer

ScamShield provides **risk indicators, not verdicts of fraud**. It can be wrong in both
directions. Always independently verify important claims through official channels, and if you
think you've already been scammed, contact your bank immediately.

---

<div align="center">

**Built for hackathon judges and skeptical relatives alike.**

⭐ Star this repo if ScamShield saved you from a bad day.

</div>
