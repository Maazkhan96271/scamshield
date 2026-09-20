# ScamShield Browser Extension

Companion MV3 extension for [ScamShield](../README.md). It runs the **same weighted rule
engine** as the web app, entirely **on-device** — nothing you paste or select ever leaves
your browser.

## What it does

- 📋 **Grab selected text** from any web page with one click (email bodies, webmail,
  marketplace listings, comment sections…)
- 🔍 **Instant verdict** — LOW / MEDIUM / HIGH risk with the exact indicators, observed
  evidence, and hedged inference for each
- 🚫 **Zero network calls** — the rule engine is bundled into the popup; no API, no
  telemetry, no tracking

## Install locally (Chrome / Edge / Brave)

1. Clone this repository.
2. Open `chrome://extensions` (or `edge://extensions`).
3. Enable **Developer mode**.
4. Click **Load unpacked** and select the `extension/` folder.

Keyboard shortcut: `Alt+Shift+S` opens the popup on any tab.

## Publishing

For store distribution, zip the folder contents (manifest.json at the archive root) and
submit to the Chrome Web Store / Edge Add-ons. The icon (`icon128.png`) can be generated
from `scripts/gen-icons.ts` output by resizing `public/icon-192.png` to 128×128.

## Privacy

- No permissions beyond `storage`, `activeTab`, and `scripting` (selection grab).
- Selections and verdicts stay in the popup's memory; only the last risk level is kept in
  `chrome.storage.local` for the icon badge — clearable at any time.
