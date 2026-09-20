import sharp from "sharp";
import { writeFile } from "node:fs/promises";

// 512×512 SVG source of the ScamShield shield logo (same art as src/app/icon.svg).
const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="512" height="512">
  <rect width="32" height="32" rx="7" fill="#0a0a09"/>
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#fbbf24"/>
      <stop offset="1" stop-color="#d97706"/>
    </linearGradient>
  </defs>
  <path d="M16 4.6 7.2 7.9v6.8c0 5.1 3.5 9.4 8.8 11.4 5.3-2 8.8-6.3 8.8-11.4V7.9L16 4.6Z" fill="none" stroke="url(#g)" stroke-width="2.1" stroke-linejoin="round"/>
  <path d="m12.2 15.8 2.7 2.7 5-5.3" fill="none" stroke="url(#g)" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>
</svg>`;

// Full-bleed variant with no rounded corners (maskable/PWA icons get cropped by launchers).
const svgFull = svg
  .replace(`<rect width="32" height="32" rx="7" fill="#0a0a09"/>`, `<rect width="32" height="32" fill="#0a0a09"/>`)
  .replace(`stroke-width="2.1" stroke-linejoin="round"`, `stroke-width="1.9" stroke-linejoin="round"`);

await writeFile("public/icon-512.png", await sharp(Buffer.from(svg)).resize(512, 512).png().toBuffer());
await writeFile("public/icon-192.png", await sharp(Buffer.from(svg)).resize(192, 192).png().toBuffer());
await writeFile("public/apple-icon.png", await sharp(Buffer.from(svg)).resize(180, 180).png().toBuffer());
await writeFile("public/maskable-icon.png", await sharp(Buffer.from(svgFull)).resize(512, 512).png().toBuffer());
console.log("icons written");
