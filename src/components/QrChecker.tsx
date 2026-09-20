"use client";

import { useRef, useState } from "react";
import jsQR from "jsqr";

const URL_LIKE = /^(https?:\/\/|www\.)\S+$/i;
const BARE_DOMAIN_LIKE = /^(?:[a-z0-9-]+\.)+[a-z]{2,}(\/\S*)?$/i;

/** True when the decoded QR payload should be analyzed as a link rather than message text. */
export function isUrlLike(text: string): boolean {
  const t = text.trim();
  return URL_LIKE.test(t) || BARE_DOMAIN_LIKE.test(t);
}

/**
 * QR scam checker — QR codes from messages, posters and parking meters are a
 * major scam delivery channel (quishing). Decoding happens fully in-browser;
 * only the decoded string is sent for analysis.
 */
export default function QrChecker({
  onAnalyze,
  loading,
}: {
  onAnalyze: (mode: "text" | "url", content: string) => void;
  loading: boolean;
}) {
  const [decoding, setDecoding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [decoded, setDecoded] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  async function handleFile(file: File) {
    setError(null);
    setDecoded(null);
    if (!/^image\/(png|jpeg|webp)$/.test(file.type)) {
      setError("Choose a PNG, JPEG or WebP image of the QR code.");
      return;
    }
    setDecoding(true);
    try {
      const bitmap = await createImageBitmap(file);
      const canvas = document.createElement("canvas");
      canvas.width = bitmap.width;
      canvas.height = bitmap.height;
      const ctx = canvas.getContext("2d");
      if (!ctx) throw new Error("canvas unavailable");
      ctx.drawImage(bitmap, 0, 0);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(data.data, data.width, data.height);
      if (!code) {
        setError("No QR code found in that image — try a sharper crop.");
        return;
      }
      setDecoded(code.data);
    } catch {
      setError("Couldn't read that image. Try another screenshot.");
    } finally {
      setDecoding(false);
    }
  }

  async function analyzeDecoded() {
    if (!decoded || loading) return;
    onAnalyze(isUrlLike(decoded) ? "url" : "text", decoded);
  }

  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <h2 className="text-lg font-medium">
        QR code check
        <span className="ml-2 align-middle text-xs font-normal text-muted">decoded in your browser — the image never uploads</span>
      </h2>
      <p className="mt-1 text-xs leading-5 text-muted">
        Scammers hide phishing links inside QR codes (&ldquo;quishing&rdquo;) on posters, parking
        meters and &ldquo;verify your account&rdquo; cards. Scan before you tap.
      </p>

      <label
        onDragOver={(e) => {
          e.preventDefault();
        }}
        onDrop={(e) => {
          e.preventDefault();
          const file = e.dataTransfer.files?.[0];
          if (file) void handleFile(file);
        }}
        className="mt-3 flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed border-line bg-background/60 px-6 py-6 text-center transition hover:border-accent/40"
      >
        <span className="flex h-10 w-10 items-center justify-center rounded-lg border border-line bg-surface-2 text-muted">
          <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5" aria-hidden>
            <path d="M3.5 8.5v-3a2 2 0 0 1 2-2h3M15.5 3.5h3a2 2 0 0 1 2 2v3M20.5 15.5v3a2 2 0 0 1-2 2h-3M8.5 20.5h-3a2 2 0 0 1-2-2v-3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
            <rect x="8" y="8" width="8" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.6" />
          </svg>
        </span>
        <span className="mt-2 text-sm font-medium">{decoding ? "Decoding…" : "Drop or click to upload a QR screenshot"}</span>
        <span className="mt-1 text-xs text-muted">PNG, JPEG, WebP · decoded locally with jsQR</span>
        <input
          ref={inputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          className="hidden"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void handleFile(file);
          }}
        />
      </label>

      {error && (
        <p role="alert" className="mt-3 rounded-lg border border-danger/40 bg-danger/10 p-3 text-sm text-danger">
          {error}
        </p>
      )}

      {decoded && (
        <div className="mt-3 rounded-xl border border-line bg-background/60 p-3">
          <p className="break-all font-mono text-xs text-foreground/85">{decoded}</p>
          <button
            type="button"
            onClick={() => void analyzeDecoded()}
            disabled={loading}
            className="mt-3 inline-flex h-10 items-center justify-center rounded-lg bg-accent px-4 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:opacity-40"
          >
            {isUrlLike(decoded) ? "Analyze decoded link" : "Analyze decoded text"}
          </button>
        </div>
      )}
    </div>
  );
}
