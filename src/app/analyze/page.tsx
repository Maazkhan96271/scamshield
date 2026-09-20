"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  confidenceBand,
  MAX_CONTENT_LENGTH,
  MAX_IMAGE_BYTES,
  MESSAGE_KINDS,
  signalSeverity,
  type AnalysisMode,
  type AnalysisResult,
  type FlagCategory,
  type Highlight,
  type MessageKind,
  type RiskLevel,
  type SignalSeverity,
} from "@/lib/scam";
import { addHistory } from "@/lib/history";

const RISK_EMOJI: Record<RiskLevel, string> = {
  HIGH: "🚨",
  MEDIUM: "⚠️",
  LOW: "✅",
};

const RISK_TITLE: Record<RiskLevel, string> = {
  HIGH: "High Risk",
  MEDIUM: "Medium Risk",
  LOW: "Low Risk",
};

const SEV_ORDER: Record<SignalSeverity, number> = { high: 3, medium: 2, low: 1 };

const SEVERITY_META: Record<SignalSeverity, { label: string; chip: string; mark: string; dot: string }> = {
  high: {
    label: "High severity",
    chip: "border-danger/50 bg-danger/10 text-danger",
    mark: "bg-danger/25 text-danger decoration-danger/60 underline decoration-2 underline-offset-4",
    dot: "bg-danger",
  },
  medium: {
    label: "Medium severity",
    chip: "border-warn/50 bg-warn/10 text-warn",
    mark: "bg-warn/25 text-warn decoration-warn/60 underline decoration-2 underline-offset-4",
    dot: "bg-warn",
  },
  low: {
    label: "Low severity",
    chip: "border-line bg-surface-2 text-muted",
    mark: "bg-accent/20 text-accent decoration-accent/60 underline decoration-2 underline-offset-4",
    dot: "bg-accent",
  },
};

const CATEGORY_META: Record<FlagCategory, { icon: string; label: string }> = {
  urgency: { icon: "⏰", label: "Urgency" },
  authority: { icon: "🎭", label: "Impersonation" },
  credentials: { icon: "🔐", label: "Sensitive information" },
  payment: { icon: "💳", label: "Payment request" },
  links: { icon: "🔗", label: "Suspicious link" },
  prize: { icon: "🎁", label: "Prize bait" },
  opportunity: { icon: "💰", label: "Too-good-to-be-true" },
  delivery: { icon: "📦", label: "Delivery trick" },
  techsupport: { icon: "🖥️", label: "Fake tech support" },
  secrecy: { icon: "🤫", label: "Secrecy pressure" },
  attachments: { icon: "📎", label: "Attachment" },
  software: { icon: "⬇️", label: "Software install" },
  tone: { icon: "✍️", label: "Formatting anomalies" },
};

const SAMPLES: { label: string; kind: MessageKind; text: string }[] = [
  {
    label: "Phishing email",
    kind: "email",
    text: "Dear Customer,\n\nWe detected unusual activity in your account. Your access will be permanently suspended within 24 hours unless you confirm your identity immediately. Click here to verify your password and card details: http://secure-paypal-verification.top/login\n\nThank you,\nPayPal Security Team",
  },
  {
    label: "Smishing SMS",
    kind: "sms",
    text: "ROYAL MAIL: Your parcel is on hold, unpaid customs fee of £2.99. Pay now to reschedule delivery: bit.ly/rm-parcel-4u",
  },
  {
    label: "WhatsApp job offer",
    kind: "whatsapp",
    text: "Hi! You've been selected for a work-from-home position. Earn $500 a day, guaranteed income, paid in bitcoin. Just pay the $50 processing fee to unlock your account and start today!!!",
  },
  {
    label: "Payment request",
    kind: "payment",
    text: "Invoice #8841 final notice. Your account will be suspended if the balance is not cleared within 24 hours. Make a payment of $1,450 via wire transfer or gift card to release your funds.",
  },
];

const RISK_STYLES: Record<RiskLevel, { chip: string; bar: string; label: string }> = {
  HIGH: { chip: "border-danger/50 bg-danger/10 text-danger", bar: "from-warn to-danger", label: "HIGH RISK" },
  MEDIUM: { chip: "border-warn/50 bg-warn/10 text-warn", bar: "from-safe to-warn", label: "MEDIUM RISK" },
  LOW: { chip: "border-safe/50 bg-safe/10 text-safe", bar: "from-safe to-safe", label: "LOW RISK" },
};

interface UploadedImage {
  dataUrl: string;
  name: string;
  size: number;
}

function ShieldLogo({ className = "h-6 w-6" }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" className={className} aria-hidden>
      <path
        d="M12 2.5 4.5 5.2v6.1c0 4.6 3.2 8.4 7.5 10.2 4.3-1.8 7.5-5.6 7.5-10.2V5.2L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="m8.7 12.1 2.3 2.3 4.3-4.6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function ScanButton({
  label,
  onClick,
  disabled,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-accent px-5 text-sm font-semibold text-background shadow-[0_0_36px_-14px_rgba(45,212,191,0.5)] transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
    >
      {label}
    </button>
  );
}

interface TriggerPart {
  text: string;
  h?: Highlight;
}

/** "Show me exactly what triggered the warning" — highlights matched phrases in the original text. */
function TriggerSection({
  text,
  highlights,
  sourceLabel,
}: {
  text: string;
  highlights: Highlight[];
  sourceLabel: string;
}) {
  const { parts, matched } = useMemo(() => {
    const claimed: { start: number; end: number; h: Highlight; display: string }[] = [];
    const lower = text.toLowerCase();
    const ordered = [...highlights].sort(
      (a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity] || b.text.length - a.text.length,
    );
    for (const h of ordered) {
      const start = lower.indexOf(h.text.toLowerCase());
      if (start === -1) continue;
      const end = start + h.text.length;
      if (claimed.some((c) => start < c.end && end > c.start)) continue;
      claimed.push({ start, end, h, display: text.slice(start, end) });
    }
    claimed.sort((a, b) => a.start - b.start);
    const parts: TriggerPart[] = [];
    let pos = 0;
    for (const c of claimed) {
      if (c.start > pos) parts.push({ text: text.slice(pos, c.start) });
      parts.push({ text: c.display, h: c.h });
      pos = c.end;
    }
    if (pos < text.length) parts.push({ text: text.slice(pos) });
    return { parts, matched: claimed };
  }, [text, highlights]);

  if (matched.length === 0) return null;

  return (
    <div className="panel rounded-2xl border-accent/25 p-5 sm:p-6">
      <h2 className="font-medium">🔍 What triggered the warning</h2>
      <p className="mt-1 text-xs text-muted">
        Suspicious phrases highlighted in the original {sourceLabel} — every mark matches an indicator above.
      </p>
      <div className="mt-3 max-h-72 overflow-y-auto whitespace-pre-wrap break-words rounded-xl border border-line bg-background/60 p-4 font-mono text-sm leading-7 text-foreground/85">
        {parts.map((p, i) =>
          p.h ? (
            <mark
              key={i}
              title={CATEGORY_META[p.h.category].label}
              className={`rounded px-0.5 font-semibold ${SEVERITY_META[p.h.severity].mark}`}
            >
              {p.text}
            </mark>
          ) : (
            <span key={i}>{p.text}</span>
          ),
        )}
      </div>
      <ul className="mt-3 flex flex-wrap gap-1.5">
        {matched.map((m, i) => (
          <li
            key={i}
            className="flex max-w-full items-center gap-1.5 rounded-full border border-line bg-surface-2/60 px-2.5 py-1 text-xs"
          >
            <span className={`h-2 w-2 shrink-0 rounded-full ${SEVERITY_META[m.h.severity].dot}`} aria-hidden />
            <span className="font-medium text-foreground/85">{CATEGORY_META[m.h.category].label}</span>
            <span className="max-w-[12rem] truncate font-mono text-muted">“{m.display}”</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function AnalyzePage() {
  const [content, setContent] = useState("");
  const [kind, setKind] = useState<MessageKind>("email");
  const [urlInput, setUrlInput] = useState("");
  const [image, setImage] = useState<UploadedImage | null>(null);
  const [dragging, setDragging] = useState(false);
  const [activeMode, setActiveMode] = useState<AnalysisMode>("text");
  const [scannedText, setScannedText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const chars = content.length;
  const overLimit = chars > MAX_CONTENT_LENGTH;

  /** Switching message type starts a fresh scan — text, verdict and errors are cleared. */
  function switchKind(next: MessageKind) {
    if (next === kind) return;
    setKind(next);
    setContent("");
    setResult(null);
    setError(null);
    setScannedText("");
  }

  function handleFile(file: File) {
    setError(null);
    setResult(null);
    if (!/^image\/(png|jpeg|webp)$/.test(file.type)) {
      setError("Please choose a PNG, JPEG or WebP image.");
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setError("Screenshot is too large — max 5 MB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setImage({ dataUrl: String(reader.result), name: file.name, size: file.size });
    };
    reader.readAsDataURL(file);
  }

  async function runScan(mode: AnalysisMode) {
    if (loading) return;
    if (mode === "text") {
      if (!content.trim() || overLimit) return;
    } else if (mode === "url") {
      if (!urlInput.trim()) return;
    } else if (!image) {
      return;
    }

    setActiveMode(mode);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const payload =
        mode === "text"
          ? { mode: "text", content, kind }
          : mode === "url"
            ? { mode: "url", url: urlInput.trim() }
            : { mode: "image", imageDataUrl: image!.dataUrl };
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data?.error === "string" ? data.error : "Analysis failed");
      const result = data as AnalysisResult;
      setScannedText(mode === "text" ? content : mode === "url" ? urlInput.trim() : "");
      setResult(result);
      // Archive the scan in the encrypted on-device history (best effort).
      void addHistory({
        mode,
        kind: mode === "text" ? kind : undefined,
        preview:
          mode === "text"
            ? content
            : mode === "url"
              ? urlInput.trim()
              : "Screenshot scan",
        url: mode === "url" ? urlInput.trim() : undefined,
        result,
      }).catch(() => undefined);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  const loadingText =
    activeMode === "url"
      ? "Fetching and inspecting the page…"
      : activeMode === "image"
        ? "Reading the screenshot…"
        : "Weighing the red flags…";

  return (
    <div className="flex min-h-screen flex-col">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-line/70 bg-background/80 backdrop-blur-md">
        <nav className="mx-auto flex h-16 w-full max-w-6xl items-center justify-between px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/30 bg-accent/10 text-accent">
              <ShieldLogo className="h-5 w-5" />
            </span>
            <span className="text-lg font-semibold tracking-tight">
              Scam<span className="text-accent">Shield</span>
            </span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/history" className="text-sm text-muted transition-colors hover:text-foreground">
              History
            </Link>
            <Link href="/" className="text-sm text-muted transition-colors hover:text-foreground">
              ← Back to home
            </Link>
          </div>
        </nav>
      </header>

      <main className="mx-auto grid w-full max-w-6xl flex-1 gap-8 px-4 py-10 sm:px-6 lg:grid-cols-[0.95fr_1.05fr] lg:items-start">
        {/* Input column — three stacked scanners */}
        <section className="space-y-5">
          {/* 1. Message text */}
          <div className="panel rounded-2xl p-5 sm:p-6">
            <h2 className="flex items-baseline justify-between text-lg font-medium">
              Message text
              <span className="font-mono text-xs font-normal text-muted">{kindLabel(kind)}</span>
            </h2>
            <div className="mt-3 flex flex-wrap gap-1.5" role="group" aria-label="Message type">
              {MESSAGE_KINDS.map((k) => (
                <button
                  key={k.value}
                  type="button"
                  onClick={() => switchKind(k.value)}
                  className={`rounded-lg border px-2.5 py-1 text-xs transition ${
                    kind === k.value
                      ? "border-accent/60 bg-accent/15 text-accent"
                      : "border-line bg-surface-2/60 text-muted hover:border-accent/30 hover:text-foreground"
                  }`}
                >
                  {k.label}
                </button>
              ))}
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              rows={6}
              placeholder="Paste suspicious message here…"
              className={`mt-3 w-full resize-y rounded-xl border bg-background/60 p-4 font-mono text-sm leading-6 text-foreground placeholder:text-muted/60 focus:outline-none focus:ring-2 focus:ring-accent/40 ${
                overLimit ? "border-danger/60" : "border-line focus:border-accent/50"
              }`}
            />
            <div className="mt-1.5 flex items-center justify-between font-mono text-xs">
              <span className={overLimit ? "text-danger" : "text-muted"}>
                {chars.toLocaleString()} / {MAX_CONTENT_LENGTH.toLocaleString()}
              </span>
              {overLimit && <span className="text-danger">Message too long</span>}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="text-xs text-muted">Samples:</span>
              {SAMPLES.map((s) => (
                <button
                  key={s.label}
                  type="button"
                  onClick={() => {
                    setKind(s.kind);
                    setContent(s.text);
                    setResult(null);
                    setError(null);
                  }}
                  className="rounded-full border border-line bg-surface-2/60 px-2.5 py-1 text-xs text-muted transition hover:border-accent/40 hover:text-accent"
                >
                  {s.label}
                </button>
              ))}
            </div>
            <ScanButton label="🔍 Analyze" onClick={() => runScan("text")} disabled={loading || !content.trim() || overLimit} />
          </div>

          {/* 2. URL */}
          <div className="panel rounded-2xl p-5 sm:p-6">
            <h2 className="text-lg font-medium">
              Link check
              <span className="ml-2 align-middle text-xs font-normal text-muted">fetches safely, without opening it for you</span>
            </h2>
            <label htmlFor="url-input" className="mt-3 block text-sm font-medium">
              Enter suspicious URL
            </label>
            <input
              id="url-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/verify"
              className="mt-2 w-full rounded-xl border border-line bg-background/60 px-4 py-3 font-mono text-sm text-foreground placeholder:text-muted/60 focus:border-accent/50 focus:outline-none focus:ring-2 focus:ring-accent/40"
            />
            <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
              <button
                type="button"
                onClick={() => {
                  setUrlInput("https://secure-paypal-verification.top/login");
                  setResult(null);
                  setError(null);
                }}
                className="rounded-full border border-line bg-surface-2/60 px-2.5 py-1 font-mono text-xs text-muted transition hover:border-accent/40 hover:text-accent"
              >
                Try a fake PayPal login
              </button>
              <ScanButton label="Analyze URL" onClick={() => runScan("url")} disabled={loading || !urlInput.trim()} />
            </div>
          </div>

          {/* 3. Screenshot */}
          <div className="panel rounded-2xl p-5 sm:p-6">
            <h2 className="text-lg font-medium">Screenshot</h2>
            <div className="mt-3">
              {image ? (
                <div className="rounded-xl border border-line bg-background/60 p-3">
                  {/* eslint-disable-next-line @next/next/no-img-element */}
                  <img
                    src={image.dataUrl}
                    alt={`Screenshot preview: ${image.name}`}
                    className="max-h-56 w-full rounded-lg border border-line/60 object-contain"
                  />
                  <div className="mt-2 flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs text-muted">{image.name}</span>
                    <button
                      type="button"
                      onClick={() => setImage(null)}
                      className="rounded-md border border-line px-2 py-1 text-xs text-muted transition hover:border-danger/50 hover:text-danger"
                    >
                      Remove
                    </button>
                  </div>
                </div>
              ) : (
                <label
                  onDragOver={(e) => {
                    e.preventDefault();
                    setDragging(true);
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={(e) => {
                    e.preventDefault();
                    setDragging(false);
                    const file = e.dataTransfer.files?.[0];
                    if (file) handleFile(file);
                  }}
                  className={`flex cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed px-6 py-8 text-center transition ${
                    dragging ? "border-accent/70 bg-accent/10" : "border-line bg-background/60 hover:border-accent/40"
                  }`}
                >
                  <span className="flex h-11 w-11 items-center justify-center rounded-xl border border-line bg-surface-2 text-muted">
                    <svg viewBox="0 0 24 24" fill="none" className="h-5 w-5" aria-hidden>
                      <rect x="3.5" y="4.5" width="17" height="15" rx="2.5" stroke="currentColor" strokeWidth="1.5" />
                      <circle cx="9" cy="10" r="1.75" stroke="currentColor" strokeWidth="1.5" />
                      <path d="m5.5 17.5 4.2-4.2 3 3 2.6-2.6 3.2 3.2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </span>
                  <span className="mt-2.5 text-sm font-medium">Drop screenshot</span>
                  <span className="mt-1 text-xs text-muted">or click to browse — PNG, JPEG, WebP · max 5 MB</span>
                  <input
                    type="file"
                    accept="image/png,image/jpeg,image/webp"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleFile(file);
                    }}
                  />
                </label>
              )}
            </div>
            <div className="mt-4 flex flex-wrap items-center justify-between gap-2">
              <p className="text-xs leading-5 text-muted">
                Uses AI vision — needs <span className="font-mono text-foreground/80">NOVITA_API_KEY</span> in your Keys/API keys.
              </p>
              <ScanButton
                label="Analyze Screenshot"
                onClick={() => runScan("image")}
                disabled={loading || !image}
              />
            </div>
          </div>
        </section>

        {/* Result column */}
        <section aria-live="polite">
          {loading && (
            <div className="panel relative flex min-h-[420px] flex-col items-center justify-center overflow-hidden rounded-2xl">
              <div className="scanline" aria-hidden />
              <ShieldLogo className="h-10 w-10 text-accent" />
              <p className="mt-4 font-medium">{loadingText}</p>
              <p className="mt-1 font-mono text-xs text-muted">checking urgency · authority · payments · links</p>
            </div>
          )}

          {!loading && error && (
            <div className="panel flex min-h-[420px] items-center rounded-2xl p-6">
              <p role="alert" className="rounded-lg border border-danger/40 bg-danger/10 p-4 text-sm leading-6 text-danger">
                {error}
              </p>
            </div>
          )}

          {!loading && !error && !result && (
            <div className="panel flex min-h-[420px] flex-col items-center justify-center rounded-2xl p-8 text-center">
              <span className="flex h-14 w-14 items-center justify-center rounded-xl border border-line bg-surface-2 text-muted">
                <ShieldLogo className="h-7 w-7" />
              </span>
              <h2 className="mt-4 text-lg font-medium">Your verdict appears here</h2>
              <p className="mt-2 max-w-sm text-sm leading-6 text-muted">
                Paste a message, drop in a link, or upload a screenshot — ScamShield grades the risk,
                lists the red flags it finds, and suggests safe next steps.
              </p>
              <p className="mt-6 font-mono text-[11px] uppercase tracking-widest text-muted">
                verdicts are guidance, not guarantees
              </p>
            </div>
          )}

          {!loading && !error && result && (
            <div className="rise-in space-y-4">
              {/* Verdict header */}
              <div className="panel panel-glow rounded-2xl p-5 sm:p-6">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <span className="text-4xl leading-none" aria-hidden>
                      {RISK_EMOJI[result.risk_level]}
                    </span>
                    <div>
                      <h2 className="text-xl font-bold tracking-tight">{RISK_TITLE[result.risk_level]}</h2>
                      <p className="mt-0.5 text-sm text-muted">
                        {result.signals.length > 0
                          ? `${result.signals.length} risk indicator${result.signals.length === 1 ? "" : "s"} detected`
                          : "No risk indicators detected"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {activeMode === "image" && image && (
                      /* eslint-disable-next-line @next/next/no-img-element */
                      <img
                        src={image.dataUrl}
                        alt="Scanned screenshot thumbnail"
                        className="h-10 w-14 rounded border border-line object-cover"
                      />
                    )}
                    <span
                      className={`rounded-md border px-3 py-1.5 font-mono text-sm font-bold tracking-wide ${RISK_STYLES[result.risk_level].chip}`}
                    >
                      {RISK_STYLES[result.risk_level].label}
                    </span>
                  </div>
                </div>
                <p className="mt-3 font-mono text-xs text-muted">
                  {result.source === "ai" ? "AI + rule engine analysis" : "rule engine analysis"} · confidence in verdict:{" "}
                  <span className="text-accent">{confidenceBand(result.confidence)}</span> (not a probability of fraud)
                </p>
                <p className="mt-4 text-[15px] leading-7 text-foreground/90">{result.explanation}</p>
                {result.claimed_organization && (
                  <p className="mt-3 text-sm text-muted">
                    Claims to be from:{" "}
                    <span className="rounded-md border border-warn/40 bg-warn/10 px-2 py-0.5 font-mono text-xs font-semibold text-warn">
                      {result.claimed_organization}
                    </span>
                  </p>
                )}
                {result.note && (
                  <p className="mt-3 rounded-lg border border-warn/40 bg-warn/10 p-3 text-sm text-warn">{result.note}</p>
                )}
              </div>

              {/* What triggered the warning — the killer feature */}
              <TriggerSection
                text={result.extracted_text ?? scannedText}
                highlights={result.highlights}
                sourceLabel={
                  activeMode === "image" ? "screenshot transcription" : activeMode === "url" ? "URL" : "message"
                }
              />

              {/* Scanned link */}
              {result.scanned_url && (
                <div className="panel rounded-2xl p-5 sm:p-6">
                  <h2 className="font-medium">Link checked</h2>
                  <p className="mt-2 break-all font-mono text-xs text-warn">{result.scanned_url}</p>
                  {result.page_title && (
                    <p className="mt-2 text-sm text-muted">
                      Page title: <span className="text-foreground/85">“{result.page_title}”</span>
                    </p>
                  )}
                </div>
              )}

              {/* Flags */}
              {result.signals.length > 0 && (
                <div className="panel rounded-2xl p-5 sm:p-6">
                  <h2 className="font-medium">
                    Observable indicators <span className="font-mono text-sm text-muted">({result.signals.length})</span>
                  </h2>
                  <ul className="mt-4 space-y-4">
                    {result.signals.map((flag, i) => {
                      const sev = SEVERITY_META[signalSeverity(flag.weight)];
                      return (
                        <li key={i} className="flex gap-3">
                          <span
                            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-line bg-surface-2 text-base"
                            aria-hidden
                          >
                            {CATEGORY_META[flag.category].icon}
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <p className="text-sm font-medium">{flag.title}</p>
                              <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${sev.chip}`}>
                                {sev.label}
                              </span>
                            </div>
                            {flag.evidence && (
                              <p className="mt-1 break-words font-mono text-xs leading-5 text-foreground/75">
                                <span className="font-semibold text-safe">Observed:</span> {flag.evidence}
                              </p>
                            )}
                            {flag.inference && (
                              <p className="mt-1 text-sm leading-6 text-muted">
                                <span className="font-medium text-foreground/80">Inference:</span> {flag.inference}
                              </p>
                            )}
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}

              {/* Links */}
              {!result.scanned_url && result.extracted_urls.length > 0 && (
                <div className="panel rounded-2xl p-5 sm:p-6">
                  <h2 className="font-medium">Links in the message</h2>
                  <ul className="mt-3 space-y-1.5 font-mono text-xs">
                    {result.extracted_urls.map((link, i) => (
                      <li key={i} className="break-all rounded-md border border-line/70 bg-background/60 px-3 py-2 text-warn">
                        {link}
                      </li>
                    ))}
                  </ul>
                  <p className="mt-3 text-xs text-muted">
                    Don’t click these. If the message claims to be from a service you use, open that service’s app instead.
                  </p>
                </div>
              )}

              {/* Recommendations */}
              <div className="panel rounded-2xl border-accent/25 p-5 sm:p-6">
                <h2 className="font-medium text-accent">🛡️ What you should do</h2>
                <ul className="mt-4 space-y-3">
                  {result.recommended_actions.map((rec, i) => (
                    <li key={i} className="flex gap-3 text-sm leading-6">
                      <span className="pt-0.5 font-mono text-xs font-bold text-accent">{String(i + 1).padStart(2, "0")}</span>
                      <span className="text-foreground/90">{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </section>
      </main>

      <footer className="border-t border-line/70 py-8">
        <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-3 px-4 text-sm text-muted sm:flex-row sm:px-6">
          <span>ScamShield © 2026</span>
          <p>If you think you’ve already been scammed, contact your bank immediately.</p>
        </div>
      </footer>
    </div>
  );
}

function kindLabel(kind: MessageKind): string {
  return MESSAGE_KINDS.find((k) => k.value === kind)?.label ?? "Email";
}
