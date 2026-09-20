"use client";

import { useEffect, useMemo, useState } from "react";
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
import QrChecker from "@/components/QrChecker";
import EmailHeaderChecker from "@/components/EmailHeaderChecker";

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

const RISK_STYLES: Record<RiskLevel, { chip: string; bar: string; label: string; barBorder: string }> = {
  HIGH: { chip: "border-danger/50 bg-danger/10 text-danger", bar: "from-warn to-danger", label: "HIGH RISK", barBorder: "border-l-danger" },
  MEDIUM: { chip: "border-warn/50 bg-warn/10 text-warn", bar: "from-safe to-warn", label: "MEDIUM RISK", barBorder: "border-l-warn" },
  LOW: { chip: "border-safe/50 bg-safe/10 text-safe", bar: "from-safe to-safe", label: "LOW RISK", barBorder: "border-l-safe" },
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
      className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-accent px-5 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:cursor-not-allowed disabled:opacity-40"
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
      <h2 className="kicker">🔍 What triggered the warning</h2>
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
  const [copied, setCopied] = useState(false);
  const [reportCopied, setReportCopied] = useState(false);

  /** Ctrl/Cmd+Enter anywhere on the page starts the scan for the active mode. */
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter" && !loading) {
        e.preventDefault();
        if (activeMode === "text" && content.trim()) void runScan("text");
        else if (activeMode === "url" && urlInput.trim()) void runScan("url");
        else if (activeMode === "image" && image) void runScan("image");
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeMode, content, urlInput, image, loading]);

  /** Compact, human-readable summary of a verdict for the clipboard / share sheet. */
  function verdictSummary(r: AnalysisResult): string {
    const lines = [
      `ScamShield verdict: ${r.risk_level} risk`,
      `${r.signals.length} risk indicator${r.signals.length === 1 ? "" : "s"} detected`,
    ];
    if (r.claimed_organization) lines.push(`Claims to be from: ${r.claimed_organization}`);
    if (r.extracted_urls.length > 0) lines.push(`Links found: ${r.extracted_urls.slice(0, 3).join(", ")}`);
    lines.push(r.explanation);
    lines.push("— analyzed with ScamShield (guidance, not certainty)");
    return lines.join("\n");
  }

  /** Formal incident report for forwarding to a bank, employer or IT security team. */
  function incidentReport(r: AnalysisResult): string {
    const lines = [
      "=== SCAM INCIDENT REPORT ===",
      `Generated: ${new Date().toLocaleString()} via ScamShield`,
      "",
      `Risk level: ${r.risk_level} (${r.signals.length} indicator${r.signals.length === 1 ? "" : "s"} detected)`,
    ];
    if (r.claimed_organization) lines.push(`Message claims to be from: ${r.claimed_organization}`);
    if (r.scanned_url) lines.push(`URL checked: ${r.scanned_url}`);
    else if (r.extracted_urls.length > 0) lines.push(`URLs found: ${r.extracted_urls.join(", ")}`);
    if (r.extracted_text) lines.push("", "--- Original message (transcribed) ---", r.extracted_text);
    lines.push("", "--- Indicators observed ---");
    for (const s of r.signals) {
      lines.push(`• [${signalSeverity(s.weight).toUpperCase()}] ${s.title}${s.evidence ? ` — observed: ${s.evidence}` : ""}`);
    }
    lines.push("", "--- Summary ---", r.explanation);
    lines.push("", "--- Recommended actions ---");
    r.recommended_actions.forEach((a, i) => lines.push(`${i + 1}. ${a}`));
    lines.push("", "Note: automated indicator analysis — not a determination of fraud. Verify through official channels.");
    return lines.join("\n");
  }

  async function copyIncidentReport() {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(incidentReport(result));
      setReportCopied(true);
      setTimeout(() => setReportCopied(false), 2000);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

  async function shareVerdict() {
    if (!result) return;
    const text = verdictSummary(result);
    if (typeof navigator.share === "function") {
      try {
        await navigator.share({ title: "ScamShield verdict", text });
        return;
      } catch {
        /* user dismissed — fall through to clipboard */
      }
    }
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — ignore */
    }
  }

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

  /** Content shared into ScamShield from another app (PWA share target) pre-fills and auto-scans. */
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    const sharedText = params.get("text");
    const sharedUrl = params.get("url");
    // Deferred so the effect body itself never sets state synchronously.
    const t = window.setTimeout(() => {
      if (sharedText) {
        setContent(sharedText.slice(0, MAX_CONTENT_LENGTH));
        setKind("sms");
        setActiveMode("text");
        setScannedText(sharedText.slice(0, MAX_CONTENT_LENGTH));
        void runScan("text", sharedText.slice(0, MAX_CONTENT_LENGTH));
        window.history.replaceState(null, "", "/analyze");
      } else if (sharedUrl) {
        setUrlInput(sharedUrl);
        void runScan("url", undefined, sharedUrl);
        window.history.replaceState(null, "", "/analyze");
      }
    }, 0);
    return () => window.clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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

  async function runScan(mode: AnalysisMode, overrideText?: string, overrideUrl?: string) {
    if (loading) return;
    const text = overrideText ?? content;
    const url = overrideUrl ?? urlInput;
    if (mode === "text") {
      if (!text.trim() || text.length > MAX_CONTENT_LENGTH) return;
    } else if (mode === "url") {
      if (!url.trim()) return;
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
          ? { mode: "text", content: text, kind }
          : mode === "url"
            ? { mode: "url", url: url.trim() }
            : { mode: "image", imageDataUrl: image!.dataUrl };
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(typeof data?.error === "string" ? data.error : "Analysis failed");
      const result = data as AnalysisResult;
      setScannedText(mode === "text" ? text : mode === "url" ? url.trim() : "");
      setResult(result);
      // Archive the scan in the encrypted on-device history (best effort).
      void addHistory({
        mode,
        kind: mode === "text" ? kind : undefined,
        preview: mode === "text" ? text : mode === "url" ? url.trim() : "Screenshot scan",
        url: mode === "url" ? url.trim() : undefined,
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
            <span className="hidden font-mono text-[11px] uppercase tracking-widest text-muted sm:block">Ctrl+Enter</span>
          </div>

          {/* 2. QR code */}
          <QrChecker
            loading={loading}
            onAnalyze={(mode, decoded) => {
              if (mode === "url") {
                setUrlInput(decoded);
                void runScan("url", undefined, decoded);
              } else {
                setKind("sms");
                setContent(decoded);
                void runScan("text", decoded);
              }
            }}
          />

          {/* 3b. Email headers */}
          <EmailHeaderChecker />

          {/* 4. URL */}
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
          {loading && <ScanPanel loadingText={loadingText} />}

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
              {/* Verdict header — forensic bar with risk-colored left rule */}
              <div className={`panel panel-glow rounded-2xl border-l-4 ${RISK_STYLES[result.risk_level].barBorder} p-5 sm:p-6`}>
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
                    <button
                      type="button"
                      onClick={() => void copyIncidentReport()}
                      className="rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
                      title="Copy a formal incident report for your bank or IT team"
                    >
                      {reportCopied ? "✓ Copied" : "Copy report"}
                    </button>
                    <button
                      type="button"
                      onClick={() => void shareVerdict()}
                      className="rounded-md border border-line px-2.5 py-1.5 text-xs font-medium text-muted transition hover:border-accent/40 hover:text-accent"
                      title="Copy or share this verdict"
                    >
                      {copied ? "✓ Copied" : "Share"}
                    </button>
                  </div>
                </div>
                <p className="mt-3 font-mono text-[11px] uppercase tracking-widest text-muted">
                  {result.source === "ai" ? "AI + rule engine" : "rule engine"} · confidence in verdict:{" "}
                  <span className="text-accent">{confidenceBand(result.confidence)}</span> · not a probability of fraud
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
                  <h2 className="kicker">Link checked</h2>
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
                    <span className="kicker mr-2">Observed</span>
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
                  <h2 className="kicker">Links in the message</h2>
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

              {/* Community report */}
              {result.extracted_urls.length > 0 && (
                <CommunityReportCard urls={result.extracted_urls} phones={extractPhones(scannedText)} />
              )}

              {/* Recommendations */}
              <div className="panel rounded-2xl border-accent/25 p-5 sm:p-6">
                <h2 className="kicker">🛡️ What you should do</h2>
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

const SCAN_STEPS = [
  "parsing message structure…",
  "extracting and parsing links…",
  "checking sender IDs and domains…",
  "weighing urgency & threat patterns…",
  "scanning payment & credential requests…",
  "compiling observed evidence…",
];

/**
 * Forensic scanning panel — cycles through engine steps so the wait reads as
 * an instrument working, not a spinner.
 */
function ScanPanel({ loadingText }: { loadingText: string }) {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => setStep((s) => (s + 1) % SCAN_STEPS.length), 700);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className="panel relative flex min-h-[420px] flex-col items-center justify-center overflow-hidden rounded-2xl">
      <div className="scanline" aria-hidden />
      <ShieldLogo className="h-10 w-10 text-accent" />
      <p className="mt-4 font-medium">{loadingText}</p>
      <ul className="mt-5 w-full max-w-sm space-y-1.5 px-6 font-mono text-xs" aria-hidden>
        {SCAN_STEPS.map((label, i) => {
          const state = i < step ? "done" : i === step ? "active" : "pending";
          return (
            <li
              key={label}
              className={`flex items-center gap-2.5 transition-colors duration-300 ${
                state === "done" ? "text-safe" : state === "active" ? "text-accent" : "text-muted/40"
              }`}
            >
              <span className="w-4 shrink-0 text-center">{state === "done" ? "✓" : state === "active" ? "▸" : "·"}</span>
              {label}
            </li>
          );
        })
        }
      </ul>
    </div>
  );
}

/** Phone-number-looking tokens from the analyzed text (for community reporting). */
function extractPhones(text: string): string[] {
  return [...new Set((text.match(/(?:\+?\d[\d\s-]{7,}\d)/g) ?? []).map((p) => p.trim()))].slice(0, 3);
}

/**
 * Community scam-report block — shows crowd-sourced report counts for the
 * links/numbers in this scan and lets the user file a report (scam or legit).
 * Only the domain/number and the verdict word are sent — no message content.
 */
function CommunityReportCard({ urls, phones }: { urls: string[]; phones: string[] }) {
  const targets = useMemo(() => {
    const list: { kind: "domain" | "phone"; value: string }[] = [];
    for (const raw of urls.slice(0, 3)) {
      try {
        const host = new URL(raw.startsWith("http") ? raw : `http://${raw}`).hostname;
        if (host) list.push({ kind: "domain", value: host });
      } catch {
        /* ignore malformed links */
      }
    }
    for (const p of phones) list.push({ kind: "phone", value: p });
    return list.slice(0, 4);
  }, [urls, phones]);

  const [stats, setStats] = useState<Record<string, { reports: number } | null>>({});
  const [sent, setSent] = useState<Record<string, "scam" | "legit">>({});

  useEffect(() => {
    let alive = true;
    for (const t of targets) {
      const key = `${t.kind}:${t.value}`;
      fetch(`/api/community?target=${t.kind}&value=${encodeURIComponent(t.value)}`)
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (alive) setStats((prev) => ({ ...prev, [key]: data }));
        })
        .catch(() => {
          if (alive) setStats((prev) => ({ ...prev, [key]: null }));
        });
    }
    return () => {
      alive = false;
    };
  }, [targets]);

  async function report(t: { kind: "domain" | "phone"; value: string }, verdict: "scam" | "legit") {
    const key = `${t.kind}:${t.value}`;
    setSent((prev) => ({ ...prev, [key]: verdict }));
    try {
      const r = await fetch("/api/community/report", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ target: t.kind, value: t.value, verdict }),
      });
      const data = r.ok ? await r.json() : null;
      setStats((prev) => ({ ...prev, [key]: data }));
    } catch {
      /* keep optimistic state */
    }
  }

  if (targets.length === 0) return null;

  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <h2 className="kicker">🧭 Community reports</h2>
      <p className="mt-1 text-xs text-muted">
        Crowd-sourced flags for the targets in this scan. Reports contain only the domain/number and a
        verdict word — never your message. Community signals are hints, not proof.
      </p>
      <ul className="mt-4 space-y-3">
        {targets.map((t) => {
          const key = `${t.kind}:${t.value}`;
          const s = stats[key];
          const voted = sent[key];
          return (
            <li key={key} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line/70 bg-background/50 px-3.5 py-3">
              <div className="min-w-0">
                <p className="break-all font-mono text-xs text-foreground/85">{t.value}</p>
                <p className="mt-0.5 text-[11px] text-muted">
                  {s ? `${s.reports} report${s.reports === 1 ? "" : "s"} filed` : "no community reports yet"}
                  {s && s.reports >= 3 ? " · commonly reported as a scam" : ""}
                </p>
              </div>
              {voted ? (
                <span className="rounded-md border border-safe/40 bg-safe/10 px-2.5 py-1 text-[11px] font-medium text-safe">
                  ✓ reported
                </span>
              ) : (
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    onClick={() => void report(t, "scam")}
                    className="rounded-md border border-danger/40 bg-danger/5 px-2.5 py-1 text-[11px] font-medium text-danger transition hover:bg-danger/15"
                  >
                    🚩 Report scam
                  </button>
                  <button
                    type="button"
                    onClick={() => void report(t, "legit")}
                    className="rounded-md border border-line px-2.5 py-1 text-[11px] text-muted transition hover:border-safe/40 hover:text-safe"
                  >
                    Mark legit
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
