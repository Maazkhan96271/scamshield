"use client";

import { useState } from "react";
import { analyzeEmailHeaders, type EmailHeaderAnalysis } from "@/lib/email-headers";

const AUTH_CHIP: Record<string, string> = {
  pass: "border-safe/50 bg-safe/10 text-safe",
  softfail: "border-warn/50 bg-warn/10 text-warn",
  fail: "border-danger/50 bg-danger/10 text-danger",
  none: "border-line bg-surface-2 text-muted",
  unknown: "border-line bg-surface-2 text-muted",
};

/**
 * Email header checker — paste the raw headers (or a whole .eml export) and
 * ScamShield extracts SPF/DKIM/DMARC results, Reply-To hijacks, and
 * display-name/domain mismatches. All parsing happens locally.
 */
export default function EmailHeaderChecker() {
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState("");
  const [analysis, setAnalysis] = useState<EmailHeaderAnalysis | null>(null);

  function analyze() {
    if (!raw.trim()) return;
    setAnalysis(analyzeEmailHeaders(raw));
  }

  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between text-left"
        aria-expanded={open}
      >
        <span>
          <span className="text-lg font-medium">Email headers</span>
          <span className="ml-2 align-middle text-xs font-normal text-muted">
            SPF · DKIM · DMARC · Reply-To hijack detection
          </span>
        </span>
        <span className="text-muted transition-transform" style={{ transform: open ? "rotate(180deg)" : "none" }} aria-hidden>
          ▾
        </span>
      </button>

      {open && (
        <div className="mt-3">
          <p className="text-xs leading-5 text-muted">
            In your mail client: <span className="font-mono text-foreground/80">Show original / View source</span>, then paste
            the header block below. Parsed locally — nothing is uploaded.
          </p>
          <textarea
            value={raw}
            onChange={(e) => setRaw(e.target.value)}
            rows={5}
            placeholder={"From: PayPal Service <billing@random.xyz>\nReply-To: payouts-help@mail-secure.ru\nAuthentication-Results: mx.example.com; spf=fail ..."}
            className="mt-2 w-full resize-y rounded-xl border border-line bg-background/60 p-3 font-mono text-xs leading-5 text-foreground placeholder:text-muted/60 focus:border-accent/50 focus:outline-none focus:ring-2 focus:ring-accent/40"
          />
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              onClick={analyze}
              disabled={!raw.trim()}
              className="inline-flex h-10 items-center rounded-lg bg-accent px-4 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:opacity-40"
            >
              Check headers
            </button>
            {analysis && (
              <button
                type="button"
                onClick={() => {
                  setRaw("");
                  setAnalysis(null);
                }}
                className="rounded-lg border border-line px-3 py-2 text-sm text-muted transition hover:text-foreground"
              >
                Clear
              </button>
            )}
          </div>

          {analysis && (
            <div className="mt-4 space-y-3">
              <div className="flex flex-wrap items-center gap-2 text-xs">
                {(["spf", "dkim", "dmarc"] as const).map((k) => (
                  <span key={k} className={`rounded-md border px-2 py-1 font-mono font-semibold uppercase ${AUTH_CHIP[analysis[k]]}`}>
                    {k}: {analysis[k]}
                  </span>
                ))}
              </div>
              {analysis.from && (
                <p className="text-xs text-muted">
                  From <span className="font-mono text-foreground/85">{analysis.from}</span>
                  {analysis.replyTo && analysis.replyToDomain !== analysis.fromDomain && (
                    <>
                      {" "}
                      · replies diverted to <span className="font-mono text-warn">{analysis.replyTo}</span>
                    </>
                  )}
                </p>
              )}
              {analysis.flags.length > 0 ? (
                <ul className="space-y-2">
                  {analysis.flags.map((f, i) => (
                    <li key={i} className="rounded-lg border border-warn/40 bg-warn/5 p-3">
                      <p className="text-sm font-medium text-warn">{f.title}</p>
                      <p className="mt-1 font-mono text-xs text-foreground/75">{f.evidence}</p>
                      <p className="mt-1 text-xs leading-5 text-muted">{f.inference}</p>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="rounded-lg border border-safe/40 bg-safe/10 p-3 text-sm text-safe">
                  No header red flags found. Authentication checks passing is a good sign — but header checks
                  can&apos;t confirm a message is safe, only that it was sent by an authorized server.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
