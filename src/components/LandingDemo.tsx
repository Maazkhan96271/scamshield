"use client";

import { useState } from "react";
import Link from "next/link";
import { analyzeHeuristics, confidenceBand, signalSeverity, type AnalysisResult, type RiskLevel } from "@/lib/scam";

const RISK_META: Record<RiskLevel, { chip: string; emoji: string }> = {
  HIGH: { chip: "border-danger/50 bg-danger/10 text-danger", emoji: "🚨" },
  MEDIUM: { chip: "border-warn/50 bg-warn/10 text-warn", emoji: "⚠️" },
  LOW: { chip: "border-safe/50 bg-safe/10 text-safe", emoji: "✅" },
};

const SAMPLE =
  "URGENT! Your bank account will be blocked within 30 minutes. Verify your OTP here: https://bank-security-login.example.com";

export default function LandingDemo() {
  const [text, setText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);

  function run(input: string) {
    const t = input.trim();
    if (!t) return;
    // Rule engine runs fully client-side — nothing is sent anywhere.
    setResult(analyzeHeuristics(t, "sms"));
  }

  return (
    <div className="panel rounded-2xl p-5 sm:p-6">
      <p className="kicker">Try it now · runs in your browser</p>
      <textarea
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          if (result) setResult(null);
        }}
        onKeyDown={(e) => {
          if ((e.ctrlKey || e.metaKey) && e.key === "Enter") run(text);
        }}
        rows={3}
        maxLength={8000}
        placeholder="Paste a suspicious message and hit Analyze — or load the sample below."
        className="mt-3 w-full resize-y rounded-xl border border-line bg-background/60 p-3.5 font-mono text-sm leading-6 text-foreground placeholder:text-muted/60 focus:border-accent/50 focus:outline-none focus:ring-2 focus:ring-accent/40"
      />
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => run(text)}
          disabled={!text.trim()}
          className="h-10 rounded-lg bg-accent px-5 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:opacity-40"
        >
          🔍 Analyze
        </button>
        <button
          type="button"
          onClick={() => {
            setText(SAMPLE);
            run(SAMPLE);
          }}
          className="h-10 rounded-lg border border-line px-4 text-sm text-muted transition hover:border-accent/40 hover:text-accent"
        >
          Load sample scam
        </button>
        <span className="ml-auto hidden font-mono text-[11px] uppercase tracking-widest text-muted sm:block">
          Ctrl+Enter · no upload
        </span>
      </div>

      {result && (
        <div className="rise-in mt-4 rounded-xl border border-line bg-background/60 p-4">
          <div className="flex flex-wrap items-center gap-2.5">
            <span aria-hidden>{RISK_META[result.risk_level].emoji}</span>
            <span className={`rounded-md border px-2 py-0.5 font-mono text-xs font-bold ${RISK_META[result.risk_level].chip}`}>
              {result.risk_level} RISK
            </span>
            <span className="text-xs text-muted">
              {result.signals.length} indicator{result.signals.length === 1 ? "" : "s"} · confidence in verdict:{" "}
              <span className="text-accent">{confidenceBand(result.confidence)}</span>
            </span>
          </div>
          {result.signals.length > 0 ? (
            <ul className="mt-3 space-y-2">
              {result.signals.slice(0, 4).map((s, i) => {
                const sev = signalSeverity(s.weight);
                const dot = sev === "high" ? "bg-danger" : sev === "medium" ? "bg-warn" : "bg-accent";
                return (
                  <li key={i} className="flex gap-2.5 text-sm">
                    <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${dot}`} aria-hidden />
                    <span>
                      <span className="font-medium">{s.title}</span>
                      {s.evidence && <span className="block truncate font-mono text-xs text-muted">“{s.evidence}”</span>}
                    </span>
                  </li>
                );
              })}
              {result.signals.length > 4 && (
                <li className="text-xs text-muted">+{result.signals.length - 4} more indicators</li>
              )}
            </ul>
          ) : (
            <p className="mt-2 text-sm text-muted">
              No known indicators in that text — that is not a guarantee. Stay cautious with links and payments.
            </p>
          )}
          <Link href="/analyze" className="mt-3 inline-block text-sm font-medium text-accent hover:underline">
            Full analysis with trigger highlighting →
          </Link>
        </div>
      )}
    </div>
  );
}
