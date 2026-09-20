"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  confidenceBand,
  signalSeverity,
  MESSAGE_KINDS,
  type AnalysisResult,
  type RiskLevel,
  type SignalSeverity,
} from "@/lib/scam";
import { clearHistory, deleteHistoryEntry, getHistory, mergeHistory, HISTORY_LIMIT, type HistoryEntry } from "@/lib/history";
import { exportBackup, importBackup } from "@/lib/history-backup";

const RISK_EMOJI: Record<RiskLevel, string> = { HIGH: "🚨", MEDIUM: "⚠️", LOW: "✅" };

const RISK_CHIP: Record<RiskLevel, string> = {
  HIGH: "border-danger/50 bg-danger/10 text-danger",
  MEDIUM: "border-warn/50 bg-warn/10 text-warn",
  LOW: "border-safe/50 bg-safe/10 text-safe",
};

const SEV_META: Record<SignalSeverity, { dot: string }> = {
  high: { dot: "bg-danger" },
  medium: { dot: "bg-warn" },
  low: { dot: "bg-accent" },
};

const CATEGORY_LABEL: Partial<Record<AnalysisResult["signals"][number]["category"], string>> = {
  urgency: "Urgency",
  authority: "Impersonation",
  credentials: "Sensitive info",
  payment: "Payment",
  links: "Link",
  prize: "Prize bait",
  opportunity: "Too-good-to-be-true",
  delivery: "Delivery",
  techsupport: "Tech support",
  secrecy: "Secrecy",
  attachments: "Attachment",
  software: "Software install",
  tone: "Formatting",
};

const MODE_LABEL: Record<HistoryEntry["mode"], string> = {
  text: "Message",
  url: "Link",
  image: "Screenshot",
};

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

function formatWhen(at: number): string {
  const diff = Date.now() - at;
  const mins = Math.round(diff / 60_000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days} d ago`;
  return new Date(at).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export default function HistoryPage() {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [backupOpen] = useState(true);
  const [passphrase, setPassphrase] = useState("");
  const [backupMsg, setBackupMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  useEffect(() => {
    let alive = true;
    void getHistory().then((list) => {
      if (alive) setEntries(list);
    });
    return () => {
      alive = false;
    };
  }, []);

  async function handleClear() {
    await clearHistory();
    setEntries([]);
    setConfirmClear(false);
  }

  async function handleDelete(id: string) {
    await deleteHistoryEntry(id);
    setEntries((prev) => (prev ? prev.filter((e) => e.id !== id) : prev));
  }

  async function handleExport() {
    if (!entries || entries.length === 0) return;
    try {
      const backup = await exportBackup(entries, passphrase);
      const blob = new Blob([backup], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `scamshield-history-${new Date().toISOString().slice(0, 10)}.txt`;
      a.click();
      URL.revokeObjectURL(url);
      setBackupMsg({ kind: "ok", text: "Backup downloaded. Keep the passphrase safe — it can't be recovered." });
    } catch (e) {
      setBackupMsg({ kind: "err", text: e instanceof Error ? e.message : "Export failed." });
    }
  }

  async function handleImport(file: File) {
    try {
      const text = await file.text();
      const restored = await importBackup(text, passphrase);
      const merged = await mergeHistory(restored);
      setEntries(merged);
      setBackupMsg({ kind: "ok", text: `Restored ${restored.length} entr${restored.length === 1 ? "y" : "ies"}.` });
    } catch (e) {
      setBackupMsg({ kind: "err", text: e instanceof Error ? e.message : "Import failed." });
    }
  }

  return (
    <div className="flex min-h-screen flex-col">
      {/* Nav */}
      <header className="sticky top-0 z-40 border-b border-line/70 bg-background/80 backdrop-blur-md">
        <nav className="mx-auto flex h-16 w-full max-w-5xl items-center justify-between px-4 sm:px-6">
          <Link href="/" className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg border border-accent/30 bg-accent/10 text-accent">
              <ShieldLogo className="h-5 w-5" />
            </span>
            <span className="text-lg font-semibold tracking-tight">
              Scam<span className="text-accent">Shield</span>
            </span>
          </Link>
          <div className="flex items-center gap-4">
            <Link href="/analyze" className="text-sm text-muted transition-colors hover:text-foreground">
              New scan
            </Link>
            <Link href="/" className="text-sm text-muted transition-colors hover:text-foreground">
              ← Home
            </Link>
          </div>
        </nav>
      </header>

      <main className="mx-auto w-full max-w-5xl flex-1 px-4 py-10 sm:px-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Scan history</h1>
            <p className="mt-1 text-sm text-muted">
              Your last {HISTORY_LIMIT} scans, encrypted on this device only — never sent to any server.
            </p>
          </div>
          {entries && entries.length > 0 && (
            <div className="flex items-center gap-2">
              {confirmClear ? (
                <>
                  <button
                    type="button"
                    onClick={() => void handleClear()}
                    className="rounded-lg border border-danger/50 bg-danger/10 px-3 py-2 text-sm font-medium text-danger transition hover:bg-danger/20"
                  >
                    Yes, delete all
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmClear(false)}
                    className="rounded-lg border border-line px-3 py-2 text-sm text-muted transition hover:text-foreground"
                  >
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={() => setConfirmClear(true)}
                  className="rounded-lg border border-line px-3 py-2 text-sm text-muted transition hover:border-danger/50 hover:text-danger"
                >
                  Clear history
                </button>
              )}
            </div>
          )}
        </div>

        {backupOpen && (
          <div className="panel mt-4 rounded-2xl border-accent/25 p-5">
            <h2 className="font-medium">Encrypted backup</h2>
            <p className="mt-1 text-xs leading-5 text-muted">
              Export your history as a passphrase-encrypted file (PBKDF2 + AES-256-GCM). The passphrase
              never leaves this device and cannot be recovered — if you lose it, the backup is unreadable.
            </p>
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Passphrase (min 8 characters)"
              className="mt-3 w-full max-w-md rounded-xl border border-line bg-background/60 px-4 py-2.5 text-sm text-foreground placeholder:text-muted/60 focus:border-accent/50 focus:outline-none focus:ring-2 focus:ring-accent/40"
            />
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={() => void handleExport()}
                disabled={passphrase.length < 8 || !entries || entries.length === 0}
                className="inline-flex h-10 items-center rounded-lg bg-accent px-4 text-sm font-semibold text-background transition hover:bg-accent-strong disabled:opacity-40"
              >
                Download encrypted backup
              </button>
              <label className="inline-flex h-10 cursor-pointer items-center rounded-lg border border-line px-4 text-sm text-muted transition hover:border-accent/40 hover:text-accent">
                Restore from file
                <input
                  type="file"
                  accept=".txt"
                  className="hidden"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) void handleImport(file);
                  }}
                />
              </label>
            </div>
            {backupMsg && (
              <p
                role="status"
                className={`mt-3 rounded-lg border p-3 text-sm ${
                  backupMsg.kind === "ok" ? "border-safe/40 bg-safe/10 text-safe" : "border-danger/40 bg-danger/10 text-danger"
                }`}
              >
                {backupMsg.text}
              </p>
            )}
          </div>
        )}

        <div className="mt-8">
          {entries === null && (
            <div className="panel flex min-h-48 items-center justify-center rounded-2xl">
              <p className="font-mono text-xs text-muted">decrypting local history…</p>
            </div>
          )}

          {entries !== null && entries.length === 0 && (
            <div className="panel flex min-h-64 flex-col items-center justify-center rounded-2xl p-8 text-center">
              <span className="flex h-14 w-14 items-center justify-center rounded-xl border border-line bg-surface-2 text-muted">
                <ShieldLogo className="h-7 w-7" />
              </span>
              <h2 className="mt-4 text-lg font-medium">No scans yet</h2>
              <p className="mt-2 max-w-sm text-sm leading-6 text-muted">
                Everything you analyze is saved here — encrypted — so you can look back at verdicts
                without re-running them.
              </p>
              <Link
                href="/analyze"
                className="mt-6 inline-flex h-11 items-center rounded-lg bg-accent px-5 text-sm font-semibold text-background transition hover:bg-accent-strong"
              >
                Analyze your first message
              </Link>
            </div>
          )}

          {entries !== null && entries.length > 0 && (
            <ul className="space-y-3">
              {entries.map((entry) => (
                <li key={entry.id} className="panel rounded-2xl p-4 sm:p-5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="text-xl leading-none" aria-hidden>
                        {RISK_EMOJI[entry.result.risk_level]}
                      </span>
                      <span className={`rounded-md border px-2 py-0.5 font-mono text-xs font-bold ${RISK_CHIP[entry.result.risk_level]}`}>
                        {entry.result.risk_level}
                      </span>
                      <span className="rounded-md border border-line bg-surface-2/60 px-2 py-0.5 text-xs text-muted">
                        {MODE_LABEL[entry.mode]}
                        {entry.mode === "text" && entry.kind
                          ? ` · ${MESSAGE_KINDS.find((k) => k.value === entry.kind)?.label ?? ""}`
                          : ""}
                      </span>
                      <span className="text-xs text-muted">{formatWhen(entry.at)}</span>
                    </div>
                    <button
                      type="button"
                      onClick={() => void handleDelete(entry.id)}
                      className="rounded-md border border-line px-2 py-1 text-xs text-muted transition hover:border-danger/50 hover:text-danger"
                      aria-label="Delete this history entry"
                    >
                      Delete
                    </button>
                  </div>

                  <p className="mt-3 line-clamp-2 break-words font-mono text-xs leading-5 text-foreground/75">
                    {entry.mode === "url" ? entry.url ?? entry.preview : entry.preview}
                  </p>

                  <p className="mt-2 text-xs text-muted">
                    {entry.result.signals.length} indicator{entry.result.signals.length === 1 ? "" : "s"} · confidence in
                    verdict: <span className="text-accent">{confidenceBand(entry.result.confidence)}</span>
                    {entry.result.claimed_organization ? <> · claims to be {entry.result.claimed_organization}</> : null}
                  </p>

                  {entry.result.signals.length > 0 && (
                    <ul className="mt-3 flex flex-wrap gap-1.5">
                      {entry.result.signals.slice(0, 4).map((s, i) => {
                        const sev = signalSeverity(s.weight);
                        return (
                          <li
                            key={i}
                            className="flex items-center gap-1.5 rounded-full border border-line bg-surface-2/60 px-2.5 py-1 text-xs text-foreground/85"
                          >
                            <span className={`h-1.5 w-1.5 rounded-full ${SEV_META[sev].dot}`} aria-hidden />
                            {CATEGORY_LABEL[s.category] ?? "Indicator"}
                          </li>
                        );
                      })}
                      {entry.result.signals.length > 4 && (
                        <li className="px-1 py-1 text-xs text-muted">+{entry.result.signals.length - 4} more</li>
                      )}
                    </ul>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <p className="mt-8 text-center text-xs text-muted">
          Encrypted with AES-256-GCM in your browser. Clearing your browser data or this history removes it
          permanently — there is no cloud copy.
        </p>
      </main>
    </div>
  );
}
