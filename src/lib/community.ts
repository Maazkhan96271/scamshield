/**
 * Community scam-report feed — a lightweight, privacy-preserving registry of
 * domains and phone numbers that users have flagged as scams.
 *
 * Design constraints:
 * - No personal data is ever stored (no IPs, no user agents, no free-text).
 * - Counts decay over time so stale reports don't haunt a domain forever.
 * - Bounded memory: the registry caps at a fixed number of keys.
 *
 * This is an in-memory store, suitable for a single-server demo deployment.
 * Swap `recordReport`/`getReports` for a database call to make it durable.
 */

const MAX_KEYS = 10_000;
const HALF_LIFE_MS = 1000 * 60 * 60 * 24 * 30; // 30 days

export type ReportTargetKind = "domain" | "phone";

export interface ReportStats {
  kind: ReportTargetKind;
  /** Decay-weighted report count. */
  score: number;
  /** Number of reports folded into the score. */
  reports: number;
  /** Epoch ms of the most recent report. */
  lastReportAt: number;
}

interface ReportRecord extends ReportStats {
  reportedScams: number;
  reportedLegit: number;
}

declare global {
  var __scamshieldReports: Map<string, ReportRecord> | undefined;
}

const store: Map<string, ReportRecord> =
  globalThis.__scamshieldReports ?? (globalThis.__scamshieldReports = new Map());

function normalize(kind: ReportTargetKind, raw: string): string | null {
  const t = raw.trim().toLowerCase();
  if (!t) return null;
  if (kind === "phone") {
    const digits = t.replace(/[^\d+]/g, "");
    return digits.length >= 7 ? digits.slice(-10) : null;
  }
  try {
    const host = (t.includes("://") ? new URL(t).hostname : t.replace(/^www\./, "")).toLowerCase();
    return /^[a-z0-9.-]+$/.test(host) ? host : null;
  } catch {
    return null;
  }
}

function decayed(rec: ReportRecord): number {
  const age = Math.max(0, Date.now() - rec.lastReportAt);
  return rec.score * Math.pow(0.5, age / HALF_LIFE_MS);
}

export function recordReport(
  kind: ReportTargetKind,
  raw: string,
  verdict: "scam" | "legit",
): ReportStats | null {
  const key = normalize(kind, raw);
  if (!key) return null;
  const id = `${kind}:${key}`;
  const existing = store.get(id) ?? { kind, score: 0, reports: 0, lastReportAt: Date.now(), reportedScams: 0, reportedLegit: 0 };
  existing.score = decayed(existing) + (verdict === "scam" ? 1 : -0.5);
  existing.reports += 1;
  existing.lastReportAt = Date.now();
  if (verdict === "scam") existing.reportedScams += 1;
  else existing.reportedLegit += 1;
  store.set(id, existing);

  // Evict coldest keys when over capacity.
  if (store.size > MAX_KEYS) {
    const entries = [...store.entries()].sort((a, b) => decayed(a[1]) - decayed(b[1]));
    for (const [k] of entries.slice(0, store.size - MAX_KEYS)) store.delete(k);
  }
  return toStats(existing);
}

export function getReports(kind: ReportTargetKind, raw: string): ReportStats | null {
  const key = normalize(kind, raw);
  if (!key) return null;
  const rec = store.get(`${kind}:${key}`);
  return rec ? toStats(rec) : null;
}

function toStats(rec: ReportRecord): ReportStats {
  return { kind: rec.kind, score: Math.round(decayed(rec) * 100) / 100, reports: rec.reports, lastReportAt: rec.lastReportAt };
}

/** True when the decayed community score suggests a commonly-reported scam target. */
export function isCommunityFlagged(kind: ReportTargetKind, raw: string): boolean {
  const stats = getReports(kind, raw);
  return stats !== null && stats.score >= 2;
}
