"use client";

/**
 * On-device scan history, encrypted at rest.
 *
 * Every entry is serialized to JSON and encrypted with AES-256-GCM before it
 * touches localStorage. The key lives in the user's browser only — a random
 * CryptoKey per browser profile, stored non-extractable-safe in IndexedDB.
 * If the profile is wiped, history is unrecoverable by design; the server
 * never sees any of it.
 */

import type { AnalysisResult, AnalysisMode, MessageKind } from "./scam";

const DB_NAME = "scamshield-history";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const KEY_ID = "history-key";
export const HISTORY_LIMIT = 50; // keep the most recent 50 scans, drop the rest

export interface HistoryEntry {
  id: string;
  /** Epoch milliseconds. */
  at: number;
  mode: AnalysisMode;
  kind?: MessageKind;
  /** Snippet of what was scanned (also encrypted at rest). */
  preview: string;
  url?: string;
  result: AnalysisResult;
}

/* ---------------- IndexedDB: non-extractable AES-GCM key ---------------- */

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("IndexedDB unavailable"));
  });
}

async function loadKey(): Promise<CryptoKey> {
  const db = await openDb();
  const existing = await new Promise<CryptoKey | undefined>((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readonly");
    const req = tx.objectStore(KEY_STORE).get(KEY_ID);
    req.onsuccess = () => resolve(req.result as CryptoKey | undefined);
    req.onerror = () => reject(req.error);
  });
  db.close();
  if (existing) return existing;

  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const db2 = await openDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db2.transaction(KEY_STORE, "readwrite");
    tx.objectStore(KEY_STORE).put(key, KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db2.close();
  return key;
}

let keyPromise: Promise<CryptoKey> | null = null;
function getKey(): Promise<CryptoKey> {
  keyPromise ??= loadKey();
  return keyPromise;
}

/* ------------------------------ crypto ------------------------------ */

async function encryptJson(value: unknown): Promise<ArrayBuffer> {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  // iv prefix + ciphertext
  const out = new Uint8Array(iv.length + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), iv.length);
  return out.buffer;
}

async function decryptJson<T>(blob: ArrayBuffer): Promise<T> {
  const key = await getKey();
  const iv = blob.slice(0, 12);
  const ciphertext = blob.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return JSON.parse(new TextDecoder().decode(plaintext)) as T;
}

/* ------------------------------ records ------------------------------ */

interface HistoryBlob {
  v: 1;
  entries: HistoryEntry[];
}

const EMPTY: HistoryBlob = { v: 1, entries: [] };

async function readAll(): Promise<HistoryEntry[]> {
  try {
    const db = await openDb();
    const raw = await new Promise<ArrayBuffer | undefined>((resolve, reject) => {
      const tx = db.transaction(KEY_STORE, "readonly");
      const req = tx.objectStore(KEY_STORE).get("history");
      req.onsuccess = () => resolve(req.result as ArrayBuffer | undefined);
      req.onerror = () => reject(req.error);
    });
    db.close();
    if (!raw) return EMPTY.entries;
    const blob = await decryptJson<HistoryBlob>(raw);
    return Array.isArray(blob?.entries) ? blob.entries : EMPTY.entries;
  } catch {
    // Corrupt, tampered, or unavailable — treat as empty rather than crash.
    return EMPTY.entries;
  }
}

async function writeAll(entries: HistoryEntry[]): Promise<void> {
  const db = await openDb();
  const encrypted = await encryptJson({ v: 1, entries } satisfies HistoryBlob);
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readwrite");
    tx.objectStore(KEY_STORE).put(encrypted, "history");
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

function makeId(): string {
  if (typeof crypto.randomUUID === "string") return crypto.randomUUID();
  return `${Date.now().toString(36)}-${crypto.getRandomValues(new Uint8Array(8)).join("")}`;
}

/* ------------------------------ public API ------------------------------ */

export async function addHistory(input: {
  mode: AnalysisMode;
  kind?: MessageKind;
  preview: string;
  url?: string;
  result: AnalysisResult;
}): Promise<void> {
  const entries = await readAll();
  entries.unshift({
    id: makeId(),
    at: Date.now(),
    mode: input.mode,
    kind: input.kind,
    preview: input.preview.slice(0, 240),
    url: input.url,
    result: input.result,
  });
  await writeAll(entries.slice(0, HISTORY_LIMIT));
}

export async function getHistory(): Promise<HistoryEntry[]> {
  return (await readAll()).sort((a, b) => b.at - a.at);
}

export async function clearHistory(): Promise<void> {
  await writeAll([]);
}

export async function deleteHistoryEntry(id: string): Promise<void> {
  const entries = await readAll();
  await writeAll(entries.filter((e) => e.id !== id));
}
