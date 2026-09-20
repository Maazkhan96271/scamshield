"use client";

/**
 * Passphrase-encrypted history backup.
 *
 * Export: history JSON → AES-256-GCM encrypted with a key derived from the
 * user's passphrase via PBKDF2 (310k iterations, SHA-256) → base64 file.
 * Import: the reverse, strictly validating the decrypted payload shape.
 *
 * The passphrase never leaves the device and is never stored anywhere.
 */

import type { HistoryEntry } from "./history";

const PBKDF2_ITERATIONS = 310_000;

interface BackupPayload {
  app: "scamshield-history";
  v: 1;
  exportedAt: number;
  entries: HistoryEntry[];
}

const MAGIC = "SCAMSHIELD-BK1:"; // base64 payload marker

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Encrypts history into a portable backup string. Throws on empty passphrase. */
export async function exportBackup(entries: HistoryEntry[], passphrase: string): Promise<string> {
  if (passphrase.length < 8) throw new Error("Use a passphrase of at least 8 characters.");
  const payload: BackupPayload = {
    app: "scamshield-history",
    v: 1,
    exportedAt: Date.now(),
    entries,
  };

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, new TextEncoder().encode(JSON.stringify(payload))),
  );

  const blob = new Uint8Array(salt.length + iv.length + ciphertext.length);
  blob.set(salt, 0);
  blob.set(iv, salt.length);
  blob.set(ciphertext, salt.length + iv.length);
  return `${MAGIC}${toBase64(blob)}`;
}

/** Decrypts a backup string back into history entries. Throws with friendly messages. */
export async function importBackup(backup: string, passphrase: string): Promise<HistoryEntry[]> {
  const trimmed = backup.trim();
  if (!trimmed.startsWith(MAGIC)) throw new Error("That doesn't look like a ScamShield backup file.");
  const blob = fromBase64(trimmed.slice(MAGIC.length));
  if (blob.length < 16 + 12 + 16) throw new Error("Backup file is truncated or corrupted.");

  const salt = blob.slice(0, 16);
  const iv = blob.slice(16, 28);
  const ciphertext = blob.slice(28);

  const key = await deriveKey(passphrase, salt);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, ciphertext as BufferSource);
  } catch {
    throw new Error("Wrong passphrase — the backup could not be decrypted.");
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("Backup decrypted but the contents are unreadable.");
  }
  const payload = parsed as Partial<BackupPayload>;
  if (payload.app !== "scamshield-history" || !Array.isArray(payload.entries)) {
    throw new Error("Backup is valid but not a ScamShield history file.");
  }
  return payload.entries;
}
