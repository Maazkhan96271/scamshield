"use client";

import { useEffect, useState } from "react";

interface BeforeInstallPromptEvent extends Event {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: "accepted" | "dismissed" }>;
}

/**
 * "Install ScamShield" button — appears once the browser fires
 * `beforeinstallprompt` (Chrome/Edge/Android). On iOS Safari users install
 * via Share → Add to Home Screen; the manifest supports that too.
 */
export default function InstallPwaButton({ className = "" }: { className?: string }) {
  const [deferred, setDeferred] = useState<BeforeInstallPromptEvent | null>(null);
  const [installed, setInstalled] = useState(false);

  useEffect(() => {
    const onPrompt = (e: Event) => {
      e.preventDefault();
      setDeferred(e as BeforeInstallPromptEvent);
    };
    const onInstalled = () => {
      setInstalled(true);
      setDeferred(null);
    };
    window.addEventListener("beforeinstallprompt", onPrompt);
    window.addEventListener("appinstalled", onInstalled);
    // Already running as the installed app — hide the button. Deferred so the
    // effect body itself never sets state synchronously.
    const t = window.setTimeout(() => {
      if (window.matchMedia("(display-mode: standalone)").matches) setInstalled(true);
    }, 0);
    return () => {
      window.removeEventListener("beforeinstallprompt", onPrompt);
      window.removeEventListener("appinstalled", onInstalled);
      window.clearTimeout(t);
    };
  }, []);

  if (installed || !deferred) return null;

  async function install() {
    if (!deferred) return;
    await deferred.prompt();
    const { outcome } = await deferred.userChoice;
    if (outcome === "accepted") setInstalled(true);
    setDeferred(null);
  }

  return (
    <button
      type="button"
      onClick={() => void install()}
      className={`inline-flex items-center gap-2 rounded-lg border border-accent/40 bg-accent/10 px-4 py-2 text-sm font-medium text-accent transition hover:bg-accent/20 ${className}`}
    >
      <svg viewBox="0 0 24 24" fill="none" className="h-4 w-4" aria-hidden>
        <path d="M12 3v12m0 0 4.5-4.5M12 15l-4.5-4.5" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M4.5 17.5v1.2A2.3 2.3 0 0 0 6.8 21h10.4a2.3 2.3 0 0 0 2.3-2.3v-1.2" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
      Install app
    </button>
  );
}
