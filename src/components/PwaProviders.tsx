"use client";

import { useEffect } from "react";
import InstallPwaButton from "./InstallPwaButton";

/** Registers the service worker once and shows the install control. */
export default function PwaProviders({ slot = "nav" }: { slot?: "nav" | "hero" }) {
  useEffect(() => {
    if (!("serviceWorker" in navigator)) return;
    const register = () => {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    };
    if (document.readyState === "complete") register();
    else window.addEventListener("load", register, { once: true });
  }, []);

  if (slot === "hero") return null;
  return <InstallPwaButton />;
}
