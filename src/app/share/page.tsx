import { redirect } from "next/navigation";

/**
 * PWA share target — receives shares from the Android share sheet:
 *   GET /share?title=...&text=...&url=...
 * Forwards the shared content into the analyzer via query params.
 */
export default async function SharePage({
  searchParams,
}: {
  searchParams: Promise<{ title?: string; text?: string; url?: string }>;
}) {
  const { title, text, url } = await searchParams;
  const shared = [title, text].filter(Boolean).join("\n").trim();

  if (url && !shared) {
    redirect(`/analyze?url=${encodeURIComponent(url)}`);
  }
  if (shared) {
    redirect(`/analyze?text=${encodeURIComponent(shared)}`);
  }
  redirect("/analyze");
}
