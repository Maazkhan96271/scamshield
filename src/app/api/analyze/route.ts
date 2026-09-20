import { NextResponse } from "next/server";
import {
  analyzeImage,
  analyzeMessage,
  analyzeUrlMessage,
  MAX_CONTENT_LENGTH,
  MAX_IMAGE_BYTES,
  MAX_URL_LENGTH,
  MESSAGE_KINDS,
  type MessageKind,
} from "@/lib/scam";

const KIND_VALUES = new Set(MESSAGE_KINDS.map((k) => k.value));
const IMAGE_DATA_URL = /^data:image\/(png|jpe?g|webp);base64,/;

export async function POST(req: Request) {
  let body: { mode?: unknown; content?: unknown; kind?: unknown; url?: unknown; imageDataUrl?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const mode = body?.mode;

  if (mode === "text") {
    const { content, kind } = body;
    if (typeof content !== "string" || content.trim().length === 0) {
      return NextResponse.json({ error: "Provide the message text to analyze." }, { status: 400 });
    }
    if (content.length > MAX_CONTENT_LENGTH) {
      return NextResponse.json({ error: `Message is too long (max ${MAX_CONTENT_LENGTH} characters).` }, { status: 400 });
    }
    const safeKind: MessageKind =
      typeof kind === "string" && KIND_VALUES.has(kind as MessageKind) ? (kind as MessageKind) : "email";
    return NextResponse.json(await analyzeMessage(content.trim(), safeKind));
  }

  if (mode === "url") {
    const { url } = body;
    if (typeof url !== "string" || url.trim().length === 0) {
      return NextResponse.json({ error: "Provide a link to check." }, { status: 400 });
    }
    if (url.length > MAX_URL_LENGTH) {
      return NextResponse.json({ error: "That URL is too long to analyze." }, { status: 400 });
    }
    try {
      return NextResponse.json(await analyzeUrlMessage(url));
    } catch (e) {
      return NextResponse.json(
        { error: e instanceof Error ? e.message : "Couldn't analyze that link." },
        { status: 400 },
      );
    }
  }

  if (mode === "image") {
    const { imageDataUrl } = body;
    if (typeof imageDataUrl !== "string" || !IMAGE_DATA_URL.test(imageDataUrl)) {
      return NextResponse.json({ error: "Upload a PNG, JPEG or WebP screenshot." }, { status: 400 });
    }
    if (imageDataUrl.length > MAX_IMAGE_BYTES * 1.4) {
      return NextResponse.json({ error: "Screenshot is too large (max 5 MB)." }, { status: 400 });
    }
    try {
      return NextResponse.json(await analyzeImage(imageDataUrl));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Screenshot analysis failed.";
      const status = message.includes("NOVITA_API_KEY") ? 422 : 502;
      return NextResponse.json({ error: message }, { status });
    }
  }

  return NextResponse.json({ error: "Unknown analysis mode." }, { status: 400 });
}
