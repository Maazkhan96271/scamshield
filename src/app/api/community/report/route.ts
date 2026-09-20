import { NextResponse } from "next/server";
import { recordReport, type ReportTargetKind } from "@/lib/community";

const KINDS: ReportTargetKind[] = ["domain", "phone"];

/**
 * POST /api/community { target: "domain" | "phone", value: string, verdict: "scam" | "legit" }
 * Records an anonymous community report. No personal data is accepted or stored.
 */
export async function POST(req: Request) {
  let body: { target?: unknown; value?: unknown; verdict?: unknown };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { target, value, verdict } = body;
  if (typeof target !== "string" || !KINDS.includes(target as ReportTargetKind)) {
    return NextResponse.json({ error: "target must be 'domain' or 'phone'" }, { status: 400 });
  }
  if (typeof value !== "string" || value.trim().length === 0 || value.length > 2048) {
    return NextResponse.json({ error: "Provide the domain or phone number to report." }, { status: 400 });
  }
  if (verdict !== "scam" && verdict !== "legit") {
    return NextResponse.json({ error: "verdict must be 'scam' or 'legit'" }, { status: 400 });
  }

  const stats = recordReport(target as ReportTargetKind, value, verdict);
  if (!stats) {
    return NextResponse.json({ error: "That value doesn't look like a valid domain or number." }, { status: 400 });
  }
  return NextResponse.json({ ok: true, stats });
}
