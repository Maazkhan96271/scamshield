import { NextResponse } from "next/server";
import { getReports, type ReportTargetKind } from "@/lib/community";

const KINDS: ReportTargetKind[] = ["domain", "phone"];

/** GET /api/community?target=domain&value=secure-paypal.top */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const kind = url.searchParams.get("target") as ReportTargetKind | null;
  const value = url.searchParams.get("value") ?? "";
  if (!kind || !KINDS.includes(kind)) {
    return NextResponse.json({ error: "target must be 'domain' or 'phone'" }, { status: 400 });
  }
  const stats = getReports(kind, value);
  return NextResponse.json({ target: kind, value, stats });
}
