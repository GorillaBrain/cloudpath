import { NextResponse } from "next/server";
import {
  DEMO_WORKSPACE_ID,
  getNorthstarDemoEnvironment,
  runFullAnalysisTS,
} from "@/lib/engine/ts-analyzer";

export async function GET() {
  const backendUrl = process.env.BACKEND_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL;

  if (backendUrl) {
    try {
      const res = await fetch(`${backendUrl.replace(/\/$/, "")}/api/demo`, {
        cache: "no-store",
      });
      if (res.ok) {
        const data = await res.json();
        return NextResponse.json(data);
      }
    } catch {
      // Fallback to deterministic local TypeScript analysis engine
    }
  }

  const demoScan = runFullAnalysisTS(
    getNorthstarDemoEnvironment(),
    "demo_environment",
    "Northstar Financial Technologies — Production AWS",
    DEMO_WORKSPACE_ID
  );
  demoScan.id = "scan-northstar-demo-001";
  return NextResponse.json(demoScan);
}
