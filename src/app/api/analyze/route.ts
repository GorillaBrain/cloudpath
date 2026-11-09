import { NextRequest, NextResponse } from "next/server";
import {
  DEMO_WORKSPACE_ID,
  runFullAnalysisTS,
} from "@/lib/engine/ts-analyzer";
import { RiskWeights } from "@/types/cloudpath";

const rateLimitMap = new Map<string, number[]>();

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const windowMs = 60_000;
  const maxReq = 45;
  const timestamps = (rateLimitMap.get(ip) ?? []).filter(
    (t) => now - t < windowMs
  );
  if (timestamps.length >= maxReq) return false;
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return true;
}

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for") || "127.0.0.1";
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { detail: "Rate limit exceeded. Please wait before submitting additional analysis jobs." },
      { status: 429 }
    );
  }

  let body: {
    scan_name?: string;
    source_type?: string;
    workspace_id?: string;
    content?: string | Record<string, unknown>;
    filename?: string;
    risk_weights?: RiskWeights;
  };

  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { detail: "Invalid JSON request body." },
      { status: 400 }
    );
  }

  const headerWs = req.headers.get("x-workspace-id");
  if (headerWs && body.workspace_id && headerWs !== body.workspace_id) {
    return NextResponse.json(
      { detail: "Cross-workspace access violation: X-Workspace-Id header mismatch." },
      { status: 403 }
    );
  }

  const workspaceId = headerWs || body.workspace_id || DEMO_WORKSPACE_ID;
  const scanName = (body.scan_name || "Cloud Configuration Analysis").slice(0, 140);
  const sourceType = body.source_type || "custom_json";

  if (!body.content) {
    return NextResponse.json(
      { detail: "Missing configuration content payload." },
      { status: 400 }
    );
  }

  // Forward to standalone Python FastAPI + NetworkX service if configured
  const backendUrl = process.env.BACKEND_API_URL || process.env.NEXT_PUBLIC_BACKEND_URL;
  if (backendUrl) {
    try {
      const pyRes = await fetch(`${backendUrl.replace(/\/$/, "")}/api/analyze`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Workspace-Id": workspaceId,
        },
        body: JSON.stringify({
          scan_name: scanName,
          source_type: sourceType,
          workspace_id: workspaceId,
          content: body.content,
          filename: body.filename,
          risk_weights: body.risk_weights,
        }),
      });
      if (pyRes.ok) {
        return NextResponse.json(await pyRes.json());
      }
      const errJson = await pyRes.json().catch(() => ({}));
      if (pyRes.status === 400 || pyRes.status === 403 || pyRes.status === 413) {
        return NextResponse.json(
          { detail: errJson.detail || "Configuration validation failed." },
          { status: pyRes.status }
        );
      }
    } catch {
      // Fallback to embedded TypeScript engine when external container is unreachable
    }
  }

  try {
    const result = runFullAnalysisTS(
      body.content,
      sourceType,
      scanName,
      workspaceId,
      body.risk_weights,
      body.filename
    );
    return NextResponse.json(result);
  } catch (err) {
    return NextResponse.json(
      { detail: (err as Error).message || "Configuration validation failed." },
      { status: 400 }
    );
  }
}
