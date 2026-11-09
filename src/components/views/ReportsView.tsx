"use client";

import React from "react";
import { Download, Printer, FileJson, ShieldCheck } from "lucide-react";
import {
  useCloudPath,
  getSeverityBadgeClasses,
} from "@/context/CloudPathContext";

export function ReportsView() {
  const { activeScan } = useCloudPath();

  const handleDownloadJson = () => {
    const jsonString = JSON.stringify(activeScan, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cloudpath-report-${activeScan.organization
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handlePrintPdf = () => {
    window.print();
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Export Action Bar */}
      <div className="no-print bg-[#11131A] p-4 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white">
            Executive &amp; Technical Security Posture Reports
          </h2>
          <p className="text-xs text-slate-400">
            Export machine-readable JSON findings or generate a print-ready PDF audit dossier
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleDownloadJson}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-md bg-[#161B29] hover:bg-slate-800 text-cyan-300 border border-cyan-500/30 text-xs font-medium cursor-pointer"
          >
            <FileJson className="w-4 h-4" />
            Export Full JSON Report
          </button>

          <button
            onClick={handlePrintPdf}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
          >
            <Printer className="w-4 h-4" />
            Generate PDF Audit Report
          </button>
        </div>
      </div>

      {/* Printable Report Document */}
      <div className="rounded-xl bg-[#11131A] border border-slate-800 p-8 space-y-8">
        <div className="border-b border-slate-800 pb-6 flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase">
              <ShieldCheck className="w-4 h-4" />
              CloudPath Attack Path &amp; Identity Risk Assessment
            </div>
            <h1 className="text-2xl font-bold text-white mt-1">
              {activeScan.organization} — AWS Security Posture Dossier
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Account ID: {activeScan.account_id} • Snapshot ID: {activeScan.id}{" "}
              • Generated: {new Date(activeScan.created_at).toUTCString()}
            </p>
          </div>

          <div className="p-3 rounded-lg bg-[#161B29] border border-slate-700 text-right">
            <div className="text-[10px] font-mono uppercase text-slate-400">
              OVERALL POSTURE INDEX
            </div>
            <div className="text-2xl font-bold font-mono text-cyan-400">
              {activeScan.summary_metrics.overall_posture_score} / 100
            </div>
          </div>
        </div>

        {/* Executive Summary Metrics */}
        <div>
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            1. Executive Telemetry Summary
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
            <div className="p-3.5 rounded bg-[#151926] border border-slate-800">
              <span className="text-slate-400 block">Total Cloud Assets</span>
              <span className="text-xl font-bold font-mono text-white">
                {activeScan.summary_metrics.total_assets}
              </span>
            </div>
            <div className="p-3.5 rounded bg-[#151926] border border-slate-800">
              <span className="text-slate-400 block">
                Discovered Attack Paths
              </span>
              <span className="text-xl font-bold font-mono text-cyan-400">
                {activeScan.summary_metrics.total_attack_paths}
              </span>
            </div>
            <div className="p-3.5 rounded bg-[#151926] border border-slate-800">
              <span className="text-slate-400 block">Critical Findings</span>
              <span className="text-xl font-bold font-mono text-red-400">
                {activeScan.summary_metrics.critical_findings}
              </span>
            </div>
            <div className="p-3.5 rounded bg-[#151926] border border-slate-800">
              <span className="text-slate-400 block">
                Publicly Exposed Assets
              </span>
              <span className="text-xl font-bold font-mono text-amber-400">
                {activeScan.summary_metrics.publicly_exposed_resources}
              </span>
            </div>
          </div>
        </div>

        {/* Discovered Attack Paths Summary */}
        <div>
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            2. Multi-Hop Attack Paths &amp; Shortest Escalation Routes
          </h3>
          <div className="space-y-3">
            {activeScan.attack_paths.map((p) => (
              <div
                key={p.id}
                className="p-4 rounded-lg bg-[#151926] border border-slate-800 space-y-1.5 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-cyan-400">
                    {p.id}: {p.title}
                  </span>
                  <span
                    className={`font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                      p.risk_breakdown.severity
                    )}`}
                  >
                    {p.risk_breakdown.severity} ({p.risk_breakdown.final_score})
                  </span>
                </div>
                <p className="text-slate-300">{p.summary}</p>
                <div className="text-[11px] font-mono text-slate-400">
                  Formula: {p.risk_breakdown.formula_summary}
                </div>
                <div className="text-[11px] text-emerald-300">
                  Remediation: {p.remediation.title}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Findings & Remediations */}
        <div>
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3">
            3. Prioritized Findings &amp; Remediation Plan
          </h3>
          <div className="space-y-2.5">
            {activeScan.findings.map((f) => (
              <div
                key={f.id}
                className="p-3.5 rounded bg-[#151926] border border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
              >
                <div>
                  <div className="font-semibold text-white">
                    [{f.id} / {f.rule_id}] {f.title}
                  </div>
                  <div className="text-slate-400 text-[11px] mt-0.5">
                    Resource: {f.affected_resource_name} • Action:{" "}
                    {f.remediation.title}
                  </div>
                </div>
                <span
                  className={`shrink-0 font-mono text-[11px] px-2.5 py-0.5 rounded border ${getSeverityBadgeClasses(
                    f.severity
                  )}`}
                >
                  {f.severity} • {f.risk_breakdown.final_score}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
