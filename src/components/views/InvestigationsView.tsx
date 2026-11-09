"use client";

import React from "react";
import {
  Crosshair,
  ArrowRight,
  ShieldAlert,
  ExternalLink,
  CheckCircle2,
  Network,
  FileCode2,
} from "lucide-react";
import {
  useCloudPath,
  getSeverityBadgeClasses,
} from "@/context/CloudPathContext";

export function InvestigationsView() {
  const {
    activeScan,
    selectedAttackPathId,
    setSelectedAttackPathId,
    setActiveTab,
  } = useCloudPath();

  const currentPath =
    activeScan.attack_paths.find((p) => p.id === selectedAttackPathId) ||
    activeScan.attack_paths[0] ||
    null;

  if (!currentPath) {
    return (
      <div className="p-8 text-center text-sm text-slate-400">
        No attack paths discovered in the current workspace snapshot.
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-6">
      {/* Path Selector Header */}
      <div className="bg-[#11131A] p-4 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Crosshair className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-white">
              Attack Path Deep Investigation Dossier
            </h2>
            <p className="text-xs text-slate-400">
              End-to-end traversal analysis, permission chain evidence, MITRE ATT&amp;CK mapping, and least-privilege remediation
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <select
            aria-label="Select Attack Path to Investigate"
            value={currentPath.id}
            onChange={(e) => setSelectedAttackPathId(e.target.value)}
            className="bg-[#161B29] border border-slate-700 rounded-md px-3 py-1.5 text-xs text-slate-100"
          >
            {activeScan.attack_paths.map((p) => (
              <option key={p.id} value={p.id}>
                [{p.id}] {p.title} (Score {p.risk_breakdown.final_score})
              </option>
            ))}
          </select>

          <button
            onClick={() => setActiveTab("graph")}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 text-xs font-medium cursor-pointer"
          >
            <Network className="w-3.5 h-3.5" />
            Visualize in Graph Explorer
          </button>
        </div>
      </div>

      {/* Overview Banner */}
      <div className="rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-cyan-400">
                {currentPath.id}
              </span>
              {currentPath.is_shortest_path && (
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                  Shortest Path to Crown-Jewel Resource
                </span>
              )}
              <span className="text-[11px] px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/25">
                {currentPath.epistemic_class}
              </span>
            </div>
            <h3 className="text-lg font-bold text-white">{currentPath.title}</h3>
            <p className="text-xs text-slate-300 max-w-4xl">
              {currentPath.summary}
            </p>
          </div>

          <div className="text-right">
            <span
              className={`inline-block text-sm font-mono font-bold px-3 py-1 rounded border ${getSeverityBadgeClasses(
                currentPath.risk_breakdown.severity
              )}`}
            >
              {currentPath.risk_breakdown.severity} •{" "}
              {currentPath.risk_breakdown.final_score} / 100
            </span>
            <div className="text-[11px] font-mono text-slate-400 mt-1">
              Confidence: {Math.round(currentPath.risk_breakdown.confidence * 100)}%
            </div>
          </div>
        </div>

        {/* 1. Entry Point / 2. Intermediate / 3. Destination / 4. Objectives */}
        <div className="grid sm:grid-cols-4 gap-3 pt-2 text-xs">
          <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800">
            <div className="text-[10px] font-mono uppercase text-cyan-400">
              1. Entry Point Principal
            </div>
            <div className="font-semibold text-white mt-1">
              {currentPath.entry_point_name}
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
              Type: {currentPath.entry_point_type}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800">
            <div className="text-[10px] font-mono uppercase text-amber-400">
              2. Intermediate Pivots ({currentPath.intermediate_ids.length})
            </div>
            <div className="font-semibold text-white mt-1 truncate">
              {currentPath.hops
                .slice(0, -1)
                .map((h) => h.target_name)
                .join(" → ") || "Direct Single-Hop"}
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
              Total Hops: {currentPath.hop_count}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800">
            <div className="text-[10px] font-mono uppercase text-purple-400">
              3. Crown-Jewel Destination
            </div>
            <div className="font-semibold text-white mt-1">
              {currentPath.target_name}
            </div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">
              Type: {currentPath.target_type}
            </div>
          </div>

          <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800">
            <div className="text-[10px] font-mono uppercase text-red-400">
              4. Potential Attacker Objectives
            </div>
            <ul className="mt-1 space-y-0.5 text-[11px] text-slate-200">
              {currentPath.attacker_objectives.map((obj, idx) => (
                <li key={idx}>• {obj}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Step-by-Step Permission Relationships & Evidence */}
      <div className="rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-4">
        <h3 className="text-sm font-semibold text-white">
          Step-by-Step Permission Relationships &amp; Configuration Evidence
        </h3>

        <div className="space-y-3">
          {currentPath.hops.map((hop) => (
            <div
              key={hop.step}
              className="p-4 rounded-lg bg-[#151926] border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4"
            >
              <div className="space-y-1.5 max-w-3xl">
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono font-semibold">
                    Step {hop.step}
                  </span>
                  <span className="font-semibold text-white">
                    {hop.source_name} ({hop.source_type})
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-amber-300 border border-slate-700">
                    {hop.edge_type}: {hop.edge_label}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-semibold text-white">
                    {hop.target_name} ({hop.target_type})
                  </span>
                </div>

                <p className="text-xs text-slate-300">{hop.why_it_matters}</p>
                <div className="text-[11px] font-mono text-slate-400">
                  Evidence: {hop.evidence}
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5 shrink-0">
                {hop.permissions_used.map((p) => (
                  <span
                    key={p}
                    className="text-[11px] font-mono px-2.5 py-1 rounded bg-red-500/15 text-red-300 border border-red-500/30"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Bottom Split: Risk Assessment & MITRE ATT&CK vs Remediation Diff */}
      <div className="grid lg:grid-cols-12 gap-5">
        <div className="lg:col-span-5 rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-4">
          <h3 className="text-sm font-semibold text-white">
            Risk Assessment &amp; MITRE ATT&amp;CK Cloud Mapping
          </h3>

          <div className="p-3 rounded bg-[#151926] border border-slate-800 text-xs space-y-2">
            <div className="font-mono text-cyan-300 text-[11px]">
              {currentPath.risk_breakdown.formula_summary}
            </div>
            {currentPath.risk_breakdown.factors.map((f) => (
              <div
                key={f.factor}
                className="flex items-center justify-between border-t border-slate-800/80 pt-1.5 text-[11px]"
              >
                <span className="text-slate-300">{f.factor}</span>
                <span className="font-mono text-white">
                  {f.raw_score} × {f.weight} = +{f.weighted_contribution}
                </span>
              </div>
            ))}
          </div>

          <div className="p-3 rounded bg-amber-500/10 border border-amber-500/25 text-[11px] text-amber-200">
            <strong>Epistemic Distinction:</strong> MITRE ATT&amp;CK mappings below
            indicate which adversary techniques this cloud configuration weakness
            would enable if exploited—not observed telemetry of a live attack.
          </div>

          <div className="space-y-2">
            {currentPath.mitre_techniques.map((m) => (
              <div
                key={m.technique_id}
                className="p-3 rounded bg-[#151926] border border-slate-800 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-violet-300">
                    {m.technique_id} • {m.name}
                  </span>
                  <a
                    href={m.url}
                    target="_blank"
                    rel="noreferrer"
                    className="text-slate-400 hover:text-white"
                  >
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
                <div className="text-[10px] font-mono text-cyan-400 mt-0.5">
                  Tactic: {m.tactic}
                </div>
                <p className="text-[11px] text-slate-400 mt-1">
                  {m.mapping_note}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-7 rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              Recommended Remediation to Break This Attack Path
            </h3>
            <span className="text-xs font-mono px-2.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
              {currentPath.remediation.priority}
            </span>
          </div>

          <div className="text-sm font-bold text-white">
            {currentPath.remediation.title}
          </div>
          <p className="text-xs text-slate-300">
            {currentPath.remediation.why_it_matters}
          </p>
          <div className="p-3 rounded bg-[#151926] border border-slate-800 text-xs text-slate-300">
            <strong className="text-amber-300">Operational Impact:</strong>{" "}
            {currentPath.remediation.operational_impact}
          </div>

          <div className="grid md:grid-cols-2 gap-3">
            <div>
              <div className="text-[10px] font-mono uppercase text-red-400 mb-1 flex items-center gap-1">
                <FileCode2 className="w-3 h-3" />
                Current Vulnerable Configuration
              </div>
              <pre className="p-3 rounded bg-[#090A0F] border border-red-500/30 text-[11px] font-mono text-red-200 overflow-x-auto max-h-64">
                {currentPath.remediation.before_config}
              </pre>
            </div>
            <div>
              <div className="text-[10px] font-mono uppercase text-emerald-400 mb-1 flex items-center gap-1">
                <ShieldAlert className="w-3 h-3" />
                Recommended Least-Privilege Configuration
              </div>
              <pre className="p-3 rounded bg-[#090A0F] border border-emerald-500/30 text-[11px] font-mono text-emerald-200 overflow-x-auto max-h-64">
                {currentPath.remediation.suggested_config}
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
