"use client";

import React, { useState, useMemo } from "react";
import {
  Search,
  Filter,
  AlertTriangle,
  ExternalLink,
  Network,
  CheckCircle2,
  Code2,
} from "lucide-react";
import {
  useCloudPath,
  getSeverityBadgeClasses,
} from "@/context/CloudPathContext";

export function FindingsView() {
  const {
    activeScan,
    selectedFindingId,
    setSelectedFindingId,
    setSelectedAttackPathId,
    setActiveTab,
  } = useCloudPath();

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");

  const categories = useMemo(() => {
    const s = new Set<string>();
    activeScan.findings.forEach((f) => s.add(f.category));
    return Array.from(s);
  }, [activeScan.findings]);

  const filteredFindings = useMemo(() => {
    return activeScan.findings.filter((f) => {
      if (severityFilter !== "ALL" && f.severity !== severityFilter)
        return false;
      if (categoryFilter !== "ALL" && f.category !== categoryFilter)
        return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        return (
          f.title.toLowerCase().includes(q) ||
          f.affected_resource_name.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          f.explanation.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [activeScan.findings, severityFilter, categoryFilter, search]);

  const activeFinding =
    filteredFindings.find((f) => f.id === selectedFindingId) ||
    filteredFindings[0] ||
    null;

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      {/* Header & Filter Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-[#11131A] p-4 rounded-lg border border-slate-800">
        <div>
          <h2 className="text-base font-semibold text-white">
            Security Findings &amp; Remediation Intelligence
          </h2>
          <p className="text-xs text-slate-400">
            Traceable policy evaluations, explainable 0–100 risk scores, and least-privilege configuration diffs
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search rule, resource, policy..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-[#161B29] border border-slate-700/80 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 w-56 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              aria-label="Filter Findings by Severity"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
            >
              <option value="ALL">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>
          </div>

          <select
            aria-label="Filter Findings by Category"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="ALL">All Categories</option>
            {categories.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Master-Detail Split */}
      <div className="grid lg:grid-cols-12 gap-5">
        {/* Left List */}
        <div className="lg:col-span-5 space-y-2.5 max-h-[calc(100vh-14rem)] overflow-y-auto pr-1">
          {filteredFindings.map((f) => {
            const isSelected = activeFinding?.id === f.id;
            return (
              <div
                key={f.id}
                onClick={() => setSelectedFindingId(f.id)}
                className={`p-3.5 rounded-lg border transition-colors cursor-pointer ${
                  isSelected
                    ? "bg-[#161C2C] border-cyan-500/60"
                    : "bg-[#11131A] border-slate-800 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[11px] font-mono text-cyan-400">
                    {f.id} • {f.rule_id}
                  </span>
                  <span
                    className={`text-[11px] font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                      f.severity
                    )}`}
                  >
                    {f.severity} ({f.risk_breakdown.final_score})
                  </span>
                </div>
                <div className="text-xs font-semibold text-white mt-1.5">
                  {f.title}
                </div>
                <div className="mt-2 flex items-center justify-between text-[11px] text-slate-400">
                  <span className="font-mono truncate">
                    {f.affected_resource_name} ({f.affected_resource_type})
                  </span>
                  <span>{f.category}</span>
                </div>
              </div>
            );
          })}
          {filteredFindings.length === 0 && (
            <div className="p-8 rounded-lg bg-[#11131A] border border-slate-800 text-center text-xs text-slate-400">
              No findings match the current filter criteria.
            </div>
          )}
        </div>

        {/* Right Finding Detail & Remediation Diff */}
        <div className="lg:col-span-7">
          {activeFinding ? (
            <div className="rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-5">
              <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono text-cyan-400">
                      {activeFinding.id} ({activeFinding.rule_id})
                    </span>
                    <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {activeFinding.epistemic_class}
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">
                    {activeFinding.title}
                  </h3>
                  <div className="text-xs text-slate-400 font-mono mt-1">
                    Affected ARN: {activeFinding.affected_resource_id}
                  </div>
                </div>

                <div className="text-right">
                  <span
                    className={`inline-block text-xs font-mono px-3 py-1 rounded border ${getSeverityBadgeClasses(
                      activeFinding.severity
                    )}`}
                  >
                    {activeFinding.severity} • Score{" "}
                    {activeFinding.risk_breakdown.final_score} / 100
                  </span>
                  <div className="text-[10px] text-slate-400 font-mono mt-1">
                    Confidence:{" "}
                    {Math.round(activeFinding.risk_breakdown.confidence * 100)}%
                  </div>
                </div>
              </div>

              {/* Explanation & Impact */}
              <div className="grid md:grid-cols-2 gap-4 text-xs">
                <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800 space-y-1.5">
                  <div className="text-[11px] font-mono uppercase text-cyan-400">
                    Technical Explanation &amp; Evidence
                  </div>
                  <p className="text-slate-200 leading-relaxed">
                    {activeFinding.explanation}
                  </p>
                  <p className="text-[11px] font-mono text-slate-400 pt-1">
                    Evidence: {activeFinding.evidence}
                  </p>
                </div>

                <div className="p-3.5 rounded-lg bg-[#151926] border border-slate-800 space-y-1.5">
                  <div className="text-[11px] font-mono uppercase text-red-400 flex items-center gap-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    Potential Security Impact
                  </div>
                  <p className="text-slate-200 leading-relaxed">
                    {activeFinding.potential_impact}
                  </p>
                  {activeFinding.attack_path_Open_refs.length > 0 && (
                    <div className="pt-1.5 flex flex-wrap items-center gap-1.5">
                      <span className="text-[11px] text-slate-400">
                        Attack Paths:
                      </span>
                      {activeFinding.attack_path_Open_refs.map((pid) => (
                        <button
                          key={pid}
                          onClick={() => {
                            setSelectedAttackPathId(pid);
                            setActiveTab("graph");
                          }}
                          className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/25 cursor-pointer"
                        >
                          <Network className="w-3 h-3" />
                          {pid}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Transparent Risk Score Breakdown */}
              <div className="p-4 rounded-lg bg-[#141824] border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold uppercase font-mono text-slate-300">
                    Explainable Risk Score Formula Breakdown
                  </h4>
                  <span className="text-[11px] font-mono text-cyan-300">
                    {activeFinding.risk_breakdown.formula_summary}
                  </span>
                </div>

                <div className="grid sm:grid-cols-5 gap-2">
                  {activeFinding.risk_breakdown.factors.map((factor) => (
                    <div
                      key={factor.factor}
                      className="p-2.5 rounded bg-[#0E111B] border border-slate-800/90 text-[11px]"
                    >
                      <div className="text-slate-400 text-[10px] truncate" title={factor.factor}>
                        {factor.factor}
                      </div>
                      <div className="font-mono font-bold text-white mt-1">
                        +{factor.weighted_contribution}{" "}
                        <span className="text-[10px] text-slate-400 font-normal">
                          ({factor.raw_score}×{factor.weight})
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400 mt-1 line-clamp-2">
                        {factor.justification}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK Mapping */}
              {activeFinding.mitre_techniques.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-semibold uppercase font-mono text-slate-400">
                    Applicable MITRE ATT&amp;CK Cloud Techniques (Configuration Weakness)
                  </h4>
                  <div className="grid sm:grid-cols-2 gap-2.5">
                    {activeFinding.mitre_techniques.map((m) => (
                      <div
                        key={m.technique_id}
                        className="p-3 rounded bg-[#141824] border border-slate-800 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-semibold text-violet-300">
                            {m.technique_id} — {m.name}
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
                        <div className="text-[10px] text-cyan-400 font-mono mt-0.5">
                          Tactic: {m.tactic}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">
                          {m.mapping_note}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Actionable Remediation Before / After Diff */}
              <div className="p-4 rounded-lg bg-[#0D131A] border border-emerald-500/30 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    <h4 className="text-xs font-bold text-emerald-300 uppercase font-mono">
                      Remediation Guidance • {activeFinding.remediation.priority}
                    </h4>
                  </div>
                  <span className="text-[11px] text-slate-400">
                    Read-Only Recommendation (Does not auto-mutate cloud state)
                  </span>
                </div>

                <div className="text-sm font-semibold text-white">
                  {activeFinding.remediation.title}
                </div>
                <p className="text-xs text-slate-300">
                  {activeFinding.remediation.why_it_matters}
                </p>
                <div className="text-xs text-amber-300/90 bg-amber-500/10 border border-amber-500/20 px-3 py-2 rounded">
                  <strong>Operational Impact:</strong>{" "}
                  {activeFinding.remediation.operational_impact}
                </div>

                <div className="grid md:grid-cols-2 gap-3 pt-1">
                  <div>
                    <div className="text-[10px] font-mono uppercase text-red-400 mb-1 flex items-center gap-1">
                      <Code2 className="w-3 h-3" />
                      Before Configuration (Vulnerable)
                    </div>
                    <pre className="p-3 rounded bg-[#090A0F] border border-red-500/30 text-[11px] font-mono text-red-200 overflow-x-auto max-h-56">
                      {activeFinding.remediation.before_config}
                    </pre>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono uppercase text-emerald-400 mb-1 flex items-center gap-1">
                      <Code2 className="w-3 h-3" />
                      Suggested Least-Privilege Configuration
                    </div>
                    <pre className="p-3 rounded bg-[#090A0F] border border-emerald-500/30 text-[11px] font-mono text-emerald-200 overflow-x-auto max-h-56">
                      {activeFinding.remediation.suggested_config}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
