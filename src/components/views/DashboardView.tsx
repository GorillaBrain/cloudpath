"use client";

import React from "react";
import {
  Database,
  Users,
  AlertOctagon,
  GitBranch,
  Globe,
  KeyRound,
  ArrowUpRight,
  Crosshair,
  ShieldCheck,
  Clock,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";
import {
  useCloudPath,
  getSeverityBadgeClasses,
} from "@/context/CloudPathContext";
import { AttackGraphCanvas } from "@/components/graph/AttackGraphCanvas";

const SEVERITY_COLORS: Record<string, string> = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#10b981",
  Informational: "#64748b",
};

export function DashboardView() {
  const {
    activeScan,
    setActiveTab,
    selectedAttackPathId,
    setSelectedAttackPathId,
    setSelectedFindingId,
    setSelectedAssetId,
  } = useCloudPath();

  const m = activeScan.summary_metrics;

  const riskChartData = Object.entries(m.risk_distribution).map(
    ([name, count]) => ({
      name,
      count,
      color: SEVERITY_COLORS[name] || "#06b6d4",
    })
  );

  const assetChartData = Object.entries(m.asset_distribution).map(
    ([name, value]) => ({
      name,
      value,
    })
  );

  const metricCards = [
    {
      label: "Total Assets Analyzed",
      value: m.total_assets,
      sub: `${Object.keys(m.asset_distribution).length} AWS resource classes`,
      icon: Database,
      accent: "text-cyan-400",
      onClick: () => setActiveTab("assets"),
    },
    {
      label: "Cloud Identities",
      value: m.total_identities,
      sub: "Users, Roles, Groups & External",
      icon: Users,
      accent: "text-violet-400",
      onClick: () => setActiveTab("assets"),
    },
    {
      label: "Critical Findings",
      value: m.critical_findings,
      sub: `${activeScan.findings.length} total findings detected`,
      icon: AlertOctagon,
      accent: "text-red-400",
      onClick: () => setActiveTab("findings"),
    },
    {
      label: "High-Risk Attack Paths",
      value: m.high_risk_attack_paths,
      sub: `${m.total_attack_paths} total paths discovered`,
      icon: GitBranch,
      accent: "text-orange-400",
      onClick: () => setActiveTab("graph"),
    },
    {
      label: "Publicly Exposed Assets",
      value: m.publicly_exposed_resources,
      sub: "Internet-reachable S3 / SG / EC2",
      icon: Globe,
      accent: "text-amber-400",
      onClick: () => setActiveTab("assets"),
    },
    {
      label: "Excessive Permissions",
      value: m.excessive_permission_count,
      sub: "Wildcards, PassRole & Policy Mutation",
      icon: KeyRound,
      accent: "text-red-400",
      onClick: () => setActiveTab("findings"),
    },
  ];

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Compact Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3.5">
        {metricCards.map((card) => {
          const Icon = card.icon;
          return (
            <button
              key={card.label}
              onClick={card.onClick}
              className="text-left p-4 rounded-lg bg-[#11131A] hover:bg-[#151822] border border-slate-800/90 transition-colors cursor-pointer group"
            >
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400">
                  {card.label}
                </span>
                <Icon className={`w-4 h-4 ${card.accent}`} />
              </div>
              <div className="mt-2 flex items-baseline justify-between">
                <span className="text-2xl font-bold font-mono text-white">
                  {card.value}
                </span>
                <ArrowUpRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 transition-colors" />
              </div>
              <div className="mt-1 text-[11px] text-slate-400 truncate">
                {card.sub}
              </div>
            </button>
          );
        })}
      </div>

      {/* Middle Row: Attack Path Summary Panel + Interactive Graph Preview */}
      <div className="grid lg:grid-cols-12 gap-5">
        {/* Prioritized Attack Paths Summary */}
        <div className="lg:col-span-5 rounded-lg bg-[#11131A] border border-slate-800 flex flex-col">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Highest-Risk Attack Paths (Remediate First)
              </h2>
              <p className="text-xs text-slate-400">
                Computed via BFS/DFS &amp; Dijkstra shortest-path traversal
              </p>
            </div>
            <button
              onClick={() => setActiveTab("investigations")}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
            >
              All Investigations →
            </button>
          </div>

          <div className="p-4 space-y-3 flex-1 overflow-y-auto max-h-[380px]">
            {activeScan.attack_paths.map((path) => {
              const isSelected = selectedAttackPathId === path.id;
              return (
                <div
                  key={path.id}
                  onClick={() => setSelectedAttackPathId(path.id)}
                  className={`p-3 rounded-lg border transition-colors cursor-pointer ${
                    isSelected
                      ? "bg-[#161C2C] border-cyan-500/50"
                      : "bg-[#141722] border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-cyan-400 font-semibold">
                        {path.id}
                      </span>
                      {path.is_shortest_path && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          Shortest Path
                        </span>
                      )}
                    </div>
                    <span
                      className={`text-[11px] font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                        path.risk_breakdown.severity
                      )}`}
                    >
                      Score {path.risk_breakdown.final_score} ({path.risk_breakdown.severity})
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-white mt-1.5">
                    {path.title}
                  </div>
                  <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                    {path.summary}
                  </p>

                  <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px]">
                    <span className="text-slate-400 font-mono">
                      {path.hop_count} Hops •{" "}
                      {path.permissions_involved.slice(0, 2).join(", ")}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedAttackPathId(path.id);
                        setActiveTab("investigations");
                      }}
                      className="text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1 font-medium cursor-pointer"
                    >
                      <Crosshair className="w-3 h-3" />
                      Investigate
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Interactive Attack Graph Live Preview */}
        <div className="lg:col-span-7 rounded-lg bg-[#11131A] border border-slate-800 flex flex-col h-[450px]">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-white">
                Interactive Attack Topology Preview
              </h2>
              <p className="text-xs text-slate-400">
                Click any attack path on the left to highlight its blast radius, or open the full explorer
              </p>
            </div>
            <button
              onClick={() => setActiveTab("graph")}
              className="px-3 py-1.5 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-300 border border-cyan-500/30 text-xs font-medium cursor-pointer"
            >
              Open Full Graph Explorer →
            </button>
          </div>
          <div className="flex-1 min-h-0">
            <AttackGraphCanvas
              graphNodes={activeScan.nodes}
              graphEdges={activeScan.edges}
              attackPaths={activeScan.attack_paths}
              selectedPathId={selectedAttackPathId}
              onSelectPath={setSelectedAttackPathId}
              compactPreview={true}
            />
          </div>
        </div>
      </div>

      {/* Analytics Row: Risk Distribution + Asset Distribution + Recent Analysis Activity */}
      <div className="grid lg:grid-cols-12 gap-5">
        <div className="lg:col-span-4 rounded-lg bg-[#11131A] border border-slate-800 p-4">
          <h3 className="text-sm font-semibold text-white">
            Finding Severity Distribution
          </h3>
          <p className="text-xs text-slate-400 mb-4">
            Weighted risk score distribution across {activeScan.findings.length} findings
          </p>
          <div className="h-52">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskChartData}>
                <XAxis
                  dataKey="name"
                  stroke="#94a3b8"
                  fontSize={11}
                  tickLine={false}
                />
                <YAxis
                  stroke="#94a3b8"
                  fontSize={11}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0E111B",
                    borderColor: "#1e293b",
                    fontSize: "12px",
                    color: "#f8fafc",
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskChartData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="lg:col-span-4 rounded-lg bg-[#11131A] border border-slate-800 p-4">
          <h3 className="text-sm font-semibold text-white">
            Cloud Asset Inventory Breakdown
          </h3>
          <p className="text-xs text-slate-400 mb-2">
            Normalized AWS IAM, Compute, Network &amp; Storage entities
          </p>
          <div className="h-52 flex items-center">
            <ResponsiveContainer width="55%" height="100%">
              <PieChart>
                <Pie
                  data={assetChartData}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={42}
                  outerRadius={72}
                  paddingAngle={3}
                  fill="#06b6d4"
                >
                  {assetChartData.map((_, idx) => {
                    const palette = [
                      "#06b6d4",
                      "#8b5cf6",
                      "#f97316",
                      "#10b981",
                      "#ef4444",
                      "#3b82f6",
                      "#eab308",
                    ];
                    return (
                      <Cell key={idx} fill={palette[idx % palette.length]} />
                    );
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0E111B",
                    borderColor: "#1e293b",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="w-[45%] space-y-1.5 text-xs">
              {assetChartData.map((item) => (
                <div
                  key={item.name}
                  className="flex items-center justify-between text-slate-300"
                >
                  <span className="truncate text-[11px]">{item.name}</span>
                  <span className="font-mono font-semibold text-white">
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="lg:col-span-4 rounded-lg bg-[#11131A] border border-slate-800 p-4 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white">
              Posture Telemetry &amp; Audit Activity
            </h3>
            <p className="text-xs text-slate-400 mb-3">
              Real-time analysis job metadata
            </p>
            <div className="space-y-2.5 text-xs">
              <div className="p-2.5 rounded bg-[#151926] border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                  Overall Posture Index
                </span>
                <span className="font-mono font-bold text-cyan-400">
                  {m.overall_posture_score} / 100
                </span>
              </div>
              <div className="p-2.5 rounded bg-[#151926] border border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-violet-400" />
                  Snapshot Timestamp
                </span>
                <span className="font-mono text-slate-200 text-[11px]">
                  {new Date(activeScan.created_at).toLocaleString()}
                </span>
              </div>
              <div className="p-2.5 rounded bg-[#151926] border border-slate-800">
                <div className="text-slate-400 text-[11px]">
                  Top Remediation Priority
                </div>
                <div className="text-white font-medium mt-0.5 truncate">
                  {activeScan.findings[0]?.title}
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={() => setActiveTab("reports")}
            className="mt-4 w-full py-2 rounded bg-[#181D2C] hover:bg-slate-800 border border-slate-700 text-xs font-medium text-cyan-300 transition-colors cursor-pointer"
          >
            Export Executive PDF &amp; JSON Report →
          </button>
        </div>
      </div>

      {/* Bottom Table: Recent Security Findings */}
      <div className="rounded-lg bg-[#11131A] border border-slate-800 overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white">
              Priority Misconfigurations &amp; Identity Risks
            </h2>
            <p className="text-xs text-slate-400">
              Click any finding to inspect policy statements, risk score breakdown, and remediation diffs
            </p>
          </div>
          <button
            onClick={() => setActiveTab("findings")}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
          >
            View All {activeScan.findings.length} Findings →
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400 bg-[#0D0F17]">
                <th className="py-2.5 px-4">ID / Rule</th>
                <th className="py-2.5 px-4">Severity &amp; Score</th>
                <th className="py-2.5 px-4">Finding Title</th>
                <th className="py-2.5 px-4">Affected Cloud Asset</th>
                <th className="py-2.5 px-4">Epistemic Basis</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {activeScan.findings.slice(0, 6).map((f) => (
                <tr
                  key={f.id}
                  className="hover:bg-[#151926] transition-colors"
                >
                  <td className="py-3 px-4 font-mono text-cyan-400">
                    {f.id}{" "}
                    <span className="text-slate-500">({f.rule_id})</span>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-flex items-center gap-1.5 font-mono text-[11px] px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                        f.severity
                      )}`}
                    >
                      {f.severity} • {f.risk_breakdown.final_score}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-medium text-white">
                    {f.title}
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => {
                        setSelectedAssetId(f.affected_resource_id);
                        setActiveTab("assets");
                      }}
                      className="font-mono text-slate-300 hover:text-cyan-400 underline decoration-slate-700 cursor-pointer"
                    >
                      {f.affected_resource_name} ({f.affected_resource_type})
                    </button>
                  </td>
                  <td className="py-3 px-4 text-slate-400 text-[11px]">
                    {f.epistemic_class}
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => {
                        setSelectedFindingId(f.id);
                        setActiveTab("findings");
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] cursor-pointer"
                    >
                      Remediate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
