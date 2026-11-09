"use client";

import React, { useMemo, useState, useCallback } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  MarkerType,
  useNodesState,
  useEdgesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Search,
  Filter,
  RotateCcw,
  EyeOff,
  Flame,
  Download,
  Layers,
  ArrowRight,
  ShieldAlert,
  CheckCircle2,
  Crosshair,
} from "lucide-react";
import { CustomGraphNode, CustomNodeData } from "./CustomGraphNode";
import {
  AttackPath,
  GraphEdge,
  GraphNode,
  NodeType,
  SeverityLevel,
} from "@/types/cloudpath";
import { getSeverityBadgeClasses } from "@/context/CloudPathContext";

const COLUMN_BY_TYPE: Record<NodeType, number> = {
  ExternalPrincipal: 0,
  SecurityGroup: 0,
  VPC: 0,
  IAMUser: 0,
  IAMGroup: 1,
  EC2Instance: 1,
  IAMPolicy: 2,
  TrustRelationship: 2,
  IAMRole: 3,
  S3Bucket: 4,
  SensitiveResource: 4,
};

interface AttackGraphCanvasProps {
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  attackPaths: AttackPath[];
  selectedPathId: string | null;
  onSelectPath: (pathId: string | null) => void;
  onOpenInvestigation?: (pathId: string) => void;
  compactPreview?: boolean;
}

export function AttackGraphCanvas({
  graphNodes,
  graphEdges,
  attackPaths,
  selectedPathId,
  onSelectPath,
  onOpenInvestigation,
  compactPreview = false,
}: AttackGraphCanvasProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [hideUnrelated, setHideUnrelated] = useState(false);
  const [highlightCriticalOnly, setHighlightCriticalOnly] = useState(false);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const nodeTypes = useMemo(() => ({ cloudNode: CustomGraphNode }), []);

  const activePath = useMemo(
    () => attackPaths.find((p) => p.id === selectedPathId) ?? null,
    [attackPaths, selectedPathId]
  );

  const criticalNodeIds = useMemo(() => {
    const s = new Set<string>();
    for (const p of attackPaths) {
      if (p.risk_breakdown.severity === "Critical") {
        p.node_chain.forEach((id) => s.add(id));
      }
    }
    return s;
  }, [attackPaths]);

  const { computedNodes, computedEdges } = useMemo(() => {
    const highlightedNodes = new Set<string>(
      activePath
        ? activePath.node_chain
        : highlightCriticalOnly
        ? Array.from(criticalNodeIds)
        : []
    );
    const highlightedEdges = new Set<string>(
      activePath ? activePath.edge_chain : []
    );

    const filteredGraphNodes = graphNodes.filter((n) => {
      if (hideUnrelated && activePath && !highlightedNodes.has(n.id)) {
        return false;
      }
      if (severityFilter !== "ALL" && n.severity !== severityFilter) {
        if (!highlightedNodes.has(n.id)) return false;
      }
      if (
        searchQuery.trim() &&
        !n.label.toLowerCase().includes(searchQuery.toLowerCase()) &&
        !n.type.toLowerCase().includes(searchQuery.toLowerCase())
      ) {
        if (!highlightedNodes.has(n.id)) return false;
      }
      return true;
    });

    const visibleNodeIds = new Set(filteredGraphNodes.map((n) => n.id));

    // Deterministic layered layout by column
    const colCounts: Record<number, number> = {};
    const rfNodes: Node<CustomNodeData>[] = filteredGraphNodes.map((n) => {
      const col = COLUMN_BY_TYPE[n.type] ?? 2;
      const rowIdx = colCounts[col] ?? 0;
      colCounts[col] = rowIdx + 1;

      const isHighlighted = highlightedNodes.has(n.id);
      const isDimmed =
        (activePath !== null || highlightCriticalOnly) && !isHighlighted;

      return {
        id: n.id,
        type: "cloudNode",
        position: {
          x: col * 285 + 30,
          y: rowIdx * 128 + (col % 2 === 1 ? 45 : 15),
        },
        data: {
          label: n.label,
          nodeType: n.type,
          service: n.service,
          isPublic: n.is_public,
          isCritical: n.is_critical,
          sensitivity: n.sensitivity,
          riskScore: n.risk_score,
          severity: n.severity,
          isHighlighted,
          isDimmed,
          isEntry: activePath ? activePath.entry_point_id === n.id : false,
          isTarget: activePath ? activePath.target_id === n.id : false,
        },
      };
    });

    const rfEdges: Edge[] = graphEdges
      .filter(
        (e) => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target)
      )
      .map((e) => {
        const isEdgeActive =
          highlightedEdges.has(e.id) ||
          (highlightCriticalOnly &&
            criticalNodeIds.has(e.source) &&
            criticalNodeIds.has(e.target));

        const strokeColor = isEdgeActive
          ? e.is_escalation
            ? "#ef4444"
            : "#06b6d4"
          : e.is_escalation
          ? "#f97316"
          : "#334155";

        return {
          id: e.id,
          source: e.source,
          target: e.target,
          label: compactPreview ? undefined : e.label,
          animated: isEdgeActive || e.is_escalation,
          style: {
            stroke: strokeColor,
            strokeWidth: isEdgeActive ? 2.6 : 1.4,
            opacity:
              (activePath || highlightCriticalOnly) && !isEdgeActive
                ? 0.22
                : 0.92,
          },
          labelStyle: {
            fill: isEdgeActive ? "#e2e8f0" : "#94a3b8",
            fontSize: 10,
            fontFamily: "monospace",
          },
          labelBgStyle: {
            fill: "#0d0f17",
            fillOpacity: 0.85,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color: strokeColor,
          },
        };
      });

    return { computedNodes: rfNodes, computedEdges: rfEdges };
  }, [
    graphNodes,
    graphEdges,
    activePath,
    highlightCriticalOnly,
    criticalNodeIds,
    hideUnrelated,
    severityFilter,
    searchQuery,
    compactPreview,
  ]);

  const [nodes, setNodes, onNodesChange] = useNodesState(computedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(computedEdges);

  React.useEffect(() => {
    setNodes(computedNodes);
    setEdges(computedEdges);
  }, [computedNodes, computedEdges, setNodes, setEdges]);

  const selectedNodeObj = useMemo(
    () => graphNodes.find((n) => n.id === selectedNodeId) ?? null,
    [graphNodes, selectedNodeId]
  );

  const handleExportSvg = useCallback(() => {
    const svgLines: string[] = [
      `<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="900" viewBox="0 0 1600 900">`,
      `<rect width="100%" height="100%" fill="#090A0F"/>`,
      `<text x="30" y="40" fill="#06B6D4" font-family="monospace" font-size="18" font-weight="bold">CloudPath — Attack Path Topology Export</text>`,
    ];
    const posMap = new Map<string, { x: number; y: number }>();
    for (const n of computedNodes) {
      posMap.set(n.id, n.position);
    }
    for (const e of computedEdges) {
      const s = posMap.get(e.source);
      const t = posMap.get(e.target);
      if (s && t) {
        svgLines.push(
          `<line x1="${s.x + 190}" y1="${s.y + 40}" x2="${t.x}" y2="${t.y + 40}" stroke="#06B6D4" stroke-width="2" />`
        );
      }
    }
    for (const n of computedNodes) {
      const { x, y } = n.position;
      svgLines.push(
        `<rect x="${x}" y="${y}" width="190" height="75" rx="8" fill="#121520" stroke="#334155" stroke-width="2"/>`,
        `<text x="${x + 12}" y="${y + 25}" fill="#94A3B8" font-family="monospace" font-size="10">${n.data.nodeType}</text>`,
        `<text x="${x + 12}" y="${y + 46}" fill="#F8FAFC" font-family="sans-serif" font-size="12" font-weight="bold">${n.data.label}</text>`,
        `<text x="${x + 12}" y="${y + 64}" fill="#06B6D4" font-family="monospace" font-size="10">Risk: ${n.data.riskScore}</text>`
      );
    }
    svgLines.push(`</svg>`);
    const blob = new Blob([svgLines.join("\n")], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `cloudpath-attack-graph-${Date.now()}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  }, [computedNodes, computedEdges]);

  return (
    <div className="flex flex-col h-full w-full">
      {/* Top Interactive Graph Controls Toolbar */}
      {!compactPreview && (
        <div className="p-3 bg-[#10131D] border-b border-slate-800 flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            {/* Search input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search principal, role, S3..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="bg-[#161B29] border border-slate-700/80 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500 w-52"
              />
            </div>

            {/* Attack Path Selector */}
            <div className="flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              <select
                aria-label="Isolate Attack Path"
                value={selectedPathId || "ALL"}
                onChange={(e) =>
                  onSelectPath(e.target.value === "ALL" ? null : e.target.value)
                }
                className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 max-w-xs"
              >
                <option value="ALL">
                  Show All Discovered Paths ({attackPaths.length})
                </option>
                {attackPaths.map((p) => (
                  <option key={p.id} value={p.id}>
                    [{p.id}] {p.entry_point_name} → {p.target_name} ({p.hop_count} hops • Score {p.risk_breakdown.final_score})
                  </option>
                ))}
              </select>
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400" />
              <select
                aria-label="Filter by Severity"
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
              >
                <option value="ALL">All Severities</option>
                <option value="Critical">Critical Only</option>
                <option value="High">High &amp; Critical</option>
                <option value="Medium">Medium</option>
              </select>
            </div>
          </div>

          {/* Action Toggles */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setHideUnrelated((v) => !v)}
              disabled={!activePath}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs border transition-colors cursor-pointer ${
                hideUnrelated && activePath
                  ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/40"
                  : "bg-[#161B29] text-slate-300 border-slate-700/80 hover:bg-slate-800 disabled:opacity-40"
              }`}
            >
              <EyeOff className="w-3.5 h-3.5" />
              Isolate Selected Path
            </button>

            <button
              onClick={() => {
                onSelectPath(null);
                setHighlightCriticalOnly((v) => !v);
              }}
              className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs border transition-colors cursor-pointer ${
                highlightCriticalOnly
                  ? "bg-red-500/20 text-red-300 border-red-500/40"
                  : "bg-[#161B29] text-slate-300 border-slate-700/80 hover:bg-slate-800"
              }`}
            >
              <Flame className="w-3.5 h-3.5 text-red-400" />
              Highlight Critical Paths
            </button>

            <button
              onClick={() => {
                setSearchQuery("");
                setSeverityFilter("ALL");
                setHideUnrelated(false);
                setHighlightCriticalOnly(false);
                setSelectedNodeId(null);
                onSelectPath(null);
              }}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs bg-[#161B29] text-slate-300 border border-slate-700/80 hover:bg-slate-800 cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Reset Graph
            </button>

            <button
              onClick={handleExportSvg}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/25 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              Export SVG
            </button>
          </div>
        </div>
      )}

      {/* Main Graph Canvas + Side Inspection Drawer */}
      <div className="flex-1 flex min-h-0 relative">
        <div className="flex-1 h-full bg-[#090A0F]">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => setSelectedNodeId(node.id)}
            fitView
            fitViewOptions={{ padding: 0.18 }}
            minZoom={0.25}
            maxZoom={1.75}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#1e293b" gap={22} size={1} />
            <Controls className="!bg-[#141824] !border-slate-700 !text-slate-200 [&>button]:!bg-[#141824] [&>button]:!border-slate-700 [&>button]:!fill-slate-200" />
            {!compactPreview && (
              <MiniMap
                nodeColor={(n) =>
                  n.data?.severity === "Critical"
                    ? "#ef4444"
                    : n.data?.severity === "High"
                    ? "#f97316"
                    : "#06b6d4"
                }
                maskColor="rgba(9, 10, 15, 0.75)"
                className="!bg-[#10131D] !border !border-slate-800 !rounded-md"
              />
            )}
          </ReactFlow>
        </div>

        {/* Detailed Side Panel for Selected Attack Path or Selected Node */}
        {!compactPreview && (activePath || selectedNodeObj) && (
          <div className="w-96 shrink-0 bg-[#0E111B] border-l border-slate-800 overflow-y-auto p-4 space-y-4">
            {activePath ? (
              <>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-cyan-400">
                        {activePath.id}
                      </span>
                      {activePath.is_shortest_path && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                          Shortest Path (Dijkstra)
                        </span>
                      )}
                    </div>
                    <h3 className="text-sm font-semibold text-white mt-1">
                      {activePath.title}
                    </h3>
                  </div>
                  <span
                    className={`text-xs font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                      activePath.risk_breakdown.severity
                    )}`}
                  >
                    {activePath.risk_breakdown.final_score} / 100
                  </span>
                </div>

                {/* Epistemic Classification Notice */}
                <div className="p-2.5 rounded-md bg-cyan-500/10 border border-cyan-500/25 text-[11px] text-cyan-200">
                  <div className="font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                    {activePath.epistemic_class}
                  </div>
                  <p className="text-slate-300 text-[10px] mt-0.5">
                    Derived from static IAM &amp; resource policy evaluation. Not a confirmed live exploitation event.
                  </p>
                </div>

                {/* Entry -> Target Metadata */}
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded bg-[#141824] border border-slate-800">
                    <div className="text-[10px] text-slate-400 uppercase font-mono">
                      Starting Identity
                    </div>
                    <div className="font-semibold text-slate-100 truncate mt-0.5">
                      {activePath.entry_point_name}
                    </div>
                    <div className="text-[10px] text-cyan-400 font-mono">
                      {activePath.entry_point_type}
                    </div>
                  </div>
                  <div className="p-2.5 rounded bg-[#141824] border border-slate-800">
                    <div className="text-[10px] text-slate-400 uppercase font-mono">
                      Destination Target
                    </div>
                    <div className="font-semibold text-slate-100 truncate mt-0.5">
                      {activePath.target_name}
                    </div>
                    <div className="text-[10px] text-purple-400 font-mono">
                      {activePath.target_type} ({activePath.hop_count} hops)
                    </div>
                  </div>
                </div>

                {/* Hop-by-hop chain */}
                <div>
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono mb-2">
                    Traversal Chain ({activePath.hop_count} Hops)
                  </h4>
                  <div className="space-y-2">
                    {activePath.hops.map((hop) => (
                      <div
                        key={hop.step}
                        className="p-2.5 rounded-md bg-[#141824] border border-slate-800/90 text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="font-mono text-cyan-400">
                            Hop #{hop.step} • {hop.edge_type}
                          </span>
                          <span className="text-slate-400 font-mono text-[10px]">
                            {hop.edge_label}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5 font-medium text-slate-200 text-[11px]">
                          <span className="truncate">{hop.source_name}</span>
                          <ArrowRight className="w-3 h-3 text-cyan-400 shrink-0" />
                          <span className="truncate">{hop.target_name}</span>
                        </div>
                        {hop.permissions_used.length > 0 && (
                          <div className="flex flex-wrap gap-1 pt-1">
                            {hop.permissions_used.map((perm) => (
                              <span
                                key={perm}
                                className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/25"
                              >
                                {perm}
                              </span>
                            ))}
                          </div>
                        )}
                        <p className="text-[11px] text-slate-400 pt-0.5">
                          {hop.evidence}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Risk Assessment Formula */}
                <div className="p-3 rounded-md bg-[#141824] border border-slate-800 space-y-2">
                  <div className="text-xs font-semibold text-white">
                    Explainable Risk Breakdown
                  </div>
                  <p className="text-[10px] font-mono text-cyan-300 leading-relaxed">
                    {activePath.risk_breakdown.formula_summary}
                  </p>
                  <div className="space-y-1.5 pt-1">
                    {activePath.risk_breakdown.factors.map((f) => (
                      <div key={f.factor} className="text-[11px]">
                        <div className="flex justify-between text-slate-300">
                          <span>{f.factor}</span>
                          <span className="font-mono">
                            {f.raw_score} × {f.weight} ={" "}
                            <strong className="text-white">
                              +{f.weighted_contribution}
                            </strong>
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Remediation preview */}
                <div className="p-3 rounded-md bg-emerald-500/10 border border-emerald-500/25 space-y-1.5">
                  <div className="text-xs font-semibold text-emerald-300 flex items-center gap-1.5">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Recommended Remediation
                  </div>
                  <div className="text-xs text-white font-medium">
                    {activePath.remediation.title}
                  </div>
                  <p className="text-[11px] text-slate-300">
                    {activePath.remediation.summary}
                  </p>
                  {onOpenInvestigation && (
                    <button
                      onClick={() => onOpenInvestigation(activePath.id)}
                      className="mt-2 w-full py-1.5 px-3 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      <Crosshair className="w-3.5 h-3.5" />
                      Open Full Path Investigation &amp; Diff
                    </button>
                  )}
                </div>
              </>
            ) : (
              selectedNodeObj && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                      {selectedNodeObj.type}
                    </span>
                    <button
                      onClick={() => setSelectedNodeId(null)}
                      className="text-xs text-slate-400 hover:text-white"
                    >
                      Close
                    </button>
                  </div>
                  <h3 className="text-sm font-semibold text-white break-all">
                    {selectedNodeObj.label}
                  </h3>
                  <div className="text-[11px] font-mono text-slate-400 break-all">
                    ARN/ID: {selectedNodeObj.id}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className="p-2 rounded bg-[#141824] border border-slate-800">
                      <span className="text-slate-400 text-[10px] block">
                        Risk Score
                      </span>
                      <span className="font-mono font-bold text-white">
                        {selectedNodeObj.risk_score} ({selectedNodeObj.severity})
                      </span>
                    </div>
                    <div className="p-2 rounded bg-[#141824] border border-slate-800">
                      <span className="text-slate-400 text-[10px] block">
                        Exposure
                      </span>
                      <span className="font-mono text-white">
                        {selectedNodeObj.is_public ? "Public" : "Internal"}
                      </span>
                    </div>
                  </div>
                  {selectedNodeObj.metadata.permissions &&
                    selectedNodeObj.metadata.permissions.length > 0 && (
                      <div>
                        <div className="text-xs font-semibold text-slate-300 mb-1.5">
                          Effective Allowed Actions
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {selectedNodeObj.metadata.permissions.map((p) => (
                            <span
                              key={p}
                              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                </div>
              )
            )}
          </div>
        )}
      </div>
    </div>
  );
}
