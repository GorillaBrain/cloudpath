"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import {
  User,
  KeyRound,
  Users,
  FileCode2,
  Database,
  Server,
  ShieldAlert,
  Globe,
  Lock,
  Cloud,
} from "lucide-react";
import { NodeType, SeverityLevel } from "@/types/cloudpath";

export interface CustomNodeData extends Record<string, unknown> {
  label: string;
  nodeType: NodeType;
  service: string;
  isPublic: boolean;
  isCritical: boolean;
  sensitivity: string;
  riskScore: number;
  severity: SeverityLevel;
  isHighlighted: boolean;
  isDimmed: boolean;
  isEntry: boolean;
  isTarget: boolean;
}

function getNodeIcon(type: NodeType) {
  switch (type) {
    case "IAMUser":
      return User;
    case "IAMRole":
      return KeyRound;
    case "IAMGroup":
      return Users;
    case "IAMPolicy":
      return FileCode2;
    case "S3Bucket":
      return Database;
    case "EC2Instance":
      return Server;
    case "SecurityGroup":
      return ShieldAlert;
    case "ExternalPrincipal":
      return Globe;
    case "SensitiveResource":
      return Lock;
    default:
      return Cloud;
  }
}

function getSeverityAccent(severity: SeverityLevel, isHighlighted: boolean) {
  if (isHighlighted) {
    return "border-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.35)] bg-[#141A29]";
  }
  switch (severity) {
    case "Critical":
      return "border-red-500/70 bg-[#181218]";
    case "High":
      return "border-orange-500/60 bg-[#181512]";
    case "Medium":
      return "border-amber-500/50 bg-[#14161F]";
    default:
      return "border-slate-700/80 bg-[#121520]";
  }
}

export function CustomGraphNode({ data }: { data: CustomNodeData }) {
  const Icon = getNodeIcon(data.nodeType);
  const borderClass = getSeverityAccent(data.severity, data.isHighlighted);

  return (
    <div
      className={`relative min-w-[205px] max-w-[235px] rounded-lg border px-3 py-2.5 transition-all duration-200 ${borderClass} ${
        data.isDimmed ? "opacity-25 scale-95" : "opacity-100"
      }`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!w-2.5 !h-2.5 !bg-cyan-400 !border-slate-950"
      />

      {/* Top Badges */}
      <div className="flex items-center justify-between gap-1.5 mb-1.5">
        <span className="inline-flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-slate-900/90 text-slate-300 border border-slate-700/70">
          <Icon className="w-3 h-3 text-cyan-400" />
          {data.nodeType}
        </span>

        <div className="flex items-center gap-1">
          {data.isPublic && (
            <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-red-500/20 text-red-300 border border-red-500/40">
              PUBLIC
            </span>
          )}
          {data.isEntry && (
            <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">
              ENTRY
            </span>
          )}
          {data.isTarget && (
            <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-purple-500/25 text-purple-200 border border-purple-500/40">
              TARGET
            </span>
          )}
        </div>
      </div>

      {/* Resource Label */}
      <div className="text-xs font-semibold text-white truncate" title={data.label}>
        {data.label}
      </div>

      {/* Bottom Risk & Service Row */}
      <div className="mt-2 pt-1.5 border-t border-slate-800/90 flex items-center justify-between text-[10px]">
        <span className="text-slate-400 font-mono uppercase">
          aws:{data.service}
        </span>
        <span
          className={`font-mono font-semibold px-1.5 py-0.5 rounded ${
            data.severity === "Critical"
              ? "bg-red-500/20 text-red-300"
              : data.severity === "High"
              ? "bg-orange-500/20 text-orange-300"
              : data.severity === "Medium"
              ? "bg-amber-500/20 text-amber-300"
              : "bg-slate-800 text-slate-300"
          }`}
        >
          Risk {data.riskScore}
        </span>
      </div>

      <Handle
        type="source"
        position={Position.Right}
        className="!w-2.5 !h-2.5 !bg-cyan-400 !border-slate-950"
      />
    </div>
  );
}
