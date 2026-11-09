"use client";

import React from "react";
import {
  Shield,
  LayoutDashboard,
  Network,
  AlertTriangle,
  Database,
  Crosshair,
  FileText,
  UploadCloud,
  Settings,
  Github,
  Building2,
  Lock,
  Sparkles,
  CheckCircle2,
} from "lucide-react";
import { useCloudPath } from "@/context/CloudPathContext";
import { ActiveTab } from "@/types/cloudpath";

const NAV_ITEMS: {
  id: ActiveTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badgeKey?: "paths" | "findings" | "assets";
}[] = [
  { id: "dashboard", label: "Posture Overview", icon: LayoutDashboard },
  {
    id: "graph",
    label: "Attack Graph Explorer",
    icon: Network,
    badgeKey: "paths",
  },
  {
    id: "findings",
    label: "Security Findings",
    icon: AlertTriangle,
    badgeKey: "findings",
  },
  { id: "assets", label: "Cloud Asset Inventory", icon: Database, badgeKey: "assets" },
  { id: "investigations", label: "Path Investigations", icon: Crosshair },
  { id: "reports", label: "Compliance & Reports", icon: FileText },
  { id: "import", label: "Import Center", icon: UploadCloud },
  { id: "settings", label: "Workspace & Scoring", icon: Settings },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const {
    activeTab,
    setActiveTab,
    workspaces,
    currentWorkspace,
    switchWorkspace,
    scans,
    activeScan,
    setActiveScanById,
    userEmail,
  } = useCloudPath();

  if (activeTab === "landing") {
    return <>{children}</>;
  }

  return (
    <div className="min-h-screen bg-[#090A0F] text-slate-100 flex">
      {/* Left Navigation Sidebar */}
      <aside className="no-print w-64 shrink-0 bg-[#0D0F17] border-r border-slate-800/80 flex flex-col justify-between">
        <div>
          {/* Brand Header */}
          <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/80">
            <button
              onClick={() => setActiveTab("landing")}
              className="flex items-center gap-2.5 text-left group cursor-pointer"
            >
              <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-semibold tracking-tight text-white text-sm">
                    CloudPath
                  </span>
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    CSPM
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Identity & Attack Graph
                </p>
              </div>
            </button>
          </div>

          {/* Workspace Switcher */}
          <div className="p-3 border-b border-slate-800/80">
            <label className="block text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-1">
              <Building2 className="w-3 h-3 text-cyan-400" />
              Isolated Workspace
            </label>
            <select
              aria-label="Select Workspace"
              value={currentWorkspace.id}
              onChange={(e) => switchWorkspace(e.target.value)}
              className="w-full bg-[#141824] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              {workspaces.map((ws) => (
                <option key={ws.id} value={ws.id}>
                  {ws.name}
                </option>
              ))}
            </select>
            <div className="mt-1.5 flex items-center justify-between text-[11px] text-slate-400">
              <span className="flex items-center gap-1">
                <Lock className="w-3 h-3 text-emerald-400" />
                RLS Isolated
              </span>
              <span className="font-mono text-[10px] text-slate-400">
                AWS:{activeScan.account_id}
              </span>
            </div>
          </div>

          {/* Navigation Menu */}
          <nav className="p-2.5 space-y-1">
            {NAV_ITEMS.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              let badgeCount: number | null = null;
              if (item.badgeKey === "paths") {
                badgeCount = activeScan.summary_metrics.total_attack_paths;
              } else if (item.badgeKey === "findings") {
                badgeCount = activeScan.findings.length;
              } else if (item.badgeKey === "assets") {
                badgeCount = activeScan.summary_metrics.total_assets;
              }

              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-colors cursor-pointer ${
                    isActive
                      ? "bg-cyan-500/15 text-cyan-300 border border-cyan-500/30"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent"
                  }`}
                >
                  <span className="flex items-center gap-2.5">
                    <Icon
                      className={`w-4 h-4 ${
                        isActive ? "text-cyan-400" : "text-slate-400"
                      }`}
                    />
                    {item.label}
                  </span>
                  {badgeCount !== null && (
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                        isActive
                          ? "bg-cyan-500/20 text-cyan-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {badgeCount}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Bottom Status & Operator Profile */}
        <div className="p-3 border-t border-slate-800/80 space-y-2.5 bg-[#0A0C12]">
          <div className="p-2.5 rounded-md bg-[#121622] border border-slate-800 text-[11px] space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 font-medium">Engine Mode</span>
              <span className="flex items-center gap-1 text-emerald-400 font-mono text-[10px]">
                <CheckCircle2 className="w-3 h-3" /> Read-Only Static
              </span>
            </div>
            <p className="text-slate-400 text-[10px] leading-relaxed">
              Zero live credential access. Explicit Deny &amp; multi-hop BFS/Dijkstra active.
            </p>
          </div>

          <div className="flex items-center justify-between px-1 text-xs">
            <div className="truncate">
              <div className="text-slate-200 font-medium truncate text-[11px]">
                {userEmail || "Anonymous Analyst"}
              </div>
              <div className="text-slate-400 text-[10px]">
                {currentWorkspace.isDemo
                  ? "Public Demo Mode"
                  : "Authenticated Tenant"}
              </div>
            </div>
            <a
              href="https://github.com/GorillaBrain/cloudpath"
              target="_blank"
              rel="noreferrer"
              title="GitHub Repository"
              className="p-1.5 rounded-md text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <Github className="w-4 h-4" />
            </a>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top Context Bar */}
        <header className="no-print h-16 px-6 bg-[#0D0F17]/90 backdrop-blur border-b border-slate-800/80 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-sm font-semibold text-white truncate">
                  {activeScan.organization}
                </h1>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                  {activeScan.provider.toUpperCase()} • {activeScan.account_id}
                </span>
                <span className="hidden md:inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-violet-500/10 text-violet-300 border border-violet-500/25">
                  <Sparkles className="w-3 h-3" />
                  Source: {activeScan.source_type}
                </span>
              </div>
              <p className="text-xs text-slate-400 truncate">
                Active Snapshot: {activeScan.name}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {scans.length > 1 && (
              <select
                aria-label="Select Analysis Snapshot"
                value={activeScan.id}
                onChange={(e) => setActiveScanById(e.target.value)}
                className="bg-[#141824] border border-slate-700 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({new Date(s.created_at).toLocaleTimeString()})
                  </option>
                ))}
              </select>
            )}

            <button
              onClick={() => setActiveTab("import")}
              className="px-3 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors cursor-pointer"
            >
              + Import Cloud Config
            </button>
          </div>
        </header>

        {/* Page View Container */}
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
