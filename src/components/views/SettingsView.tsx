"use client";

import React, { useState } from "react";
import {
  Sliders,
  Lock,
  Trash2,
  Plus,
  UserCheck,
  RotateCcw,
} from "lucide-react";
import { useCloudPath } from "@/context/CloudPathContext";
import { DEFAULT_RISK_WEIGHTS } from "@/lib/engine/ts-analyzer";

export function SettingsView() {
  const {
    workspaces,
    currentWorkspace,
    switchWorkspace,
    createWorkspace,
    purgeCurrentWorkspace,
    riskWeights,
    updateRiskWeights,
    userEmail,
    signInWithEmail,
    signOut,
  } = useCloudPath();

  const [newWorkspaceName, setNewWorkspaceName] = useState("");
  const [emailInput, setEmailInput] = useState(
    userEmail || "secops-lead@northstar-fin.io"
  );
  const [passwordInput, setPasswordInput] = useState("");
  const [authStatus, setAuthStatus] = useState<string | null>(null);
  const [localWeights, setLocalWeights] = useState(riskWeights);

  const handleApplyWeights = () => {
    updateRiskWeights(localWeights);
    setAuthStatus(
      "Risk scoring formula weights updated and applied to all findings and attack paths."
    );
  };

  const handleResetWeights = () => {
    setLocalWeights(DEFAULT_RISK_WEIGHTS);
    updateRiskWeights(DEFAULT_RISK_WEIGHTS);
  };

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      <div className="bg-[#11131A] p-5 rounded-lg border border-slate-800">
        <h2 className="text-base font-semibold text-white">
          Workspace Isolation, Risk Engine Calibration &amp; Data Retention
        </h2>
        <p className="text-xs text-slate-400">
          Manage Supabase workspace authentication, customize the 5-factor risk scoring weights, and enforce data retention controls
        </p>
      </div>

      {authStatus && (
        <div className="p-3.5 rounded-lg bg-cyan-500/15 border border-cyan-500/30 text-xs text-cyan-200">
          {authStatus}
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        {/* Configurable Risk Scoring Weights */}
        <div className="p-5 rounded-lg bg-[#11131A] border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono uppercase text-cyan-400">
              <Sliders className="w-4 h-4" />
              Risk Scoring Model Weights
            </div>
            <button
              onClick={handleResetWeights}
              className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" /> Reset Defaults
            </button>
          </div>

          <p className="text-xs text-slate-400">
            Adjust factor weights (automatically normalized to 1.00) to recalibrate all finding and attack path scores in real time.
          </p>

          {(
            [
              ["exposure", "Public & Network Exposure"],
              ["privilege", "Privilege & Escalation Scope"],
              ["sensitivity", "Resource Sensitivity & Impact"],
              ["reachability", "Attack Path Hop Reachability"],
              ["trust", "Identity Trust Boundary Risk"],
            ] as const
          ).map(([key, label]) => (
            <div key={key} className="space-y-1 text-xs">
              <div className="flex justify-between text-slate-200">
                <span>{label}</span>
                <span className="font-mono text-cyan-400">
                  {localWeights[key].toFixed(2)}
                </span>
              </div>
              <input
                type="range"
                min={0.05}
                max={0.8}
                step={0.05}
                value={localWeights[key]}
                onChange={(e) =>
                  setLocalWeights((prev) => ({
                    ...prev,
                    [key]: parseFloat(e.target.value),
                  }))
                }
                className="w-full accent-cyan-400"
              />
            </div>
          ))}

          <button
            onClick={handleApplyWeights}
            className="w-full py-2 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
          >
            Recalculate Workspace Risk Scores
          </button>
        </div>

        {/* Workspace Isolation & Authentication */}
        <div className="space-y-6">
          <div className="p-5 rounded-lg bg-[#11131A] border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-xs font-mono uppercase text-emerald-400">
              <UserCheck className="w-4 h-4" />
              Operator Authentication (Supabase Auth)
            </div>

            {userEmail ? (
              <div className="p-3 rounded bg-[#161B29] border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <div className="text-slate-400 text-[11px]">
                    Signed in as:
                  </div>
                  <div className="font-mono font-semibold text-white">
                    {userEmail}
                  </div>
                </div>
                <button
                  onClick={signOut}
                  className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs cursor-pointer"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <div className="space-y-2.5 text-xs">
                <input
                  type="email"
                  placeholder="secops@enterprise.io"
                  value={emailInput}
                  onChange={(e) => setEmailInput(e.target.value)}
                  className="w-full bg-[#161B29] border border-slate-700 rounded px-3 py-2 text-white"
                />
                <input
                  type="password"
                  placeholder="Optional password (or instant demo session)"
                  value={passwordInput}
                  onChange={(e) => setPasswordInput(e.target.value)}
                  className="w-full bg-[#161B29] border border-slate-700 rounded px-3 py-2 text-white"
                />
                <button
                  onClick={async () => {
                    const res = await signInWithEmail(
                      emailInput,
                      passwordInput || undefined
                    );
                    setAuthStatus(
                      res.error || `Authenticated session as ${emailInput}`
                    );
                  }}
                  className="w-full py-2 rounded bg-cyan-500 text-slate-950 font-semibold cursor-pointer"
                >
                  Sign In to Workspace
                </button>
              </div>
            )}
          </div>

          <div className="p-5 rounded-lg bg-[#11131A] border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-xs font-mono uppercase text-violet-400">
              <Lock className="w-4 h-4" />
              Workspace Isolation &amp; Data Retention
            </div>

            <div className="space-y-2 text-xs">
              <label className="block text-slate-400">
                Active Isolated Workspace
              </label>
              <select
                aria-label="Active Isolated Workspace"
                value={currentWorkspace.id}
                onChange={(e) => switchWorkspace(e.target.value)}
                className="w-full bg-[#161B29] border border-slate-700 rounded px-3 py-2 text-white"
              >
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name} (Retention: {w.retentionDays}d)
                  </option>
                ))}
              </select>
            </div>

            <div className="flex gap-2 text-xs">
              <input
                type="text"
                placeholder="New isolated workspace name..."
                value={newWorkspaceName}
                onChange={(e) => setNewWorkspaceName(e.target.value)}
                className="flex-1 bg-[#161B29] border border-slate-700 rounded px-3 py-1.5 text-white"
              />
              <button
                onClick={() => {
                  if (newWorkspaceName.trim()) {
                    createWorkspace(newWorkspaceName);
                    setNewWorkspaceName("");
                    setAuthStatus("Created new isolated workspace.");
                  }
                }}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Create
              </button>
            </div>

            <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
              <div className="text-[11px] text-slate-400">
                Purge all uploaded snapshots in current private workspace
              </div>
              <button
                onClick={() => {
                  purgeCurrentWorkspace();
                  setAuthStatus("Purged snapshots for current workspace.");
                }}
                disabled={currentWorkspace.isDemo}
                className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 text-xs disabled:opacity-40 cursor-pointer"
              >
                <Trash2 className="w-3.5 h-3.5" /> Purge Workspace Data
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
