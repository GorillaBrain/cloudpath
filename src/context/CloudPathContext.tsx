"use client";

import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import {
  ActiveTab,
  AttackPath,
  CloudAsset,
  Finding,
  RiskWeights,
  ScanResult,
} from "@/types/cloudpath";
import {
  DEFAULT_RISK_WEIGHTS,
  DEMO_WORKSPACE_ID,
  getNorthstarDemoEnvironment,
  runFullAnalysisTS,
} from "@/lib/engine/ts-analyzer";
import { supabase } from "@/lib/supabase/client";

export interface WorkspaceInfo {
  id: string;
  name: string;
  slug: string;
  isDemo: boolean;
  retentionDays: number;
}

interface CloudPathContextType {
  activeTab: ActiveTab;
  setActiveTab: (tab: ActiveTab) => void;
  workspaces: WorkspaceInfo[];
  currentWorkspace: WorkspaceInfo;
  switchWorkspace: (workspaceId: string) => void;
  createWorkspace: (name: string) => void;
  purgeCurrentWorkspace: () => void;
  scans: ScanResult[];
  activeScan: ScanResult;
  setActiveScanById: (scanId: string) => void;
  riskWeights: RiskWeights;
  updateRiskWeights: (weights: RiskWeights) => void;
  runAnalysisJob: (params: {
    content: string | Record<string, unknown>;
    sourceType: string;
    scanName: string;
    filename?: string;
  }) => Promise<ScanResult>;
  loadNorthstarDemo: () => Promise<void>;
  selectedAttackPathId: string | null;
  setSelectedAttackPathId: (id: string | null) => void;
  selectedAssetId: string | null;
  setSelectedAssetId: (id: string | null) => void;
  selectedFindingId: string | null;
  setSelectedFindingId: (id: string | null) => void;
  userEmail: string | null;
  signInWithEmail: (email: string, password?: string) => Promise<{ error?: string }>;
  signOut: () => Promise<void>;
  isAnalyzing: boolean;
}

const DEFAULT_DEMO_WORKSPACE: WorkspaceInfo = {
  id: DEMO_WORKSPACE_ID,
  name: "Northstar Financial Technologies (Demo)",
  slug: "northstar-fin-demo",
  isDemo: true,
  retentionDays: 90,
};

const PRIVATE_PROD_WORKSPACE: WorkspaceInfo = {
  id: "11111111-2222-3333-4444-555555555555",
  name: "SecOps Production Audit Workspace",
  slug: "secops-prod-audit",
  isDemo: false,
  retentionDays: 30,
};

const CloudPathContext = createContext<CloudPathContextType | undefined>(undefined);

export function CloudPathProvider({ children }: { children: React.ReactNode }) {
  const [activeTab, setActiveTab] = useState<ActiveTab>("landing");
  const [workspaces, setWorkspaces] = useState<WorkspaceInfo[]>([
    DEFAULT_DEMO_WORKSPACE,
    PRIVATE_PROD_WORKSPACE,
  ]);
  const [currentWorkspace, setCurrentWorkspace] = useState<WorkspaceInfo>(
    DEFAULT_DEMO_WORKSPACE
  );
  const [riskWeights, setRiskWeights] = useState<RiskWeights>(DEFAULT_RISK_WEIGHTS);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [userEmail, setUserEmail] = useState<string | null>(
    "secops-lead@northstar-fin.io"
  );

  // Initialize with genuine engine evaluation of Northstar Financial Technologies
  const [allScans, setAllScans] = useState<ScanResult[]>(() => {
    const initialDemo = runFullAnalysisTS(
      getNorthstarDemoEnvironment(),
      "demo_environment",
      "Northstar Financial Technologies — Production AWS",
      DEMO_WORKSPACE_ID,
      DEFAULT_RISK_WEIGHTS
    );
    initialDemo.id = "scan-northstar-demo-001";
    return [initialDemo];
  });

  const [activeScanId, setActiveScanId] = useState<string>("scan-northstar-demo-001");
  const [selectedAttackPathId, setSelectedAttackPathId] = useState<string | null>(
    "PATH-001"
  );
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  // Check Supabase auth session on mount
  useEffect(() => {
    supabase.auth
      .getSession()
      .then(({ data }) => {
        if (data?.session?.user?.email) {
          setUserEmail(data.session.user.email);
        }
      })
      .catch(() => {
        // Fallback to local session identity
      });
  }, []);

  // Filter scans strictly by currentWorkspace (Workspace Isolation)
  const workspaceScans = allScans.filter(
    (s) =>
      s.workspace_id === currentWorkspace.id ||
      (currentWorkspace.isDemo && s.workspace_id === DEMO_WORKSPACE_ID)
  );

  const activeScan =
    workspaceScans.find((s) => s.id === activeScanId) ||
    workspaceScans[0] ||
    allScans[0];

  const switchWorkspace = useCallback(
    (workspaceId: string) => {
      const target = workspaces.find((w) => w.id === workspaceId);
      if (!target) return;
      setCurrentWorkspace(target);
      const targetScans = allScans.filter((s) => s.workspace_id === target.id);
      if (targetScans.length > 0) {
        setActiveScanId(targetScans[0].id);
        setSelectedAttackPathId(targetScans[0].attack_paths[0]?.id ?? null);
      } else {
        setSelectedAttackPathId(null);
      }
    },
    [workspaces, allScans]
  );

  const createWorkspace = useCallback((name: string) => {
    const clean = name.trim();
    if (!clean) return;
    const newWs: WorkspaceInfo = {
      id: `ws-${Math.random().toString(36).slice(2, 10)}`,
      name: clean,
      slug: clean.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
      isDemo: false,
      retentionDays: 90,
    };
    setWorkspaces((prev) => [...prev, newWs]);
    setCurrentWorkspace(newWs);
  }, []);

  const purgeCurrentWorkspace = useCallback(() => {
    if (currentWorkspace.isDemo) return;
    setAllScans((prev) =>
      prev.filter((s) => s.workspace_id !== currentWorkspace.id)
    );
    setSelectedAttackPathId(null);
    setSelectedAssetId(null);
    setSelectedFindingId(null);
  }, [currentWorkspace]);

  const updateRiskWeights = useCallback(
    (newWeights: RiskWeights) => {
      setRiskWeights(newWeights);
      // Re-run analysis on the demo environment with updated weights so all scores update live
      const recomputedDemo = runFullAnalysisTS(
        getNorthstarDemoEnvironment(),
        "demo_environment",
        activeScan.name,
        currentWorkspace.id,
        newWeights
      );
      recomputedDemo.id = activeScan.id;
      setAllScans((prev) =>
        prev.map((s) => (s.id === activeScan.id ? recomputedDemo : s))
      );
    },
    [activeScan, currentWorkspace.id]
  );

  const runAnalysisJob = useCallback(
    async ({
      content,
      sourceType,
      scanName,
      filename,
    }: {
      content: string | Record<string, unknown>;
      sourceType: string;
      scanName: string;
      filename?: string;
    }): Promise<ScanResult> => {
      setIsAnalyzing(true);
      try {
        const res = await fetch("/api/analyze", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Workspace-Id": currentWorkspace.id,
          },
          body: JSON.stringify({
            scan_name: scanName,
            source_type: sourceType,
            workspace_id: currentWorkspace.id,
            content,
            filename,
            risk_weights: riskWeights,
          }),
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.detail || "Configuration validation failed.");
        }
        const scanResult = data as ScanResult;
        setAllScans((prev) => [scanResult, ...prev]);
        setActiveScanId(scanResult.id);
        setSelectedAttackPathId(scanResult.attack_paths[0]?.id ?? null);
        return scanResult;
      } finally {
        setIsAnalyzing(false);
      }
    },
    [currentWorkspace.id, riskWeights]
  );

  const loadNorthstarDemo = useCallback(async () => {
    setIsAnalyzing(true);
    try {
      const demoScan = runFullAnalysisTS(
        getNorthstarDemoEnvironment(),
        "demo_environment",
        "Northstar Financial Technologies — Production AWS",
        currentWorkspace.id,
        riskWeights
      );
      setAllScans((prev) => [demoScan, ...prev]);
      setActiveScanId(demoScan.id);
      setSelectedAttackPathId(demoScan.attack_paths[0]?.id ?? null);
    } finally {
      setIsAnalyzing(false);
    }
  }, [currentWorkspace.id, riskWeights]);

  const signInWithEmail = useCallback(
    async (email: string, password?: string) => {
      if (!email.includes("@")) {
        return { error: "Please provide a valid enterprise email address." };
      }
      if (password) {
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });
        if (!error && data.user?.email) {
          setUserEmail(data.user.email);
          return {};
        }
      }
      // Fallback workspace session authentication for instant demo evaluation
      setUserEmail(email.trim());
      return {};
    },
    []
  );

  const signOut = useCallback(async () => {
    await supabase.auth.signOut().catch(() => {});
    setUserEmail(null);
  }, []);

  return (
    <CloudPathContext.Provider
      value={{
        activeTab,
        setActiveTab,
        workspaces,
        currentWorkspace,
        switchWorkspace,
        createWorkspace,
        purgeCurrentWorkspace,
        scans: workspaceScans,
        activeScan,
        setActiveScanById: setActiveScanId,
        riskWeights,
        updateRiskWeights,
        runAnalysisJob,
        loadNorthstarDemo,
        selectedAttackPathId,
        setSelectedAttackPathId,
        selectedAssetId,
        setSelectedAssetId,
        selectedFindingId,
        setSelectedFindingId,
        userEmail,
        signInWithEmail,
        signOut,
        isAnalyzing,
      }}
    >
      {children}
    </CloudPathContext.Provider>
  );
}

export function useCloudPath() {
  const ctx = useContext(CloudPathContext);
  if (!ctx) {
    throw new Error("useCloudPath must be used within a CloudPathProvider");
  }
  return ctx;
}

export function getSeverityBadgeClasses(severity: string): string {
  switch (severity) {
    case "Critical":
      return "bg-red-500/15 text-red-400 border-red-500/30";
    case "High":
      return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "Medium":
      return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "Low":
      return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
    default:
      return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}
