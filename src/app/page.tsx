"use client";

import React from "react";
import { useCloudPath } from "@/context/CloudPathContext";
import { AppShell } from "@/components/layout/AppShell";
import { LandingView } from "@/components/views/LandingView";
import { DashboardView } from "@/components/views/DashboardView";
import { AttackGraphView } from "@/components/views/AttackGraphView";
import { FindingsView } from "@/components/views/FindingsView";
import { AssetsView } from "@/components/views/AssetsView";
import { InvestigationsView } from "@/components/views/InvestigationsView";
import { ReportsView } from "@/components/views/ReportsView";
import { ImportCenterView } from "@/components/views/ImportCenterView";
import { SettingsView } from "@/components/views/SettingsView";

export default function HomePage() {
  const { activeTab } = useCloudPath();

  return (
    <AppShell>
      {activeTab === "landing" && <LandingView />}
      {activeTab === "dashboard" && <DashboardView />}
      {activeTab === "graph" && <AttackGraphView />}
      {activeTab === "findings" && <FindingsView />}
      {activeTab === "assets" && <AssetsView />}
      {activeTab === "investigations" && <InvestigationsView />}
      {activeTab === "reports" && <ReportsView />}
      {activeTab === "import" && <ImportCenterView />}
      {activeTab === "settings" && <SettingsView />}
    </AppShell>
  );
}
