"use client";

import React from "react";
import { useCloudPath } from "@/context/CloudPathContext";
import { AttackGraphCanvas } from "@/components/graph/AttackGraphCanvas";

export function AttackGraphView() {
  const {
    activeScan,
    selectedAttackPathId,
    setSelectedAttackPathId,
    setActiveTab,
  } = useCloudPath();

  return (
    <div className="h-[calc(100vh-4rem)] w-full flex flex-col">
      <AttackGraphCanvas
        graphNodes={activeScan.nodes}
        graphEdges={activeScan.edges}
        attackPaths={activeScan.attack_paths}
        selectedPathId={selectedAttackPathId}
        onSelectPath={setSelectedAttackPathId}
        onOpenInvestigation={(pathId) => {
          setSelectedAttackPathId(pathId);
          setActiveTab("investigations");
        }}
      />
    </div>
  );
}
