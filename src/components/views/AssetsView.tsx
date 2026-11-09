"use client";

import React, { useState, useMemo } from "react";
import { Search, Filter, Globe, Lock, Network } from "lucide-react";
import {
  useCloudPath,
  getSeverityBadgeClasses,
} from "@/context/CloudPathContext";

export function AssetsView() {
  const {
    activeScan,
    selectedAssetId,
    setSelectedAssetId,
    setSelectedAttackPathId,
    setActiveTab,
  } = useCloudPath();

  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("ALL");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [exposureFilter, setExposureFilter] = useState("ALL");
  const [serviceFilter, setServiceFilter] = useState("ALL");

  const assetTypes = useMemo(
    () => Array.from(new Set(activeScan.assets.map((a) => a.type))),
    [activeScan.assets]
  );
  const services = useMemo(
    () => Array.from(new Set(activeScan.assets.map((a) => a.service))),
    [activeScan.assets]
  );

  const filteredAssets = useMemo(() => {
    return activeScan.assets.filter((a) => {
      if (typeFilter !== "ALL" && a.type !== typeFilter) return false;
      if (riskFilter !== "ALL" && a.risk_level !== riskFilter) return false;
      if (exposureFilter === "PUBLIC" && !a.is_public) return false;
      if (exposureFilter === "PRIVATE" && a.is_public) return false;
      if (serviceFilter !== "ALL" && a.service !== serviceFilter) return false;
      if (search.trim()) {
        const q = search.toLowerCase();
        const permMatch = a.permissions.some((p) =>
          p.toLowerCase().includes(q)
        );
        return (
          a.name.toLowerCase().includes(q) ||
          a.id.toLowerCase().includes(q) ||
          a.type.toLowerCase().includes(q) ||
          permMatch
        );
      }
      return true;
    });
  }, [
    activeScan.assets,
    typeFilter,
    riskFilter,
    exposureFilter,
    serviceFilter,
    search,
  ]);

  const inspectedAsset =
    filteredAssets.find((a) => a.id === selectedAssetId) ||
    filteredAssets[0] ||
    null;

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      {/* Filter Bar */}
      <div className="bg-[#11131A] p-4 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white">
            Cloud Asset Discovery &amp; Inventory ({filteredAssets.length} /{" "}
            {activeScan.assets.length})
          </h2>
          <p className="text-xs text-slate-400">
            Filter by resource type, risk level, public exposure, permission, or AWS service
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search name, ARN, or permission (e.g. iam:PassRole)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="bg-[#161B29] border border-slate-700/80 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-200 w-72 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <Filter className="w-3.5 h-3.5 text-slate-400 ml-1" />
          <select
            aria-label="Filter by Resource Type"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="ALL">All Resource Types</option>
            {assetTypes.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>

          <select
            aria-label="Filter by Risk Level"
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            aria-label="Filter by Public Exposure"
            value={exposureFilter}
            onChange={(e) => setExposureFilter(e.target.value)}
            className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="ALL">All Exposure States</option>
            <option value="PUBLIC">Publicly Exposed Only</option>
            <option value="PRIVATE">Private / Internal Only</option>
          </select>

          <select
            aria-label="Filter by Cloud Service"
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="bg-[#161B29] border border-slate-700/80 rounded-md px-2.5 py-1.5 text-xs text-slate-200"
          >
            <option value="ALL">All AWS Services</option>
            {services.map((s) => (
              <option key={s} value={s}>
                aws:{s}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Asset Table + Inspector Drawer */}
      <div className="grid lg:grid-cols-12 gap-5">
        <div className="lg:col-span-7 rounded-lg bg-[#11131A] border border-slate-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 text-[11px] font-mono uppercase text-slate-400 bg-[#0D0F17]">
                  <th className="py-2.5 px-4">Resource Name</th>
                  <th className="py-2.5 px-4">Type &amp; Service</th>
                  <th className="py-2.5 px-4">Exposure</th>
                  <th className="py-2.5 px-4">Risk Score</th>
                  <th className="py-2.5 px-4">Relationships</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {filteredAssets.map((a) => {
                  const isSelected = inspectedAsset?.id === a.id;
                  return (
                    <tr
                      key={a.id}
                      onClick={() => setSelectedAssetId(a.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? "bg-[#161C2C]"
                          : "hover:bg-[#151926]"
                      }`}
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white">{a.name}</div>
                        <div className="text-[10px] font-mono text-slate-400 truncate max-w-[230px]">
                          {a.id}
                        </div>
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <span className="text-cyan-400">{a.type}</span>
                        <span className="text-slate-500 block text-[10px]">
                          aws:{a.service}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        {a.is_public ? (
                          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-300 border border-red-500/30">
                            <Globe className="w-3 h-3" /> Public
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                            <Lock className="w-3 h-3" /> Internal
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`text-[11px] font-mono px-2 py-0.5 rounded border ${getSeverityBadgeClasses(
                            a.risk_level
                          )}`}
                        >
                          {a.risk_level} ({a.risk_score})
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                        {a.relationships_summary.length} outbound
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Asset Deep Inspector */}
        <div className="lg:col-span-5">
          {inspectedAsset ? (
            <div className="rounded-lg bg-[#11131A] border border-slate-800 p-5 space-y-4">
              <div className="flex items-start justify-between border-b border-slate-800 pb-3">
                <div>
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400">
                    {inspectedAsset.type} • aws:{inspectedAsset.service}
                  </span>
                  <h3 className="text-base font-bold text-white mt-1.5">
                    {inspectedAsset.name}
                  </h3>
                  <div className="text-[11px] font-mono text-slate-400 break-all mt-0.5">
                    {inspectedAsset.id}
                  </div>
                </div>
                <span
                  className={`text-xs font-mono px-2.5 py-1 rounded border ${getSeverityBadgeClasses(
                    inspectedAsset.risk_level
                  )}`}
                >
                  Risk {inspectedAsset.risk_score}
                </span>
              </div>

              <div className="grid grid-cols-3 gap-2 text-xs">
                <div className="p-2.5 rounded bg-[#151926] border border-slate-800">
                  <span className="text-[10px] text-slate-400 block font-mono">
                    PROVIDER / REGION
                  </span>
                  <span className="font-mono text-white">
                    {inspectedAsset.provider.toUpperCase()} ({inspectedAsset.region})
                  </span>
                </div>
                <div className="p-2.5 rounded bg-[#151926] border border-slate-800">
                  <span className="text-[10px] text-slate-400 block font-mono">
                    SENSITIVITY
                  </span>
                  <span className="font-mono uppercase text-white">
                    {inspectedAsset.sensitivity}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-[#151926] border border-slate-800">
                  <span className="text-[10px] text-slate-400 block font-mono">
                    EXPOSURE
                  </span>
                  <span className="font-mono text-white">
                    {inspectedAsset.is_public ? "Publicly Exposed" : "Private"}
                  </span>
                </div>
              </div>

              {inspectedAsset.permissions.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase font-mono text-slate-400 mb-1.5">
                    Evaluated Effective Permissions ({inspectedAsset.permissions.length})
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {inspectedAsset.permissions.map((perm) => (
                      <span
                        key={perm}
                        className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/25"
                      >
                        {perm}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {inspectedAsset.relationships_summary.length > 0 && (
                <div>
                  <h4 className="text-xs font-semibold uppercase font-mono text-slate-400 mb-1.5">
                    Graph Relationships
                  </h4>
                  <ul className="space-y-1 text-xs font-mono text-slate-300 bg-[#151926] p-3 rounded border border-slate-800">
                    {inspectedAsset.relationships_summary.map((rel, i) => (
                      <li key={i}>• {rel}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <h4 className="text-xs font-semibold uppercase font-mono text-slate-400">
                    Configuration Evidence (JSON)
                  </h4>
                  <button
                    onClick={() => {
                      const pathWithAsset = activeScan.attack_paths.find((p) =>
                        p.node_chain.includes(inspectedAsset.id)
                      );
                      if (pathWithAsset) {
                        setSelectedAttackPathId(pathWithAsset.id);
                      }
                      setActiveTab("graph");
                    }}
                    className="inline-flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 cursor-pointer"
                  >
                    <Network className="w-3.5 h-3.5" />
                    Locate in Attack Graph
                  </button>
                </div>
                <pre className="p-3 rounded bg-[#090A0F] border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-64">
                  {JSON.stringify(inspectedAsset.raw_evidence, null, 2)}
                </pre>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
