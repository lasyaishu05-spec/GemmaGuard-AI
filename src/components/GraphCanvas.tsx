"use client";

import React, { useState, useMemo } from "react";
import { GraphNode, DependencyLink } from "@/types";
import { ShieldCheck, AlertTriangle, FileCode } from "lucide-react";

interface GraphCanvasProps {
  dependenciesTraversed?: string[];
  nodes?: GraphNode[];
  links?: DependencyLink[];
  isLoading?: boolean;
}

export const GraphCanvas: React.FC<GraphCanvasProps> = ({
  dependenciesTraversed,
  nodes: customNodes,
  links: customLinks,
  isLoading = false,
}) => {
  // Dynamically parse dependencies_traversed into SVG nodes and links
  const { computedNodes, computedLinks } = useMemo(() => {
    if (customNodes && customLinks && customNodes.length > 0) {
      return { computedNodes: customNodes, computedLinks: customLinks };
    }

    const rawList = dependenciesTraversed || [];
    if (rawList.length === 0) {
      return { computedNodes: [], computedLinks: [] };
    }

    const parsedEdges: { source: string; target: string; relation: string }[] = [];
    const nodeSet = new Set<string>();

    rawList.forEach((dep) => {
      // Support multiple formats: "A ──(REL)──> B", "A --(REL)--> B", "A -> B"
      let src = "";
      let tgt = "";
      let rel = "CALLS";

      if (dep.includes("──(") && dep.includes(")──>")) {
        const parts = dep.split(/──\(|\)──>/);
        if (parts.length >= 3) {
          src = parts[0].trim();
          rel = parts[1].trim();
          tgt = parts[2].trim();
        }
      } else if (dep.includes("--(") && dep.includes(")-->")) {
        const parts = dep.split(/--\(|\)-->/);
        if (parts.length >= 3) {
          src = parts[0].trim();
          rel = parts[1].trim();
          tgt = parts[2].trim();
        }
      } else if (dep.includes("->")) {
        const parts = dep.split("->");
        src = parts[0].trim();
        tgt = parts[1].trim();
        rel = "IMPORTS";
      }

      if (src && tgt) {
        parsedEdges.push({ source: src, target: tgt, relation: rel });
        nodeSet.add(src);
        nodeSet.add(tgt);
      }
    });

    const uniqueNodes = Array.from(nodeSet);
    const total = uniqueNodes.length;

    // Distribute node coordinates dynamically across canvas (width: 500, height: 240)
    const generatedNodes: GraphNode[] = uniqueNodes.map((name, idx) => {
      // Calculate layered x and y coordinates
      const column = idx % 3;
      const row = Math.floor(idx / 3);
      const x = 70 + column * 180;
      const y = 60 + row * 90;

      const isHealed = name.toLowerCase().includes("heal") || name.toLowerCase().includes("patch");
      const isTarget = name.toLowerCase().includes("eval") || name.toLowerCase().includes("sandbox") || name.toLowerCase().includes("billing") || name.toLowerCase().includes("main");
      const isEntry = idx === 0 || name.toLowerCase().includes("route") || name.toLowerCase().includes("session");

      return {
        id: name,
        label: name.split("/").pop() || name,
        file: name,
        type: isHealed
          ? "healed"
          : isTarget
          ? "vulnerable"
          : isEntry
          ? "entrypoint"
          : "upstream",
        x,
        y: Math.min(y, 200),
      };
    });

    const generatedLinks: DependencyLink[] = parsedEdges.map((edge) => ({
      source: edge.source,
      target: edge.target,
      relation: edge.relation,
      risk: edge.relation.toLowerCase().includes("heal")
        ? "safe"
        : edge.relation.toLowerCase().includes("eval") || edge.relation.toLowerCase().includes("call")
        ? "high"
        : "medium",
    }));

    return { computedNodes: generatedNodes, computedLinks: generatedLinks };
  }, [dependenciesTraversed, customNodes, customLinks]);

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const activeNode =
    computedNodes.find((n) => n.id === selectedNodeId) || computedNodes[0] || null;

  const getNodeColor = (type: GraphNode["type"]) => {
    switch (type) {
      case "vulnerable_target":
      case "vulnerable":
        return {
          stroke: "#e11d48",
          fill: "#ffe4e6",
          text: "text-rose-700",
          border: "border-rose-300",
        };
      case "healed_patch":
      case "healed":
        return {
          stroke: "#059669",
          fill: "#d1fae5",
          text: "text-emerald-800",
          border: "border-emerald-300",
        };
      case "entrypoint":
        return {
          stroke: "#4f46e5",
          fill: "#e0e7ff",
          text: "text-indigo-800",
          border: "border-indigo-300",
        };
      default:
        return {
          stroke: "#64748b",
          fill: "#f1f5f9",
          text: "text-slate-700",
          border: "border-slate-300",
        };
    }
  };

  if (isLoading) {
    return (
      <div className="relative w-full rounded-xl border border-slate-200 bg-white p-4 overflow-hidden card-shadow animate-pulse">
        <div className="h-4 w-48 bg-slate-200 rounded mb-4" />
        <div className="h-56 w-full bg-slate-100 rounded-lg flex items-center justify-center">
          <div className="text-xs text-slate-400 font-mono">
            Redrawing NetworkX AST Dependency Web...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="relative w-full rounded-xl border border-slate-200 bg-white p-4 overflow-hidden card-shadow">
      {/* Canvas Header */}
      <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-500" />
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">
            Graph-RAG AST Dependency Topology
          </span>
        </div>
        <span className="text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded font-mono">
          {computedNodes.length} Nodes • {computedLinks.length} Edges
        </span>
      </div>

      {/* SVG Canvas Area */}
      <div className="relative h-56 w-full bg-slate-50/50 rounded-lg border border-slate-100">
        <svg className="w-full h-full" viewBox="0 0 520 240">
          {/* Render Edge Lines */}
          {computedLinks.map((link, idx) => {
            const s = computedNodes.find((n) => n.id === link.source);
            const t = computedNodes.find((n) => n.id === link.target);
            if (!s || !t) return null;

            const isHealed = link.risk === "safe";
            const isHigh = link.risk === "high";

            return (
              <g key={`edge-${idx}`}>
                <line
                  x1={s.x}
                  y1={s.y}
                  x2={t.x}
                  y2={t.y}
                  stroke={isHealed ? "#10b981" : isHigh ? "#f43f5e" : "#94a3b8"}
                  strokeWidth={isHealed ? "2.5" : isHigh ? "2" : "1.5"}
                  strokeDasharray={isHealed ? "4 2" : "none"}
                />

                {/* Animated traveling photon particle on the line */}
                <circle r={isHealed ? "3" : "2"} fill={isHealed ? "#059669" : isHigh ? "#e11d48" : "#6366f1"}>
                  <animateMotion
                    path={`M ${s.x} ${s.y} L ${t.x} ${t.y}`}
                    dur={`${2.0 + idx * 0.3}s`}
                    repeatCount="indefinite"
                  />
                </circle>

                <text
                  x={(s.x + t.x) / 2}
                  y={(s.y + t.y) / 2 - 4}
                  fill="#64748b"
                  fontSize="8"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="select-none pointer-events-none font-semibold"
                >
                  {link.relation || link.label}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {computedNodes.map((node) => {
            const color = getNodeColor(node.type);
            const isSelected = (activeNode?.id ?? "") === node.id;
            return (
              <g
                key={node.id}
                transform={`translate(${node.x}, ${node.y})`}
                onClick={() => setSelectedNodeId(node.id)}
                className="cursor-pointer group"
              >
                {/* Outer halo when selected */}
                {isSelected && (
                  <circle
                    r="19"
                    fill="none"
                    stroke={color.stroke}
                    strokeWidth="2"
                    strokeDasharray="3 3"
                    className="opacity-70"
                  />
                )}

                {/* Main Node Circle */}
                <circle
                  r="13"
                  fill={color.fill}
                  stroke={color.stroke}
                  strokeWidth={isSelected ? "2.5" : "1.5"}
                  className="transition-all duration-200 group-hover:scale-110"
                />

                {/* Inner Icon Indicator */}
                {node.type === "vulnerable_target" || node.type === "vulnerable" ? (
                  <circle r="4" fill="#e11d48" />
                ) : node.type === "healed_patch" || node.type === "healed" ? (
                  <circle r="4" fill="#059669" />
                ) : (
                  <circle r="3" fill="#4f46e5" />
                )}

                {/* Node Label Text */}
                <text
                  y="24"
                  fill={isSelected ? "#0f172a" : "#475569"}
                  fontSize="9.5"
                  fontWeight={isSelected ? "bold" : "600"}
                  fontFamily="sans-serif"
                  textAnchor="middle"
                  className="select-none"
                >
                  {node.label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Node Inspector Drawer */}
      {activeNode && (
        <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-medium">Selected Node:</span>
            <span className="font-mono text-xs bg-slate-100 text-slate-800 px-2 py-0.5 rounded border border-slate-200">
              {activeNode.file}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {(activeNode.type === "vulnerable_target" || activeNode.type === "vulnerable") && (
              <span className="text-rose-700 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded text-xs font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-rose-600" /> Vulnerable Target
              </span>
            )}
            {(activeNode.type === "healed_patch" || activeNode.type === "healed") && (
              <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded text-xs font-semibold flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-600" /> gemma3:1b Validated
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
