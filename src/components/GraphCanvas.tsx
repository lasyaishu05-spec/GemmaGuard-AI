"use client";

import React, { useState } from "react";
import { GraphNode, DependencyLink } from "@/types";
import { ShieldCheck, AlertTriangle, FileCode } from "lucide-react";

interface GraphCanvasProps {
  nodes: GraphNode[];
  links: DependencyLink[];
  activeStep: number;
}

export const GraphCanvas: React.FC<GraphCanvasProps> = ({ nodes, links }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>("main");

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
      case "upstream_consumer":
      case "upstream":
        return {
          stroke: "#7c3aed",
          fill: "#ede9fe",
          text: "text-purple-800",
          border: "border-purple-300",
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

  const selectedNode = nodes.find((n) => n.id === selectedNodeId) || nodes[0];

  return (
    <div className="relative w-full rounded-xl border border-slate-200 bg-white p-4 overflow-hidden card-shadow">
      {/* Canvas Header */}
      <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-100">
        <div className="flex items-center gap-2">
          <span className="flex h-2 w-2 rounded-full bg-emerald-500" />
          <span className="text-xs font-bold text-slate-800 uppercase tracking-wide">
            AST Dependency Topology
          </span>
        </div>
        <span className="text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded font-mono">
          Interactive Node Explorer
        </span>
      </div>

      {/* SVG Canvas Area */}
      <div className="relative h-56 w-full bg-slate-50/50 rounded-lg border border-slate-100">
        <svg className="w-full h-full" viewBox="0 0 500 240">
          <defs>
            <linearGradient id="linkGradGreen" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.7" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.9" />
            </linearGradient>
          </defs>

          {/* Render Edge Lines */}
          {links.map((link, idx) => {
            const s = nodes.find((n) => n.id === link.source);
            const t = nodes.find((n) => n.id === link.target);
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

                {/* Animated traveling particle */}
                <circle r={isHealed ? "3" : "2"} fill={isHealed ? "#059669" : isHigh ? "#e11d48" : "#6366f1"}>
                  <animateMotion
                    path={`M ${s.x} ${s.y} L ${t.x} ${t.y}`}
                    dur={`${2.2 + idx * 0.4}s`}
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
          {nodes.map((node) => {
            const color = getNodeColor(node.type);
            const isSelected = selectedNodeId === node.id;
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
      {selectedNode && (
        <div className="mt-3 pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className="text-slate-500 font-medium">Selected Node:</span>
            <span className="font-mono text-xs bg-slate-100 text-slate-800 px-2 py-0.5 rounded border border-slate-200">
              {selectedNode.file}
            </span>
          </div>
          <div className="flex items-center gap-2">
            {(selectedNode.type === "vulnerable_target" || selectedNode.type === "vulnerable") && (
              <span className="text-rose-700 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded text-xs font-semibold flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 text-rose-600" /> Vulnerable Target
              </span>
            )}
            {(selectedNode.type === "healed_patch" || selectedNode.type === "healed") && (
              <span className="text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded text-xs font-semibold flex items-center gap-1">
                <ShieldCheck className="w-3 h-3 text-emerald-600" /> Gemma 27B Validated
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
