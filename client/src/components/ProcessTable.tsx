import React from "react";
import ThreatTierBadge from "./ThreatTierBadge";

interface ProcessFeatures {
  fe: number;
  fa: number;
  fn: number;
  fc: number;
}

interface ProcessData {
  pid: number;
  name: string;
  features: ProcessFeatures;
  risk_score: number;
  tier: "CLEAN" | "MONITOR" | "SUSPICIOUS" | "ALERT";
  last_updated: string;
}

interface ProcessTableProps {
  processes: ProcessData[];
  onKillProcess?: (pid: number) => void;
  loading?: boolean;
}

const ProcessTable: React.FC<ProcessTableProps> = ({
  processes,
  onKillProcess,
  loading = false,
}) => {
  const getRiskColor = (score: number) => {
    if (score < 0.4) return "text-green-400";
    if (score < 0.65) return "text-yellow-400";
    if (score < 0.85) return "text-orange-400";
    return "text-red-400";
  };

  const getFeatureBar = (value: number, max: number = 10) => {
    const percentage = Math.min((value / max) * 100, 100);
    const color =
      value < 3 ? "bg-green-500" : value < 6 ? "bg-yellow-500" : "bg-red-500";
    return (
      <div className="w-16 h-2 bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${color} transition-all duration-300`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-500"></div>
      </div>
    );
  }

  if (processes.length === 0) {
    return (
      <div className="text-center py-12 text-gray-400">
        <p>No processes being monitored</p>
        <p className="text-sm mt-2">
          Start the behavioral monitor to see process data
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-700">
            <th className="text-left py-3 px-4 text-gray-400 font-medium">
              Process
            </th>
            <th className="text-left py-3 px-2 text-gray-400 font-medium">
              PID
            </th>
            <th
              className="text-center py-3 px-2 text-gray-400 font-medium"
              title="Encryption Frequency"
            >
              <span className="cursor-help">fe</span>
            </th>
            <th
              className="text-center py-3 px-2 text-gray-400 font-medium"
              title="File Access"
            >
              <span className="cursor-help">fa</span>
            </th>
            <th
              className="text-center py-3 px-2 text-gray-400 font-medium"
              title="Network Activity"
            >
              <span className="cursor-help">fn</span>
            </th>
            <th
              className="text-center py-3 px-2 text-gray-400 font-medium"
              title="CPU Usage"
            >
              <span className="cursor-help">fc</span>
            </th>
            <th className="text-center py-3 px-2 text-gray-400 font-medium">
              Risk
            </th>
            <th className="text-center py-3 px-2 text-gray-400 font-medium">
              Tier
            </th>
            <th className="text-right py-3 px-4 text-gray-400 font-medium">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {processes.map((proc) => (
            <tr
              key={proc.pid}
              className={`border-b border-gray-800 hover:bg-gray-800/50 transition-colors
                ${proc.tier === "ALERT" ? "bg-red-900/10" : ""}
                ${proc.tier === "SUSPICIOUS" ? "bg-orange-900/10" : ""}
              `}
            >
              <td className="py-3 px-4">
                <span className="text-white font-medium">{proc.name}</span>
              </td>
              <td className="py-3 px-2 text-gray-400 font-mono text-xs">
                {proc.pid}
              </td>
              <td className="py-3 px-2">
                <div className="flex flex-col items-center gap-1">
                  {getFeatureBar(proc.features.fe)}
                  <span className="text-xs text-gray-500">
                    {proc.features.fe.toFixed(1)}
                  </span>
                </div>
              </td>
              <td className="py-3 px-2">
                <div className="flex flex-col items-center gap-1">
                  {getFeatureBar(proc.features.fa)}
                  <span className="text-xs text-gray-500">
                    {proc.features.fa.toFixed(1)}
                  </span>
                </div>
              </td>
              <td className="py-3 px-2">
                <div className="flex flex-col items-center gap-1">
                  {getFeatureBar(proc.features.fn)}
                  <span className="text-xs text-gray-500">
                    {proc.features.fn.toFixed(1)}
                  </span>
                </div>
              </td>
              <td className="py-3 px-2">
                <div className="flex flex-col items-center gap-1">
                  {getFeatureBar(proc.features.fc)}
                  <span className="text-xs text-gray-500">
                    {proc.features.fc.toFixed(1)}
                  </span>
                </div>
              </td>
              <td className="py-3 px-2 text-center">
                <span className={`font-bold ${getRiskColor(proc.risk_score)}`}>
                  {(proc.risk_score * 100).toFixed(1)}%
                </span>
              </td>
              <td className="py-3 px-2 text-center">
                <ThreatTierBadge tier={proc.tier} size="sm" />
              </td>
              <td className="py-3 px-4 text-right">
                {proc.tier !== "CLEAN" && onKillProcess && (
                  <button
                    onClick={() => onKillProcess(proc.pid)}
                    className="px-3 py-1 text-xs bg-red-600 hover:bg-red-700 text-white rounded transition-colors"
                  >
                    Kill
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Legend */}
      <div className="mt-4 p-3 bg-gray-800/50 rounded-lg">
        <p className="text-xs text-gray-400 mb-2">Feature Legend:</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs text-gray-500">
          <span>
            <strong className="text-cyan-400">fe</strong> - Encryption Frequency
            (weight: 0.4)
          </span>
          <span>
            <strong className="text-cyan-400">fa</strong> - File Access Anomaly
            (weight: 0.3)
          </span>
          <span>
            <strong className="text-cyan-400">fn</strong> - Network Anomaly
            (weight: 0.2)
          </span>
          <span>
            <strong className="text-cyan-400">fc</strong> - CPU/Resource Abuse
            (weight: 0.1)
          </span>
        </div>
      </div>
    </div>
  );
};

export default ProcessTable;
