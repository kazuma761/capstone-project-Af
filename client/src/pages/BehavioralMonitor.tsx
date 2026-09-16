import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import ProcessTable from "../components/ProcessTable";
import RiskGauge from "../components/RiskGauge";
import ThreatTierBadge from "../components/ThreatTierBadge";
import { behavioralAPI } from "../services/api";
import { WS_URL } from "../config";

interface Stats {
  is_running: boolean;
  total_processes: number;
  tier_distribution: {
    CLEAN: number;
    MONITOR: number;
    SUSPICIOUS: number;
    ALERT: number;
  };
  average_risk_score: number;
  total_alerts: number;
}

interface Process {
  pid: number;
  name: string;
  features: { fe: number; fa: number; fn: number; fc: number };
  risk_score: number;
  tier: "CLEAN" | "MONITOR" | "SUSPICIOUS" | "ALERT";
  last_updated: string;
}

interface ScanProgress {
  scanned: number;
  found: number;
}

const BehavioralMonitor: React.FC = () => {
  const [isRunning, setIsRunning] = useState(false);
  const [stats, setStats] = useState<Stats | null>(null);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [loading, setLoading] = useState(true);
  const [tierFilter, setTierFilter] = useState<string | null>(null);
  // const [scanProgress, setScanProgress] = useState<ScanProgress | null>(null);
  const [, setScanProgress] = useState<ScanProgress | null>(null);
  const [, setRecentAlerts] = useState<Process[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  // WebSocket connection for real-time updates
  useEffect(() => {
    const wsUrl = WS_URL;
    const clientId = `behavioral_${Date.now()}`;

    const connectWS = () => {
      wsRef.current = new WebSocket(`${wsUrl}/ws/${clientId}`);

      wsRef.current.onmessage = (event: MessageEvent) => {
        try {
          const message = JSON.parse(event.data);

          if (message.type === "process_scanned") {
            // Real-time process update
            setScanProgress(message.progress);
            const newProcess = message.process;

            setProcesses((prev: Process[]) => {
              const existing = prev.find(
                (p: Process) => p.pid === newProcess.pid
              );
              if (existing) {
                return prev.map((p: Process) =>
                  p.pid === newProcess.pid ? newProcess : p
                );
              }
              return [...prev, newProcess].sort(
                (a: Process, b: Process) => b.risk_score - a.risk_score
              );
            });

            // Update stats in real-time
            setStats((prevStats: Stats | null) => {
              if (!prevStats) {
                return {
                  is_running: true,
                  total_processes: 1,
                  tier_distribution: {
                    CLEAN: 0,
                    MONITOR: 0,
                    SUSPICIOUS: 0,
                    ALERT: 0,
                    [newProcess.tier]: 1,
                  },
                  average_risk_score: newProcess.risk_score,
                  total_alerts:
                    newProcess.tier === "ALERT" ||
                    newProcess.tier === "SUSPICIOUS"
                      ? 1
                      : 0,
                };
              }

              const newTierDist = { ...prevStats.tier_distribution };
              newTierDist[newProcess.tier as keyof typeof newTierDist] =
                (newTierDist[newProcess.tier as keyof typeof newTierDist] ||
                  0) + 1;

              const newTotal = prevStats.total_processes + 1;
              const newAvg =
                (prevStats.average_risk_score * prevStats.total_processes +
                  newProcess.risk_score) /
                newTotal;
              const newAlerts =
                prevStats.total_alerts +
                (newProcess.tier === "ALERT" || newProcess.tier === "SUSPICIOUS"
                  ? 1
                  : 0);

              return {
                ...prevStats,
                is_running: true,
                total_processes: newTotal,
                tier_distribution: newTierDist,
                average_risk_score: newAvg,
                total_alerts: newAlerts,
              };
            });
          } else if (message.type === "behavioral_alert") {
            // New threat detected
            setRecentAlerts((prev: Process[]) =>
              [message.process, ...prev].slice(0, 5)
            );
          } else if (message.type === "behavioral_update") {
            // Periodic stats update
            setScanProgress({
              scanned: message.process_count,
              found: message.process_count,
            });
          }
        } catch (e) {
          console.error("WS parse error:", e);
        }
      };

      wsRef.current.onclose = () => {
        setTimeout(connectWS, 3000);
      };
    };

    connectWS();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, processesRes] = await Promise.all([
        behavioralAPI.getStats(),
        behavioralAPI.getProcesses(tierFilter || undefined),
      ]);
      setStats(statsRes.data);
      setProcesses(processesRes.data.processes);
      setIsRunning(statsRes.data.is_running);
    } catch (error) {
      console.error("Failed to fetch behavioral data:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000); // Poll every 3 seconds (reduced from 2)
    return () => clearInterval(interval);
  }, [tierFilter]);

  const handleToggleMonitor = async () => {
    try {
      if (isRunning) {
        await behavioralAPI.stop();
        setIsRunning(false);
      } else {
        // Clear old data when starting fresh scan
        setProcesses([]);
        setStats({
          is_running: true,
          total_processes: 0,
          tier_distribution: { CLEAN: 0, MONITOR: 0, SUSPICIOUS: 0, ALERT: 0 },
          average_risk_score: 0,
          total_alerts: 0,
        });
        await behavioralAPI.start();
        setIsRunning(true);
      }
      fetchData();
    } catch (error) {
      console.error("Failed to toggle monitor:", error);
    }
  };

  const handleKillProcess = async (pid: number) => {
    if (
      !confirm(
        `Are you sure you want to terminate process ${pid}? This may require administrator privileges.`
      )
    )
      return;

    try {
      const response = await behavioralAPI.killProcess(pid);
      if (response.data.status === "killed") {
        alert(`Process ${pid} (${response.data.name}) terminated successfully`);
        // Remove from local state immediately
        setProcesses((prev: Process[]) =>
          prev.filter((p: Process) => p.pid !== pid)
        );
        fetchData();
      }
    } catch (error: any) {
      const message =
        error.response?.data?.detail || error.message || "Unknown error";
      alert(
        `Failed to kill process: ${message}\n\nNote: Killing system processes requires administrator privileges.`
      );
      console.error("Failed to kill process:", error);
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link to="/dashboard" className="text-gray-400 hover:text-white">
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M10 19l-7-7m0 0l7-7m-7 7h18"
                />
              </svg>
            </Link>
            <h1 className="text-xl font-bold">APSA Behavioral Monitor</h1>
            <span
              className={`px-2 py-1 rounded text-xs ${
                isRunning ? "bg-green-600" : "bg-gray-600"
              }`}
            >
              {isRunning ? "ACTIVE" : "INACTIVE"}
            </span>
          </div>

          <button
            onClick={handleToggleMonitor}
            className={`px-4 py-2 rounded-lg font-medium transition-colors ${
              isRunning
                ? "bg-red-600 hover:bg-red-700"
                : "bg-cyan-600 hover:bg-cyan-700"
            }`}
          >
            {isRunning ? "Stop Monitor" : "Start Monitor"}
          </button>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 py-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          {/* Average Risk Gauge */}
          <div className="bg-gray-800 rounded-xl p-4 flex flex-col items-center">
            <h3 className="text-sm text-gray-400 mb-2">Average Risk Score</h3>
            <RiskGauge value={stats?.average_risk_score || 0} size={140} />
          </div>

          {/* Process Count */}
          <div className="bg-gray-800 rounded-xl p-4">
            <h3 className="text-sm text-gray-400 mb-2">Monitored Processes</h3>
            <p className="text-3xl font-bold text-cyan-400">
              {stats?.total_processes || 0}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Active processes being analyzed
            </p>
          </div>

          {/* Tier Distribution */}
          <div className="bg-gray-800 rounded-xl p-4">
            <h3 className="text-sm text-gray-400 mb-2">Threat Distribution</h3>
            <div className="space-y-2">
              <div className="flex justify-between items-center">
                <ThreatTierBadge tier="ALERT" size="sm" />
                <span className="text-red-400 font-bold">
                  {stats?.tier_distribution.ALERT || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <ThreatTierBadge tier="SUSPICIOUS" size="sm" />
                <span className="text-orange-400 font-bold">
                  {stats?.tier_distribution.SUSPICIOUS || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <ThreatTierBadge tier="MONITOR" size="sm" />
                <span className="text-yellow-400 font-bold">
                  {stats?.tier_distribution.MONITOR || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <ThreatTierBadge tier="CLEAN" size="sm" />
                <span className="text-green-400 font-bold">
                  {stats?.tier_distribution.CLEAN || 0}
                </span>
              </div>
            </div>
          </div>

          {/* Total Alerts */}
          <div className="bg-gray-800 rounded-xl p-4">
            <h3 className="text-sm text-gray-400 mb-2">Total Alerts</h3>
            <p className="text-3xl font-bold text-red-400">
              {stats?.total_alerts || 0}
            </p>
            <p className="text-xs text-gray-500 mt-1">
              Threats detected this session
            </p>
          </div>
        </div>

        {/* APSA Info Card */}
        <div className="bg-gradient-to-r from-cyan-900/30 to-purple-900/30 rounded-xl p-4 mb-6 border border-cyan-500/30">
          <h3 className="text-lg font-semibold text-cyan-400 mb-2">
            Adaptive Pattern Signature Analysis (APSA)
          </h3>
          <p className="text-sm text-gray-300 mb-3">
            Real-time behavioral analysis using probabilistic risk scoring with
            learned weights. The system monitors encryption frequency, file
            access patterns, network anomalies, and CPU usage to detect
            ransomware and cryptojacking threats.
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
            <div className="bg-gray-800/50 rounded p-2">
              <span className="text-cyan-400 font-bold">P(R|X) = σ(θᵀx)</span>
              <p className="text-gray-400 mt-1">Probabilistic Risk Score</p>
            </div>
            <div className="bg-gray-800/50 rounded p-2">
              <span className="text-cyan-400 font-bold">
                Mahalanobis Distance
              </span>
              <p className="text-gray-400 mt-1">
                Coordinated Anomaly Detection
              </p>
            </div>
            <div className="bg-gray-800/50 rounded p-2">
              <span className="text-cyan-400 font-bold">EMA Baseline</span>
              <p className="text-gray-400 mt-1">Adaptive Learning</p>
            </div>
            <div className="bg-gray-800/50 rounded p-2">
              <span className="text-cyan-400 font-bold">4 Tiers</span>
              <p className="text-gray-400 mt-1">
                Clean/Monitor/Suspicious/Alert
              </p>
            </div>
          </div>
        </div>

        {/* Feature Weights Info Card */}
        <div className="bg-gray-800 rounded-xl p-4 mb-6 border border-gray-700">
          <h3 className="text-lg font-semibold text-white mb-3">
            Behavioral Feature Weights
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-gradient-to-br from-red-900/40 to-red-800/20 rounded-lg p-3 border border-red-500/30">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl font-bold text-red-400">fe</span>
                <span className="text-xs bg-red-500/30 px-2 py-0.5 rounded text-red-300">
                  w=0.4
                </span>
              </div>
              <p className="text-sm font-medium text-white">
                Encryption Frequency
              </p>
              <p className="text-xs text-gray-400 mt-1">
                Detects ransomware by monitoring file encryption patterns and
                crypto API usage
              </p>
            </div>
            <div className="bg-gradient-to-br from-orange-900/40 to-orange-800/20 rounded-lg p-3 border border-orange-500/30">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl font-bold text-orange-400">fa</span>
                <span className="text-xs bg-orange-500/30 px-2 py-0.5 rounded text-orange-300">
                  w=0.3
                </span>
              </div>
              <p className="text-sm font-medium text-white">File Access</p>
              <p className="text-xs text-gray-400 mt-1">
                Tracks unusual file system activity, rapid reads/writes, and
                batch operations
              </p>
            </div>
            <div className="bg-gradient-to-br from-yellow-900/40 to-yellow-800/20 rounded-lg p-3 border border-yellow-500/30">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl font-bold text-yellow-400">fn</span>
                <span className="text-xs bg-yellow-500/30 px-2 py-0.5 rounded text-yellow-300">
                  w=0.2
                </span>
              </div>
              <p className="text-sm font-medium text-white">Network Anomaly</p>
              <p className="text-xs text-gray-400 mt-1">
                Monitors C2 communication, unusual outbound connections, and
                data exfiltration
              </p>
            </div>
            <div className="bg-gradient-to-br from-cyan-900/40 to-cyan-800/20 rounded-lg p-3 border border-cyan-500/30">
              <div className="flex items-center gap-2 mb-2">
                <span className="text-2xl font-bold text-cyan-400">fc</span>
                <span className="text-xs bg-cyan-500/30 px-2 py-0.5 rounded text-cyan-300">
                  w=0.1
                </span>
              </div>
              <p className="text-sm font-medium text-white">CPU Abuse</p>
              <p className="text-xs text-gray-400 mt-1">
                Identifies cryptojacking by detecting sustained high CPU usage
                patterns
              </p>
            </div>
          </div>
        </div>

        {/* Filter Tabs */}
        <div className="flex gap-2 mb-4">
          <button
            onClick={() => setTierFilter(null)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tierFilter === null
                ? "bg-cyan-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            }`}
          >
            All
          </button>
          {["ALERT", "SUSPICIOUS", "MONITOR", "CLEAN"].map((tier) => (
            <button
              key={tier}
              onClick={() => setTierFilter(tier)}
              className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
                tierFilter === tier
                  ? "bg-cyan-600 text-white"
                  : "bg-gray-800 text-gray-400 hover:bg-gray-700"
              }`}
            >
              {tier}
            </button>
          ))}
        </div>

        {/* Process Table */}
        <div className="bg-gray-800 rounded-xl p-4">
          <h2 className="text-lg font-semibold mb-4">Process Analysis</h2>
          <ProcessTable
            processes={
              tierFilter
                ? processes.filter((p: Process) => p.tier === tierFilter)
                : processes
            }
            onKillProcess={handleKillProcess}
            loading={loading}
          />
        </div>
      </main>
    </div>
  );
};

export default BehavioralMonitor;
