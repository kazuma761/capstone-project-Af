import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { scanAPI } from "../services/api";
import { wsService } from "../services/websocket";

export default function Dashboard() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const [scans, setScans] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  // const [monitoringActive, setMonitoringActive] = useState(true);
  const [, setMonitoringActive] = useState(true);
  
  const [recentActivity, setRecentActivity] = useState<string[]>([]);

  useEffect(() => {
    loadHistory();
    setupRealtimeUpdates();
  }, []);

  const loadHistory = async () => {
    try {
      const response = await scanAPI.getHistory();
      setScans(response.data);
    } catch (error) {
      console.error("Failed to load history:", error);
    } finally {
      setLoading(false);
    }
  };

  const setupRealtimeUpdates = () => {
    if (user?.id) {
      wsService.connect(user.id);
      wsService.subscribe("dashboard", handleRealtimeUpdate);
    }

    return () => {
      wsService.unsubscribe("dashboard");
    };
  };

  const handleRealtimeUpdate = (data: any) => {
    console.log("Dashboard update:", data);

    if (data.type === "file_detected") {
      addActivity(`📁 New file detected: ${data.filename}`);
      setMonitoringActive(true);
    } else if (data.type === "file_deleted") {
      addActivity(`🗑️ File deleted: ${data.filename}`);
    } else if (data.type === "auto_scan_started") {
      addActivity(`🔍 Auto-scanning: ${data.filename}`);
    } else if (data.status === "completed") {
      // Refresh scan history when scan completes
      loadHistory();
      const emoji = data.threat_level === "clean" ? "✅" : "⚠️";
      addActivity(
        `${emoji} Scan completed: ${data.result?.scanner || "Scanner"}`
      );
    }
  };

  const addActivity = (message: string) => {
    setRecentActivity((prev) => [
      `${new Date().toLocaleTimeString()}: ${message}`,
      ...prev.slice(0, 9), // Keep last 10 activities
    ]);
  };

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  const getThreatColor = (level: string) => {
    switch (level) {
      case "clean":
        return "text-green-600";
      case "low":
        return "text-yellow-600";
      case "medium":
        return "text-orange-600";
      case "high":
        return "text-red-600";
      default:
        return "text-gray-600";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900">
      <nav className="bg-gray-800/50 backdrop-blur-sm border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-white">
            Cyber Detection System
          </h1>
          <div className="flex items-center gap-4">
            <span className="text-gray-300">Welcome, {user?.name}</span>
            <button
              onClick={handleLogout}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Logout
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 border border-gray-700">
            <h2 className="text-2xl font-bold mb-4 text-white">
              Start New Scan
            </h2>
            <Link
              to="/scanner"
              className="inline-block bg-blue-600 text-white px-8 py-3 rounded-lg hover:bg-blue-700 text-lg font-semibold transition-colors"
            >
              Launch Scanner
            </Link>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 border border-gray-700">
            <h2 className="text-2xl font-bold mb-4 text-white">
              Downloads Folder
            </h2>
            <p className="text-gray-300 mb-4">
              View and scan files in your Downloads folder
            </p>
            <Link
              to="/downloads"
              className="inline-block bg-green-600 text-white px-8 py-3 rounded-lg hover:bg-green-700 text-lg font-semibold transition-colors"
            >
              Open Downloads
            </Link>
          </div>

          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 border border-cyan-700 md:col-span-2">
            <h2 className="text-2xl font-bold mb-4 text-cyan-400">
              APSA Behavioral Monitor
            </h2>
            <p className="text-gray-300 mb-4">
              Real-time process monitoring using Adaptive Pattern Signature
              Analysis (APSA) for ransomware and cryptojacking detection
            </p>
            <Link
              to="/behavioral"
              className="inline-block bg-cyan-600 text-white px-8 py-3 rounded-lg hover:bg-cyan-700 text-lg font-semibold transition-colors"
            >
              Open Behavioral Monitor
            </Link>
          </div>
        </div>

        {recentActivity.length > 0 && (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 mb-8 border border-gray-700">
            <h2 className="text-2xl font-bold mb-4 text-white">
              Recent Activity
            </h2>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {recentActivity.map((activity, idx) => (
                <div
                  key={idx}
                  className="text-sm text-gray-300 py-1 border-b border-gray-700 last:border-0"
                >
                  {activity}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 border border-gray-700">
          <h2 className="text-2xl font-bold mb-4 text-white">Recent Scans</h2>

          {loading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
              <p className="text-gray-400 mt-4">Loading...</p>
            </div>
          ) : scans.length === 0 ? (
            <p className="text-gray-400">
              No scans yet. Start your first scan!
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-gray-700/50">
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Type
                    </th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Target
                    </th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Threat Level
                    </th>
                    <th className="text-left py-3 px-4 text-xs font-medium text-gray-300 uppercase tracking-wider">
                      Date
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {scans.map((scan) => (
                    <tr key={scan.id} className="hover:bg-gray-700/30">
                      <td className="py-3 px-4 capitalize text-gray-300">
                        {scan.scanType}
                      </td>
                      <td className="py-3 px-4 truncate max-w-xs text-gray-300">
                        {scan.target}
                      </td>
                      <td className="py-3 px-4 capitalize text-gray-300">
                        {scan.status}
                      </td>
                      <td
                        className={`py-3 px-4 capitalize font-semibold ${getThreatColor(
                          scan.threatLevel
                        )}`}
                      >
                        {scan.threatLevel || "N/A"}
                      </td>
                      <td className="py-3 px-4 text-gray-300">
                        {new Date(scan.createdAt).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
