import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/authStore";
import { useWebSocket } from "../hooks/useWebSocket";
import {
  FiRefreshCw,
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiFile,
} from "react-icons/fi";
import { API_URL } from "../config";

interface FileItem {
  name: string;
  path: string;
  size: number;
  modified: number;
  scanning?: boolean;
  scanResult?: "safe" | "threat" | "error";
  scanDetails?: string;
}

export default function Downloads() {
  const navigate = useNavigate();
  const { token } = useAuthStore();
  const [files, setFiles] = useState<FileItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState<Set<string>>(new Set());
  const [scanningAll, setScanningAll] = useState(false);
  // const [scanProgress, setScanProgress] = useState({ current: 0, total: 0 });
  const [, setScanProgress] = useState({ current: 0, total: 0 });

  useWebSocket((message) => {
    if (message.type === "file_detected") {
      // Add new file to list
      setFiles((prev) => {
        const exists = prev.some((f) => f.path === message.file_path);
        if (exists) return prev;
        return [
          ...prev,
          {
            name: message.filename,
            path: message.file_path,
            size: message.size,
            modified: Date.now(),
          },
        ];
      });
    } else if (message.type === "file_deleted") {
      // Remove file from list and cache
      setFiles((prev) => prev.filter((f) => f.path !== message.file_path));
      const cachedScans = JSON.parse(localStorage.getItem("fileScans") || "{}");
      delete cachedScans[message.file_path];
      localStorage.setItem("fileScans", JSON.stringify(cachedScans));
    } else if (message.type === "scan_completed") {
      // Update scan result
      const scanData = {
        scanResult: (message.threats_found > 0 ? "threat" : "safe") as
          | "safe"
          | "threat",
        scanDetails:
          message.threats_found > 0
            ? `${message.threats_found} threat(s) found`
            : "Clean",
        timestamp: Date.now(),
      };

      setFiles((prev) =>
        prev.map((f) => {
          if (f.path === message.file_path) {
            // Cache the scan result
            const cachedScans = JSON.parse(
              localStorage.getItem("fileScans") || "{}"
            );
            cachedScans[message.file_path] = scanData;
            localStorage.setItem("fileScans", JSON.stringify(cachedScans));

            return {
              ...f,
              scanning: false,
              ...scanData,
            };
          }
          return f;
        })
      );
      setScanning((prev) => {
        const next = new Set(prev);
        next.delete(message.file_path);
        return next;
      });
    }
  });

  useEffect(() => {
    loadFiles();
  }, []);

  const loadFiles = async () => {
    try {
      const response = await fetch(`${API_URL}/api/downloads/list`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json();

      // Merge with existing scan results from localStorage
      const cachedScans = JSON.parse(localStorage.getItem("fileScans") || "{}");
      const filesWithCache = (data.files || []).map((file: FileItem) => {
        const cached = cachedScans[file.path];
        if (cached && cached.timestamp > Date.now() - 24 * 60 * 60 * 1000) {
          // 24 hour cache
          return { ...file, ...cached };
        }
        return file;
      });

      setFiles(filesWithCache);
    } catch (error) {
      console.error("Failed to load files:", error);
    } finally {
      setLoading(false);
    }
  };

  const scanFile = async (file: FileItem) => {
    setScanning((prev) => new Set(prev).add(file.path));
    setFiles((prev) =>
      prev.map((f) =>
        f.path === file.path
          ? { ...f, scanning: true, scanResult: undefined }
          : f
      )
    );

    try {
      const response = await fetch(`${API_URL}/api/downloads/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ file_path: file.path }),
      });

      if (!response.ok) throw new Error("Scan failed");
    } catch (error) {
      console.error("Scan error:", error);
      setFiles((prev) =>
        prev.map((f) =>
          f.path === file.path
            ? {
                ...f,
                scanning: false,
                scanResult: "error",
                scanDetails: "Scan failed",
              }
            : f
        )
      );
      setScanning((prev) => {
        const next = new Set(prev);
        next.delete(file.path);
        return next;
      });
    }
  };

  const scanAllFiles = async () => {
    // Filter files that haven't been scanned or need rescanning
    const filesToScan = files.filter(
      (f) => !f.scanResult || f.scanResult === "error"
    );

    if (filesToScan.length === 0) {
      alert("All files are already scanned!");
      return;
    }

    setScanningAll(true);
    setScanProgress({ current: 0, total: filesToScan.length });

    // Scan ALL files in parallel - each updates immediately when done
    let completed = 0;

    await Promise.all(
      filesToScan.map(async (file) => {
        await scanFile(file);
        completed++;
        setScanProgress({ current: completed, total: filesToScan.length });
      })
    );

    setScanningAll(false);
    setScanProgress({ current: 0, total: 0 });
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString();
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900">
      <nav className="bg-gray-800/50 backdrop-blur-sm border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <FiShield className="text-blue-400 text-2xl mr-2" />
              <span className="text-white text-xl font-bold">
                Downloads Monitor
              </span>
            </div>
            <div className="flex items-center space-x-4">
              <button
                onClick={() => navigate("/dashboard")}
                className="text-gray-300 hover:text-white px-3 py-2 rounded-md"
              >
                Dashboard
              </button>
              <button
                onClick={() => navigate("/scanner")}
                className="text-gray-300 hover:text-white px-3 py-2 rounded-md"
              >
                Scanner
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-bold text-white">Downloads Folder</h1>
          <div className="flex items-center gap-3">
            
            <button
              onClick={scanAllFiles}
              disabled={loading || scanningAll || files.length === 0}
              className="flex items-center space-x-2 bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed font-semibold"
            >
              <FiShield />
              <span>Scan All</span>
            </button>
            <button
              onClick={loadFiles}
              disabled={loading}
              className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            >
              <FiRefreshCw className={loading ? "animate-spin" : ""} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {loading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
            <p className="text-gray-400 mt-4">Loading files...</p>
          </div>
        ) : files.length === 0 ? (
          <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg p-12 text-center">
            <FiFile className="text-gray-600 text-6xl mx-auto mb-4" />
            <p className="text-gray-400 text-lg">
              No files in Downloads folder
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {files.map((file) => (
              <div
                key={file.path}
                className="bg-gray-800/50 backdrop-blur-sm rounded-lg border border-gray-700 p-5 hover:bg-gray-700/50 transition-all"
              >
                <div className="flex items-center justify-between gap-4">
                  {/* File Info */}
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <FiFile className="text-blue-400 text-2xl flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <h3 className="text-white font-semibold text-lg truncate">
                        {file.name}
                      </h3>
                      <div className="flex items-center gap-4 mt-1">
                        <span className="text-gray-300 text-sm">
                          📦 {formatSize(file.size)}
                        </span>
                        <span className="text-gray-300 text-sm">
                          🕒 {formatDate(file.modified)}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Status */}
                  <div className="flex items-center gap-4">
                    <div className="min-w-[150px]">
                      {file.scanning ? (
                        <span className="flex items-center text-yellow-400 font-semibold">
                          <FiRefreshCw className="animate-spin mr-2 text-lg" />
                          Scanning...
                        </span>
                      ) : file.scanResult === "safe" ? (
                        <span className="flex items-center text-green-400 font-semibold">
                          <FiCheckCircle className="mr-2 text-lg" />
                          {file.scanDetails}
                        </span>
                      ) : file.scanResult === "threat" ? (
                        <span className="flex items-center text-red-400 font-semibold">
                          <FiAlertTriangle className="mr-2 text-lg" />
                          {file.scanDetails}
                        </span>
                      ) : file.scanResult === "error" ? (
                        <span className="flex items-center text-orange-400 font-semibold">
                          <FiAlertTriangle className="mr-2 text-lg" />
                          {file.scanDetails}
                        </span>
                      ) : (
                        <span className="text-gray-400 font-semibold">
                          Not scanned
                        </span>
                      )}
                    </div>

                    {/* Scan Button */}
                    <button
                      onClick={() => scanFile(file)}
                      disabled={file.scanning || scanning.has(file.path)}
                      className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 font-bold transition-all shadow-lg hover:shadow-xl text-base"
                    >
                      <FiShield className="text-xl" />
                      <span>{file.scanResult ? "Rescan" : "Scan"}</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
