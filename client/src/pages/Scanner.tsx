import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { scanAPI } from "../services/api";
import { wsService } from "../services/websocket";
import { useAuthStore } from "../store/authStore";
import ScanProgress from "../components/ScanProgress";
import AnalysisModal from "../components/AnalysisModal";

type ScanType = "url" | "pdf" | "file" | "image" | "message";

export default function Scanner() {
  const navigate = useNavigate();
  const { user } = useAuthStore();
  const [scanType, setScanType] = useState<ScanType>("url");
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanData, setScanData] = useState<any>(null);
  const [showModal, setShowModal] = useState(false);

  useEffect(() => {
    if (user?.id) {
      wsService.connect(user.id);
      wsService.subscribe("scanner", handleWSMessage);
    }

    return () => {
      wsService.unsubscribe("scanner");
    };
  }, [user]);

  const handleWSMessage = (data: any) => {
    setScanData(data);
    if (data.status === "completed") {
      setScanning(false);
    }
  };

  const handleScan = async () => {
    try {
      setScanning(true);
      setScanData(null);

      if (scanType === "url") {
        await scanAPI.scanURL(url);
      } else if (scanType === "message") {
        const response = await scanAPI.scanMessage(message);
        // For message scan, we get immediate response
        setScanData({
          scan_id: response.data.scan_id,
          status: "completed",
          progress: 100,
          result: response.data.result,
          threat_level: response.data.result?.threat_level || "clean",
        });
        setScanning(false);
      } else if (file) {
        if (scanType === "pdf") {
          await scanAPI.scanPDF(file);
        } else if (scanType === "file") {
          await scanAPI.scanFile(file);
        } else if (scanType === "image") {
          await scanAPI.scanImage(file);
        }
      }
    } catch (error) {
      console.error("Scan failed:", error);
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900">
      <nav className="bg-gray-800/50 backdrop-blur-sm border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4 py-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-white">Scanner</h1>
          <div className="flex gap-3">
            <button
              onClick={() => navigate("/downloads")}
              className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Downloads
            </button>
            <button
              onClick={() => navigate("/dashboard")}
              className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Dashboard
            </button>
          </div>
        </div>
      </nav>

      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-8 border border-gray-700">
          <h2 className="text-2xl font-bold mb-6 text-white">
            Select Scan Type
          </h2>

          <div className="grid grid-cols-5 gap-3 mb-6">
            {(["url", "message", "pdf", "file", "image"] as ScanType[]).map(
              (type) => (
                <button
                  key={type}
                  onClick={() => setScanType(type)}
                  className={`py-3 px-4 rounded-lg font-semibold capitalize transition-colors ${
                    scanType === type
                      ? "bg-blue-600 text-white"
                      : "bg-gray-700 text-gray-300 hover:bg-gray-600"
                  }`}
                >
                  {type === "message" ? "Scam Check" : type}
                </button>
              )
            )}
          </div>

          {scanType === "url" ? (
            <div className="mb-6">
              <label className="block text-gray-300 mb-2 font-semibold">
                Enter URL
              </label>
              <input
                type="url"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-gray-400"
              />
            </div>
          ) : scanType === "message" ? (
            <div className="mb-6">
              <label className="block text-gray-300 mb-2 font-semibold">
                Paste Suspicious Message
              </label>
              <textarea
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Paste the suspicious email, SMS, or message here to check if it's a scam...

Example: Congratulations! You've won $1,000,000! Click here to claim your prize immediately..."
                rows={6}
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 placeholder-gray-400 resize-none"
              />
              <p className="mt-2 text-sm text-gray-400">
                Our AI will analyze the message for scam indicators like
                urgency, financial requests, impersonation, and suspicious
                links.
              </p>
            </div>
          ) : (
            <div className="mb-6">
              <label className="block text-gray-300 mb-2 font-semibold">
                Upload File
              </label>
              <input
                type="file"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
                accept={
                  scanType === "pdf"
                    ? ".pdf"
                    : scanType === "image"
                    ? "image/*"
                    : "*"
                }
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:bg-blue-600 file:text-white hover:file:bg-blue-700"
              />
            </div>
          )}

          <button
            onClick={handleScan}
            disabled={
              scanning ||
              (scanType === "url"
                ? !url
                : scanType === "message"
                ? !message
                : !file)
            }
            className="w-full bg-blue-600 text-white py-4 rounded-lg hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed text-lg font-bold transition-colors"
          >
            {scanning
              ? "Scanning..."
              : scanType === "message"
              ? "Analyze Message"
              : "Start Scan"}
          </button>
        </div>

        {scanData && (
          <div className="mt-8 bg-gray-800/50 backdrop-blur-sm rounded-lg shadow-lg p-6 border border-gray-700">
            <ScanProgress data={scanData} />

            {scanData.status === "completed" && (
              <button
                onClick={() => setShowModal(true)}
                className="mt-4 w-full bg-green-600 text-white py-3 rounded-lg hover:bg-green-700 font-semibold transition-colors"
              >
                View Detailed Analysis
              </button>
            )}
          </div>
        )}
      </div>

      {showModal && scanData && (
        <AnalysisModal data={scanData} onClose={() => setShowModal(false)} />
      )}
    </div>
  );
}
