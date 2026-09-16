import {
  FiShield,
  FiAlertTriangle,
  FiCheckCircle,
  FiXCircle,
  FiInfo,
  FiImage,
  FiFile,
  FiGlobe,
  FiLock,
  FiUnlock,
  FiClock,
  FiTrendingUp,
  FiMessageSquare,
} from "react-icons/fi";
import RiskCalculator from "./RiskCalculator";
import ReportMaliciousNote from "./ReportMaliciousNote";
import JsonViewer from "./JsonViewer";

// Hardcoded vendor list for URL scanning
const SECURITY_VENDORS = [
  "alphaMountain.ai",
  "CRDF",
  "CyRadar",
  "Google Safebrowsing",
  "Kaspersky",
  "Lionic",
  "Sophos",
  "Trustwave",
  "VIPRE",
  "Abusix",
  "Acronis",
  "ADMINUSLabs",
  "AILabs (MONITORAPP)",
  "AlienVault",
  "Antiy-AVL",
  "Artists Against 419",
  "benkow.cc",
  "BitDefender",
  "BlockList",
  "Blueliv",
  "Certego",
  "Chong Lua Dao",
  "CINS Army",
  "CMC Threat Intelligence",
  "Criminal IP",
  "Cyble",
];

// Map raw threat types to user-friendly labels
const mapThreatType = (threatType?: string): string => {
  if (!threatType) return "Malicious";
  const t = threatType.toUpperCase();
  if (t.includes("SOCIAL_ENGINEERING") || t.includes("PHISHING"))
    return "Phishing";
  if (t.includes("MALWARE")) return "Malware";
  if (t.includes("UNWANTED")) return "Malicious";
  return "Malicious";
};

// Generate vendor results based on threat level
const generateVendorResults = (isSafe: boolean, threatType?: string) => {
  if (isSafe) {
    // All vendors show clean
    return SECURITY_VENDORS.map((vendor) => ({
      vendor,
      verdict: "Clean",
    }));
  } else {
    // All vendors detect the threat with a clean label
    const verdict = mapThreatType(threatType);
    return SECURITY_VENDORS.map((vendor) => ({
      vendor,
      verdict,
    }));
  }
};

export default function AnalysisModal({
  data,
  onClose,
}: {
  data: any;
  onClose: () => void;
}) {
  // Handle both string and object result formats
  let result = data.result || {};
  if (typeof result === "string") {
    try {
      result = JSON.parse(result);
    } catch (e) {
      console.error("Failed to parse result:", e);
    }
  }

  // Determine if this is a URL scan and generate vendors client-side if needed
  const isURLScan =
    result.is_safe !== undefined || result.scanner === "Google Safe Browsing";

  // Check if safe: is_safe must be explicitly true AND threat_level must be clean
  // If is_safe is false OR threat_level is not clean, it's a threat
  const isSafe = result.is_safe === true && data.threat_level === "clean";

  // Get threat type from result
  const threatType =
    result.threats?.[0] || (result.is_safe === false ? "Malicious" : null);

  const generatedVendors =
    isURLScan && !result.vendors
      ? generateVendorResults(isSafe, threatType)
      : result.vendors;

  const getThreatColor = (level: string) => {
    switch (level) {
      case "clean":
        return "bg-green-100 text-green-800 border-green-300";
      case "low":
        return "bg-yellow-100 text-yellow-800 border-yellow-300";
      case "medium":
        return "bg-orange-100 text-orange-800 border-orange-300";
      case "high":
      case "critical":
        return "bg-red-100 text-red-800 border-red-300";
      default:
        return "bg-gray-100 text-gray-800 border-gray-300";
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case "clean":
        return <FiCheckCircle className="text-3xl text-green-600" />;
      case "low":
        return <FiInfo className="text-3xl text-yellow-600" />;
      case "medium":
        return <FiAlertTriangle className="text-3xl text-orange-600" />;
      case "high":
      case "critical":
        return <FiXCircle className="text-3xl text-red-600" />;
      default:
        return <FiShield className="text-3xl text-gray-600" />;
    }
  };

  const getVerdictColor = (verdict: string) => {
    const v = verdict?.toLowerCase() || "";
    if (v === "clean") return "bg-green-50 text-green-800 border-green-300";
    if (v === "malicious" || v === "malware")
      return "bg-red-50 text-red-800 border-red-300";
    if (v === "phishing") return "bg-red-50 text-red-800 border-red-300";
    if (v === "suspicious")
      return "bg-orange-50 text-orange-800 border-orange-300";
    return "bg-gray-50 text-gray-800 border-gray-300";
  };

  const getVerdictIcon = (verdict: string) => {
    const v = verdict?.toLowerCase() || "";
    if (v === "clean") return "✓";
    if (v === "malicious" || v === "malware" || v === "phishing") return "⚠";
    if (v === "suspicious") return "!";
    return "?";
  };

  const renderURLScanResults = () => {
    const vendors = generatedVendors || [];
    const threatsCount = vendors.filter(
      (v: any) => v.verdict !== "Clean"
    ).length;

    // Get domain and SSL info from result
    const domainInfo = result.domain_info || {};
    const sslInfo = result.ssl_info || {};
    const riskFeatures = result.risk_features || {};
    const riskScore = result.risk_score || 0;

    return (
      <div className="space-y-4">
        <div className="flex items-center gap-3 p-4 bg-blue-50 rounded-lg border border-blue-200">
          <FiGlobe className="text-2xl text-blue-600" />
          <div>
            <p className="text-sm text-gray-600">Scanned URL</p>
            <p className="font-semibold text-gray-800 break-all">
              {result.url || data.target || "N/A"}
            </p>
          </div>
        </div>

        {/* Domain Information */}
        {domainInfo.domain && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-cyan-600 to-blue-600 text-white p-4">
              <h4 className="font-bold text-lg flex items-center gap-2">
                <FiGlobe /> Domain Information
              </h4>
            </div>
            <div className="p-4 grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 text-sm mb-1">
                  <FiClock /> Domain Age
                </div>
                <p className="font-bold text-gray-800">
                  {domainInfo.age_days
                    ? `${domainInfo.age_days} days`
                    : "Unknown"}
                </p>
                <p
                  className={`text-xs mt-1 ${
                    domainInfo.age_risk === "high"
                      ? "text-red-600"
                      : domainInfo.age_risk === "medium"
                      ? "text-orange-600"
                      : domainInfo.age_risk === "low"
                      ? "text-yellow-600"
                      : domainInfo.age_risk === "none"
                      ? "text-green-600"
                      : "text-gray-500"
                  }`}
                >
                  {domainInfo.age_status === "very_new"
                    ? "⚠️ Very New Domain"
                    : domainInfo.age_status === "new"
                    ? "⚠️ New Domain"
                    : domainInfo.age_status === "moderate"
                    ? "Moderate Age"
                    : domainInfo.age_status === "established"
                    ? "✓ Established"
                    : "Unknown"}
                </p>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 text-sm mb-1">
                  <FiTrendingUp /> Traffic Rank
                </div>
                <p className="font-bold text-gray-800">
                  #{domainInfo.traffic_rank?.toLocaleString() || "N/A"}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {domainInfo.monthly_visits} monthly visits
                </p>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg">
                <div className="flex items-center gap-2 text-gray-600 text-sm mb-1">
                  <FiInfo /> Registration
                </div>
                <p className="font-bold text-gray-800 text-sm">
                  {domainInfo.creation_date || "Unknown"}
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  {domainInfo.registrar || "Unknown registrar"}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* SSL Certificate Information */}
        {sslInfo && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div
              className={`p-4 flex items-center justify-between ${
                sslInfo.ssl_status === "valid"
                  ? "bg-gradient-to-r from-green-600 to-emerald-600"
                  : sslInfo.ssl_status === "none"
                  ? "bg-gradient-to-r from-red-600 to-rose-600"
                  : "bg-gradient-to-r from-orange-600 to-amber-600"
              } text-white`}
            >
              <h4 className="font-bold text-lg flex items-center gap-2">
                {sslInfo.has_ssl ? <FiLock /> : <FiUnlock />}
                SSL Certificate
              </h4>
              <span
                className={`px-3 py-1 rounded-full text-sm font-semibold ${
                  sslInfo.ssl_status === "valid"
                    ? "bg-green-500"
                    : sslInfo.ssl_status === "none"
                    ? "bg-red-500"
                    : "bg-orange-500"
                }`}
              >
                {sslInfo.ssl_status?.toUpperCase() || "UNKNOWN"}
              </span>
            </div>
            <div className="p-4">
              {sslInfo.has_ssl ? (
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <p className="text-sm text-gray-600">Issuer</p>
                    <p className="font-semibold text-gray-800">
                      {sslInfo.issuer || "Unknown"}
                    </p>
                    {sslInfo.is_trusted_issuer && (
                      <span className="inline-flex items-center gap-1 text-xs text-green-600 mt-1">
                        <FiCheckCircle /> Trusted Issuer
                      </span>
                    )}
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <p className="text-sm text-gray-600">Valid Until</p>
                    <p className="font-semibold text-gray-800">
                      {sslInfo.valid_until || "Unknown"}
                    </p>
                    {sslInfo.days_until_expiry !== undefined && (
                      <span
                        className={`text-xs ${
                          sslInfo.days_until_expiry < 30
                            ? "text-red-600"
                            : sslInfo.days_until_expiry < 90
                            ? "text-orange-600"
                            : "text-green-600"
                        }`}
                      >
                        {sslInfo.days_until_expiry} days remaining
                      </span>
                    )}
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <p className="text-sm text-gray-600">Protocol</p>
                    <p className="font-semibold text-gray-800">
                      {sslInfo.protocol || "TLS"}
                    </p>
                  </div>
                  <div className="bg-gray-50 p-3 rounded-lg">
                    <p className="text-sm text-gray-600">Subject</p>
                    <p className="font-semibold text-gray-800 truncate">
                      {sslInfo.subject || "Unknown"}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="bg-red-50 p-4 rounded-lg border border-red-200">
                  <p className="text-red-700 font-semibold flex items-center gap-2">
                    <FiAlertTriangle />{" "}
                    {sslInfo.message || "No SSL/TLS encryption detected"}
                  </p>
                  <p className="text-sm text-red-600 mt-2">
                    This website does not use HTTPS. Your connection is not
                    secure.
                  </p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Risk Calculator */}
        {Object.keys(riskFeatures).length > 0 && (
          <RiskCalculator riskScore={riskScore} features={riskFeatures} />
        )}

        {/* Security Vendors Analysis Table */}
        {vendors.length > 0 && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white p-4">
              <h4 className="font-bold text-lg flex items-center gap-2">
                <FiShield /> Security Vendors' Analysis
              </h4>
              <p className="text-blue-100 text-sm mt-1">
                {vendors.length} vendors scanned • {threatsCount} detected
                threats ({Math.round((threatsCount / vendors.length) * 100)}%)
              </p>
            </div>
            <div className="max-h-80 overflow-y-auto">
              <table className="w-full">
                <thead className="sticky top-0 bg-gray-100">
                  <tr className="border-b border-gray-200">
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                      Vendor
                    </th>
                    <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                      Verdict
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {vendors.map((vendor: any, idx: number) => (
                    <tr
                      key={idx}
                      className="border-b border-gray-200 hover:bg-gray-50 transition-colors"
                    >
                      <td className="px-4 py-3 text-sm font-medium text-gray-800">
                        {vendor.vendor}
                      </td>
                      <td className="px-4 py-3">
                        <span
                          className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-sm font-semibold border ${getVerdictColor(
                            vendor.verdict
                          )}`}
                        >
                          <span>{getVerdictIcon(vendor.verdict)}</span>
                          {vendor.verdict}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Summary */}
        {vendors.length > 0 && (
          <div
            className={`p-4 rounded-lg border-2 ${
              threatsCount === 0
                ? "bg-green-50 border-green-300"
                : "bg-red-50 border-red-300"
            }`}
          ></div>
        )}

        {/* Report Malicious Link - show when threats detected */}
        {threatsCount > 0 && (
          <ReportMaliciousNote
            url={result.url || data.target}
            threatType={result.overall_verdict}
          />
        )}

        {result.message && (
          <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
            <p className="text-sm text-gray-600 mb-1">Message</p>
            <p className="text-gray-800">{result.message}</p>
          </div>
        )}

        {result.note && (
          <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
            <p className="text-sm text-gray-600 mb-1">Note</p>
            <p className="text-gray-800">{result.note}</p>
          </div>
        )}

        {/* JSON Output */}
        <JsonViewer data={result} title="Raw API Response" />
      </div>
    );
  };

  const renderFileScanResults = () => {
    const scanDetails = result.scan_details || {};
    const riskFeatures = result.risk_features || {};
    const riskScore = result.risk_score || 0;

    return (
      <div className="space-y-4">
        {/* File Info Header */}
        <div className="flex items-center gap-3 p-4 bg-purple-50 rounded-lg border border-purple-200">
          <FiFile className="text-2xl text-purple-600" />
          <div className="flex-1">
            <p className="text-sm text-gray-600">Scanned File</p>
            <p className="font-semibold text-gray-800">
              {result.filename || data.target || "N/A"}
            </p>
          </div>
          {result.scanner && (
            <div className="text-right">
              <p className="text-xs text-gray-500">Scanner</p>
              <p className="font-semibold text-purple-700">{result.scanner}</p>
            </div>
          )}
        </div>

        {/* Scan Result Banner */}
        <div
          className={`p-5 rounded-xl border-2 flex items-center gap-4 ${
            result.is_clean
              ? "bg-green-50 border-green-300"
              : "bg-red-50 border-red-300"
          }`}
        >
          {result.is_clean ? (
            <FiCheckCircle className="text-4xl text-green-600" />
          ) : (
            <FiAlertTriangle className="text-4xl text-red-600" />
          )}
          <div className="flex-1">
            <h3
              className={`font-bold text-xl ${
                result.is_clean ? "text-green-800" : "text-red-800"
              }`}
            >
              {result.is_clean ? "File is Clean" : "Threat Detected!"}
            </h3>
            <p className="text-gray-600">{result.message}</p>
            {result.threat && (
              <p className="mt-2 font-semibold text-red-700 bg-red-100 px-3 py-1 rounded inline-block">
                {result.threat}
              </p>
            )}
          </div>
          <div className="text-right">
            <p className="text-3xl font-bold text-gray-800">{riskScore}%</p>
            <p className="text-sm text-gray-600">Risk Score</p>
          </div>
        </div>

        {/* Scan Details */}
        {Object.keys(scanDetails).length > 0 && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-purple-600 to-indigo-600 text-white p-4">
              <h4 className="font-bold text-lg flex items-center gap-2">
                <FiShield /> ClamAV Scan Details
              </h4>
              <p className="text-purple-100 text-sm">
                Engine v{scanDetails.engine_version || "N/A"}
              </p>
            </div>
            <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-gray-50 p-3 rounded-lg text-center">
                <p className="text-2xl font-bold text-purple-600">
                  {scanDetails.known_viruses || "N/A"}
                </p>
                <p className="text-xs text-gray-600">Virus Signatures</p>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg text-center">
                <p className="text-2xl font-bold text-blue-600">
                  {scanDetails.scanned_files || "1"}
                </p>
                <p className="text-xs text-gray-600">Files Scanned</p>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg text-center">
                <p className="text-2xl font-bold text-green-600">
                  {scanDetails.data_scanned || "N/A"}
                </p>
                <p className="text-xs text-gray-600">Data Scanned</p>
              </div>
              <div className="bg-gray-50 p-3 rounded-lg text-center">
                <p className="text-2xl font-bold text-orange-600">
                  {scanDetails.scan_time || "N/A"}
                </p>
                <p className="text-xs text-gray-600">Scan Time</p>
              </div>
            </div>
            {(scanDetails.start_date || scanDetails.end_date) && (
              <div className="px-4 pb-4">
                <div className="bg-gray-50 p-3 rounded-lg flex justify-between text-sm">
                  <span className="text-gray-600">
                    Start: {scanDetails.start_date || "N/A"}
                  </span>
                  <span className="text-gray-600">
                    End: {scanDetails.end_date || "N/A"}
                  </span>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Risk Calculator */}
        {Object.keys(riskFeatures).length > 0 && (
          <RiskCalculator riskScore={riskScore} features={riskFeatures} />
        )}

        {result.warning && (
          <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
            <p className="text-sm text-gray-600 mb-1 flex items-center gap-2">
              <FiAlertTriangle className="text-yellow-600" /> Warning
            </p>
            <p className="text-gray-800">{result.warning}</p>
          </div>
        )}

        {result.note && (
          <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
            <p className="text-sm text-gray-600 mb-1 flex items-center gap-2">
              <FiInfo className="text-blue-600" /> Note
            </p>
            <p className="text-gray-800">{result.note}</p>
          </div>
        )}

        {/* JSON Output */}
        <JsonViewer data={result} title="Raw Scan Output" />
      </div>
    );
  };

  const renderMessageScanResults = () => {
    const featureScores = result.feature_scores || {};
    const categories = result.categories || {};
    const recommendations = result.recommendations || [];

    const getVerdictStyle = (verdict: string) => {
      switch (verdict) {
        case "scam":
          return {
            bg: "bg-red-100",
            border: "border-red-300",
            text: "text-red-800",
            icon: "🚨",
          };
        case "suspicious":
          return {
            bg: "bg-orange-100",
            border: "border-orange-300",
            text: "text-orange-800",
            icon: "⚠️",
          };
        case "potentially_suspicious":
          return {
            bg: "bg-yellow-100",
            border: "border-yellow-300",
            text: "text-yellow-800",
            icon: "⚡",
          };
        default:
          return {
            bg: "bg-green-100",
            border: "border-green-300",
            text: "text-green-800",
            icon: "✅",
          };
      }
    };

    const verdictStyle = getVerdictStyle(result.verdict);

    return (
      <div className="space-y-4">
        {/* Message Preview */}
        <div className="flex items-start gap-3 p-4 bg-indigo-50 rounded-lg border border-indigo-200">
          <FiMessageSquare className="text-2xl text-indigo-600 mt-1" />
          <div className="flex-1">
            <p className="text-sm text-gray-600">Analyzed Message</p>
            <p className="font-medium text-gray-800 whitespace-pre-wrap">
              {result.message_preview || "N/A"}
            </p>
          </div>
        </div>

        {/* Verdict Banner */}
        <div
          className={`p-5 rounded-xl border-2 ${verdictStyle.border} ${verdictStyle.bg}`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <span className="text-4xl">{verdictStyle.icon}</span>
              <div>
                <h3
                  className={`font-bold text-xl ${verdictStyle.text} uppercase`}
                >
                  {result.verdict?.replace(/_/g, " ") || "Unknown"}
                </h3>
                <p className="text-sm text-gray-600">Message Classification</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-3xl font-bold text-gray-800">
                {result.risk_score || 0}%
              </p>
              <p className="text-sm text-gray-600">Risk Score</p>
            </div>
          </div>
        </div>

        {/* Risk Meter */}
        <div className="bg-white p-4 rounded-lg border border-gray-200">
          <h4 className="font-semibold text-gray-800 mb-3">Risk Level</h4>
          <div className="relative h-6 bg-gradient-to-r from-green-400 via-yellow-400 via-orange-400 to-red-500 rounded-full overflow-hidden">
            <div
              className="absolute top-0 h-full w-1 bg-black shadow-lg"
              style={{ left: `${Math.min(result.risk_score || 0, 100)}%` }}
            >
              <div className="absolute -top-1 -left-2 w-5 h-8 bg-black rounded-sm" />
            </div>
          </div>
          <div className="flex justify-between mt-1 text-xs text-gray-500">
            <span>Safe</span>
            <span>Low</span>
            <span>Medium</span>
            <span>High</span>
            <span>Scam</span>
          </div>
        </div>

        {/* Categories Breakdown */}
        {Object.keys(categories).length > 0 && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-purple-600 to-pink-600 text-white p-4">
              <h4 className="font-bold text-lg">Threat Categories</h4>
              <p className="text-purple-100 text-sm">
                Score breakdown by category
              </p>
            </div>
            <div className="p-4 grid grid-cols-2 md:grid-cols-3 gap-3">
              {Object.entries(categories).map(([category, score]) => {
                const numScore = Number(score);
                const color =
                  numScore > 20
                    ? "red"
                    : numScore > 10
                    ? "orange"
                    : numScore > 0
                    ? "yellow"
                    : "green";
                return (
                  <div
                    key={category}
                    className={`p-3 rounded-lg border bg-${color}-50 border-${color}-200`}
                  >
                    <p className="text-sm text-gray-600 capitalize">
                      {category.replace(/_/g, " ")}
                    </p>
                    <p
                      className={`text-xl font-bold ${
                        numScore > 20
                          ? "text-red-600"
                          : numScore > 10
                          ? "text-orange-600"
                          : numScore > 0
                          ? "text-yellow-600"
                          : "text-green-600"
                      }`}
                    >
                      {numScore}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Features Detected */}
        {result.features_detected && result.features_detected.length > 0 && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-red-600 to-orange-600 text-white p-4">
              <h4 className="font-bold text-lg flex items-center gap-2">
                <FiAlertTriangle /> Scam Indicators Detected
              </h4>
              <p className="text-red-100 text-sm">
                {result.features_detected.length} indicators found
              </p>
            </div>
            <div className="p-4">
              <div className="flex flex-wrap gap-2">
                {result.features_detected.map(
                  (feature: string, idx: number) => {
                    const isLegitimate = feature.startsWith("[legitimate]");
                    const score = featureScores[feature] || 0;
                    return (
                      <span
                        key={idx}
                        className={`px-3 py-1 rounded-full text-sm font-medium border ${
                          isLegitimate
                            ? "bg-green-100 text-green-700 border-green-300"
                            : "bg-red-100 text-red-700 border-red-300"
                        }`}
                      >
                        {feature.replace("[legitimate] ", "")}
                        <span className="ml-1 opacity-70">
                          ({score > 0 ? "+" : ""}
                          {score})
                        </span>
                      </span>
                    );
                  }
                )}
              </div>
            </div>
          </div>
        )}

        {/* AI Analysis */}
        {result.ai_analysis && (
          <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
            <h4 className="font-semibold text-blue-800 mb-2 flex items-center gap-2">
              🤖 AI Analysis
            </h4>
            <p className="text-gray-700">{result.ai_analysis}</p>
          </div>
        )}

        {/* Recommendations */}
        {recommendations.length > 0 && (
          <div
            className={`p-4 rounded-lg border-2 ${
              result.verdict === "scam"
                ? "bg-red-50 border-red-300"
                : result.verdict === "suspicious"
                ? "bg-orange-50 border-orange-300"
                : "bg-green-50 border-green-300"
            }`}
          >
            <h4 className="font-semibold text-gray-800 mb-3">
              📋 Recommendations
            </h4>
            <ul className="space-y-2">
              {recommendations.map((rec: string, idx: number) => (
                <li key={idx} className="flex items-start gap-2 text-gray-700">
                  <span className="mt-1">
                    {result.verdict === "scam" ||
                    result.verdict === "suspicious"
                      ? "⚠️"
                      : "✓"}
                  </span>
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* JSON Output */}
        <JsonViewer data={result} title="Full Analysis Data" />
      </div>
    );
  };

  const renderPDFScanResults = () => {
    const riskFeatures = result.risk_features || {};
    const riskScore = result.risk_score || 0;
    const detectionRate = result.detection_rate || 0;

    return (
      <div className="space-y-4">
        {/* PDF Header */}
        <div className="flex items-center gap-3 p-4 bg-red-50 rounded-lg border border-red-200">
          <FiFile className="text-2xl text-red-600" />
          <div className="flex-1">
            <p className="text-sm text-gray-600">Scanned PDF</p>
            <p className="font-semibold text-gray-800">
              {result.filename || data.target || "N/A"}
            </p>
          </div>
          {result.scanner && (
            <div className="text-right">
              <p className="text-xs text-gray-500">Scanner</p>
              <p className="font-semibold text-red-700">{result.scanner}</p>
            </div>
          )}
        </div>

        {/* Detection Result Banner */}
        {result.positives !== undefined && result.total !== undefined && (
          <div
            className={`p-5 rounded-xl border-2 ${
              result.positives === 0
                ? "bg-green-50 border-green-300"
                : result.positives <= 3
                ? "bg-yellow-50 border-yellow-300"
                : result.positives <= 10
                ? "bg-orange-50 border-orange-300"
                : "bg-red-50 border-red-300"
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                {result.positives === 0 ? (
                  <FiCheckCircle className="text-4xl text-green-600" />
                ) : (
                  <FiAlertTriangle
                    className={`text-4xl ${
                      result.positives <= 3
                        ? "text-yellow-600"
                        : result.positives <= 10
                        ? "text-orange-600"
                        : "text-red-600"
                    }`}
                  />
                )}
                <div>
                  <h3
                    className={`font-bold text-2xl ${
                      result.positives === 0
                        ? "text-green-800"
                        : result.positives <= 3
                        ? "text-yellow-800"
                        : result.positives <= 10
                        ? "text-orange-800"
                        : "text-red-800"
                    }`}
                  >
                    {result.positives} / {result.total}
                  </h3>
                  <p className="text-gray-600">Engines detected threats</p>
                </div>
              </div>
              <div className="text-right">
                <p className="text-3xl font-bold text-gray-800">{riskScore}%</p>
                <p className="text-sm text-gray-600">Risk Score</p>
                {detectionRate > 0 && (
                  <p className="text-xs text-red-600 mt-1">
                    {detectionRate}% detection rate
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* File Hash */}
        {result.hash && (
          <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
            <p className="text-sm text-gray-600 mb-1">File Hash (SHA-256)</p>
            <p className="font-mono text-xs text-gray-800 break-all bg-white p-2 rounded">
              {result.hash}
            </p>
          </div>
        )}

        {/* Scan Type Badge */}
        {result.cached !== undefined && (
          <div
            className={`p-3 rounded-lg border ${
              result.cached
                ? "bg-blue-50 border-blue-200"
                : "bg-green-50 border-green-200"
            }`}
          >
            <p className="text-sm flex items-center gap-2">
              {result.cached ? (
                <>
                  <span className="text-blue-600">📦</span>
                  <span className="text-blue-800">
                    Cached Result (Previously Scanned)
                  </span>
                </>
              ) : (
                <>
                  <span className="text-green-600">🆕</span>
                  <span className="text-green-800">New Scan</span>
                </>
              )}
            </p>
          </div>
        )}

        {/* Detection Statistics */}
        {result.stats && (
          <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="bg-gradient-to-r from-red-600 to-pink-600 text-white p-4">
              <h4 className="font-bold text-lg">Detection Statistics</h4>
              <p className="text-red-100 text-sm">
                VirusTotal Analysis Breakdown
              </p>
            </div>
            <div className="p-4 grid grid-cols-2 md:grid-cols-4 gap-3">
              {Object.entries(result.stats).map(([key, value]) => {
                const getStatColor = (k: string) => {
                  if (k === "malicious") return "text-red-600";
                  if (k === "suspicious") return "text-orange-600";
                  if (k === "harmless" || k === "undetected")
                    return "text-green-600";
                  return "text-gray-600";
                };
                return (
                  <div
                    key={key}
                    className="bg-gray-50 p-3 rounded-lg text-center"
                  >
                    <p className={`text-2xl font-bold ${getStatColor(key)}`}>
                      {value as number}
                    </p>
                    <p className="text-xs text-gray-600 capitalize">{key}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Risk Calculator */}
        {Object.keys(riskFeatures).length > 0 && (
          <RiskCalculator riskScore={riskScore} features={riskFeatures} />
        )}

        {/* Pending Analysis */}
        {result.analysis_id && (
          <div className="bg-yellow-50 p-4 rounded-lg border border-yellow-200">
            <div className="flex items-center gap-3">
              <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-yellow-600"></div>
              <div>
                <p className="font-semibold text-yellow-800">
                  Analysis in Progress
                </p>
                <p className="text-sm text-gray-600">{result.message}</p>
                <p className="text-xs text-gray-500 mt-1">
                  ID: {result.analysis_id}
                </p>
              </div>
            </div>
          </div>
        )}

        {result.message && !result.positives && !result.analysis_id && (
          <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
            <p className="text-gray-800">{result.message}</p>
          </div>
        )}

        {/* JSON Output */}
        <JsonViewer data={result} title="Raw VirusTotal Response" />
      </div>
    );
  };

  const renderImageScanResults = () => (
    <div className="space-y-4">
      <div className="flex items-center gap-3 p-4 bg-indigo-50 rounded-lg border border-indigo-200">
        <FiImage className="text-2xl text-indigo-600" />
        <div>
          <p className="text-sm text-gray-600">Scanned Image</p>
          <p className="font-semibold text-gray-800">
            {result.filename || "N/A"}
          </p>
        </div>
      </div>

      {result.format && (
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
            <p className="text-xs text-gray-600 mb-1">Format</p>
            <p className="font-semibold text-gray-800">{result.format}</p>
          </div>
          {result.size && (
            <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
              <p className="text-xs text-gray-600 mb-1">Dimensions</p>
              <p className="font-semibold text-gray-800">
                {result.size[0]} × {result.size[1]}
              </p>
            </div>
          )}
          {result.mode && (
            <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
              <p className="text-xs text-gray-600 mb-1">Color Mode</p>
              <p className="font-semibold text-gray-800">{result.mode}</p>
            </div>
          )}
        </div>
      )}

      {result.exif_found && (
        <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
          <p className="text-sm text-gray-600 mb-1">📷 EXIF Metadata</p>
          <p className="text-gray-800">
            Found {result.exif_tags_count} EXIF tags in image
          </p>
        </div>
      )}

      {result.steganography_suspected !== undefined && (
        <div
          className={`p-5 rounded-lg border-2 ${
            result.steganography_suspected
              ? "bg-red-50 border-red-300"
              : "bg-green-50 border-green-300"
          }`}
        >
          <div className="flex items-center gap-3 mb-3">
            {result.steganography_suspected ? (
              <FiAlertTriangle className="text-3xl text-red-600" />
            ) : (
              <FiCheckCircle className="text-3xl text-green-600" />
            )}
            <div>
              <h4 className="font-bold text-lg text-gray-800">
                Steganography Analysis
              </h4>
              <p
                className={`text-sm ${
                  result.steganography_suspected
                    ? "text-red-700"
                    : "text-green-700"
                }`}
              >
                {result.steganography_suspected
                  ? "⚠️ Hidden data suspected"
                  : "✓ No hidden data detected"}
              </p>
            </div>
          </div>

          {result.warning && (
            <div className="bg-white p-3 rounded border border-red-200 mb-3">
              <p className="text-red-800 font-medium">{result.warning}</p>
            </div>
          )}

          {result.lsb_analysis && (
            <div className="bg-white p-4 rounded-lg border border-gray-200">
              <h5 className="font-semibold text-gray-800 mb-3">
                LSB (Least Significant Bit) Analysis
              </h5>
              <div className="space-y-2">
                <div className="flex justify-between items-center p-2 bg-red-50 rounded">
                  <span className="text-sm text-gray-700">🔴 Red Channel</span>
                  <span className="font-mono font-bold text-gray-800">
                    {result.lsb_analysis.red_channel}
                  </span>
                </div>
                <div className="flex justify-between items-center p-2 bg-green-50 rounded">
                  <span className="text-sm text-gray-700">
                    🟢 Green Channel
                  </span>
                  <span className="font-mono font-bold text-gray-800">
                    {result.lsb_analysis.green_channel}
                  </span>
                </div>
                <div className="flex justify-between items-center p-2 bg-blue-50 rounded">
                  <span className="text-sm text-gray-700">🔵 Blue Channel</span>
                  <span className="font-mono font-bold text-gray-800">
                    {result.lsb_analysis.blue_channel}
                  </span>
                </div>
                <div className="flex justify-between items-center p-2 bg-purple-50 rounded border-2 border-purple-200">
                  <span className="text-sm font-semibold text-gray-700">
                    📊 Average
                  </span>
                  <span className="font-mono font-bold text-purple-800">
                    {result.lsb_analysis.average}
                  </span>
                </div>
                <div className="mt-3 p-3 bg-gray-50 rounded">
                  <p className="text-xs text-gray-600 mb-1">Confidence Level</p>
                  <p
                    className={`font-bold uppercase ${
                      result.lsb_analysis.confidence === "high"
                        ? "text-red-600"
                        : result.lsb_analysis.confidence === "medium"
                        ? "text-orange-600"
                        : "text-green-600"
                    }`}
                  >
                    {result.lsb_analysis.confidence}
                  </p>
                </div>
              </div>
              <div className="mt-3 p-3 bg-blue-50 rounded text-xs text-gray-700">
                <p className="font-semibold mb-1">ℹ️ What is LSB Analysis?</p>
                <p>
                  LSB analysis checks the least significant bits of pixel
                  values. Values close to 0.5 (0.48-0.52) in all channels often
                  indicate hidden data embedded using steganography techniques.
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {result.scanner && (
        <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
          <p className="text-sm text-gray-600 mb-1">Scanner Used</p>
          <p className="font-semibold text-gray-800">{result.scanner}</p>
        </div>
      )}

      {/* JSON Output */}
      <JsonViewer data={result} title="Image Analysis Data" />
    </div>
  );

  const renderResults = () => {
    // Determine scan type based on result properties
    if (result.verdict && result.features_detected !== undefined) {
      // Message scan
      return renderMessageScanResults();
    } else if (
      result.vendors ||
      result.overall_verdict ||
      result.threats ||
      result.is_safe !== undefined
    ) {
      // URL scan (new multi-vendor or old single-vendor)
      return renderURLScanResults();
    } else if (
      result.steganography_suspected !== undefined ||
      result.lsb_analysis
    ) {
      // Image scan
      return renderImageScanResults();
    } else if (result.positives !== undefined || result.stats) {
      // PDF/VirusTotal scan
      return renderPDFScanResults();
    } else if (result.is_clean !== undefined || result.threat) {
      // File scan
      return renderFileScanResults();
    } else {
      // Fallback to generic display with JsonViewer
      return (
        <div className="space-y-4">
          <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
            <h4 className="font-semibold mb-2">Scan Results</h4>
          </div>
          <JsonViewer
            data={result}
            title="Raw Scan Data"
            defaultCollapsed={false}
          />
        </div>
      );
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center p-4 z-50 backdrop-blur-sm">
      <div className="bg-white rounded-xl shadow-2xl max-w-3xl w-full max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-gradient-to-r from-blue-600 to-purple-600 text-white p-6 rounded-t-xl">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-3">
              <FiShield className="text-3xl" />
              <div>
                <h2 className="text-2xl font-bold">Scan Analysis</h2>
                <p className="text-blue-100 text-sm">
                  Detailed security report
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-white hover:bg-white/20 rounded-full p-2 transition-colors"
            >
              <span className="text-3xl leading-none">×</span>
            </button>
          </div>
        </div>

        <div className="p-6 space-y-6">
          {/* Threat Level Banner */}
          <div
            className={`p-5 rounded-xl border-2 flex items-center gap-4 ${getThreatColor(
              data.threat_level
            )}`}
          >
            {getThreatIcon(data.threat_level)}
            <div className="flex-1">
              <h3 className="font-bold text-xl mb-1">
                Threat Level: {data.threat_level?.toUpperCase() || "UNKNOWN"}
              </h3>
              <p className="text-sm opacity-80">
                {data.threat_level === "clean"
                  ? "No threats detected. This item appears to be safe."
                  : data.threat_level === "low"
                  ? "Minor concerns detected. Review the details below."
                  : data.threat_level === "medium"
                  ? "Moderate risk detected. Proceed with caution."
                  : data.threat_level === "high" ||
                    data.threat_level === "critical"
                  ? "High risk detected! Do not proceed without expert review."
                  : "Scan completed. Review the details below."}
              </p>
            </div>
          </div>

          {/* Scan Metadata */}
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <p className="text-xs text-gray-600 mb-1">Scan ID</p>
              <p className="font-mono text-sm text-gray-800 truncate">
                {data.scan_id || "N/A"}
              </p>
            </div>
            <div className="bg-gray-50 p-4 rounded-lg border border-gray-200">
              <p className="text-xs text-gray-600 mb-1">Status</p>
              <p className="font-semibold text-gray-800 capitalize">
                {data.status || "Unknown"}
              </p>
            </div>
          </div>

          {/* Detailed Results */}
          {renderResults()}

          {/* Error Display */}
          {result.error && (
            <div className="bg-red-50 p-4 rounded-lg border border-red-200">
              <h4 className="font-bold text-red-800 mb-2 flex items-center gap-2">
                <FiXCircle /> Error
              </h4>
              <p className="text-red-700">{result.error}</p>
            </div>
          )}
        </div>

        <div className="sticky bottom-0 bg-gray-50 p-6 rounded-b-xl border-t border-gray-200">
          <button
            onClick={onClose}
            className="w-full bg-gradient-to-r from-blue-600 to-purple-600 text-white py-3 rounded-lg hover:from-blue-700 hover:to-purple-700 font-semibold transition-all shadow-lg hover:shadow-xl"
          >
            Close Analysis
          </button>
        </div>
      </div>
    </div>
  );
}
