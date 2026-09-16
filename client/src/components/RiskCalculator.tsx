import { FiAlertTriangle, FiShield, FiCheck, FiInfo } from "react-icons/fi";

interface RiskFeature {
  score: number;
  max: number;
  status: string;
  detail: string;
}

interface RiskCalculatorProps {
  riskScore: number;
  features: Record<string, RiskFeature>;
}

const getStatusColor = (status: string) => {
  switch (status.toLowerCase()) {
    case "safe":
      return {
        bg: "bg-green-100",
        text: "text-green-700",
        border: "border-green-300",
        bar: "bg-green-500",
      };
    case "low risk":
      return {
        bg: "bg-yellow-100",
        text: "text-yellow-700",
        border: "border-yellow-300",
        bar: "bg-yellow-500",
      };
    case "medium risk":
      return {
        bg: "bg-orange-100",
        text: "text-orange-700",
        border: "border-orange-300",
        bar: "bg-orange-500",
      };
    case "high risk":
      return {
        bg: "bg-red-100",
        text: "text-red-700",
        border: "border-red-300",
        bar: "bg-red-500",
      };
    default:
      return {
        bg: "bg-gray-100",
        text: "text-gray-700",
        border: "border-gray-300",
        bar: "bg-gray-500",
      };
  }
};

const getStatusIcon = (status: string) => {
  switch (status.toLowerCase()) {
    case "safe":
      return <FiCheck className="text-green-600" />;
    case "low risk":
      return <FiInfo className="text-yellow-600" />;
    case "medium risk":
      return <FiAlertTriangle className="text-orange-600" />;
    case "high risk":
      return <FiAlertTriangle className="text-red-600" />;
    default:
      return <FiInfo className="text-gray-600" />;
  }
};

const getRiskLevelFromScore = (score: number) => {
  if (score >= 70)
    return { level: "High Risk", color: "text-red-600", bg: "bg-red-500" };
  if (score >= 40)
    return {
      level: "Medium Risk",
      color: "text-orange-600",
      bg: "bg-orange-500",
    };
  if (score >= 20)
    return { level: "Low Risk", color: "text-yellow-600", bg: "bg-yellow-500" };
  return { level: "Safe", color: "text-green-600", bg: "bg-green-500" };
};

const featureLabels: Record<string, string> = {
  domain_age: "Domain Age",
  ssl_certificate: "SSL Certificate",
  vendor_detection: "Security Vendors",
  traffic_popularity: "Traffic & Popularity",
};

export default function RiskCalculator({
  riskScore,
  features,
}: RiskCalculatorProps) {
  const riskLevel = getRiskLevelFromScore(riskScore);

  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
      {/* Header with overall score */}
      <div className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <FiShield className="text-2xl" />
            <div>
              <h4 className="font-bold text-lg">Risk Assessment</h4>
              <p className="text-indigo-100 text-sm">
                Feature-based risk calculation
              </p>
            </div>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold">{riskScore}%</div>
            <div
              className={`text-sm font-semibold px-2 py-1 rounded ${riskLevel.bg} bg-opacity-30`}
            >
              {riskLevel.level}
            </div>
          </div>
        </div>
      </div>

      {/* Risk meter visualization */}
      <div className="p-4 bg-gray-50 border-b border-gray-200">
        <div className="relative h-6 bg-gradient-to-r from-green-400 via-yellow-400 via-orange-400 to-red-500 rounded-full overflow-hidden">
          <div
            className="absolute top-0 h-full w-1 bg-black shadow-lg transition-all duration-500"
            style={{ left: `${Math.min(riskScore, 100)}%` }}
          >
            <div className="absolute -top-1 -left-2 w-5 h-8 bg-black rounded-sm" />
          </div>
        </div>
        <div className="flex justify-between mt-1 text-xs text-gray-500">
          <span>0% Safe</span>
          <span>25% Low</span>
          <span>50% Medium</span>
          <span>75% High</span>
          <span>100%</span>
        </div>
      </div>

      {/* Feature breakdown */}
      <div className="p-4">
        <h5 className="font-semibold text-gray-800 mb-3 flex items-center gap-2">
          <FiInfo className="text-indigo-500" />
          Risk Factors Analyzed
        </h5>
        <div className="space-y-3">
          {Object.entries(features).map(([key, feature]) => {
            const colors = getStatusColor(feature.status);
            const percentage = Math.round((feature.score / feature.max) * 100);

            return (
              <div
                key={key}
                className={`p-3 rounded-lg border ${colors.border} ${colors.bg}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getStatusIcon(feature.status)}
                    <span className="font-semibold text-gray-800">
                      {featureLabels[key] || key}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-bold ${colors.text}`}>
                      {feature.score}/{feature.max}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-xs font-semibold ${colors.bg} ${colors.text} border ${colors.border}`}
                    >
                      {feature.status}
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className="h-2 bg-gray-200 rounded-full overflow-hidden mb-2">
                  <div
                    className={`h-full ${colors.bar} transition-all duration-500`}
                    style={{ width: `${percentage}%` }}
                  />
                </div>

                <p className="text-sm text-gray-600">{feature.detail}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Footer */}
      <div className="p-4 bg-gray-50 border-t border-gray-200">
        <p className="text-xs text-gray-500">
          <FiInfo className="inline mr-1" />
          Risk score is calculated based on domain reputation, SSL validity,
          security vendor analysis, and traffic patterns. Lower scores indicate
          safer URLs.
        </p>
      </div>
    </div>
  );
}
