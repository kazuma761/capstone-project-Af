import {
  FiAlertTriangle,
  FiExternalLink,
  FiCopy,
  FiCheck,
} from "react-icons/fi";
import { useState } from "react";

interface ReportMaliciousNoteProps {
  url?: string;
  threatType?: string;
}

export default function ReportMaliciousNote({
  url,
  threatType,
}: ReportMaliciousNoteProps) {
  const [copiedStep, setCopiedStep] = useState<number | null>(null);

  const reportingSteps = [
    {
      title: "Google Safe Browsing",
      description: "Report phishing and malware sites to Google",
      url: "https://safebrowsing.google.com/safebrowsing/report_phish/",
      icon: "🔍",
    },
    {
      title: "FBI IC3",
      description: "Report internet crimes to the FBI",
      url: "https://www.ic3.gov/complaint",
      icon: "🏛️",
    },
    {
      title: "FTC ReportFraud",
      description: "Report fraud to the Federal Trade Commission",
      url: "https://reportfraud.ftc.gov/",
      icon: "📋",
    },
    {
      title: "APWG eCrime",
      description: "Report phishing emails and websites",
      url: "https://apwg.org/reportphishing/",
      icon: "🎣",
    },
    {
      title: "Microsoft Security",
      description: "Report unsafe websites to Microsoft",
      url: "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site",
      icon: "🪟",
    },
  ];

  const copyToClipboard = async (text: string, stepIndex: number) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedStep(stepIndex);
      setTimeout(() => setCopiedStep(null), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="bg-gradient-to-br from-amber-50 to-orange-50 rounded-lg border-2 border-amber-300 overflow-hidden">
      {/* Header */}
      <div className="bg-gradient-to-r from-amber-500 to-orange-500 text-white p-4">
        <div className="flex items-center gap-3">
          <FiAlertTriangle className="text-2xl animate-pulse" />
          <div>
            <h4 className="font-bold text-lg">Report Malicious Link</h4>
            <p className="text-amber-100 text-sm">
              Help protect others by reporting this threat
            </p>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* URL to report */}
        {url && (
          <div className="bg-white p-3 rounded-lg border border-amber-200">
            <p className="text-sm text-gray-600 mb-1">
              Malicious URL to report:
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-sm bg-gray-100 p-2 rounded font-mono text-red-700 break-all">
                {url}
              </code>
              <button
                onClick={() => copyToClipboard(url, -1)}
                className="p-2 bg-amber-100 hover:bg-amber-200 rounded transition-colors"
                title="Copy URL"
              >
                {copiedStep === -1 ? (
                  <FiCheck className="text-green-600" />
                ) : (
                  <FiCopy className="text-amber-700" />
                )}
              </button>
            </div>
            {threatType && (
              <p className="mt-2 text-sm">
                <span className="font-semibold text-red-700">Threat Type:</span>{" "}
                <span className="capitalize">{threatType}</span>
              </p>
            )}
          </div>
        )}

        {/* Steps to report */}
        <div>
          <h5 className="font-semibold text-gray-800 mb-3">
            📝 Steps to Report:
          </h5>
          <ol className="space-y-3">
            {reportingSteps.map((step, index) => (
              <li
                key={index}
                className="bg-white p-3 rounded-lg border border-gray-200 hover:border-amber-300 transition-colors"
              >
                <div className="flex items-start gap-3">
                  <span className="text-2xl">{step.icon}</span>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <h6 className="font-semibold text-gray-800">
                        {index + 1}. {step.title}
                      </h6>
                      <a
                        href={step.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        Visit <FiExternalLink className="text-xs" />
                      </a>
                    </div>
                    <p className="text-sm text-gray-600 mt-1">
                      {step.description}
                    </p>
                  </div>
                </div>
              </li>
            ))}
          </ol>
        </div>

        {/* Additional tips */}
        <div className="bg-blue-50 p-4 rounded-lg border border-blue-200">
          <h5 className="font-semibold text-blue-800 mb-2">
            💡 Additional Tips:
          </h5>
          <ul className="text-sm text-blue-700 space-y-1">
            <li>• Take screenshots of the malicious page as evidence</li>
            <li>• Note the date and time you discovered the threat</li>
            <li>• Include any emails or messages that led you to the site</li>
            <li>• Report to your email provider if it came via email</li>
            <li>• Consider reporting to your local cybercrime unit</li>
          </ul>
        </div>

        {/* Warning */}
        <div className="bg-red-50 p-3 rounded-lg border border-red-200">
          <p className="text-sm text-red-700 flex items-start gap-2">
            <FiAlertTriangle className="mt-0.5 flex-shrink-0" />
            <span>
              <strong>Warning:</strong> Do not revisit the malicious URL. Use
              the copied URL for reporting purposes only. Never enter personal
              information on suspicious websites.
            </span>
          </p>
        </div>
      </div>
    </div>
  );
}
