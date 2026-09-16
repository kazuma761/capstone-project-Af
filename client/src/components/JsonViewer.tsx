import { useState } from "react";
import {
  FiCode,
  FiCopy,
  FiCheck,
  FiChevronDown,
  FiChevronUp,
} from "react-icons/fi";

interface JsonViewerProps {
  data: any;
  title?: string;
  defaultCollapsed?: boolean;
}

const syntaxHighlight = (json: string): string => {
  // Replace JSON syntax with styled spans
  return json.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g,
    (match) => {
      let cls = "text-purple-600"; // number
      if (/^"/.test(match)) {
        if (/:$/.test(match)) {
          cls = "text-blue-600 font-semibold"; // key
          match = match.replace(/"/g, "").replace(":", "");
          return `<span class="${cls}">"${match}"</span>:`;
        } else {
          cls = "text-green-600"; // string
        }
      } else if (/true|false/.test(match)) {
        cls = "text-amber-600 font-semibold"; // boolean
      } else if (/null/.test(match)) {
        cls = "text-red-600"; // null
      }
      return `<span class="${cls}">${match}</span>`;
    }
  );
};

export default function JsonViewer({
  data,
  title = "JSON Output",
  defaultCollapsed = true,
}: JsonViewerProps) {
  const [isCollapsed, setIsCollapsed] = useState(defaultCollapsed);
  const [copied, setCopied] = useState(false);

  const jsonString = JSON.stringify(data, null, 2);
  const highlightedJson = syntaxHighlight(jsonString);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(jsonString);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  };

  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between bg-gray-800 text-white p-3 cursor-pointer hover:bg-gray-700 transition-colors"
        onClick={() => setIsCollapsed(!isCollapsed)}
      >
        <div className="flex items-center gap-2">
          <FiCode className="text-lg" />
          <span className="font-semibold">{title}</span>
          <span className="text-xs bg-gray-700 px-2 py-0.5 rounded">
            {Object.keys(data).length} keys
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={(e) => {
              e.stopPropagation();
              copyToClipboard();
            }}
            className="p-1.5 hover:bg-gray-600 rounded transition-colors"
            title="Copy JSON"
          >
            {copied ? <FiCheck className="text-green-400" /> : <FiCopy />}
          </button>
          {isCollapsed ? <FiChevronDown /> : <FiChevronUp />}
        </div>
      </div>

      {/* Content */}
      {!isCollapsed && (
        <div className="bg-gray-50 p-4 max-h-96 overflow-auto">
          <pre
            className="text-sm font-mono leading-relaxed"
            dangerouslySetInnerHTML={{ __html: highlightedJson }}
          />
        </div>
      )}

      {/* Collapsed preview */}
      {isCollapsed && (
        <div className="bg-gray-50 p-3 border-t border-gray-200">
          <p className="text-sm text-gray-500 truncate font-mono">
            {jsonString.substring(0, 100)}...
          </p>
          <p className="text-xs text-gray-400 mt-1">
            Click to expand full JSON response
          </p>
        </div>
      )}
    </div>
  );
}
