import { Line, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement
);

const getThreatColorClass = (level: string) => {
  switch (level) {
    case "clean":
      return {
        bg: "bg-green-500",
        text: "text-green-500",
        border: "border-green-500",
        light: "bg-green-100",
      };
    case "low":
      return {
        bg: "bg-yellow-500",
        text: "text-yellow-500",
        border: "border-yellow-500",
        light: "bg-yellow-100",
      };
    case "medium":
      return {
        bg: "bg-orange-500",
        text: "text-orange-500",
        border: "border-orange-500",
        light: "bg-orange-100",
      };
    case "high":
    case "critical":
      return {
        bg: "bg-red-500",
        text: "text-red-500",
        border: "border-red-500",
        light: "bg-red-100",
      };
    default:
      return {
        bg: "bg-blue-500",
        text: "text-blue-500",
        border: "border-blue-500",
        light: "bg-blue-100",
      };
  }
};

export default function ScanProgress({ data }: { data: any }) {
  const progress = data.progress || 0;
  const threatLevel = data.threat_level || "unknown";
  const colors = getThreatColorClass(threatLevel);

  // Determine progress bar color based on status and threat level
  const getProgressBarColor = () => {
    if (data.status === "completed") {
      switch (threatLevel) {
        case "clean":
          return "bg-green-500";
        case "low":
          return "bg-yellow-500";
        case "medium":
          return "bg-orange-500";
        case "high":
        case "critical":
          return "bg-red-500";
        default:
          return "bg-blue-500";
      }
    }
    return "bg-blue-500";
  };

  const chartData = {
    labels: ["Start", "Progress", "Complete"],
    datasets: [
      {
        label: "Scan Progress",
        data: [
          0,
          progress || 50,
          data.status === "completed" ? 100 : progress || 50,
        ],
        borderColor:
          data.status === "completed" && threatLevel !== "clean"
            ? "rgb(239, 68, 68)"
            : "rgb(59, 130, 246)",
        backgroundColor:
          data.status === "completed" && threatLevel !== "clean"
            ? "rgba(239, 68, 68, 0.5)"
            : "rgba(59, 130, 246, 0.5)",
        tension: 0.4,
      },
    ],
  };

  const options = {
    responsive: true,
    plugins: {
      legend: {
        position: "top" as const,
        labels: {
          color: "#9CA3AF",
        },
      },
      title: {
        display: true,
        text: "Real-Time Scan Progress",
        color: "#F3F4F6",
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        max: 100,
        ticks: {
          color: "#9CA3AF",
          callback: function (value: any) {
            return value + "%";
          },
        },
        grid: {
          color: "rgba(156, 163, 175, 0.2)",
        },
      },
      x: {
        ticks: {
          color: "#9CA3AF",
        },
        grid: {
          color: "rgba(156, 163, 175, 0.2)",
        },
      },
    },
  };

  // Doughnut chart for completion percentage
  const doughnutData = {
    labels: ["Completed", "Remaining"],
    datasets: [
      {
        data: [progress, 100 - progress],
        backgroundColor: [
          data.status === "completed"
            ? threatLevel === "clean"
              ? "#10B981"
              : threatLevel === "low"
              ? "#F59E0B"
              : threatLevel === "medium"
              ? "#F97316"
              : "#EF4444"
            : "#3B82F6",
          "rgba(156, 163, 175, 0.3)",
        ],
        borderWidth: 0,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "70%",
    plugins: {
      legend: {
        display: false,
      },
      tooltip: {
        callbacks: {
          label: function (context: any) {
            return context.label + ": " + context.raw + "%";
          },
        },
      },
    },
  };

  return (
    <div className="bg-gray-800/50 rounded-lg shadow-lg p-6 border border-gray-700">
      <h3 className="text-xl font-bold mb-4 text-white">Scan Progress</h3>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        {/* Progress Bar Section */}
        <div className="md:col-span-2">
          <div className="flex justify-between mb-2">
            <span
              className={`font-semibold capitalize ${
                data.status === "completed" ? colors.text : "text-blue-400"
              }`}
            >
              Status: {data.status}
            </span>
            <span
              className={`font-bold text-lg ${
                data.status === "completed" ? colors.text : "text-blue-400"
              }`}
            >
              {progress}%
            </span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-5 overflow-hidden">
            <div
              className={`h-5 rounded-full transition-all duration-500 ${getProgressBarColor()} flex items-center justify-end pr-2`}
              style={{ width: `${progress}%` }}
            >
              {progress > 15 && (
                <span className="text-xs font-bold text-white">
                  {progress}%
                </span>
              )}
            </div>
          </div>

          {/* Threat Level Indicator */}
          {data.status === "completed" && (
            <div
              className={`mt-4 p-3 rounded-lg border-2 ${colors.border} ${colors.light}`}
            >
              <div className="flex items-center gap-2">
                <div className={`w-3 h-3 rounded-full ${colors.bg}`}></div>
                <span className={`font-bold uppercase ${colors.text}`}>
                  Threat Level: {threatLevel}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Doughnut Chart */}
        <div className="relative h-32">
          <Doughnut data={doughnutData} options={doughnutOptions} />
          <div className="absolute inset-0 flex items-center justify-center">
            <span
              className={`text-2xl font-bold ${
                data.status === "completed" ? colors.text : "text-blue-400"
              }`}
            >
              {progress}%
            </span>
          </div>
        </div>
      </div>

      {data.message && (
        <p
          className={`mb-4 p-3 rounded-lg ${
            data.status === "completed" && threatLevel !== "clean"
              ? "bg-red-900/30 text-red-300 border border-red-700"
              : "bg-blue-900/30 text-blue-300 border border-blue-700"
          }`}
        >
          {data.message}
        </p>
      )}

      <div className="bg-gray-900/50 rounded-lg p-4">
        <Line options={options} data={chartData} />
      </div>
    </div>
  );
}
