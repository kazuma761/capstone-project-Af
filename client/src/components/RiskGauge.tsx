import React from "react";

interface RiskGaugeProps {
  value: number; // 0-1 probability
  size?: number;
  showLabel?: boolean;
}

const RiskGauge: React.FC<RiskGaugeProps> = ({
  value,
  size = 120,
  showLabel = true,
}) => {
  // Convert probability (0-1) to percentage
  const percentage = Math.min(Math.max(value * 100, 0), 100);

  // Calculate the stroke dash for the arc
  const radius = (size - 20) / 2;
  const circumference = Math.PI * radius; // Half circle
  const strokeDashoffset = circumference - (percentage / 100) * circumference;

  // Determine color based on value
  const getColor = (val: number) => {
    if (val < 0.4) return "#22c55e"; // green
    if (val < 0.65) return "#eab308"; // yellow
    if (val < 0.85) return "#f97316"; // orange
    return "#ef4444"; // red
  };

  const getTier = (val: number) => {
    if (val < 0.4) return "CLEAN";
    if (val < 0.65) return "MONITOR";
    if (val < 0.85) return "SUSPICIOUS";
    return "ALERT";
  };

  const color = getColor(value);
  const tier = getTier(value);

  return (
    <div className="flex flex-col items-center">
      <svg
        width={size}
        height={size / 2 + 20}
        viewBox={`0 0 ${size} ${size / 2 + 20}`}
      >
        {/* Background arc */}
        <path
          d={`M 10 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${
            size / 2
          }`}
          fill="none"
          stroke="#374151"
          strokeWidth="12"
          strokeLinecap="round"
        />

        {/* Colored arc */}
        <path
          d={`M 10 ${size / 2} A ${radius} ${radius} 0 0 1 ${size - 10} ${
            size / 2
          }`}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          style={{
            transition: "stroke-dashoffset 0.5s ease, stroke 0.3s ease",
          }}
        />

        {/* Center text */}
        <text
          x={size / 2}
          y={size / 2 - 5}
          textAnchor="middle"
          className="fill-white font-bold"
          style={{ fontSize: size / 5 }}
        >
          {percentage.toFixed(1)}%
        </text>

        {showLabel && (
          <text
            x={size / 2}
            y={size / 2 + 15}
            textAnchor="middle"
            fill={color}
            style={{ fontSize: size / 10 }}
          >
            {tier}
          </text>
        )}
      </svg>

      {/* Threshold markers */}
      <div className="flex justify-between w-full px-2 text-xs text-gray-500 -mt-2">
        <span>0%</span>
        <span>40%</span>
        <span>65%</span>
        <span>85%</span>
        <span>100%</span>
      </div>
    </div>
  );
};

export default RiskGauge;
