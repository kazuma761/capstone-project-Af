import React from "react";

type ThreatTier = "CLEAN" | "MONITOR" | "SUSPICIOUS" | "ALERT";

interface ThreatTierBadgeProps {
  tier: ThreatTier;
  size?: "sm" | "md" | "lg";
  showPulse?: boolean;
}

const tierConfig: Record<
  ThreatTier,
  { bg: string; text: string; border: string; label: string }
> = {
  CLEAN: {
    bg: "bg-green-500/20",
    text: "text-green-400",
    border: "border-green-500/50",
    label: "Clean",
  },
  MONITOR: {
    bg: "bg-yellow-500/20",
    text: "text-yellow-400",
    border: "border-yellow-500/50",
    label: "Monitor",
  },
  SUSPICIOUS: {
    bg: "bg-orange-500/20",
    text: "text-orange-400",
    border: "border-orange-500/50",
    label: "Suspicious",
  },
  ALERT: {
    bg: "bg-red-500/20",
    text: "text-red-400",
    border: "border-red-500/50",
    label: "Alert",
  },
};

const sizeClasses = {
  sm: "px-2 py-0.5 text-xs",
  md: "px-3 py-1 text-sm",
  lg: "px-4 py-1.5 text-base",
};

const ThreatTierBadge: React.FC<ThreatTierBadgeProps> = ({
  tier,
  size = "md",
  showPulse = true,
}) => {
  const config = tierConfig[tier] || tierConfig.CLEAN;
  const shouldPulse = showPulse && tier === "ALERT";

  return (
    <span
      className={`
        inline-flex items-center gap-1.5 rounded-full font-medium border
        ${config.bg} ${config.text} ${config.border} ${sizeClasses[size]}
        ${shouldPulse ? "animate-pulse" : ""}
      `}
    >
      <span
        className={`
          w-2 h-2 rounded-full 
          ${tier === "CLEAN" ? "bg-green-400" : ""}
          ${tier === "MONITOR" ? "bg-yellow-400" : ""}
          ${tier === "SUSPICIOUS" ? "bg-orange-400" : ""}
          ${tier === "ALERT" ? "bg-red-400" : ""}
        `}
      />
      {config.label}
    </span>
  );
};

export default ThreatTierBadge;
