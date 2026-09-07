import React from 'react';
import { RiskTier } from '../types';

interface RiskChipProps {
  tier: RiskTier | string;
  className?: string;
  showDot?: boolean;
}

export const RiskChip: React.FC<RiskChipProps> = ({ tier, className = '', showDot = true }) => {
  const normalizedTier = (tier || 'low').toLowerCase() as RiskTier;

  const config = {
    critical: {
      bg: 'bg-risk-critical-bg text-risk-critical',
      dot: 'bg-risk-critical',
      label: 'Critical',
    },
    high: {
      bg: 'bg-risk-high-bg text-risk-high',
      dot: 'bg-risk-high',
      label: 'High',
    },
    medium: {
      bg: 'bg-risk-medium-bg text-risk-medium',
      dot: 'bg-risk-medium',
      label: 'Medium',
    },
    low: {
      bg: 'bg-risk-low-bg text-risk-low',
      dot: 'bg-risk-low',
      label: 'Low',
    },
  };

  const current = config[normalizedTier] || config.low;

  return (
    <span
      className={`inline-flex items-center gap-[6px] py-[3px] pr-[10px] pl-[8px] rounded-full text-[12.5px] font-medium ${current.bg} ${className}`}
    >
      {showDot && <span className={`w-[7px] h-[7px] rounded-full ${current.dot}`} />}
      {current.label}
    </span>
  );
};
