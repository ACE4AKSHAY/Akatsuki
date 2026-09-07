import React from 'react';

interface AlgoChipProps {
  children: React.ReactNode;
  className?: string;
}

export const AlgoChip: React.FC<AlgoChipProps> = ({ children, className = '' }) => {
  return (
    <span
      className={`font-mono text-[12px] bg-paper border border-border rounded-sm py-[2px] px-[7px] text-ink-soft inline-block ${className}`}
    >
      {children}
    </span>
  );
};
