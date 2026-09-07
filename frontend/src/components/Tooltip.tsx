import React, { useState } from 'react';

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export const Tooltip: React.FC<TooltipProps> = ({ content, children, className = '' }) => {
  const [visible, setVisible] = useState(false);

  return (
    <div
      className={`relative inline-flex items-center ${className}`}
      onMouseEnter={() => setVisible(true)}
      onMouseLeave={() => setVisible(false)}
    >
      {children}
      {visible && (
        <div className="absolute bottom-[calc(100%+8px)] left-1/2 -translate-x-1/2 z-50 bg-ink text-white text-[12px] py-[6px] px-[10px] rounded-sm whitespace-nowrap pointer-events-none shadow-none">
          {content}
          <div className="absolute top-full left-1/2 -translate-x-1/2 border-[5px] border-transparent border-t-ink" />
        </div>
      )}
    </div>
  );
};
