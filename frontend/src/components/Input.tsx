import React from 'react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
}

export const Input: React.FC<InputProps> = ({ label, id, className = '', ...props }) => {
  const inputId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);

  return (
    <div className="flex flex-col gap-[6px]">
      {label && (
        <label htmlFor={inputId} className="text-[12.5px] text-ink-soft">
          {label}
        </label>
      )}
      <input
        id={inputId}
        className={`font-sans text-[13.5px] py-[8px] px-[10px] border border-border-strong rounded-sm bg-surface text-ink min-w-[200px] focus:border-cipher outline-none transition-colors ${className}`}
        {...props}
      />
    </div>
  );
};
