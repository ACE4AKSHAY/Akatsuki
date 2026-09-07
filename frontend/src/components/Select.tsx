import React from 'react';

interface SelectOption {
  value: string;
  label: string;
}

interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: (string | SelectOption)[];
}

export const Select: React.FC<SelectProps> = ({ label, id, options, className = '', ...props }) => {
  const selectId = id || (label ? label.toLowerCase().replace(/\s+/g, '-') : undefined);

  return (
    <div className="flex flex-col gap-[6px]">
      {label && (
        <label htmlFor={selectId} className="text-[12.5px] text-ink-soft">
          {label}
        </label>
      )}
      <select
        id={selectId}
        className={`font-sans text-[13.5px] py-[8px] px-[10px] border border-border-strong rounded-sm bg-surface text-ink min-w-[200px] focus:border-cipher outline-none transition-colors ${className}`}
        {...props}
      >
        {options.map((opt) => {
          const val = typeof opt === 'string' ? opt : opt.value;
          const lbl = typeof opt === 'string' ? opt : opt.label;
          return (
            <option key={val} value={val}>
              {lbl}
            </option>
          );
        })}
      </select>
    </div>
  );
};
