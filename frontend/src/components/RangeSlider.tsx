import React from 'react';

interface RangeSliderProps {
  label: string;
  value: number;
  min?: number;
  max?: number;
  step?: number;
  unit?: string;
  onChange: (value: number) => void;
  className?: string;
}

export const RangeSlider: React.FC<RangeSliderProps> = ({
  label,
  value,
  min = 3,
  max = 20,
  step = 1,
  unit = 'yrs',
  onChange,
  className = '',
}) => {
  const percentage = Math.min(Math.max(((value - min) / (max - min)) * 100, 0), 100);

  return (
    <div className={`w-full max-w-[420px] ${className}`}>
      <div className="flex justify-between text-[12.5px] text-ink-soft mb-2">
        <span>{label}</span>
        <b className="text-ink font-mono font-semibold">
          {value} {unit}
        </b>
      </div>
      <input
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="ecdat-slider cursor-pointer"
        style={{
          background: `linear-gradient(90deg, var(--qubit, #0E9C90) ${percentage}%, var(--border-strong, #C7CDD3) ${percentage}%)`,
        }}
      />
    </div>
  );
};
