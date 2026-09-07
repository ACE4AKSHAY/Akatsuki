import React from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost';
  children: React.ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  variant = 'primary',
  className = '',
  disabled,
  children,
  ...props
}) => {
  const baseClasses =
    'font-sans text-[13.5px] font-medium cursor-pointer rounded-sm py-[9px] px-[16px] border transition-colors inline-flex items-center justify-center gap-2';

  const variantClasses = {
    primary: 'bg-cipher text-white border-transparent hover:bg-[#1e2f5e]',
    secondary: 'bg-surface text-ink border-border-strong hover:border-ink-faint',
    ghost: 'bg-transparent text-ink-soft border-transparent hover:text-ink',
  };

  const disabledClasses = disabled ? 'opacity-40 cursor-not-allowed pointer-events-none' : '';

  return (
    <button
      className={`${baseClasses} ${variantClasses[variant]} ${disabledClasses} ${className}`}
      disabled={disabled}
      {...props}
    >
      {children}
    </button>
  );
};
