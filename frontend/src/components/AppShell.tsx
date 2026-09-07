import React from 'react';
import { Screen } from '../types';
import { RiskChip } from './RiskChip';

interface AppShellProps {
  currentScreen: Screen;
  onScreenChange: (screen: Screen) => void;
  criticalCount: number;
  scanTargetName?: string;
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({
  currentScreen,
  onScreenChange,
  criticalCount,
  scanTargetName = 'payments-platform · main branch',
  children,
}) => {
  const screens: { id: Screen; label: string; icon: React.ReactNode }[] = [
    {
      id: 'overview',
      label: 'Overview',
      icon: (
        <svg width="16" height="16" viewBox="0 0 22 22" fill="none" strokeWidth="1.6" className="shrink-0">
          <rect x="3" y="3" width="7" height="7" rx="1" />
          <rect x="12" y="3" width="7" height="7" rx="1" />
          <rect x="3" y="12" width="7" height="7" rx="1" />
          <rect x="12" y="12" width="7" height="7" rx="1" />
        </svg>
      ),
    },
    {
      id: 'inventory',
      label: 'Inventory',
      icon: (
        <svg width="16" height="16" viewBox="0 0 22 22" fill="none" strokeWidth="1.6" strokeLinecap="round" className="shrink-0">
          <line x1="3" y1="6" x2="19" y2="6" />
          <line x1="3" y1="11" x2="15" y2="11" />
          <line x1="3" y1="16" x2="17" y2="16" />
        </svg>
      ),
    },
    {
      id: 'heatmap',
      label: 'Risk heatmap',
      icon: (
        <svg width="16" height="16" viewBox="0 0 22 22" fill="none" className="shrink-0">
          <circle cx="5" cy="15" r="1.8" />
          <circle cx="10" cy="7" r="1.8" />
          <circle cx="16" cy="12" r="1.8" />
          <circle cx="19" cy="5" r="1.8" />
        </svg>
      ),
    },
    {
      id: 'detail',
      label: 'Asset detail',
      icon: (
        <svg width="16" height="16" viewBox="0 0 22 22" fill="none" strokeWidth="1.6" strokeLinecap="round" className="shrink-0">
          <rect x="4" y="3" width="14" height="16" rx="1" />
          <line x1="7" y1="8" x2="15" y2="8" />
          <line x1="7" y1="12" x2="15" y2="12" />
          <line x1="7" y1="16" x2="12" y2="16" />
        </svg>
      ),
    },
    {
      id: 'recommend',
      label: 'Recommendations',
      icon: (
        <svg width="16" height="16" viewBox="0 0 22 22" fill="none" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
          <circle cx="11" cy="11" r="8" />
          <path d="M8 11l2 2 4-5" />
        </svg>
      ),
    },
  ];

  const currentTitle = screens.find((s) => s.id === currentScreen)?.label || 'Overview';

  return (
    <div className="border border-border rounded-md overflow-hidden grid grid-cols-1 md:grid-cols-[200px_1fr] bg-surface">
      {/* Left Rail */}
      <aside className="bg-ink p-4 md:py-4 md:px-3 flex flex-row md:flex-col gap-1 overflow-x-auto md:overflow-x-visible">
        <div className="hidden md:flex items-center gap-2 text-white px-2 pb-4">
          <svg width="16" height="16" viewBox="0 0 22 22" fill="none">
            <circle cx="11" cy="11" r="9" stroke="#0E9C90" strokeWidth="1.4" />
            <circle cx="11" cy="11" r="2" fill="#0E9C90" />
          </svg>
          <span className="font-semibold text-[13px] tracking-tight">ECDAT</span>
        </div>

        {screens.map((screen) => {
          const isActive = currentScreen === screen.id;
          return (
            <button
              key={screen.id}
              type="button"
              onClick={() => onScreenChange(screen.id)}
              className={`flex items-center gap-[10px] py-[9px] px-[10px] rounded-sm text-[13px] cursor-pointer transition-colors text-left w-full font-sans border-none ${
                isActive
                  ? 'bg-[#0E9C90]/15 text-white font-medium [&_svg]:stroke-qubit [&_svg_circle]:fill-qubit'
                  : 'text-[#B7BECF] bg-transparent hover:bg-white/5 hover:text-white [&_svg]:stroke-[#B7BECF] hover:[&_svg]:stroke-white'
              }`}
            >
              {screen.icon}
              <span className="whitespace-nowrap">{screen.label}</span>
            </button>
          );
        })}
      </aside>

      {/* Main Panel */}
      <main className="min-h-[520px] flex flex-col bg-surface">
        {/* Topbar */}
        <header className="flex items-center justify-between py-3 px-5 border-b border-border">
          <div>
            <h1 className="text-[14px] font-semibold text-ink">{currentTitle}</h1>
            <div className="text-[12px] text-ink-faint mt-[2px]">Scan target: {scanTargetName}</div>
          </div>
          <div className="flex gap-3 items-center">
            <RiskChip tier="critical" showDot={true} />
            <span className="text-[12px] text-ink-faint font-mono">({criticalCount} assets)</span>
          </div>
        </header>

        {/* Content View */}
        <div className="p-5 flex-1">{children}</div>
      </main>
    </div>
  );
};
