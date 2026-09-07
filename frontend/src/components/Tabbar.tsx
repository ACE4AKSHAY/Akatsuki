import React from 'react';

interface TabOption {
  id: string;
  label: string;
}

interface TabbarProps {
  tabs: TabOption[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
}

export const Tabbar: React.FC<TabbarProps> = ({ tabs, activeTab, onChange, className = '' }) => {
  return (
    <div className={`inline-flex border border-border rounded-sm overflow-hidden ${className}`}>
      {tabs.map((tab) => {
        const isActive = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onChange(tab.id)}
            className={`font-sans text-[13px] py-[7px] px-[14px] border-none transition-colors cursor-pointer border-r border-border last:border-r-0 ${
              isActive ? 'bg-cipher-soft text-cipher font-semibold' : 'bg-surface text-ink-soft hover:text-ink'
            }`}
          >
            {tab.label}
          </button>
        );
      })}
    </div>
  );
};
