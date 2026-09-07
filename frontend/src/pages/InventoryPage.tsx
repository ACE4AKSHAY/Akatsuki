import React, { useState } from 'react';
import { FrontendAsset, RiskTier } from '../types';
import { RiskChip } from '../components/RiskChip';

interface InventoryPageProps {
  assets: FrontendAsset[];
  onSelectAsset?: (assetName: string) => void;
}

export const InventoryPage: React.FC<InventoryPageProps> = ({ assets, onSelectAsset }) => {
  const [filter, setFilter] = useState<'all' | RiskTier>('all');

  const filterOptions: { id: 'all' | RiskTier; label: string }[] = [
    { id: 'all', label: 'All' },
    { id: 'critical', label: 'Critical' },
    { id: 'high', label: 'High' },
    { id: 'medium', label: 'Medium' },
    { id: 'low', label: 'Low' },
  ];

  const filteredAssets = assets.filter((a) => filter === 'all' || a.tier === filter);

  return (
    <div>
      {/* Filter Chips */}
      <div className="flex gap-2 mb-4 flex-wrap">
        {filterOptions.map((opt) => {
          const isActive = filter === opt.id;
          return (
            <button
              key={opt.id}
              type="button"
              onClick={() => setFilter(opt.id)}
              className={`text-[12.5px] py-[6px] px-[12px] rounded-full border cursor-pointer transition-colors font-sans ${
                isActive
                  ? 'bg-ink text-white border-ink'
                  : 'bg-surface text-ink-soft border-border-strong hover:border-ink-faint'
              }`}
            >
              {opt.label}
            </button>
          );
        })}
      </div>

      {/* Inventory Table */}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[12.8px]">
          <thead>
            <tr>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong pl-0">
                Asset
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Type
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Algorithm
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Location
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Business unit
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Risk
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.map((asset, idx) => (
              <tr
                key={`${asset.name}-${idx}`}
                className="hover:bg-paper/50 cursor-pointer transition-colors"
                onClick={() => onSelectAsset?.(asset.name)}
              >
                <td className="py-[10px] pr-2 pl-0 border-b border-border text-ink font-medium">{asset.name}</td>
                <td className="py-[10px] pr-2 border-b border-border text-ink-soft">{asset.type}</td>
                <td className="py-[10px] pr-2 border-b border-border font-mono text-[12px] text-ink-soft">
                  {asset.algo}
                </td>
                <td className="py-[10px] pr-2 border-b border-border font-mono text-[12px] text-ink-soft">
                  {asset.loc}
                </td>
                <td className="py-[10px] pr-2 border-b border-border text-ink-soft">{asset.bu}</td>
                <td className="py-[10px] pr-2 border-b border-border">
                  <RiskChip tier={asset.tier || 'low'} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
