import React from 'react';
import { FrontendAsset, RiskTier } from '../types';
import { RiskChip } from '../components/RiskChip';
import { AlgoChip } from '../components/AlgoChip';

interface OverviewPageProps {
  assets: FrontendAsset[];
  scansCount?: number;
  onSelectAsset?: (assetName: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  assets,
  scansCount = 4,
  onSelectAsset,
}) => {
  const totalAssets = assets.length;
  const qvCount = assets.filter((a) => a.quantumVulnerable).length;
  const counts: Record<RiskTier, number> = {
    critical: assets.filter((a) => a.tier === 'critical').length,
    high: assets.filter((a) => a.tier === 'high').length,
    medium: assets.filter((a) => a.tier === 'medium').length,
    low: assets.filter((a) => a.tier === 'low').length,
  };

  const tiers: { id: RiskTier; label: string; colorClass: string }[] = [
    { id: 'critical', label: 'Critical', colorClass: 'bg-risk-critical' },
    { id: 'high', label: 'High', colorClass: 'bg-risk-high' },
    { id: 'medium', label: 'Medium', colorClass: 'bg-risk-medium' },
    { id: 'low', label: 'Low', colorClass: 'bg-risk-low' },
  ];

  // Top 5 highest-risk assets: auto-escalated first, then highest r
  const topAssets = [...assets]
    .sort((a, b) => {
      const scoreA = a.autoEsc ? 99 : a.r ?? 0;
      const scoreB = b.autoEsc ? 99 : b.r ?? 0;
      return scoreB - scoreA;
    })
    .slice(0, 5);

  return (
    <div>
      {/* 4 Metric Tiles */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="border border-border rounded-md p-4 bg-surface">
          <div className="text-[12px] text-ink-faint">Assets scanned</div>
          <div className="text-[26px] font-semibold mt-[6px] tracking-tight text-ink">{totalAssets}</div>
        </div>
        <div className="border border-border rounded-md p-4 bg-surface">
          <div className="text-[12px] text-ink-faint">Quantum-vulnerable</div>
          <div className="text-[26px] font-semibold mt-[6px] tracking-tight text-qubit">{qvCount}</div>
        </div>
        <div className="border border-border rounded-md p-4 bg-surface">
          <div className="text-[12px] text-ink-faint">Critical risk</div>
          <div className="text-[26px] font-semibold mt-[6px] tracking-tight text-risk-critical">
            {counts.critical}
          </div>
        </div>
        <div className="border border-border rounded-md p-4 bg-surface">
          <div className="text-[12px] text-ink-faint">Scans run</div>
          <div className="text-[26px] font-semibold mt-[6px] tracking-tight text-ink">{scansCount}</div>
        </div>
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 md:grid-cols-[1.3fr_1fr] gap-6">
        {/* Risk Distribution */}
        <div>
          <h2 className="text-[13px] font-semibold text-ink mb-3">Risk distribution</h2>
          <div className="flex flex-col gap-[10px]">
            {tiers.map((t) => {
              const count = counts[t.id];
              const pct = totalAssets > 0 ? Math.round((count / totalAssets) * 100) : 0;
              return (
                <div key={t.id} className="grid grid-cols-[70px_1fr_40px] items-center gap-3">
                  <span className="text-[12.5px] text-ink-soft">{t.label}</span>
                  <div className="h-[8px] bg-paper rounded-[4px] overflow-hidden">
                    <div
                      className={`h-full rounded-[4px] ${t.colorClass} transition-all duration-300`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="font-mono text-[12px] text-ink-faint text-right">{count}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Top 5 Highest Risk Assets */}
        <div>
          <h2 className="text-[13px] font-semibold text-ink mb-3">Top 5 highest-risk assets</h2>
          <ul className="list-none m-0 p-0 flex flex-col">
            {topAssets.map((asset, idx) => (
              <li
                key={`${asset.name}-${idx}`}
                className="flex items-center gap-3 py-[10px] border-b border-border last:border-b-0 cursor-pointer hover:bg-paper/40 transition-colors"
                onClick={() => onSelectAsset?.(asset.name)}
              >
                <span className="font-mono text-[12px] text-ink-faint w-[16px]">{idx + 1}</span>
                <span className="flex-1 text-[13px] text-ink truncate font-medium">{asset.name}</span>
                <AlgoChip>{asset.algo}</AlgoChip>
                <RiskChip tier={asset.tier || 'critical'} />
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};
