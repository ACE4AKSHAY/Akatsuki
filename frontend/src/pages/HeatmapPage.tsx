import React, { useState } from 'react';
import { FrontendAsset, RiskTier } from '../types';
import { RangeSlider } from '../components/RangeSlider';
import { RiskChip } from '../components/RiskChip';

interface HeatmapPageProps {
  assets: FrontendAsset[];
  z: number;
  onZChange: (z: number) => void;
  onSelectAsset?: (assetName: string) => void;
}

const critRow: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const tierColorMap: Record<RiskTier, string> = {
  critical: 'var(--risk-critical, #B3261E)',
  high: 'var(--risk-high, #B5590F)',
  medium: 'var(--risk-medium, #93790E)',
  low: 'var(--risk-low, #2E7D5B)',
};

export const HeatmapPage: React.FC<HeatmapPageProps> = ({
  assets,
  z,
  onZChange,
  onSelectAsset,
}) => {
  const [hoveredAsset, setHoveredAsset] = useState<FrontendAsset | null>(null);
  const maxR = 2.5;

  const thresholdLeft = Math.min((1 / maxR) * 100, 100);

  // Position calculation with row jitter
  const rowCounts: Record<number, number> = {};
  const dotElements = assets.map((a, index) => {
    const r = a.r ?? (a.x + a.y) / z;
    const tier = a.tier ?? (a.autoEsc ? 'critical' : (r >= 1.2 ? 'critical' : (r >= 0.9 ? 'high' : (r >= 0.6 ? 'medium' : 'low'))));
    const critKey = a.businessCriticality || 'Medium';
    const rowIndex = critRow[critKey] ?? 2;

    const jitter = (rowCounts[rowIndex] || 0) * 8;
    rowCounts[rowIndex] = (rowCounts[rowIndex] || 0) + 1;

    const left = Math.min((r / maxR) * 100, 97);
    const top = Math.min(rowIndex * 25 + 6 + jitter, 88);

    return {
      asset: a,
      r,
      tier,
      left,
      top,
      key: `${a.name}-${index}`,
    };
  });

  const criticalCount = assets.filter((a) => a.tier === 'critical').length;

  return (
    <div className="border border-border rounded-md p-5 bg-surface">
      {/* Slider */}
      <RangeSlider
        label="Years until a quantum computer breaks today's crypto (Z)"
        value={z}
        min={3}
        max={20}
        step={1}
        onChange={onZChange}
        className="max-w-full mb-2"
      />

      <p className="text-[12.5px] text-ink-soft mt-[6px]">
        At a <b className="text-ink font-mono">{z}-year</b> threat timeline,{' '}
        <span className="text-risk-critical font-medium">{criticalCount}</span> of {assets.length} assets are Critical.
      </p>

      {/* Quadrant Canvas */}
      <div className="relative h-[280px] mt-6 ml-[70px] border-l border-b border-border-strong bg-paper/20">
        {/* Row Labels (Y-axis: Business Criticality) */}
        <div className="absolute -left-[70px] w-[64px] text-[11px] text-ink-faint text-right top-[0%]">Critical</div>
        <div className="absolute -left-[70px] w-[64px] text-[11px] text-ink-faint text-right top-[25%]">High</div>
        <div className="absolute -left-[70px] w-[64px] text-[11px] text-ink-faint text-right top-[50%]">Medium</div>
        <div className="absolute -left-[70px] w-[64px] text-[11px] text-ink-faint text-right top-[75%]">Low</div>

        {/* Threshold Line at r = 1 */}
        <div
          className="absolute top-0 bottom-0 w-[1px] bg-ink-faint/35 z-0"
          style={{ left: `${thresholdLeft}%` }}
        />
        <div
          className="absolute -top-[18px] text-[10.5px] text-ink-faint font-mono -translate-x-1/2"
          style={{ left: `${thresholdLeft}%` }}
        >
          r = 1
        </div>

        {/* Asset Dots */}
        {dotElements.map((item) => {
          const bg = tierColorMap[item.tier];
          const isEscalated = item.asset.autoEsc;

          return (
            <div
              key={item.key}
              className={`heatmap-dot z-10 ${isEscalated ? 'is-escalated' : ''}`}
              style={{
                left: `${item.left}%`,
                top: `${item.top}%`,
                background: bg,
              }}
              onMouseEnter={() => setHoveredAsset(item.asset)}
              onMouseLeave={() => setHoveredAsset(null)}
              onClick={() => onSelectAsset?.(item.asset.name)}
              title={`${item.asset.name} — ${item.asset.algo} — r=${item.r.toFixed(2)}${
                isEscalated ? ' (auto-escalated: classically broken)' : ''
              }`}
            />
          );
        })}
      </div>

      {/* X-axis Label */}
      <div className="ml-[70px] mt-2 text-[11px] text-ink-faint font-mono">
        urgency ratio r = (X + Y) / Z →
      </div>

      {/* Hover Info Card */}
      {hoveredAsset && (
        <div className="mt-4 p-3 bg-paper border border-border rounded-sm flex items-center justify-between text-[12.5px]">
          <div>
            <span className="font-semibold text-ink">{hoveredAsset.name}</span>{' '}
            <span className="font-mono text-ink-soft">({hoveredAsset.algo})</span>
            <div className="text-[11.5px] text-ink-faint mt-1">
              X={hoveredAsset.x} yrs, Y={hoveredAsset.y} yrs, Z={z} yrs →{' '}
              <b className="font-mono text-ink">r={((hoveredAsset.x + hoveredAsset.y) / z).toFixed(2)}</b>
              {hoveredAsset.autoEsc && ' (Classically broken auto-escalation)'}
            </div>
          </div>
          <RiskChip tier={hoveredAsset.tier || 'critical'} />
        </div>
      )}

      {/* Legend Row */}
      <div className="flex gap-5 mt-5 flex-wrap items-center">
        <RiskChip tier="critical" />
        <RiskChip tier="high" />
        <RiskChip tier="medium" />
        <RiskChip tier="low" />
        <span className="text-[12.5px] text-ink-soft flex items-center gap-[6px]">
          <span className="w-[12px] h-[12px] rounded-full bg-risk-critical ring-[3px] ring-risk-critical/20 inline-block" />
          ring = classically broken (auto-escalated)
        </span>
      </div>
    </div>
  );
};
