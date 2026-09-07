import React from 'react';
import { FrontendAsset } from '../types';
import { RiskChip } from '../components/RiskChip';

interface AssetDetailPageProps {
  asset: FrontendAsset;
  z: number;
  allAssets?: FrontendAsset[];
  onSelectAsset?: (name: string) => void;
}

export const AssetDetailPage: React.FC<AssetDetailPageProps> = ({
  asset,
  z,
  allAssets = [],
  onSelectAsset,
}) => {
  const r = (asset.x + asset.y) / z;
  const isCritical = asset.autoEsc || r >= 1.2;
  const tier = asset.tier || (isCritical ? 'critical' : (r >= 0.9 ? 'high' : (r >= 0.6 ? 'medium' : 'low')));

  return (
    <div>
      {/* Asset Selector Dropdown if multiple exist */}
      {allAssets.length > 1 && (
        <div className="mb-5 flex items-center gap-3">
          <label className="text-[12.5px] text-ink-soft">Select asset to inspect:</label>
          <select
            value={asset.name}
            onChange={(e) => onSelectAsset?.(e.target.value)}
            className="font-sans text-[13px] py-1 px-2 border border-border-strong rounded-sm bg-surface text-ink focus:border-cipher outline-none"
          >
            {allAssets.map((a) => (
              <option key={a.name} value={a.name}>
                {a.name} ({a.algo})
              </option>
            ))}
          </select>
        </div>
      )}

      {/* Detail Head */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h2 className="text-[17px] font-semibold text-ink">{asset.name}</h2>
          <p className="text-[12.5px] font-mono text-ink-soft mt-1">{asset.loc}</p>
        </div>
        <RiskChip tier={tier} />
      </div>

      {/* Ratio Callout */}
      <div
        className={`flex items-center justify-between p-4 rounded-md mb-5 border border-transparent ${
          isCritical
            ? 'bg-risk-critical-bg text-risk-critical'
            : (tier === 'high' ? 'bg-risk-high-bg text-risk-high' : 'bg-paper text-ink')
        }`}
      >
        <div>
          <div className="text-[12.5px] font-medium opacity-85">Mosca's inequality: X + Y &gt; Z</div>
          <div className="text-[13px] mt-[2px]">
            {asset.x} yrs shelf-life + {asset.y} yrs migration{' '}
            {asset.x + asset.y > z ? '>' : '≤'} {z} yr threat timeline —{' '}
            {asset.autoEsc
              ? 'Classically broken primitive, immediate deprecation required.'
              : (asset.x + asset.y > z ? 'past the threshold, migrate now.' : 'within safety threshold.')}
          </div>
        </div>
        <div className="font-mono text-[20px] font-semibold">
          r = {r.toFixed(2)}
        </div>
      </div>

      {/* Breakdown Grid: X, Y, Z */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 my-5">
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">X · shelf-life</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{asset.x} yrs</div>
        </div>
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">Y · migration time</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{asset.y} yrs</div>
        </div>
        <div className="border border-border rounded-md p-4 text-center bg-surface">
          <div className="text-[11px] text-ink-faint">Z · threat timeline</div>
          <div className="text-[22px] font-semibold mt-[6px] font-mono text-ink">{z} yrs</div>
        </div>
      </div>

      {/* Recommendation Card */}
      <div className="border border-border rounded-md p-5 bg-surface">
        <h3 className="text-[13px] font-semibold text-ink mb-3">Recommended replacement</h3>
        <div className="flex flex-col md:flex-row items-stretch md:items-center gap-4 my-4">
          <div className="flex-1 border border-border rounded-sm p-3 bg-surface">
            <div className="text-[11px] text-ink-faint">Current</div>
            <div className="font-mono text-[14px] mt-1 text-ink">{asset.algo}</div>
          </div>
          <div className="text-ink-faint text-[18px] text-center">→</div>
          <div className="flex-1 border border-qubit rounded-sm p-3 bg-qubit-soft">
            <div className="text-[11px] text-ink-faint">Recommended</div>
            <div className="font-mono text-[14px] mt-1 text-qubit font-semibold">{asset.rec}</div>
          </div>
        </div>
        <div className="flex gap-6 mt-4 text-[12.5px] text-ink-soft flex-wrap">
          <span>
            Complexity: <b className="text-ink font-medium">{asset.complexity}</b>
          </span>
          <span>
            Standard: <b className="text-ink font-medium">{asset.std}</b>
          </span>
          {asset.sizeDelta && (
            <span>
              Size delta: <b className="text-ink font-medium">{asset.sizeDelta}</b>
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
