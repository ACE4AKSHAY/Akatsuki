import React from 'react';
import { FrontendAsset } from '../types';
import { Button } from '../components/Button';
import { RiskChip } from '../components/RiskChip';
import { downloadReportUrl, downloadCBOMUrl } from '../api';

interface RecommendationsPageProps {
  assets: FrontendAsset[];
  scanId?: string;
  onSelectAsset?: (name: string) => void;
}

export const RecommendationsPage: React.FC<RecommendationsPageProps> = ({
  assets,
  scanId = 'latest',
  onSelectAsset,
}) => {
  // Sort recommendations: auto-escalated first, then highest r
  const actionableAssets = assets
    .filter((a) => a.rec !== 'No change needed')
    .sort((a, b) => {
      const scoreA = a.autoEsc ? 99 : a.r ?? 0;
      const scoreB = b.autoEsc ? 99 : b.r ?? 0;
      return scoreB - scoreA;
    });

  const handleExport = (format: 'pdf' | 'csv' | 'cbom') => {
    let url: string;
    if (format === 'cbom') {
      url = downloadCBOMUrl(scanId);
    } else {
      url = downloadReportUrl(scanId, format);
    }
    window.open(url, '_blank');
  };

  return (
    <div>
      {/* Export Row */}
      <div className="flex gap-[10px] mb-5 flex-wrap">
        <Button variant="secondary" onClick={() => handleExport('pdf')}>
          Export PDF
        </Button>
        <Button variant="secondary" onClick={() => handleExport('csv')}>
          Export CSV
        </Button>
        <Button variant="secondary" onClick={() => handleExport('cbom')}>
          Export CBOM JSON
        </Button>
      </div>

      {/* Recommendations Table */}
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-[12.8px]">
          <thead>
            <tr>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong pl-0">
                Asset
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Migration
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Complexity
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Standard
              </th>
              <th className="text-left font-medium text-ink-faint text-[11px] pb-2 border-b border-border-strong">
                Risk
              </th>
            </tr>
          </thead>
          <tbody>
            {actionableAssets.map((asset, idx) => (
              <tr
                key={`${asset.name}-${idx}`}
                className="hover:bg-paper/50 cursor-pointer transition-colors"
                onClick={() => onSelectAsset?.(asset.name)}
              >
                <td className="py-[11px] pr-2 pl-0 border-b border-border font-medium text-ink">{asset.name}</td>
                <td className="py-[11px] pr-2 border-b border-border">
                  <div className="flex items-center gap-2 font-mono text-[12px]">
                    <span className="text-ink">{asset.algo}</span>
                    <span className="text-ink-faint">→</span>
                    <span className="text-qubit font-semibold">{asset.rec}</span>
                  </div>
                </td>
                <td className="py-[11px] pr-2 border-b border-border text-ink-soft">{asset.complexity}</td>
                <td className="py-[11px] pr-2 border-b border-border font-mono text-[12px] text-ink-soft">
                  {asset.std}
                </td>
                <td className="py-[11px] pr-2 border-b border-border">
                  <RiskChip tier={asset.tier || 'critical'} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
