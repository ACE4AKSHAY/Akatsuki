import React, { useState, useEffect, useMemo } from 'react';
import { Screen, FrontendAsset } from './types';
import {
  INITIAL_SAMPLE_ASSETS,
  computeAllAssetsWithZ,
  fetchLiveAssets,
  fetchScans,
  startScan,
} from './api';
import { AppShell } from './components/AppShell';
import { OverviewPage } from './pages/OverviewPage';
import { InventoryPage } from './pages/InventoryPage';
import { HeatmapPage } from './pages/HeatmapPage';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { RecommendationsPage } from './pages/RecommendationsPage';
import { Button } from './components/Button';
import { Input } from './components/Input';

export const App: React.FC = () => {
  const [currentScreen, setCurrentScreen] = useState<Screen>('overview');
  const [z, setZ] = useState<number>(8);
  const [rawAssets, setRawAssets] = useState<FrontendAsset[]>(INITIAL_SAMPLE_ASSETS);
  const [selectedAssetName, setSelectedAssetName] = useState<string>('Customer PII field encryption');
  const [scanTargetInput, setScanTargetInput] = useState<string>('github.com/org/payments-platform');
  const [activeScanId, setActiveScanId] = useState<string>('scan_default');
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [scanCount, setScanCount] = useState<number>(4);

  // Load initial data from FastAPI backend if running
  useEffect(() => {
    async function loadData() {
      try {
        const scans = await fetchScans();
        if (scans && scans.length > 0) {
          setScanCount(scans.length);
          const latest = scans[0];
          setActiveScanId(latest.scanId);
          const liveAssets = await fetchLiveAssets(latest.scanId);
          if (liveAssets && liveAssets.length > 0) {
            setRawAssets(liveAssets);
          }
        } else {
          // Try fetching without scanId
          const liveAssets = await fetchLiveAssets();
          if (liveAssets && liveAssets.length > 0) {
            setRawAssets(liveAssets);
          }
        }
      } catch (e) {
        console.warn('Backend offline or initializing; running with prototype dataset.');
      }
    }
    loadData();
  }, []);

  // Client-side reactive recomputation of Mosca ratio and risk tiers whenever Z changes
  const computedAssets = useMemo(() => {
    return computeAllAssetsWithZ(rawAssets, z);
  }, [rawAssets, z]);

  const criticalCount = useMemo(() => {
    return computedAssets.filter((a) => a.tier === 'critical').length;
  }, [computedAssets]);

  const selectedAsset = useMemo(() => {
    return computedAssets.find((a) => a.name === selectedAssetName) || computedAssets[0];
  }, [computedAssets, selectedAssetName]);

  const handleSelectAsset = (assetName: string) => {
    setSelectedAssetName(assetName);
    setCurrentScreen('detail');
  };

  const handleTriggerScan = async () => {
    if (!scanTargetInput.trim()) return;
    setIsScanning(true);
    try {
      const scanRes = await startScan(scanTargetInput, 'path');
      if (scanRes) {
        setActiveScanId(scanRes.scanId);
        setScanCount((prev) => prev + 1);
        // Wait briefly for backend processing
        setTimeout(async () => {
          const freshAssets = await fetchLiveAssets(scanRes.scanId);
          if (freshAssets && freshAssets.length > 0) {
            setRawAssets(freshAssets);
          }
          setIsScanning(false);
        }, 1200);
      } else {
        setIsScanning(false);
      }
    } catch {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-paper text-ink font-sans">
      {/* Top Document Header */}
      <header className="sticky top-0 z-50 bg-[#F2F4F5]/90 backdrop-blur-md border-b border-border">
        <div className="max-w-[1180px] mx-auto h-[56px] px-6 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <circle cx="4" cy="4" r="2" fill="#4B5262" />
              <circle cx="11" cy="4" r="2" fill="#4B5262" />
              <circle cx="18" cy="4" r="2" fill="#4B5262" />
              <circle cx="4" cy="11" r="2" fill="#4B5262" />
              <circle cx="18" cy="11" r="2" fill="#4B5262" />
              <circle cx="4" cy="18" r="2" fill="#4B5262" />
              <circle cx="11" cy="18" r="2" fill="#4B5262" />
              <circle cx="18" cy="18" r="2" fill="#4B5262" />
              <circle cx="11" cy="11" r="2.4" fill="#0E9C90" />
              <line x1="4" y1="4" x2="11" y2="11" stroke="#0E9C90" strokeWidth="1" />
              <line x1="11" y1="11" x2="18" y2="4" stroke="#E1E5E8" strokeWidth="1" />
            </svg>
            <span className="font-semibold text-[14px] tracking-tight">ECDAT</span>
          </div>

          <div className="flex items-center gap-5 text-[13.5px] font-medium text-ink-soft">
            <button
              type="button"
              onClick={() => setCurrentScreen('overview')}
              className={`hover:text-ink transition-colors cursor-pointer border-none bg-transparent ${
                currentScreen === 'overview' ? 'text-ink font-semibold' : ''
              }`}
            >
              Overview
            </button>
            <button
              type="button"
              onClick={() => setCurrentScreen('inventory')}
              className={`hover:text-ink transition-colors cursor-pointer border-none bg-transparent ${
                currentScreen === 'inventory' ? 'text-ink font-semibold' : ''
              }`}
            >
              Inventory
            </button>
            <button
              type="button"
              onClick={() => setCurrentScreen('heatmap')}
              className={`hover:text-ink transition-colors cursor-pointer border-none bg-transparent ${
                currentScreen === 'heatmap' ? 'text-ink font-semibold' : ''
              }`}
            >
              Heatmap
            </button>
            <button
              type="button"
              onClick={() => setCurrentScreen('recommend')}
              className={`hover:text-ink transition-colors cursor-pointer border-none bg-transparent ${
                currentScreen === 'recommend' ? 'text-ink font-semibold' : ''
              }`}
            >
              Recommendations
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <div className="max-w-[1180px] mx-auto px-6 py-8">
        {/* Quick Scan Input Bar */}
        <div className="mb-6 p-4 border border-border rounded-md bg-surface flex flex-col md:flex-row items-stretch md:items-end gap-3 justify-between">
          <div className="flex-1">
            <Input
              label="Repository URL or target path for automated scan"
              value={scanTargetInput}
              onChange={(e) => setScanTargetInput(e.target.value)}
              placeholder="github.com/org/payments-platform"
              className="w-full"
            />
          </div>
          <Button
            variant="primary"
            onClick={handleTriggerScan}
            disabled={isScanning}
            className="whitespace-nowrap"
          >
            {isScanning ? 'Scanning...' : 'Start scan'}
          </Button>
        </div>

        {/* Prototype Label */}
        <div className="font-mono text-[11.5px] text-ink-faint flex items-center gap-[6px] mb-3">
          <span className="w-[6px] h-[6px] rounded-full bg-qubit" />
          Interactive system — {computedAssets.length} assets loaded
        </div>

        {/* The 5-Screen App Shell */}
        <AppShell
          currentScreen={currentScreen}
          onScreenChange={setCurrentScreen}
          criticalCount={criticalCount}
          scanTargetName={scanTargetInput}
        >
          {currentScreen === 'overview' && (
            <OverviewPage
              assets={computedAssets}
              scansCount={scanCount}
              onSelectAsset={handleSelectAsset}
            />
          )}

          {currentScreen === 'inventory' && (
            <InventoryPage assets={computedAssets} onSelectAsset={handleSelectAsset} />
          )}

          {currentScreen === 'heatmap' && (
            <HeatmapPage
              assets={computedAssets}
              z={z}
              onZChange={setZ}
              onSelectAsset={handleSelectAsset}
            />
          )}

          {currentScreen === 'detail' && (
            <AssetDetailPage
              asset={selectedAsset}
              z={z}
              allAssets={computedAssets}
              onSelectAsset={setSelectedAssetName}
            />
          )}

          {currentScreen === 'recommend' && (
            <RecommendationsPage
              assets={computedAssets}
              scanId={activeScanId}
              onSelectAsset={handleSelectAsset}
            />
          )}
        </AppShell>

        {/* Footer */}
        <footer className="py-8 text-ink-faint text-[12px] font-mono text-center">
          ECDAT design system v1.0 — tokens defined in :root, wired to FastAPI backend M7.
        </footer>
      </div>
    </div>
  );
};
