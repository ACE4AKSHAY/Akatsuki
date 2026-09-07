export type RiskTier = 'critical' | 'high' | 'medium' | 'low';

export type Screen = 'overview' | 'inventory' | 'heatmap' | 'detail' | 'recommend';

export interface FrontendAsset {
  id?: string;
  name: string;
  type: string;
  algo: string;
  rec: string;
  std: string;
  complexity: string;
  loc: string;
  bu: string;
  x: number;
  y: number;
  autoEsc: boolean;
  r?: number;
  tier?: RiskTier;
  quantumVulnerable?: boolean;
  businessCriticality?: string;
  exposure?: string;
  vulnerabilityReason?: string;
  sizeDelta?: string;
}

export interface AssetSummaryResponse {
  items: any[];
  total: number;
  page: number;
  pageSize: number;
  pages: number;
  zUsed: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export interface ScanResponse {
  scanId: string;
  sourceType: string;
  target: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  assetCount: number;
  createdAt: string;
  completedAt?: string;
  error?: string;
}
