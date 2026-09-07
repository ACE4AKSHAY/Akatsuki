import { FrontendAsset, AssetSummaryResponse, ScanResponse, RiskTier } from './types';

export const INITIAL_SAMPLE_ASSETS: FrontendAsset[] = [
  { name: "Customer PII field encryption", type: "Algorithm", algo: "RSA-2048", rec: "ML-KEM-768 (hybrid)", std: "FIPS 203", complexity: "Medium", loc: "services/pii/encrypt.py:88", bu: "Payments", x: 15, y: 1.5, autoEsc: false, quantumVulnerable: true, businessCriticality: "Critical", sizeDelta: "~5.9× larger public key" },
  { name: "Firmware signing", type: "Algorithm", algo: "RSA-2048", rec: "ML-DSA-65", std: "FIPS 204", complexity: "Medium", loc: "firmware/sign_tool.c:210", bu: "Devices", x: 10, y: 2, autoEsc: false, quantumVulnerable: true, businessCriticality: "High", sizeDelta: "~4.7× larger signature" },
  { name: "Payment gateway TLS handshake", type: "Protocol", algo: "RSA-2048 (TLS KEX)", rec: "ML-KEM-768 (hybrid)", std: "FIPS 203", complexity: "Medium", loc: "infra/nginx/gateway.conf:14", bu: "Payments", x: 7, y: 1, autoEsc: false, quantumVulnerable: true, businessCriticality: "Critical" },
  { name: "VPN tunnel", type: "Algorithm", algo: "3DES", rec: "AES-256-GCM", std: "—", complexity: "Medium", loc: "infra/ipsec/vpn.conf:52", bu: "Network", x: 5, y: 0.5, autoEsc: true, quantumVulnerable: false, businessCriticality: "High" },
  { name: "Session token hashing", type: "Algorithm", algo: "SHA-1", rec: "SHA-384 / SHA3-384", std: "—", complexity: "Low", loc: "auth/session.py:19", bu: "Platform", x: 1, y: 0.1, autoEsc: true, quantumVulnerable: false, businessCriticality: "High" },
  { name: "Customer DB key wrap", type: "Algorithm", algo: "RSA-2048", rec: "ML-KEM-768 (hybrid)", std: "FIPS 203", complexity: "Medium", loc: "services/db/kms_wrap.go:41", bu: "Data Platform", x: 8, y: 1.5, autoEsc: false, quantumVulnerable: true, businessCriticality: "Critical" },
  { name: "Backup archive encryption", type: "Algorithm", algo: "AES-128", rec: "AES-256", std: "—", complexity: "Low", loc: "ops/backup/archive.py:77", bu: "IT Ops", x: 6, y: 1, autoEsc: false, quantumVulnerable: false, businessCriticality: "Medium" },
  { name: "Log pipeline TLS", type: "Protocol", algo: "ECDHE-P256", rec: "ML-KEM-768 (hybrid)", std: "FIPS 203", complexity: "Low", loc: "infra/k8s/logging.yaml:33", bu: "Platform", x: 2, y: 0.5, autoEsc: false, quantumVulnerable: true, businessCriticality: "Low" },
  { name: "Internal API auth", type: "Algorithm", algo: "HMAC-SHA256", rec: "No change needed", std: "—", complexity: "Low", loc: "services/api/auth.go:9", bu: "Platform", x: 2, y: 0.3, autoEsc: false, quantumVulnerable: false, businessCriticality: "Low" },
  { name: "Internal microservice mTLS", type: "Certificate", algo: "ECDSA-P256", rec: "ML-DSA-65", std: "FIPS 204", complexity: "Low", loc: "infra/mtls/service.crt", bu: "Platform", x: 3, y: 0.5, autoEsc: false, quantumVulnerable: true, businessCriticality: "Low" },
  { name: "Config-signing tool", type: "Algorithm", algo: "Ed25519", rec: "ML-DSA-65 (hybrid)", std: "FIPS 204", complexity: "Low", loc: "tools/config_sign.py:5", bu: "DevTools", x: 4, y: 0.5, autoEsc: false, quantumVulnerable: true, businessCriticality: "Medium" },
  { name: "Public API gateway cert", type: "Certificate", algo: "RSA-2048 / SHA-1 sig", rec: "ML-DSA-65, re-issue", std: "FIPS 204", complexity: "Medium", loc: "infra/certs/api-gw.pem", bu: "Platform", x: 5, y: 1, autoEsc: true, quantumVulnerable: true, businessCriticality: "High" },
  { name: "Legacy admin portal", type: "Protocol", algo: "TLS 1.0", rec: "TLS 1.3 + hybrid KEX", std: "FIPS 203", complexity: "High", loc: "infra/apache/admin.conf:6", bu: "IT Ops", x: 3, y: 0.5, autoEsc: true, quantumVulnerable: false, businessCriticality: "Medium" },
];

export function computeAssetTier(r: number, autoEsc: boolean): RiskTier {
  if (autoEsc) return 'critical';
  if (r >= 1.2) return 'critical';
  if (r >= 0.9) return 'high';
  if (r >= 0.6) return 'medium';
  return 'low';
}

export function computeAllAssetsWithZ(assets: FrontendAsset[], z: number): FrontendAsset[] {
  return assets.map(a => {
    const r = (a.x + a.y) / (z > 0 ? z : 8.0);
    const tier = computeAssetTier(r, a.autoEsc);
    return { ...a, r, tier };
  });
}

// Map backend canonical asset to FrontendAsset
export function mapBackendAssetToFrontend(backendItem: any): FrontendAsset {
  const enc = backendItem.ecdatEnrichment || {};
  const cp = backendItem.cryptoProperties || {};
  const occ = (backendItem.occurrences && backendItem.occurrences[0]) || {};

  return {
    id: backendItem['bom-ref'] || backendItem.id,
    name: backendItem.name || 'Cryptographic Asset',
    type: cp.assetType === 'algorithm' ? 'Algorithm' : (cp.assetType === 'certificate' ? 'Certificate' : 'Protocol'),
    algo: backendItem.name,
    rec: enc.recommendedReplacement || 'ML-KEM-768 (hybrid)',
    std: enc.referenceStandard || 'FIPS 203',
    complexity: enc.migrationComplexity || 'Medium',
    loc: occ.location ? `${occ.location}${occ.line ? `:${occ.line}` : ''}` : 'src/auth/token_signer.py:42',
    bu: enc.dataClassification === 'Customer-PII' ? 'Payments' : (enc.dataClassification === 'Firmware' ? 'Devices' : 'Platform'),
    x: enc.moscaX ?? 5.0,
    y: enc.moscaY ?? 1.0,
    autoEsc: enc.autoEscalated ?? false,
    quantumVulnerable: enc.quantumVulnerable ?? true,
    businessCriticality: enc.businessCriticality || 'High',
    exposure: enc.exposure || 'internal-only',
    vulnerabilityReason: enc.vulnerabilityReason,
    sizeDelta: enc.relativeSizeDelta,
  };
}

export async function fetchLiveAssets(scanId?: string, z?: number): Promise<FrontendAsset[]> {
  try {
    const url = new URL('/assets', window.location.origin);
    if (scanId) url.searchParams.set('scanId', scanId);
    if (z) url.searchParams.set('z', z.toString());

    const res = await fetch(url.toString());
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data: AssetSummaryResponse = await res.json();
    if (data.items && data.items.length > 0) {
      return data.items.map(mapBackendAssetToFrontend);
    }
  } catch (err) {
    console.warn('Could not fetch live assets from backend, falling back to prototype dataset:', err);
  }
  return INITIAL_SAMPLE_ASSETS;
}

export async function fetchScans(): Promise<ScanResponse[]> {
  try {
    const res = await fetch('/scans');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.warn('Could not fetch scans:', err);
    return [];
  }
}

export async function startScan(target: string, sourceType: string = 'path'): Promise<ScanResponse | null> {
  try {
    const res = await fetch('/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, sourceType }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('Failed to start scan:', err);
    return null;
  }
}

export function downloadReportUrl(scanId: string, format: 'pdf' | 'csv' | 'json'): string {
  return `/reports/${scanId}?format=${format}`;
}

export function downloadCBOMUrl(scanId: string): string {
  return `/cbom/${scanId}`;
}
