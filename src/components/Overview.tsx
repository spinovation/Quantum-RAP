import React from 'react';
import { 
  Key, 
  ShieldAlert, 
  Percent, 
  AlertTriangle,
  ArrowRight,
  TrendingDown
} from 'lucide-react';
import type { AuditResult } from '../utils/cryptoAuditor';

interface OverviewProps {
  assets: AuditResult[];
  setActiveTab: (tab: 'overview' | 'scanner' | 'inventory' | 'migration' | 'compliance' | 'ai') => void;
  setSelectedAsset: (asset: AuditResult | null) => void;
}

export const Overview: React.FC<OverviewProps> = ({ assets, setActiveTab, setSelectedAsset }) => {
  const totalAssets = assets.length;
  const vulnerableAssets = assets.filter(a => a.isVulnerable).length;
  const secureAssets = totalAssets - vulnerableAssets;
  
  // Calculate readiness score
  const readinessScore = totalAssets > 0 ? Math.round((secureAssets / totalAssets) * 100) : 0;
  
  // Count critical alert levels
  const criticalCount = assets.filter(a => a.isVulnerable && a.riskLevel === 'critical').length;
  const highCount = assets.filter(a => a.isVulnerable && a.riskLevel === 'high').length;

  // Algorithm breakdown for the bar chart
  const algoCounts: { [key: string]: number } = {};
  assets.forEach(a => {
    const name = a.algorithm.split(' ')[0]; // Group by primary algorithm name
    algoCounts[name] = (algoCounts[name] || 0) + 1;
  });

  const maxCount = Math.max(...Object.values(algoCounts), 1);

  const handleInspectAsset = (asset: AuditResult) => {
    setSelectedAsset(asset);
    setActiveTab('inventory');
    // Open the dialog programmatically if it's rendered there
    setTimeout(() => {
      const dialog = document.getElementById('asset-detail-dialog') as HTMLDialogElement;
      if (dialog) {
        dialog.showModal();
      }
    }, 50);
  };

  // SVG Gauge calculations
  const radius = 70;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (readinessScore / 100) * circumference;

  return (
    <>
      <div>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Security Dashboard</h2>
        <p>Real-time post-quantum cryptography audit and migration tracking.</p>
      </div>

      {/* Metrics Grid */}
      <div className="metrics-grid">
        <div className="glass-panel metric-card">
          <div className="metric-info">
            <h3>Discovered Keys & Certs</h3>
            <div className="metric-value">{totalAssets}</div>
            <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
              Active Cryptographic Assets
            </div>
          </div>
          <div className="metric-icon">
            <Key size={24} />
          </div>
        </div>

        <div className="glass-panel metric-card vulnerable">
          <div className="metric-info">
            <h3>Vulnerable Cryptography</h3>
            <div className="metric-value" style={{ color: 'var(--status-vulnerable)' }}>
              {vulnerableAssets}
            </div>
            <div className="metric-trend" style={{ color: 'var(--status-vulnerable)' }}>
              <TrendingDown size={14} /> Broken by Shor's/Grover's
            </div>
          </div>
          <div className="metric-icon" style={{ color: 'var(--status-vulnerable)' }}>
            <ShieldAlert size={24} />
          </div>
        </div>

        <div className="glass-panel metric-card secure">
          <div className="metric-info">
            <h3>Readiness Score</h3>
            <div className="metric-value" style={{ color: 'var(--status-secure)' }}>
              {readinessScore}%
            </div>
            <div className="metric-trend" style={{ color: 'var(--status-secure)' }}>
              PQC Standard Compliant
            </div>
          </div>
          <div className="metric-icon" style={{ color: 'var(--status-secure)' }}>
            <Percent size={24} />
          </div>
        </div>

        <div className="glass-panel metric-card warning">
          <div className="metric-info">
            <h3>High Severity Alerts</h3>
            <div className="metric-value" style={{ color: 'var(--status-warning)' }}>
              {criticalCount + highCount}
            </div>
            <div className="metric-trend" style={{ color: 'var(--status-warning)' }}>
              {criticalCount} Critical | {highCount} High
            </div>
          </div>
          <div className="metric-icon" style={{ color: 'var(--status-warning)' }}>
            <AlertTriangle size={24} />
          </div>
        </div>
      </div>

      {/* Main Charts Row */}
      <div className="dashboard-grid">
        <div className="glass-panel">
          <div className="panel-header">
            <h3 style={{ fontSize: '1.1rem' }}>Algorithm Distribution</h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Total Instances</span>
          </div>
          <div className="panel-body chart-container">
            {Object.keys(algoCounts).length === 0 ? (
              <div style={{ color: 'var(--text-muted)', padding: '2rem' }}>No data scanned yet.</div>
            ) : (
              Object.entries(algoCounts).map(([algo, count]) => {
                const heightPercent = (count / maxCount) * 160; // Max height in px
                const isSecure = algo.toLowerCase().includes('hybrid') || algo.toLowerCase().includes('ml-dsa') || algo.toLowerCase().includes('dilithium');
                return (
                  <div key={algo} className="chart-bar-wrapper">
                    <div 
                      className="chart-bar" 
                      style={{ 
                        height: `${heightPercent}px`,
                        background: isSecure 
                          ? 'linear-gradient(to top, var(--status-secure), #55ffd3)'
                          : 'linear-gradient(to top, var(--accent-purple), var(--accent-cyan))'
                      }}
                    >
                      <div className="chart-bar-tooltip">
                        {count} asset{count > 1 ? 's' : ''}
                      </div>
                    </div>
                    <span className="chart-label">{algo}</span>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Circular Gauge */}
        <div className="glass-panel readiness-widget">
          <h3 style={{ fontSize: '1.1rem', alignSelf: 'flex-start' }}>Readiness Level</h3>
          
          <div className="gauge-svg-container">
            <svg width="160" height="160" viewBox="0 0 160 160">
              <defs>
                <linearGradient id="gaugeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="var(--accent-purple)" />
                  <stop offset="100%" stopColor="var(--accent-cyan)" />
                </linearGradient>
              </defs>
              <circle className="gauge-circle-bg" cx="80" cy="80" r={radius} />
              <circle 
                className="gauge-circle-val" 
                cx="80" 
                cy="80" 
                r={radius} 
                strokeDasharray={circumference}
                strokeDashoffset={offset}
              />
            </svg>
            <div className="gauge-value">
              <div className="gauge-number" style={{ color: readinessScore > 50 ? 'var(--status-secure)' : readinessScore > 20 ? 'var(--status-warning)' : 'var(--status-vulnerable)' }}>
                {readinessScore}
              </div>
              <div className="gauge-percent">%</div>
              <div className="gauge-label">Secure</div>
            </div>
          </div>
          
          <div style={{ textAlign: 'center', fontSize: '0.9rem' }}>
            {readinessScore === 100 ? (
              <span style={{ color: 'var(--status-secure)' }}>All cryptographic assets are quantum resistant.</span>
            ) : readinessScore > 0 ? (
              <span>Your environment requires migration for {vulnerableAssets} assets.</span>
            ) : (
              <span style={{ color: 'var(--status-vulnerable)' }}>All assets are vulnerable. Scan files to begin mapping.</span>
            )}
          </div>
        </div>
      </div>

      {/* Critical Vulnerabilities List */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div className="panel-header">
          <h3 style={{ fontSize: '1.1rem' }}>Active Cryptographic Findings</h3>
          <button 
            className="btn-secondary" 
            style={{ padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}
            onClick={() => setActiveTab('inventory')}
          >
            Full Registry <ArrowRight size={14} />
          </button>
        </div>
        <div className="table-wrapper">
          <table className="quark-table">
            <thead>
              <tr>
                <th>Asset Name</th>
                <th>Type</th>
                <th>Algorithm</th>
                <th>Severity</th>
                <th>Quantum Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {assets.slice(0, 3).map((asset) => (
                <tr key={asset.id}>
                  <td style={{ fontWeight: 600 }}>{asset.name}</td>
                  <td>
                    <span style={{ textTransform: 'capitalize' }}>
                      {asset.type.replace('_', ' ')}
                    </span>
                  </td>
                  <td>{asset.algorithm} {asset.keySize ? `(${asset.keySize}-bit)` : ''}</td>
                  <td>
                    <span className={`badge ${
                      asset.riskLevel === 'critical' ? 'danger' : 
                      asset.riskLevel === 'high' ? 'danger' : 
                      asset.riskLevel === 'medium' ? 'warning' : 'success'
                    }`}>
                      {asset.riskLevel}
                    </span>
                  </td>
                  <td>
                    <span style={{ 
                      color: asset.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)',
                      fontWeight: 500,
                      fontSize: '0.88rem'
                    }}>
                      {asset.status}
                    </span>
                  </td>
                  <td>
                    <button 
                      onClick={() => handleInspectAsset(asset)}
                      className="btn-secondary" 
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                    >
                      Audit Details
                    </button>
                  </td>
                </tr>
              ))}
              {assets.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                    No cryptographic inventory found. Use the Crypto Scanner to discover keys.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
};
