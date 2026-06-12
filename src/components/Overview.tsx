import React, { useState } from 'react';
import { 
  Key, 
  ShieldAlert, 
  Percent, 
  AlertTriangle,
  ArrowRight,
  TrendingDown,
  Download,
  MessageSquare,
  Scale,
  ShieldCheck,
  Copyright
} from 'lucide-react';
import type { AuditResult } from '../utils/cryptoAuditor';

interface OverviewProps {
  assets: AuditResult[];
  setActiveTab: (tab: 'overview' | 'scanner' | 'inventory' | 'migration' | 'compliance' | 'ai') => void;
  setSelectedAsset: (asset: AuditResult | null) => void;
}

export const Overview: React.FC<OverviewProps> = ({ assets, setActiveTab, setSelectedAsset }) => {
  const [activeModal, setActiveModal] = useState<'terms' | 'privacy' | 'disclaimer' | 'support' | 'vpn' | null>(null);
  const [supportForm, setSupportForm] = useState({ name: '', email: '', subject: '', description: '' });
  const [supportSubmitted, setSupportSubmitted] = useState(false);
  const [supportLoading, setSupportLoading] = useState(false);

  const downloadVpnProfile = () => {
    const ovpnContent = `client
dev tun
proto udp
remote vpn.quarkshield.services 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server

# Post-Quantum Cryptography Algorithms Enforced
# Key Exchange: ML-KEM-768 / Kyber768
# Signature: ML-DSA-65 / Dilithium3
pq-kex mlkem768
pq-sig mldsa65

cipher AES-256-GCM
auth SHA512
verb 3

<ca>
-----BEGIN CERTIFICATE-----
MIIBszCCARqgAwIBAgIUd5b8zXFqb2p5NklMTU1OT1BRUlNUVVZX
WlhhY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFi
Y2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFjZGVm
[PQC Root CA Certificate]
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
MIIBtTCCAR2gAwIBAgIUb5c9zXFqb2p5NklMTU1OT1BRUlNUVVZX
WlhhY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFi
Y2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MDEyMzQ1Njc4OWFjZGVm
[PQC Client Certificate]
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgq2pq
NklMTU1OT1BRUlNUVVZXWlhhY2RlZmdoaWprbG1ub3BxcnN0dXZ3
eHl6MDEyMzQ1Njc4OWFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6
[PQC Client Private Key]
-----END PRIVATE KEY-----
</key>`;

    const blob = new Blob([ovpnContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', 'quarkshield-pqc-vpn.ovpn');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

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

      {/* Premium Footer Frame */}
      <div className="glass-panel" style={{ 
        marginTop: '2rem', 
        padding: '1.75rem', 
        background: 'var(--bg-card)', 
        border: '1px solid var(--border-normal)', 
        borderRadius: '8px' 
      }}>
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', 
          gap: '2rem', 
          marginBottom: '1.5rem' 
        }}>
          {/* Support Section */}
          <div>
            <h4 style={{ 
              fontSize: '0.85rem', 
              fontWeight: 700, 
              color: 'var(--text-muted)', 
              textTransform: 'uppercase', 
              letterSpacing: '0.05em', 
              marginBottom: '0.8rem',
              borderLeft: '2px solid var(--accent-cyan)',
              paddingLeft: '6px'
            }}>
              Support
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', alignItems: 'flex-start' }}>
              <button 
                onClick={() => setActiveModal('support')}
                style={{ 
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  color: 'var(--accent-cyan)', 
                  fontSize: '0.82rem', 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '0.4rem', 
                  transition: 'color 0.2s',
                  fontWeight: 500
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = '#ffffff'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
              >
                <MessageSquare size={13} />
                <span>💬 Raise a Support Request</span>
              </button>
              <button 
                onClick={() => setActiveModal('vpn')}
                style={{ 
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  color: 'var(--status-secure)', 
                  fontSize: '0.82rem', 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '0.4rem', 
                  transition: 'color 0.2s',
                  fontWeight: 500
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = '#ffffff'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--status-secure)'}
              >
                <Download size={13} />
                <span>Download Quantum Safe VPN</span>
              </button>
            </div>
          </div>

          {/* Legal Section */}
          <div>
            <h4 style={{ 
              fontSize: '0.85rem', 
              fontWeight: 700, 
              color: 'var(--text-muted)', 
              textTransform: 'uppercase', 
              letterSpacing: '0.05em', 
              marginBottom: '0.8rem',
              borderLeft: '2px solid var(--accent-purple)',
              paddingLeft: '6px'
            }}>
              Legal
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              <button 
                onClick={() => setActiveModal('terms')}
                style={{ 
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  color: 'var(--text-secondary)', 
                  fontSize: '0.82rem', 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '0.4rem', 
                  transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                <Scale size={13} />
                <span>Terms of Service</span>
              </button>
              <button 
                onClick={() => setActiveModal('privacy')}
                style={{ 
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  color: 'var(--text-secondary)', 
                  fontSize: '0.82rem', 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '0.4rem', 
                  transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                <ShieldCheck size={13} />
                <span>Privacy Policy</span>
              </button>
              <button 
                onClick={() => setActiveModal('disclaimer')}
                style={{ 
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  textAlign: 'left',
                  cursor: 'pointer',
                  color: 'var(--text-secondary)', 
                  fontSize: '0.82rem', 
                  display: 'inline-flex', 
                  alignItems: 'center', 
                  gap: '0.4rem', 
                  transition: 'color 0.2s'
                }}
                onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
                onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-secondary)'}
              >
                <AlertTriangle size={13} />
                <span>Disclaimers</span>
              </button>
            </div>
          </div>
        </div>

        {/* Contact Us & Copyright Footer row */}
        <div style={{ 
          display: 'flex', 
          justifyContent: 'space-between', 
          alignItems: 'center', 
          flexWrap: 'wrap', 
          gap: '1rem', 
          paddingTop: '1.25rem', 
          borderTop: '1px solid rgba(255, 255, 255, 0.05)', 
          fontSize: '0.82rem', 
          color: 'var(--text-secondary)' 
        }}>
          <div>
            <span style={{ fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.72rem', letterSpacing: '0.05em', marginRight: '0.5rem' }}>Contact Us:</span>
            <a href="mailto:Support@quarkshield.services" style={{ color: 'var(--accent-cyan)', textDecoration: 'none', fontWeight: 500 }}>Support@quarkshield.services</a>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
            <Copyright size={12} />
            <span>2026 Quark Shield LLC</span>
          </div>
        </div>
      </div>

      {/* Legal Dialog Overlay */}
      {activeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(6px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 10000,
          padding: '1rem'
        }}>
          <div className="glass-panel" style={{
            maxWidth: '550px',
            width: '100%',
            padding: '2rem',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-normal)',
            borderRadius: '8px',
            boxShadow: '0 20px 50px rgba(0,0,0,0.8)'
          }}>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: '#ffffff', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.5rem', textAlign: 'left' }}>
              {activeModal === 'terms' && 'Terms of Service'}
              {activeModal === 'privacy' && 'Privacy Policy'}
              {activeModal === 'disclaimer' && 'Operational Disclaimers'}
              {activeModal === 'support' && '💬 Raise a Support Request'}
              {activeModal === 'vpn' && '🔒 Download Quantum Safe VPN'}
            </h3>
            
            {/* Legal content (Terms, Privacy, Disclaimers) */}
            {(activeModal === 'terms' || activeModal === 'privacy' || activeModal === 'disclaimer') && (
              <>
                <div style={{ 
                  fontSize: '0.85rem', 
                  color: 'var(--text-secondary)', 
                  lineHeight: '1.6', 
                  maxHeight: '280px', 
                  overflowY: 'auto', 
                  marginBottom: '1.5rem', 
                  display: 'flex', 
                  flexDirection: 'column', 
                  gap: '0.75rem',
                  textAlign: 'left'
                }}>
                  {activeModal === 'terms' && (
                    <>
                      <p><strong>1. Authorized Deployment Scope:</strong> Authorized client users are granted a non-exclusive license to run this private security assessment node inside their designated network boundary.</p>
                      <p><strong>2. Threat Modeling Accuracy:</strong> All assessments, compliance indices, and risk alerts are computed based on active cryptanalysis mapped to NIST SP 800-219, CNSA 2.0, and Executive Order 14028 guidelines. Quantum readiness scoring is a security posture evaluation tool; absolute protection guarantees are not implied.</p>
                      <p><strong>3. Proprietary IP:</strong> Platform code, crawler binaries, signatures, and PQC playbooks remain the intellectual property of Quark Shield LLC.</p>
                    </>
                  )}
                  {activeModal === 'privacy' && (
                    <>
                      <p><strong>1. Data Minimization Rule:</strong> QuarkShield does not ingest, inspect, or store raw network application payloads, private user credentials, or application transaction database records. Only structural configuration parameters are parsed for audit integrity.</p>
                      <p><strong>2. Complete Isolation:</strong> Your tenant node database operates in a private network container. Telemetry feeds and compliance diagnostics remain entirely inside the client volume storage boundaries.</p>
                      <p><strong>3. OAuth Service Accounts:</strong> Stored credentials, private keys, and connection credentials configured for direct API scanning are encrypted locally inside your tenant database.</p>
                    </>
                  )}
                  {activeModal === 'disclaimer' && (
                    <>
                      <p><strong>1. Quantum Decryption Horizon:</strong> Threat models and shelf-life metrics utilize mathematical estimates (Mosca's Theorem) for quantum computer decryption capabilities. Real-world timelines may vary based on scientific development speeds.</p>
                      <p><strong>2. Hybrid Client Compatibility:</strong> Upgrading servers to hybrid post-quantum TLS schemes (like ML-KEM/Kyber) requires matching client-side handshake support. Legacy browser fallback policies should be decommissioned in accordance with secure operational guidelines.</p>
                      <p><strong>3. Third-party Ingestion:</strong> Sync connection status relies on remote API availability. Quark Shield LLC accepts no responsibility for external platform credential configuration errors.</p>
                    </>
                  )}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button 
                    className="btn-primary" 
                    onClick={() => setActiveModal(null)}
                    style={{ padding: '0.5rem 1.5rem' }}
                  >
                    Close Agreement
                  </button>
                </div>
              </>
            )}

            {/* Support Request Form */}
            {activeModal === 'support' && (
              <>
                {supportSubmitted ? (
                  <div style={{ textAlign: 'center', padding: '1rem 0' }}>
                    <div style={{ display: 'inline-flex', padding: '1rem', borderRadius: '50%', background: 'rgba(16, 185, 129, 0.1)', color: '#10b981', marginBottom: '1.25rem' }}>
                      <ShieldCheck size={40} />
                    </div>
                    <h3 style={{ fontSize: '1.3rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>Request Submitted</h3>
                    <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.6', marginBottom: '1.5rem' }}>
                      Your support request has been recorded. Our engineering team will contact you at <strong>{supportForm.email}</strong> shortly.
                    </p>
                    <button 
                      className="btn-primary" 
                      onClick={() => {
                        setActiveModal(null);
                        setSupportSubmitted(false);
                        setSupportForm({ name: '', email: '', subject: '', description: '' });
                      }}
                      style={{ padding: '0.5rem 2rem' }}
                    >
                      Done
                    </button>
                  </div>
                ) : (
                  <form onSubmit={(e) => {
                    e.preventDefault();
                    setSupportLoading(true);
                    setTimeout(() => {
                      setSupportLoading(false);
                      setSupportSubmitted(true);
                    }, 1000);
                  }} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                    <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', margin: '0 0 0.5rem 0', textAlign: 'left' }}>
                      Submit a support ticket to our operations team. We will review your node configurations and reply shortly.
                    </p>
                    
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                      <div className="form-group" style={{ textAlign: 'left' }}>
                        <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.3rem' }}>Your Name</label>
                        <input 
                          type="text" 
                          required 
                          value={supportForm.name}
                          onChange={(e) => setSupportForm({ ...supportForm, name: e.target.value })}
                          placeholder="Name"
                          style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: 'var(--text-primary)', outline: 'none', fontSize: '0.86rem' }}
                        />
                      </div>
                      <div className="form-group" style={{ textAlign: 'left' }}>
                        <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.3rem' }}>Email Address</label>
                        <input 
                          type="email" 
                          required 
                          value={supportForm.email}
                          onChange={(e) => setSupportForm({ ...supportForm, email: e.target.value })}
                          placeholder="Email"
                          style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: 'var(--text-primary)', outline: 'none', fontSize: '0.86rem' }}
                        />
                      </div>
                    </div>

                    <div className="form-group" style={{ textAlign: 'left' }}>
                      <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.3rem' }}>Subject</label>
                      <input 
                        type="text" 
                        required 
                        value={supportForm.subject}
                        onChange={(e) => setSupportForm({ ...supportForm, subject: e.target.value })}
                        placeholder="Subject"
                        style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: 'var(--text-primary)', outline: 'none', fontSize: '0.86rem' }}
                      />
                    </div>

                    <div className="form-group" style={{ textAlign: 'left' }}>
                      <label style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.3rem' }}>Description</label>
                      <textarea 
                        required 
                        rows={3}
                        value={supportForm.description}
                        onChange={(e) => setSupportForm({ ...supportForm, description: e.target.value })}
                        placeholder="Describe your issue..."
                        style={{ width: '100%', padding: '0.55rem 0.75rem', borderRadius: '6px', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: 'var(--text-primary)', outline: 'none', fontSize: '0.86rem', resize: 'none', fontFamily: 'inherit' }}
                      />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.5rem' }}>
                      <button 
                        type="button" 
                        className="btn-secondary" 
                        onClick={() => setActiveModal(null)}
                        style={{ padding: '0.45rem 1.25rem', fontSize: '0.86rem' }}
                      >
                        Cancel
                      </button>
                      <button 
                        type="submit" 
                        className="btn-primary" 
                        disabled={supportLoading}
                        style={{ padding: '0.45rem 1.5rem', fontSize: '0.86rem' }}
                      >
                        {supportLoading ? 'Submitting...' : 'Send Request'}
                      </button>
                    </div>
                  </form>
                )}
              </>
            )}

            {/* VPN Guide */}
            {activeModal === 'vpn' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', textAlign: 'left' }}>
                <p style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', margin: 0, lineHeight: '1.5' }}>
                  Connect to your tenant's secure perimeter using post-quantum cryptographic tunnels. Follow these two simple steps to install the client and connect.
                </p>

                <div style={{ borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.85rem' }}>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#ffffff', margin: '0 0 0.4rem 0' }}>
                    Step 1: Install the QuarkShield Quantum-Safe VPN Client
                  </h4>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: '0 0 0.85rem 0', lineHeight: '1.4' }}>
                    To establish a secure connection, download the precompiled QuarkShield corporate VPN client for your device from the Releases section of our main GitHub repository:
                  </p>
                  
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '0.25rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                      <div>
                        <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ffffff' }}>macOS Application Bundle</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>QuarkShieldVPN-darwin-universal.zip (universal app)</div>
                      </div>
                      <a 
                        href="https://github.com/spinovation/Quantum-RAP/releases" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="btn-secondary" 
                        style={{ 
                          padding: '0.4rem 0.8rem', 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          gap: '0.4rem', 
                          textDecoration: 'none', 
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          color: '#ffffff'
                        }}
                      >
                        <Download size={12} />
                        <span>Get from GitHub Releases</span>
                      </a>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                      <div>
                        <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ffffff' }}>Windows Installer</div>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>QuarkShieldVPN-win32-x64.zip (executable installer)</div>
                      </div>
                      <a 
                        href="https://github.com/spinovation/Quantum-RAP/releases" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="btn-secondary" 
                        style={{ 
                          padding: '0.4rem 0.8rem', 
                          display: 'inline-flex', 
                          alignItems: 'center', 
                          gap: '0.4rem', 
                          textDecoration: 'none', 
                          fontSize: '0.78rem',
                          fontWeight: 600,
                          color: '#ffffff'
                        }}
                      >
                        <Download size={12} />
                        <span>Get from GitHub Releases</span>
                      </a>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#ffffff', margin: '0 0 0.4rem 0' }}>
                    Step 2: Download PQC Profile & Connect
                  </h4>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0 0 0.75rem 0' }}>
                    Download the pre-configured `.ovpn` profile containing local post-quantum cipher suites (ML-KEM-768/Kyber and ML-DSA-65/Dilithium) and import it into your client app.
                  </p>
                  <button 
                    onClick={downloadVpnProfile}
                    className="btn-primary"
                    style={{ 
                      width: '100%', 
                      padding: '0.65rem', 
                      display: 'flex', 
                      alignItems: 'center', 
                      justifyContent: 'center', 
                      gap: '0.4rem',
                      fontSize: '0.84rem',
                      fontWeight: 600
                    }}
                  >
                    <Download size={14} />
                    <span>Download PQC VPN Profile (.ovpn)</span>
                  </button>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '0.25rem' }}>
                  <button 
                    className="btn-secondary" 
                    onClick={() => setActiveModal(null)}
                    style={{ padding: '0.45rem 1.25rem', fontSize: '0.86rem' }}
                  >
                    Close Guide
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};
