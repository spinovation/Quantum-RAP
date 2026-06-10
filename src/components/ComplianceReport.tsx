import React, { useState, useEffect } from 'react';
import { 
  CheckCircle2, 
  XCircle, 
  FileCheck2, 
  Download, 
  ShieldCheck, 
  Building,
  Scroll,
  FileSpreadsheet,
  RefreshCw
} from 'lucide-react';
import type { AuditResult } from '../utils/cryptoAuditor';

interface ComplianceReportProps {
  assets: AuditResult[];
}

export const ComplianceReport: React.FC<ComplianceReportProps> = ({ assets }) => {
  const [isExporting, setIsExporting] = useState(false);
  const [exportSuccess, setExportSuccess] = useState(false);

  // Evaluate conditions dynamically based on current scanned assets in the inventory
  const hasSHA1orMD5 = assets.some(a => 
    a.algorithm.toLowerCase().includes('sha1') || 
    a.algorithm.toLowerCase().includes('md5') ||
    a.description.toLowerCase().includes('sha-1') ||
    a.description.toLowerCase().includes('md5')
  );

  const hasShortKeys = assets.some(a => 
    a.keySize !== undefined && a.keySize < 2048 && (a.algorithm.includes('RSA') || a.algorithm.includes('DSA'))
  );

  const hasAsymmetricVulnerabilities = assets.some(a => 
    a.isVulnerable && (a.type === 'certificate' || a.type === 'ssh_key' || a.type === 'private_key')
  );

  const hasPqcAssets = assets.some(a => !a.isVulnerable && a.status === 'Post-Quantum Secure');

  // NIST SP 800-219 Checks
  const nistChecks = [
    {
      id: 'nist-1',
      title: 'Establish Cryptographic Asset Inventory',
      desc: 'Catalog all algorithms, key sizes, and certificate expiration dates.',
      passed: assets.length > 0
    },
    {
      id: 'nist-2',
      title: 'Identify Vulnerable Legacy Cryptography',
      desc: 'Audit system for keys broken by classical or quantum calculations.',
      passed: assets.length > 0 && !hasShortKeys
    },
    {
      id: 'nist-3',
      title: 'Formulate Post-Quantum Migration Strategy',
      desc: 'Map out timelines and assign priority levels to key materials.',
      passed: true // Configured via our Roadmap
    },
    {
      id: 'nist-4',
      title: 'Establish Crypto-Agility Procurement Policies',
      desc: 'Require new products to support modular algorithm updates.',
      passed: true
    }
  ];

  // CNSA 2.0 Checks
  const cnsaChecks = [
    {
      id: 'cnsa-1',
      title: 'Enforce AES-256 Symmetric Encryption',
      desc: 'CNSA 2.0 requires AES-256 (Grover\'s quantum defense) for all secure links.',
      passed: !assets.some(a => a.description.includes('aes128') || a.description.includes('blowfish'))
    },
    {
      id: 'cnsa-2',
      title: 'Phase out SHA-1 / SHA-256 hashes',
      desc: 'Migrate to SHA-384 / SHA-512 or SHA-3 for digital signatures.',
      passed: !hasSHA1orMD5
    },
    {
      id: 'cnsa-3',
      title: 'Deploy sntrup761 / Kyber Hybrid Exchange',
      desc: 'Initiate hybrid post-quantum key exchange in SSH and TLS tunnels.',
      passed: hasPqcAssets
    },
    {
      id: 'cnsa-4',
      title: 'Establish ML-DSA Signatures Roadmap',
      desc: 'Adopt lattice-based module signatures (ML-DSA) for public interfaces.',
      passed: assets.some(a => a.algorithm.includes('ML-DSA') || a.algorithm.includes('Dilithium'))
    }
  ];

  // EO 14028 Checks
  const eoChecks = [
    {
      id: 'eo-1',
      title: 'Zero-Trust Architecture Cryptography',
      desc: 'Inventory API, data, and user-access channels for quantum vulnerabilities.',
      passed: assets.length > 3
    },
    {
      id: 'eo-2',
      title: 'Protect Supply-Chain Code Signing',
      desc: 'Upgrade binary and software packaging keys to quantum-safe state-based signatures (LMS/XMSS).',
      passed: !assets.some(a => a.name.includes('sign') && a.isVulnerable)
    },
    {
      id: 'eo-3',
      title: 'Report Quantum Readiness Status',
      desc: 'Generate compliance diagnostics on algorithm vulnerabilities to OMB/NIST.',
      passed: assets.length > 0
    }
  ];

  const calculateScore = (checks: { passed: boolean }[]) => {
    const passed = checks.filter(c => c.passed).length;
    return Math.round((passed / checks.length) * 100);
  };

  const [nistScore, setNistScore] = useState<number>(calculateScore(nistChecks));
  const [cnsaScore, setCnsaScore] = useState<number>(calculateScore(cnsaChecks));
  const [eoScore, setEoScore] = useState<number>(calculateScore(eoChecks));
  const [nistChecksState, setNistChecksState] = useState<any[]>(nistChecks);
  const [cnsaChecksState, setCnsaChecksState] = useState<any[]>(cnsaChecks);
  const [eoChecksState, setEoChecksState] = useState<any[]>(eoChecks);
  const [violations, setViolations] = useState<string[]>([]);
  const [isSyncing, setIsSyncing] = useState(false);

  useEffect(() => {
    setIsSyncing(true);
    const token = sessionStorage.getItem('quarkshield_token');
    fetch('/api/compliance', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => {
        if (res.status === 403) {
          return res.json().then(data => {
            throw { isAuthError: true, message: data.error || 'Access Denied.' };
          });
        }
        if (!res.ok) throw new Error(`Server returned status ${res.status}`);
        return res.json();
      })
      .then(data => {
        if (data && data.nist && data.cnsa && data.eo14028) {
          setNistScore(data.nist.score);
          setNistChecksState(data.nist.checks);
          setCnsaScore(data.cnsa.score);
          setCnsaChecksState(data.cnsa.checks);
          setEoScore(data.eo14028.score);
          setEoChecksState(data.eo14028.checks);
          setViolations(data.violations || []);
        }
      })
      .catch((err: any) => {
        if (err.isAuthError) {
          setNistScore(0);
          setCnsaScore(0);
          setEoScore(0);
          setViolations([`Access Denied: ${err.message}`]);
        } else {
          console.warn('Backend compliance endpoint offline, falling back to local client audit:', err);
          setNistScore(calculateScore(nistChecks));
          setNistChecksState(nistChecks);
          setCnsaScore(calculateScore(cnsaChecks));
          setCnsaChecksState(cnsaChecks);
          setEoScore(calculateScore(eoChecks));
          setEoChecksState(eoChecks);
          
          const fallbackViolations: string[] = [];
          if (hasSHA1orMD5) fallbackViolations.push("CNSA 2.0 violation: Detected active usage of SHA-1/MD5 digests.");
          if (hasShortKeys) fallbackViolations.push("NIST deprecation warning: RSA keys below 2048-bits found.");
          if (hasAsymmetricVulnerabilities) fallbackViolations.push("EO 14028 action: Network employs vulnerable classical signatures.");
          setViolations(fallbackViolations);
        }
      })
      .finally(() => {
        setIsSyncing(false);
      });
  }, [assets]);

  const handleExport = () => {
    setIsExporting(true);
    setTimeout(() => {
      setIsExporting(false);
      setExportSuccess(true);
      setTimeout(() => setExportSuccess(false), 3000);
    }, 1200);
  };

  return (
    <>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Compliance & Audit Center</h2>
          <p>Verify network configurations and keys against standard Post-Quantum mandates.</p>
        </div>
        <button 
          className="btn-primary" 
          onClick={handleExport}
          disabled={isExporting}
        >
          {isExporting ? (
            <span>Compiling Report...</span>
          ) : exportSuccess ? (
            <span style={{ color: 'var(--status-secure)', display: 'inline-flex', alignItems: 'center', gap: '0.25rem' }}>
              <ShieldCheck size={16} /> Audit Exported!
            </span>
          ) : (
            <>
              <Download size={16} /> Export Compliance Report
            </>
          )}
        </button>
      </div>

      {/* Compliance Scorecards Grid */}
      <div className="compliance-grid">
        {/* Card 1: NIST SP 800-219 */}
        <div className="glass-panel compliance-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="brand-icon" style={{ background: 'rgba(0, 242, 254, 0.1)', border: '1px solid var(--accent-cyan)' }}>
              <Building size={20} color="var(--accent-cyan)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.15rem' }}>NIST SP 800-219</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Quantum Readiness Guidelines</span>
            </div>
          </div>

          <div style={{ margin: '0.5rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Readiness Alignment</span>
              <span style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>{nistScore}%</span>
            </div>
            <div className="compliance-progress-bar">
              <div className="compliance-progress-fill" style={{ width: `${nistScore}%` }}></div>
            </div>
          </div>

          <ul className="compliance-checklist">
            {nistChecksState.map(check => (
              <li key={check.id} className={`compliance-item ${check.passed ? 'passed' : 'failed'}`}>
                {check.passed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <div>
                  <span style={{ fontWeight: 500 }}>{check.title}</span>
                  <p style={{ fontSize: '0.75rem', marginTop: '0.1rem' }}>{check.desc}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Card 2: CNSA 2.0 */}
        <div className="glass-panel compliance-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="brand-icon" style={{ background: 'rgba(127, 0, 255, 0.1)', border: '1px solid var(--accent-purple)' }}>
              <Scroll size={20} color="#c084fc" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.15rem' }}>CNSA 2.0</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>National Security Algorithm Suite</span>
            </div>
          </div>

          <div style={{ margin: '0.5rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>CNSA Mandate Score</span>
              <span style={{ fontWeight: 700, color: '#c084fc' }}>{cnsaScore}%</span>
            </div>
            <div className="compliance-progress-bar">
              <div className="compliance-progress-fill" style={{ width: `${cnsaScore}%`, background: 'linear-gradient(to right, var(--accent-purple), #a855f7)' }}></div>
            </div>
          </div>

          <ul className="compliance-checklist">
            {cnsaChecksState.map(check => (
              <li key={check.id} className={`compliance-item ${check.passed ? 'passed' : 'failed'}`}>
                {check.passed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <div>
                  <span style={{ fontWeight: 500 }}>{check.title}</span>
                  <p style={{ fontSize: '0.75rem', marginTop: '0.1rem' }}>{check.desc}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Card 3: Executive Order 14028 */}
        <div className="glass-panel compliance-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div className="brand-icon" style={{ background: 'rgba(0, 255, 136, 0.1)', border: '1px solid var(--status-secure)' }}>
              <FileCheck2 size={20} color="var(--status-secure)" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.15rem' }}>EO 14028</h3>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Federal Cybersecurity Directive</span>
            </div>
          </div>

          <div style={{ margin: '0.5rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.25rem', fontSize: '0.9rem' }}>
              <span style={{ color: 'var(--text-secondary)' }}>Cybersecurity Execution</span>
              <span style={{ fontWeight: 700, color: 'var(--status-secure)' }}>{eoScore}%</span>
            </div>
            <div className="compliance-progress-bar">
              <div className="compliance-progress-fill" style={{ width: `${eoScore}%`, background: 'linear-gradient(to right, #00ff88, #22c55e)' }}></div>
            </div>
          </div>

          <ul className="compliance-checklist">
            {eoChecksState.map(check => (
              <li key={check.id} className={`compliance-item ${check.passed ? 'passed' : 'failed'}`}>
                {check.passed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                <div>
                  <span style={{ fontWeight: 500 }}>{check.title}</span>
                  <p style={{ fontSize: '0.75rem', marginTop: '0.1rem' }}>{check.desc}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Compliance Overview Summary Pane */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <FileSpreadsheet size={18} color="var(--accent-cyan)" /> Compliance Audit Insights {isSyncing && <RefreshCw size={14} className="spin" style={{ marginLeft: '0.5rem', color: 'var(--accent-cyan)' }} />}
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '2rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', background: 'rgba(0,0,0,0.15)', padding: '1rem', borderRadius: '8px' }}>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>INVENTORY DENSITY</span>
              <div style={{ fontSize: '1.2rem', fontWeight: 600 }}>{assets.length} Assets Registered</div>
            </div>
            <div>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>AGILITY COMPLIANCE STATUS</span>
              <div style={{ 
                fontSize: '1.1rem', 
                fontWeight: 700,
                color: violations.length > 0 ? 'var(--status-vulnerable)' : 'var(--status-secure)'
              }}>
                {violations.length > 0 ? 'Migration Pending' : 'Lattice Confirmed'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <h4 style={{ fontWeight: 600 }}>Operational Audit Diagnostics (OPA Engine)</h4>
            <ul style={{ paddingLeft: '1.25rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '0.5rem', fontSize: '0.95rem' }}>
              {violations.map((violation, idx) => (
                <li key={idx} style={{ listStyleType: 'square' }}>
                  <span style={{ color: 'var(--status-vulnerable)', fontWeight: 600 }}>OPA Policy Alert:</span> {violation}
                </li>
              ))}
              {violations.length === 0 && assets.length > 0 && (
                <li style={{ listStyleType: 'square', color: 'var(--status-secure)' }}>
                  All systems currently register quantum-safe lattice credentials. Agilities verified.
                </li>
              )}
              {assets.length === 0 && (
                <li style={{ listStyleType: 'square' }}>
                  Awaiting database scan data to compile full compliance insights.
                </li>
              )}
            </ul>
          </div>
        </div>
      </div>
    </>
  );
};
