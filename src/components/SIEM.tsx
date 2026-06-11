import React, { useState, useEffect, useRef } from 'react';
import { 
  Check, 
  Copy, 
  Terminal, 
  Play, 
  Trash2, 
  FileCode,
  ShieldCheck
} from 'lucide-react';

interface SIEMAlert {
  id: string;
  timestamp: string;
  source: 'Splunk' | 'Sentinel' | 'Google SecOps';
  level: 'secure' | 'info' | 'warning' | 'critical';
  title: string;
  message: string;
  details: string;
}

export const SIEM: React.FC = () => {
  // Connector Active States
  const [splunkConnected, setSplunkConnected] = useState(true);
  const [sentinelConnected, setSentinelConnected] = useState(false);
  const [secopsConnected, setSecopsConnected] = useState(true);

  // Active SIEM Rule Export Tab
  const [activeRuleTab, setActiveRuleTab] = useState<'splunk' | 'sentinel' | 'secops'>('splunk');
  const [copySuccess, setCopySuccess] = useState(false);

  // Simulator Logs and Alerts
  const [consoleLogs, setConsoleLogs] = useState<string[]>([
    `[SYSTEM] QuarkShield SIEM Exporter Agent initialized. Listening on UDP/514...`
  ]);
  const [alerts, setAlerts] = useState<SIEMAlert[]>([
    {
      id: 'alert-01',
      timestamp: new Date(Date.now() - 3600000).toLocaleTimeString(),
      source: 'Google SecOps',
      level: 'critical',
      title: 'WEAK_ALGORITHM_DETECTED',
      message: 'Server billing-db-prod utilizing legacy RSA-2048 signing keys.',
      details: 'Audit Target: 10.150.4.12 | Key Length: 2048 bits | Protocol: SSHv2'
    },
    {
      id: 'alert-02',
      timestamp: new Date(Date.now() - 1800000).toLocaleTimeString(),
      source: 'Splunk',
      level: 'warning',
      title: 'EXPIRING_CERTIFICATE',
      message: 'Certificate mail.corporate.com expires in 8 days.',
      details: 'Subject: CN=mail.corporate.com | Issuer: DigiCert SHA2 Secure Server CA | Expiry: June 19, 2026'
    }
  ]);

  const [isSimulating, setIsSimulating] = useState(false);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs terminal
  useEffect(() => {
    if (consoleEndRef.current) {
      consoleEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs]);

  // Splunk, Sentinel, SecOps Rules Database
  const siemRules = {
    splunk: {
      title: 'Splunk SPL Search Query',
      lang: 'sql',
      code: `index=security sourcetype=syslog OR sourcetype=nginx_access
| eval key_len=coalesce(ssl_key_length, key_length, 0), sig_alg=coalesce(ssl_signature_algorithm, signature_algorithm, "")
| where (key_len > 0 AND key_len < 3072 AND ssl_protocol!="TLSv1.3") 
  OR match(sig_alg, "(?i)(sha1|md5|rsa)")
  OR NOT match(ssl_cipher, "(?i)(kyber|mlkem|mldsa|dilithium)")
| eval issue=case(
    key_len > 0 AND key_len < 3072, "Weak Classical Algorithm (RSA/DH < 3072)",
    NOT match(ssl_cipher, "(?i)(kyber|mlkem|mldsa|dilithium)"), "Quantum-Vulnerable Cipher Suite (Legacy Key Exchange)",
    1=1, "Weak Cryptographic Signature"
  )
| table _time host src_ip dest_ip ssl_cipher key_len sig_alg issue`
    },
    sentinel: {
      title: 'Microsoft Sentinel KQL Rule',
      lang: 'kusto',
      code: `// Sentinel rule to detect Weak Classical Algorithms and Quantum-Vulnerable TLS tunnels
SecurityEvent
| extend KeyLength = toint(parse_json(EventData).KeyLength)
| extend CipherSuite = tostring(parse_json(EventData).CipherSuite)
| extend SignatureAlgorithm = tostring(parse_json(EventData).SignatureAlgorithm)
| where (KeyLength > 0 and KeyLength < 3072)
     or (CipherSuite !contains "ml-kem" and CipherSuite !contains "kyber" and CipherSuite !contains "ml-dsa")
| extend IssueType = case(
    KeyLength > 0 and KeyLength < 3072, "Weak Classical Algorithm (Key Size < 3072)",
    CipherSuite !contains "ml-kem", "Quantum-Vulnerable TLS Tunnel (No PQC Hybrid)",
    "Other Vulnerability"
  )
| project TimeGenerated, Computer, SourceIP = IpAddress, CipherSuite, KeyLength, SignatureAlgorithm, IssueType`
    },
    secops: {
      title: 'Google SecOps YARA-L Rule',
      lang: 'yara',
      code: `rule detect_quantum_vulnerable_systems {
  meta:
    author = "QuarkShield Security Team"
    description = "Detects systems utilizing key lengths < 3072-bit or SSL ciphers lacking post-quantum algorithms (ML-KEM/Kyber)"
    severity = "MEDIUM"

  events:
    $tls.metadata.event_type = "NETWORK_CONNECTION"
    $tls.network.tls.cipher_suite = /^(?!.*(mlkem|kyber|mldsa|dilithium)).*$/
    $tls.network.tls.client.key_length < 3072 or $tls.network.tls.client.signature_algorithm = "sha1WithRSAEncryption"
    $tls.principal.hostname = $host

  match:
    $host over 5m

  outcome:
    $vulnerable_cipher = array_distinct($tls.network.tls.cipher_suite)
    $legacy_key_length = max($tls.network.tls.client.key_length)

  condition:
    $tls
}`
    }
  };

  const copyRuleToClipboard = () => {
    navigator.clipboard.writeText(siemRules[activeRuleTab].code);
    setCopySuccess(true);
    setTimeout(() => setCopySuccess(false), 2000);
  };

  // Log Simulator Sequence
  const triggerLogSimulation = () => {
    if (isSimulating) return;
    setIsSimulating(true);
    
    setConsoleLogs(prev => [...prev, `[SIMULATOR] Ingesting telemetry feed batch...`]);

    const mockLogs = [
      {
        log: `{"time":"2026-06-11T16:28:10Z","host":"web-frontend-01","ip":"10.0.1.45","event":"TLS_HANDSHAKE","cipher":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","key_len":256,"sig_alg":"sha256WithRSAEncryption"}`,
        alert: {
          id: 'sim-' + Math.random(),
          timestamp: new Date().toLocaleTimeString(),
          source: 'Splunk' as const,
          level: 'info' as const,
          title: 'QUANTUM_VULNERABLE_TLS',
          message: 'TLS connection on web-frontend-01 lacks post-quantum key encapsulation.',
          details: 'Cipher: ECDHE-RSA-AES256-GCM | Security Level: Vulnerable to Harvest-Now-Decrypt-Later'
        }
      },
      {
        log: `{"time":"2026-06-11T16:28:11Z","host":"auth-ldap-server","ip":"10.0.2.12","event":"CERTIFICATE_ISSUED","key_type":"RSA","key_len":2048,"sig_alg":"sha1WithRSAEncryption"}`,
        alert: {
          id: 'sim-' + Math.random(),
          timestamp: new Date().toLocaleTimeString(),
          source: 'Google SecOps' as const,
          level: 'critical' as const,
          title: 'WEAK_ALGORITHM_DETECTED',
          message: 'LDAP server generated a weak RSA-2048 keypair using SHA-1 signature hashes.',
          details: 'Target ID: auth-ldap-server | Expose Score: High Vulnerability | Action: Revoke Certificate'
        }
      },
      {
        log: `{"time":"2026-06-11T16:28:12Z","host":"vpn-pqc-gateway","ip":"5.161.249.16","event":"TLS_HANDSHAKE","cipher":"TLS_ECDHE_KYBER_WITH_AES_256_GCM","key_len":1184,"sig_alg":"mldsa65"}`,
        alert: {
          id: 'sim-' + Math.random(),
          timestamp: new Date().toLocaleTimeString(),
          source: 'Splunk' as const,
          level: 'secure' as const,
          title: 'QUANTUM_SAFE_CONNECTION',
          message: 'PQC tunnel verified on vpn-pqc-gateway using hybrid ML-KEM exchange.',
          details: 'Key Exchange: ECDH X25519 + ML-KEM-768 | Verified by ML-DSA-65 Root Authority'
        }
      },
      {
        log: `{"time":"2026-06-11T16:28:13Z","host":"payroll-portal","ip":"10.0.5.8","event":"CERTIFICATE_EXPIRING","common_name":"payroll.corp.local","days_remaining":4,"issuer":"Let's Encrypt"}`,
        alert: {
          id: 'sim-' + Math.random(),
          timestamp: new Date().toLocaleTimeString(),
          source: 'Sentinel' as const,
          level: 'warning' as const,
          title: 'EXPIRING_CERTIFICATE',
          message: 'Payroll certificate expires in 4 days. System offline risk.',
          details: 'Issuer: Let\'s Encrypt | CN: payroll.corp.local | Expiry: June 15, 2026'
        }
      }
    ];

    let logIndex = 0;
    const interval = setInterval(() => {
      if (logIndex < mockLogs.length) {
        const item = mockLogs[logIndex];
        // Print raw syslog to terminal
        setConsoleLogs(prev => [...prev, `[SYSLOG] ${item.log}`]);
        
        // Expose alert if SIEM integrations are online
        setTimeout(() => {
          setConsoleLogs(prev => [...prev, `[SIEM-AGENT] Match verified for event: ${item.alert.title}`]);
          setAlerts(prev => [item.alert, ...prev]);
        }, 300);

        logIndex++;
      } else {
        clearInterval(interval);
        setIsSimulating(false);
        setConsoleLogs(prev => [...prev, `[SYSTEM] Telemetry ingestion batch completed.`]);
      }
    }, 1200);
  };

  const clearSimulationFeed = () => {
    setConsoleLogs([`[SYSTEM] QuarkShield SIEM Exporter Agent listening on UDP/514...`]);
    setAlerts([]);
  };

  return (
    <div className="siem-container" style={{ padding: '0.5rem' }}>
      {/* Header */}
      <div style={{ marginBottom: '2rem' }}>
        <h1 style={{ fontSize: '1.75rem', fontWeight: 700, color: '#ffffff', marginBottom: '0.5rem' }}>
          SIEM & Security Orchestration Hub
        </h1>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', lineHeight: '1.5' }}>
          Export post-quantum detection rules and simulate real-time log ingestion for Splunk, Microsoft Sentinel, and Google SecOps Chronicle.
        </p>
      </div>

      {/* Row 1: Connection Status Cards */}
      <div className="grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.25rem', marginBottom: '2rem' }}>
        {/* Splunk Connector */}
        <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f0f3f6' }}>Splunk Connector</span>
            <span className={`badge ${splunkConnected ? 'success' : 'muted'}`} style={{ 
              background: splunkConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255, 255, 255, 0.05)',
              border: splunkConnected ? '1px solid var(--status-secure)' : '1px solid var(--border-normal)',
              color: splunkConnected ? 'var(--status-secure)' : 'var(--text-secondary)',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.2rem 0.6rem',
              borderRadius: '4px'
            }}>
              {splunkConnected ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '1.25rem' }}>
            <div style={{ marginBottom: '0.25rem' }}>HEC Endpoint: https://splunk-hec:8088</div>
            <div>Token ID: ••••••••-4a21</div>
          </div>
          <button 
            onClick={() => setSplunkConnected(!splunkConnected)}
            className="btn-secondary" 
            style={{ width: '100%', fontSize: '0.85rem', padding: '0.5rem' }}
          >
            {splunkConnected ? 'Disconnect Agent' : 'Connect Agent'}
          </button>
        </div>

        {/* Microsoft Sentinel Connector */}
        <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f0f3f6' }}>Microsoft Sentinel</span>
            <span className={`badge ${sentinelConnected ? 'success' : 'muted'}`} style={{ 
              background: sentinelConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255, 255, 255, 0.05)',
              border: sentinelConnected ? '1px solid var(--status-secure)' : '1px solid var(--border-normal)',
              color: sentinelConnected ? 'var(--status-secure)' : 'var(--text-secondary)',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.2rem 0.6rem',
              borderRadius: '4px'
            }}>
              {sentinelConnected ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '1.25rem' }}>
            <div style={{ marginBottom: '0.25rem' }}>Workspace ID: sentinel-ws-01</div>
            <div>Secret Key: ••••••••-7fef</div>
          </div>
          <button 
            onClick={() => setSentinelConnected(!sentinelConnected)}
            className="btn-secondary" 
            style={{ width: '100%', fontSize: '0.85rem', padding: '0.5rem' }}
          >
            {sentinelConnected ? 'Disconnect Agent' : 'Connect Agent'}
          </button>
        </div>

        {/* Google SecOps Connector */}
        <div className="glass-panel" style={{ padding: '1.5rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem' }}>
            <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f0f3f6' }}>Google SecOps (Chronicle)</span>
            <span className={`badge ${secopsConnected ? 'success' : 'muted'}`} style={{ 
              background: secopsConnected ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255, 255, 255, 0.05)',
              border: secopsConnected ? '1px solid var(--status-secure)' : '1px solid var(--border-normal)',
              color: secopsConnected ? 'var(--status-secure)' : 'var(--text-secondary)',
              fontSize: '0.75rem',
              fontWeight: 600,
              padding: '0.2rem 0.6rem',
              borderRadius: '4px'
            }}>
              {secopsConnected ? 'CONNECTED' : 'OFFLINE'}
            </span>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '1.25rem' }}>
            <div style={{ marginBottom: '0.25rem' }}>Customer ID: chronicle-corp-us</div>
            <div>Auth Type: GCP Service Account</div>
          </div>
          <button 
            onClick={() => setSecopsConnected(!secopsConnected)}
            className="btn-secondary" 
            style={{ width: '100%', fontSize: '0.85rem', padding: '0.5rem' }}
          >
            {secopsConnected ? 'Disconnect Agent' : 'Connect Agent'}
          </button>
        </div>
      </div>

      {/* Row 2: Two-Column Layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: '1.5rem' }}>
        {/* Left Column: Live Terminal and Alerts */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Terminal */}
          <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Terminal size={18} style={{ color: 'var(--accent-cyan)' }} />
                <span style={{ fontSize: '1rem', fontWeight: 700, color: '#f0f3f6' }}>Syslog Exporter Stream Simulator</span>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem' }}>
                <button 
                  onClick={triggerLogSimulation}
                  disabled={isSimulating}
                  className="btn-primary" 
                  style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}
                >
                  <Play size={12} />
                  <span>{isSimulating ? 'Streaming...' : 'Simulate Log Influx'}</span>
                </button>
                <button 
                  onClick={clearSimulationFeed}
                  className="btn-secondary" 
                  style={{ fontSize: '0.78rem', padding: '0.35rem 0.6rem', border: '1px solid rgba(255,255,255,0.1)' }}
                  title="Clear Feed"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            </div>

            <div style={{ 
              height: '240px', 
              background: 'var(--bg-dark)', 
              borderRadius: '6px', 
              border: '1px solid rgba(255, 255, 255, 0.05)',
              padding: '0.75rem', 
              overflowY: 'auto',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.78rem',
              lineHeight: '1.5',
              color: 'var(--text-secondary)',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.35rem'
            }}>
              {consoleLogs.map((log, index) => {
                let color = 'var(--text-secondary)';
                if (log.startsWith('[SYSTEM]')) color = 'var(--text-muted)';
                else if (log.startsWith('[SIMULATOR]')) color = 'var(--accent-purple)';
                else if (log.includes('TLS_ECDHE_KYBER')) color = 'var(--status-secure)';
                else if (log.includes('RSA_WITH_AES') || log.includes('rsa-2048')) color = 'var(--status-vulnerable)';
                else if (log.includes('CERTIFICATE_EXPIRING')) color = 'var(--status-warning)';
                
                return (
                  <div key={index} style={{ color }}>
                    {log}
                  </div>
                );
              })}
              <div ref={consoleEndRef} />
            </div>
          </div>

          {/* Active Threats feed */}
          <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)', flexGrow: 1 }}>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f0f3f6', marginBottom: '1rem', borderLeft: '3px solid var(--accent-purple)', paddingLeft: '8px' }}>
              Threat Alerts parsed by SIEM
            </h3>

            {alerts.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '2.5rem 0', color: 'var(--text-muted)' }}>
                <ShieldCheck size={32} style={{ color: 'var(--status-secure)', marginBottom: '0.5rem', opacity: 0.7 }} />
                <div style={{ fontSize: '0.88rem', fontWeight: 600 }}>No cryptographic threat alerts triggered.</div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', maxHeight: '280px', overflowY: 'auto' }}>
                {alerts.map(alert => {
                  let borderGlow = 'rgba(255, 255, 255, 0.05)';
                  let alertBadgeBg = 'rgba(255, 255, 255, 0.05)';
                  let alertBadgeColor = 'var(--text-secondary)';
                  
                  if (alert.level === 'critical') {
                    borderGlow = 'rgba(239, 68, 68, 0.25)';
                    alertBadgeBg = 'rgba(239, 68, 68, 0.1)';
                    alertBadgeColor = 'var(--status-vulnerable)';
                  } else if (alert.level === 'warning') {
                    borderGlow = 'rgba(245, 158, 11, 0.25)';
                    alertBadgeBg = 'rgba(245, 158, 11, 0.1)';
                    alertBadgeColor = 'var(--status-warning)';
                  } else if (alert.level === 'secure') {
                    borderGlow = 'rgba(16, 185, 129, 0.25)';
                    alertBadgeBg = 'rgba(16, 185, 129, 0.1)';
                    alertBadgeColor = 'var(--status-secure)';
                  } else if (alert.level === 'info') {
                    borderGlow = 'rgba(0, 240, 255, 0.25)';
                    alertBadgeBg = 'rgba(0, 240, 255, 0.1)';
                    alertBadgeColor = 'var(--accent-cyan)';
                  }

                  return (
                    <div key={alert.id} style={{ 
                      border: `1px solid ${borderGlow}`, 
                      background: 'rgba(10, 15, 24, 0.3)',
                      borderRadius: '6px', 
                      padding: '0.75rem 1rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.35rem'
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: '0.85rem', fontWeight: 700, color: alertBadgeColor, letterSpacing: '0.02em' }}>
                          {alert.title}
                        </span>
                        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{alert.timestamp}</span>
                          <span style={{ 
                            fontSize: '0.68rem', 
                            fontWeight: 700, 
                            background: alertBadgeBg, 
                            border: `1px solid ${alertBadgeColor}`,
                            color: alertBadgeColor,
                            padding: '0.05rem 0.4rem',
                            borderRadius: '3px'
                          }}>
                            {alert.source.toUpperCase()}
                          </span>
                        </div>
                      </div>
                      <p style={{ fontSize: '0.82rem', color: '#ffffff', fontWeight: 500 }}>{alert.message}</p>
                      <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{alert.details}</p>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Rule Exporter */}
        <div className="glass-panel" style={{ padding: '1.25rem', border: '1px solid var(--border-normal)', borderRadius: '8px', background: 'var(--bg-card)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
            <FileCode size={18} style={{ color: 'var(--accent-purple)' }} />
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#f0f3f6' }}>SIEM Rule Exporter Engine</h3>
          </div>

          <div style={{ display: 'flex', gap: '0.35rem', marginBottom: '1rem', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.5rem' }}>
            <button 
              onClick={() => setActiveRuleTab('splunk')}
              className={`exporter-tab ${activeRuleTab === 'splunk' ? 'active' : ''}`}
              style={{
                background: 'none',
                border: 'none',
                color: activeRuleTab === 'splunk' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                borderBottom: activeRuleTab === 'splunk' ? '2px solid var(--accent-cyan)' : 'none',
                fontWeight: 600,
                fontSize: '0.85rem',
                padding: '0.4rem 0.8rem',
                cursor: 'pointer'
              }}
            >
              Splunk (SPL)
            </button>
            <button 
              onClick={() => setActiveRuleTab('sentinel')}
              className={`exporter-tab ${activeRuleTab === 'sentinel' ? 'active' : ''}`}
              style={{
                background: 'none',
                border: 'none',
                color: activeRuleTab === 'sentinel' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                borderBottom: activeRuleTab === 'sentinel' ? '2px solid var(--accent-cyan)' : 'none',
                fontWeight: 600,
                fontSize: '0.85rem',
                padding: '0.4rem 0.8rem',
                cursor: 'pointer'
              }}
            >
              Sentinel (KQL)
            </button>
            <button 
              onClick={() => setActiveRuleTab('secops')}
              className={`exporter-tab ${activeRuleTab === 'secops' ? 'active' : ''}`}
              style={{
                background: 'none',
                border: 'none',
                color: activeRuleTab === 'secops' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                borderBottom: activeRuleTab === 'secops' ? '2px solid var(--accent-cyan)' : 'none',
                fontWeight: 600,
                fontSize: '0.85rem',
                padding: '0.4rem 0.8rem',
                cursor: 'pointer'
              }}
            >
              Google SecOps
            </button>
          </div>

          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '1rem' }}>
            Copy this rule configuration directly into your SIEM console. It will search audit feeds for <strong>weak algorithms</strong>, <strong>expiring certificates</strong>, and <strong>quantum-vulnerable endpoints</strong>.
          </p>

          <div style={{ position: 'relative', flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ 
              background: 'var(--bg-dark)', 
              border: '1px solid rgba(255,255,255,0.05)', 
              borderRadius: '6px', 
              padding: '1rem',
              overflow: 'auto',
              maxHeight: '340px',
              flexGrow: 1
            }}>
              <pre style={{ margin: 0 }}><code style={{ 
                fontFamily: 'var(--font-mono)', 
                fontSize: '0.76rem', 
                color: 'var(--text-primary)',
                lineHeight: '1.45'
              }}>{siemRules[activeRuleTab].code}</code></pre>
            </div>
            
            <button 
              onClick={copyRuleToClipboard}
              className="btn-primary" 
              style={{ 
                marginTop: '1rem',
                display: 'flex', 
                justifyContent: 'center', 
                alignItems: 'center', 
                gap: '0.5rem',
                fontSize: '0.85rem',
                padding: '0.6rem'
              }}
            >
              {copySuccess ? <Check size={14} /> : <Copy size={14} />}
              <span>{copySuccess ? 'Copied Rule!' : 'Copy Rule Configuration'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
