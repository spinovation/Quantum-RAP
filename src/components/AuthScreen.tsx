import React, { useState } from 'react';
import { 
  Shield, 
  Lock, 
  AlertCircle, 
  KeyRound, 
  Mail,
  Download,
  MessageSquare,
  Scale,
  ShieldCheck,
  AlertTriangle,
  Copyright,
  Database,
  Radio,
  Brain,
  Terminal
} from 'lucide-react';

const capabilities = [
  {
    id: 'cmdb',
    title: 'Crypto CMDB',
    badge: 'Inventory Control',
    badgeColor: 'var(--accent-cyan)',
    description: 'Centralized discovery registry for certificates, private keys, host configurations, and application endpoints. Tracks ownership, crypto expiration lifecycles, and downstream service mappings.',
    icon: Database
  },
  {
    id: 'passive',
    title: 'Passive Discovery',
    badge: 'Tier 3 / Non-Intrusive',
    badgeColor: '#10b981',
    description: 'Continuous real-time packet capture (PCAP) analysis to identify insecure TLS handshakes, legacy SSH ciphers, and unencrypted traffic flows without agent overhead.',
    icon: Radio
  },
  {
    id: 'ai',
    title: 'AI Correlation & Threat Modeling',
    badge: 'AI-Powered',
    badgeColor: '#c084fc',
    description: "Employs Mosca's Theorem threat modeling to calculate organizational cryptographic deficits. Automatically clusters assets into wave-prioritized PQC migration playbooks.",
    icon: Brain
  },
  {
    id: 'compliance',
    title: 'OPA Compliance Audits',
    badge: 'NIST & CNSA 2.0',
    badgeColor: 'var(--accent-purple)',
    description: 'Executes declarative Rego policies via Open Policy Agent (OPA) to audit key lengths, signature validity, and compliance thresholds against NIST SP 800-219 guidelines.',
    icon: ShieldCheck
  },
  {
    id: 'siem',
    title: 'SIEM Integration',
    badge: 'Enterprise Telemetry',
    badgeColor: 'var(--status-warning)',
    description: 'Bridges security gaps by relaying real-time cryptographic audit logs, vulnerability alerts, and network telemetry directly to centralized SIEM platforms via syslog and JSON endpoints.',
    icon: Terminal
  }
];

interface AuthScreenProps {
  onAuthSuccess: (token: string, user: { id: string; email: string; role: string }) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthSuccess }) => {
  const [activeModal, setActiveModal] = useState<'terms' | 'privacy' | 'disclaimer' | null>(null);

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

  const [isRegistering, setIsRegistering] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [verificationSent, setVerificationSent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Detect whether we are accessing the Master/Admin Portal or an isolated client Node
  const isMasterPortal = (() => {
    const host = window.location.hostname;
    if (host === 'localhost' || host === '127.0.0.1') {
      return !window.location.port || window.location.port === '5000' || window.location.port === '5173';
    }
    const cleanHost = host.replace(/^www\./i, '');
    const parts = cleanHost.split('.');
    return parts.length <= 2; 
  })();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setVerificationSent(null);
    setLoading(true);

    const endpoint = isRegistering ? '/api/auth/register' : '/api/auth/login';

    if (isRegistering && password !== confirmPassword) {
      setError('Passwords do not match.');
      setLoading(false);
      return;
    }

    try {
      const payload = { email, password };

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || 'Authentication request failed.');
      }

      if (isRegistering) {
        setIsRegistering(false);
        setError(null);
        setEmail('');
        setPassword('');
        setConfirmPassword('');
        setVerificationSent(data.message || 'Registration successful! A verification link has been sent to your email address.');
      } else {
        // Login success
        onAuthSuccess(data.token, data.user);
      }
    } catch (err: any) {
      console.error('Auth request failed:', err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-wrapper" style={{ overflowY: 'auto', padding: '3rem 1rem', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-start' }}>
      <div style={{ maxWidth: '1000px', width: '100%', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        
        {/* Top Header Section spanning wide */}
        <div style={{ textAlign: 'left', width: '100%', paddingLeft: '0.25rem' }}>
          <span className="auth-header-subtitle" style={{
            textTransform: 'uppercase',
            fontSize: '0.85rem',
            fontWeight: 800,
            color: 'var(--accent-cyan)',
            letterSpacing: '0.15em',
            display: 'block',
            marginBottom: '0.25rem'
          }}>
            {isMasterPortal ? 'Central Orchestration Gateway' : 'Isolated Assessment Node'}
          </span>
          <h2 className="auth-header-title">
            Quantum Readiness Assessment Platform
          </h2>
        </div>

        {/* Two-Column Content Layout */}
        <div className="auth-container" style={{ marginTop: 0 }}>
          {/* Left Panel: Quantum Readiness Description */}
          <div className="auth-info-panel">

          <p style={{ color: 'var(--text-secondary)', fontSize: '0.98rem', lineHeight: '1.6', margin: 0 }}>
            {isMasterPortal 
              ? 'QuarkShield Master Portal serves as the central administrative engine. Authorize tenant deployments, monitor platform metrics, define compliance baseline models, and coordinate enterprise-wide migrations.'
              : 'QuarkShield Client Node provides a dedicated, isolated assessment environment to audit cryptographic keys, model risk lifetimes, and plan post-quantum security updates.'
            }
          </p>

          <div style={{
            background: 'linear-gradient(135deg, rgba(127, 0, 255, 0.04) 0%, rgba(0, 242, 254, 0.04) 100%)',
            border: '1px solid rgba(0, 242, 254, 0.15)',
            padding: '1.75rem',
            borderRadius: '12px',
            display: 'flex',
            flexDirection: 'column',
            gap: '1rem',
            boxShadow: '0 8px 32px rgba(0, 242, 254, 0.03)',
            marginTop: '1.5rem',
            textAlign: 'left'
          }}>
            <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0 }}>
              <Shield size={18} color="var(--accent-cyan)" />
              <span>Enterprise PQC Transition Gateway</span>
            </h3>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: '1.5', margin: 0 }}>
              QuarkShield automates transition planning for the post-quantum epoch. Scan host configurations, inventory certificate authorities, evaluate downstream system impacts, and verify alignment with security mandates.
            </p>
            <div style={{ display: 'flex', gap: '1.5rem', marginTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '1rem' }}>
              <div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-cyan)' }}>CNSA 2.0</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Policy Baseline</div>
              </div>
              <div style={{ borderLeft: '1px solid rgba(255,255,255,0.1)' }}></div>
              <div>
                <div style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--accent-purple)' }}>NIST FIPS</div>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Standard Compliant</div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Panel: Authentication Form Card */}
        <div className="glass-panel auth-card" style={{ margin: 0 }}>
          <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
            <div className="brand-logo" style={{ display: 'inline-flex', margin: '0 auto 1rem auto' }}>
              <Shield size={32} color="var(--accent-cyan)" />
            </div>
            <h1 style={{ fontSize: '1.8rem', fontWeight: 800, letterSpacing: '-0.03em', background: 'linear-gradient(to right, #c084fc, var(--accent-cyan))', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              QuarkShield Portal
            </h1>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: '0.25rem' }}>
              Quantum Readiness Assessment Gateway
            </p>
          </div>

          {error && (
            <div style={{ 
              background: 'rgba(239, 68, 68, 0.1)', 
              border: '1px solid var(--status-vulnerable)', 
              borderRadius: '6px', 
              padding: '0.75rem', 
              marginBottom: '1.25rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              fontSize: '0.88rem',
              color: '#f87171'
            }}>
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          {verificationSent && (
            <div style={{ 
              background: 'rgba(16, 185, 129, 0.1)', 
              border: '1px solid rgba(16, 185, 129, 0.4)', 
              borderRadius: '8px', 
              padding: '1rem', 
              marginBottom: '1.25rem',
              color: '#34d399',
              fontSize: '0.88rem',
              lineHeight: '1.4'
            }}>
              <h3 style={{ fontWeight: 600, marginBottom: '0.25rem' }}>Verification Pending</h3>
              <span>{verificationSent}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.88rem', marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                <Mail size={14} /> Email Address
              </label>
              <input 
                type="email" 
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter email address"
                required 
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-normal)',
                  color: 'var(--text-primary)',
                  outline: 'none'
                }}
              />
            </div>

            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.88rem', marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                <Lock size={14} /> Password
              </label>
              <input 
                type="password" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                required 
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.3)',
                  border: '1px solid var(--border-normal)',
                  color: 'var(--text-primary)',
                  outline: 'none'
                }}
              />
            </div>

            {isRegistering && (
              <div className="form-group">
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.88rem', marginBottom: '0.4rem', color: 'var(--text-secondary)' }}>
                  <KeyRound size={14} /> Confirm Password
                </label>
                <input 
                  type="password" 
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Confirm password"
                  required 
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    borderRadius: '6px',
                    background: 'rgba(0,0,0,0.3)',
                    border: '1px solid var(--border-normal)',
                    color: 'var(--text-primary)',
                    outline: 'none'
                  }}
                />
              </div>
            )}

            <button 
              type="submit" 
              disabled={loading}
              className="btn-primary" 
              style={{ 
                width: '100%', 
                padding: '0.85rem', 
                fontSize: '1rem', 
                fontWeight: 600,
                marginTop: '0.5rem',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center'
              }}
            >
              {loading ? 'Authenticating...' : isRegistering ? 'Create Account' : 'Authenticate Session'}
            </button>
          </form>

          <div style={{ marginTop: '1.5rem', textAlign: 'center', fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
            {isRegistering ? (
              <span>
                Already have an account?{' '}
                <button 
                  onClick={() => { setIsRegistering(false); setError(null); setVerificationSent(null); }}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', padding: 0, fontWeight: 500 }}
                >
                  Log In
                </button>
              </span>
            ) : (
              <span>
                Need a portal identity?{' '}
                <button 
                  onClick={() => { setIsRegistering(true); setError(null); setVerificationSent(null); }}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', cursor: 'pointer', padding: 0, fontWeight: 500 }}
                >
                  Register
                </button>
                <p style={{ fontSize: '0.75rem', marginTop: '0.5rem', color: 'var(--text-muted)' }}>
                  *Note: The first user registered on the Master Portal will automatically be assigned the Admin role.
                </p>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Platform Core Capabilities */}
      <div style={{ marginTop: '3.5rem', width: '100%' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h3 style={{ 
            fontSize: '1.6rem', 
            fontWeight: 800, 
            letterSpacing: '-0.02em', 
            background: 'linear-gradient(to right, #ffffff, #b3b3b3)', 
            WebkitBackgroundClip: 'text', 
            WebkitTextFillColor: 'transparent',
            margin: '0 0 0.5rem 0'
          }}>
            Platform Core Capabilities
          </h3>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.92rem', margin: 0 }}>
            Enterprise post-quantum cryptanalysis, continuous passive ingestion, and policy-driven compliance auditing.
          </p>
        </div>

        <div className="capability-grid">
          {capabilities.map((cap) => {
            const Icon = cap.icon;
            return (
              <div key={cap.id} className="capability-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div className="capability-icon-wrapper">
                    <Icon size={20} />
                  </div>
                  <span className="capability-badge" style={{ 
                    color: cap.badgeColor,
                    borderColor: cap.badgeColor
                  }}>
                    {cap.badge}
                  </span>
                </div>
                <div>
                  <h4 style={{ 
                    fontSize: '1.05rem', 
                    fontWeight: 700, 
                    color: '#ffffff', 
                    margin: '0 0 0.4rem 0',
                    letterSpacing: '-0.01em'
                  }}>
                    {cap.title}
                  </h4>
                  <p style={{ 
                    fontSize: '0.84rem', 
                    color: 'var(--text-secondary)', 
                    lineHeight: '1.5',
                    margin: 0
                  }}>
                    {cap.description}
                  </p>
                </div>
              </div>
            );
          })}
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
              paddingLeft: '6px',
              textAlign: 'left'
            }}>
              Support
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', alignItems: 'flex-start' }}>
              <a 
                href="mailto:Support@quarkshield.services?subject=QuarkShield Support Request"
                style={{ 
                  color: 'var(--accent-cyan)', 
                  fontSize: '0.82rem', 
                  textDecoration: 'none', 
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
              </a>
              <button 
                onClick={downloadVpnProfile}
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
              paddingLeft: '6px',
              textAlign: 'left'
            }}>
              Legal
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', alignItems: 'flex-start' }}>
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
          <div style={{ textAlign: 'left' }}>
            <span style={{ fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', fontSize: '0.72rem', letterSpacing: '0.05em', marginRight: '0.5rem' }}>Contact Us:</span>
            <a href="mailto:Support@quarkshield.services" style={{ color: 'var(--accent-cyan)', textDecoration: 'none', fontWeight: 500 }}>Support@quarkshield.services</a>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', color: 'var(--text-muted)', fontSize: '0.78rem' }}>
            <Copyright size={12} />
            <span>2026 Quark Shield LLC</span>
          </div>
        </div>
      </div>
      </div> {/* Closes maxWidth container */}

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
            </h3>
            
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
          </div>
        </div>
      )}
    </div>
  );
};
