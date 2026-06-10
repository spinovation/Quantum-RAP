import React, { useState } from 'react';
import { Shield, Lock, AlertCircle, KeyRound, Mail } from 'lucide-react';

interface AuthScreenProps {
  onAuthSuccess: (token: string, user: { id: string; email: string; role: string }) => void;
}

export const AuthScreen: React.FC<AuthScreenProps> = ({ onAuthSuccess }) => {
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
    <div className="auth-wrapper" style={{ overflowY: 'auto', padding: '2rem 1rem', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ maxWidth: '1000px', width: '100%', margin: 'auto', display: 'flex', flexDirection: 'column', gap: '2rem' }}>
        
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
            display: 'flex',
            flexDirection: 'column',
            gap: '1.1rem',
            background: 'rgba(255, 255, 255, 0.02)',
            border: '1px solid var(--border-normal)',
            padding: '1.5rem',
            borderRadius: '8px',
            boxShadow: 'inset 0 1px 1px rgba(255, 255, 255, 0.05)'
          }}>
            {isMasterPortal ? (
              <>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Orchestrate client tenants</strong> and spin up physically isolated secure nodes dynamically.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Define compliance models</strong> by managing OPA Rego policies for NIST SP 800-219 and CNSA 2.0.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Monitor platform health</strong> and oversee active customer databases, email relays, and server ports.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Centralized audits</strong> to run diagnostic crawls and master cryptographic tests in a secure sandbox.
                  </span>
                </div>
              </>
            ) : (
              <>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Discover certificates and keys</strong> across enterprise environments.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Identify vulnerable cryptography</strong> using Shor's and Grover's analysis.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Generate migration plans</strong> and risk timelines built on Mosca's Theorem.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>Compliance reporting</strong> for NIST SP 800-219, CNSA 2.0, and Executive Order 14028.
                  </span>
                </div>
                <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--accent-cyan)', fontWeight: 700, fontSize: '1.2rem', lineHeight: '1' }}>•</span>
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                    <strong>AI-powered remediation</strong> recommendations and config patches.
                  </span>
                </div>
              </>
            )}
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
      </div>
    </div>
  );
};
