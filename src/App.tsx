import { useState, useEffect } from 'react';
import { Sidebar } from './components/Sidebar';
import type { TabType } from './components/Sidebar';
import { Overview } from './components/Overview';
import { Scanner } from './components/Scanner';
import { Inventory } from './components/Inventory';
import { MigrationPlanner } from './components/MigrationPlanner';
import { ComplianceReport } from './components/ComplianceReport';
import { AIAdvisor } from './components/AIAdvisor';
import { AuthScreen } from './components/AuthScreen';
import { AdminPanel } from './components/AdminPanel';
import { SIEM } from './components/SIEM';
import { getDefaultInventory } from './utils/cryptoAuditor';
import type { AuditResult } from './utils/cryptoAuditor';
import { RefreshCw } from 'lucide-react';

function App() {
  const [token, setToken] = useState<string | null>(sessionStorage.getItem('quarkshield_token'));
  const [user, setUser] = useState<{ id: string; email: string; role: string; isAdminNode?: boolean; tenantPort?: number | null } | null>(null);
  const [loading, setLoading] = useState(true);
  
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [assets, setAssets] = useState<AuditResult[]>([]);
  const [selectedAsset, setSelectedAsset] = useState<AuditResult | null>(null);

  // 1. Verify active token on mount
  useEffect(() => {
    if (token) {
      fetch('/api/auth/me', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
        .then(res => {
          if (!res.ok) throw new Error('Session expired');
          return res.json();
        })
        .then(data => {
          setUser(data.user);
          setLoading(false);
        })
        .catch(err => {
          console.warn('Authentication check failed:', err.message);
          sessionStorage.removeItem('quarkshield_token');
          setToken(null);
          setUser(null);
          setLoading(false);
        });
    } else {
      setLoading(false);
    }
  }, [token]);

  // 2. Load assets from database once authenticated
  useEffect(() => {
    if (!token || !user) return;

    fetch('/api/assets', {
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => {
        if (!res.ok) throw new Error('Failed to load assets');
        return res.json();
      })
      .then(data => {
        if (data && Array.isArray(data)) {
          if (data.length === 0) {
            // Bootstrap database with defaults if empty
            const defaults = getDefaultInventory();
            handleAddAssets(defaults);
          } else {
            setAssets(data);
          }
        }
      })
      .catch(err => {
        console.warn('Backend server offline, falling back to local client state:', err);
        setAssets(getDefaultInventory());
      });
  }, [token, user]);

  const handleAddAssets = (newAssets: AuditResult[]) => {
    fetch('/api/assets', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify(newAssets)
    })
      .then(res => res.json())
      .then(() => {
        // Sync assets state from DB
        fetch('/api/assets', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
          .then(res => res.json())
          .then(data => setAssets(data));
      })
      .catch(err => {
        console.warn('Failed to register assets on server, updating client state only:', err);
        setAssets(prev => {
          const existingIds = new Set(prev.map(a => a.id));
          const filteredNew = newAssets.filter(a => !existingIds.has(a.id));
          return [...filteredNew, ...prev];
        });
      });
  };

  const handleRemoveAsset = (id: string) => {
    fetch(`/api/assets/${id}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${token}` }
    })
      .then(res => res.json())
      .then(() => {
        setAssets(prev => prev.filter(a => a.id !== id));
      })
      .catch(err => {
        console.warn('Failed to delete asset on server, updating client state only:', err);
        setAssets(prev => prev.filter(a => a.id !== id));
      });
  };

  const handleAuthSuccess = (newToken: string, newUser: { id: string; email: string; role: string; isAdminNode?: boolean; tenantPort?: number | null }) => {
    sessionStorage.setItem('quarkshield_token', newToken);
    setToken(newToken);
    setUser(newUser);
    setActiveTab('overview');
  };

  const handleLogout = () => {
    if (token) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      }).catch(err => console.error('Logout request failed:', err));
    }
    sessionStorage.removeItem('quarkshield_token');
    setToken(null);
    setUser(null);
    setActiveTab('overview');
  };

  const renderContent = () => {
    switch (activeTab) {
      case 'overview':
        return (
          <Overview 
            assets={assets} 
            setActiveTab={setActiveTab} 
            setSelectedAsset={setSelectedAsset}
          />
        );
      case 'scanner':
        return (
          <Scanner 
            onAddAssets={handleAddAssets} 
            setActiveTab={setActiveTab} 
          />
        );
      case 'inventory':
        return (
          <Inventory 
            assets={assets} 
            onRemoveAsset={handleRemoveAsset}
            selectedAsset={selectedAsset}
            setSelectedAsset={setSelectedAsset}
            onAddAssets={handleAddAssets}
          />
        );
      case 'migration':
        return <MigrationPlanner />;
      case 'compliance':
        return <ComplianceReport assets={assets} />;
      case 'ai':
        return <AIAdvisor />;
      case 'siem':
        return <SIEM />;
      case 'admin':
        return <AdminPanel showOnlyStatsAndList={true} />;
      case 'deploy':
        return <AdminPanel showOnlyDeployForm={true} />;
      default:
        return (
          <Overview 
            assets={assets} 
            setActiveTab={setActiveTab} 
            setSelectedAsset={setSelectedAsset}
          />
        );
    }
  };

  // 3. Render loading screen while validating credentials
  if (loading) {
    return (
      <div style={{ 
        height: '100vh', 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        background: 'var(--bg-dark)', 
        color: 'var(--accent-cyan)' 
      }}>
        <RefreshCw size={24} className="spin" />
        <span style={{ marginLeft: '0.75rem', fontWeight: 500 }}>Initializing Security Node...</span>
      </div>
    );
  }

  // 4. Force auth gate if unauthenticated
  if (!token || !user) {
    return <AuthScreen onAuthSuccess={handleAuthSuccess} />;
  }

  // 5. Intercept non-admin users logging into the Master Admin Portal
  if (user.isAdminNode && user.role !== 'admin') {
    const tenantUrl = user.tenantPort 
      ? (window.location.protocol === 'https:'
          ? `https://${user.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '')}.${window.location.hostname.replace('www.', '')}`
          : `http://${window.location.hostname}:${user.tenantPort}`)
      : null;

    return (
      <div style={{
        height: '100vh',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        background: 'var(--bg-dark)',
        color: 'var(--text-primary)',
        fontFamily: "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        padding: '2rem',
      }}>
        <div className="glass-panel" style={{
          maxWidth: '550px',
          width: '100%',
          padding: '2.5rem',
          textAlign: 'center',
          border: '1px solid var(--border-normal)',
          borderRadius: '8px',
          boxShadow: '0 8px 32px 0 rgba(0, 0, 0, 0.5)',
          background: 'var(--bg-card)',
        }}>
          <div style={{ marginBottom: '1.5rem' }}>
            <span style={{
              fontSize: '32px',
              fontWeight: 800,
              background: 'linear-gradient(135deg, var(--accent-cyan) 0%, var(--accent-purple) 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              letterSpacing: '0.05em',
            }}>QUARKSHIELD</span>
          </div>
          
          <h2 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#ffffff', marginBottom: '1rem' }}>
            Master Control Node
          </h2>
          
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem', lineHeight: '1.6', marginBottom: '2rem' }}>
            Hi <strong>{user.email}</strong>, this is the master administration node. Running security audits directly on this master node is restricted for client accounts.
          </p>

          {tenantUrl ? (
            <div style={{
              background: 'rgba(16, 185, 129, 0.1)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              borderRadius: '6px',
              padding: '1.25rem',
              marginBottom: '2rem',
            }}>
              <p style={{ color: 'var(--status-secure)', fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.75rem' }}>
                ✓ Your Dedicated Secure Node is Ready!
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', marginBottom: '1.25rem' }}>
                Please access your private environment on your allocated port:
              </p>
              <a 
                href={tenantUrl}
                style={{
                  display: 'inline-block',
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#ffffff',
                  fontWeight: 600,
                  fontSize: '0.9rem',
                  padding: '10px 24px',
                  textDecoration: 'none',
                  borderRadius: '4px',
                  boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
                }}
              >
                Access Your Private Portal
              </a>
            </div>
          ) : (
            <div style={{
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '6px',
              padding: '1.25rem',
              marginBottom: '2rem',
            }}>
              <p style={{ color: 'var(--status-warning)', fontSize: '0.9rem', fontWeight: 600, marginBottom: '0.5rem' }}>
                ⏳ Portal Provisioning Pending
              </p>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', lineHeight: '1.5' }}>
                The administrator is currently setting up your isolated security environment. You will receive an automated email notification at <strong>{user.email}</strong> once your private node is live.
              </p>
            </div>
          )}

          <button 
            onClick={handleLogout}
            className="btn-secondary"
            style={{
              padding: '8px 20px',
              fontSize: '0.88rem',
              width: '100%',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            Log Out Session
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="app-container">
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        vulnerabilityCount={assets.filter(a => a.isVulnerable).length}
        role={user.role}
        email={user.email}
        onLogout={handleLogout}
      />
      <main className="main-content">
        {renderContent()}
      </main>
    </div>
  );
}

export default App;
