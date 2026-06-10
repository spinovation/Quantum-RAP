import React, { useState, useEffect } from 'react';
import { 
  Server, 
  Trash2, 
  PlusCircle, 
  Activity, 
  Users, 
  Database,
  ShieldAlert,
  Layers,
  Globe,
  RefreshCw
} from 'lucide-react';

interface ClientStats {
  name: string;
  appPort: number;
  dbPort: number;
  status: 'active' | 'offline';
  userCount: number;
  assetCount: number;
}

interface ClientInfo {
  name: string;
  appPort: number;
  dbPort: number;
  status: 'active' | 'offline';
  createdAt: string;
}

interface AdminPanelProps {
  showOnlyStatsAndList?: boolean;
  showOnlyDeployForm?: boolean;
}

export const AdminPanel: React.FC<AdminPanelProps> = ({ showOnlyDeployForm }) => {
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [clientStats, setClientStats] = useState<{ [name: string]: ClientStats }>({});
  const [users, setUsers] = useState<{ id: string; email: string; email_verified: boolean; created_at: string }[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  
  // Provisioning Form State
  const [selectedUserEmail, setSelectedUserEmail] = useState('');
  const [newClientName, setNewClientName] = useState('');
  const [newAppPort, setNewAppPort] = useState('5002');
  const [newDbPort, setNewDbPort] = useState('5434');
  const [newGeminiKey, setNewGeminiKey] = useState('');
  const [isProvisioning, setIsProvisioning] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Fetch client list from Express API
  const fetchClients = async () => {
    setIsRefreshing(true);
    setErrorMessage(null);
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/clients', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!res.ok) {
        throw new Error(res.status === 403 ? 'Access Denied: Admin privileges required.' : 'Failed to fetch client list.');
      }
      const data = await res.json();
      setClients(data);
      
      // Dynamically calculate the next available ports
      if (data && data.length > 0) {
        const appPorts = data.map((c: ClientInfo) => c.appPort).filter((p: number) => p > 0);
        const dbPorts = data.map((c: ClientInfo) => c.dbPort).filter((p: number) => p > 0);
        
        const maxAppPort = appPorts.length > 0 ? Math.max(...appPorts) : 5000;
        const maxDbPort = dbPorts.length > 0 ? Math.max(...dbPorts) : 5432;
        
        setNewAppPort(String(maxAppPort + 1));
        setNewDbPort(String(maxDbPort + 1));
      } else {
        setNewAppPort('5001');
        setNewDbPort('5433');
      }
      
      // Fetch stats for each client
      data.forEach((c: ClientInfo) => {
        fetchStatsForClient(c.name);
      });

      // Fetch users (pending clients)
      const usersRes = await fetch('/api/admin/users', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (usersRes.ok) {
        const usersData = await usersRes.json();
        setUsers(usersData);
      }
    } catch (err: any) {
      console.warn('Backend admin endpoints unavailable, loading simulation mode:', err);
      // Mock Client List fallback
      const mockClients: ClientInfo[] = [
        { name: 'democlient', appPort: 5001, dbPort: 5433, status: 'active', createdAt: new Date(Date.now() - 3600000).toISOString() }
      ];
      setClients(mockClients);
      setClientStats({
        'democlient': { name: 'democlient', appPort: 5001, dbPort: 5433, status: 'active', userCount: 1, assetCount: 6 }
      });
      setUsers([
        { id: '1', email: 'pending_client@example.com', email_verified: true, created_at: new Date(Date.now() - 1800000).toISOString() },
        { id: '2', email: 'unverified_client@example.com', email_verified: false, created_at: new Date(Date.now() - 600000).toISOString() }
      ]);
      if (err.message.includes('Access Denied')) {
        setErrorMessage(err.message);
      }
    } finally {
      setIsRefreshing(false);
    }
  };

  const fetchStatsForClient = async (name: string) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/clients/${name}/stats`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (res.ok) {
        const statsData = await res.json();
        setClientStats(prev => ({ ...prev, [name]: statsData }));
      }
    } catch (err) {
      console.error(`Error loading stats for ${name}:`, err);
    }
  };

  useEffect(() => {
    fetchClients();
  }, []);

  // Handle Client Provisioning
  const handleProvision = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProvisioning(true);
    setErrorMessage(null);

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/clients', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          name: newClientName,
          appPort: Number(newAppPort),
          dbPort: Number(newDbPort),
          geminiApiKey: newGeminiKey,
          email: selectedUserEmail
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to provision client stack.');
      }

      alert(`Success: ${data.message}`);
      setNewClientName('');
      setSelectedUserEmail('');
      // Autoincrement default ports for next provision
      setNewAppPort(String(Number(newAppPort) + 1));
      setNewDbPort(String(Number(newDbPort) + 1));
      setNewGeminiKey('');
      
      // Refresh list
      fetchClients();
    } catch (err: any) {
      console.error('Provisioning failed:', err);
      setErrorMessage(err.message);
    } finally {
      setIsProvisioning(false);
    }
  };

  // Handle Client Decommissioning
  const handleDecommission = async (name: string) => {
    const confirm = window.confirm(`WARNING: Are you sure you want to decommission client '${name}'? This will completely terminate all their containers and PERMANENTLY delete their entire database volume.`);
    if (!confirm) return;

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/clients/${name}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to decommission client.');
      }
      alert(data.message);
      fetchClients();
    } catch (err: any) {
      console.error('Decommission failed:', err);
      alert(`Error: ${err.message}`);
    }
  };

  return (
    <>
      {/* 1. Header (Orchestration list mode) */}
      {!showOnlyDeployForm && (
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Administrative Orchestration Panel</h2>
            <p>Deploy physically isolated container environments and monitor client activities globally.</p>
          </div>
          <button 
            className="btn-secondary" 
            onClick={fetchClients}
            disabled={isRefreshing}
            style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
          >
            <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} /> Refresh Stacks
          </button>
        </div>
      )}

      {/* 2. Header (Deploy form mode) */}
      {showOnlyDeployForm && (
        <div>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Deploy Tenant Stack</h2>
          <p>Provision physically isolated container environments on the Hetzner host.</p>
        </div>
      )}

      {errorMessage && (
        <div style={{ 
          background: 'rgba(239, 68, 68, 0.1)', 
          border: '1px solid var(--status-vulnerable)', 
          borderRadius: '6px', 
          padding: '0.75rem', 
          margin: '1rem 0',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          color: '#f87171',
          fontSize: '0.9rem'
        }}>
          <ShieldAlert size={16} />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* 3. Stats and List Grid */}
      {!showOnlyDeployForm && (
        <>
          {/* Admin Stats Grid */}
          <div className="metrics-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', marginBottom: '1.5rem', marginTop: '1.5rem' }}>
            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Total Active Clients</h3>
                <div className="metric-value" style={{ color: 'var(--accent-cyan)' }}>{clients.length}</div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Physically Isolated Tenants
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--accent-cyan)' }}>
                <Layers size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Dynamic Server Ports</h3>
                <div className="metric-value" style={{ color: '#c084fc' }}>
                  {clients.length > 0 ? `${Math.min(...clients.map(c => c.appPort))}-${Math.max(...clients.map(c => c.appPort))}` : '0'}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Allocated Network Channels
                </div>
              </div>
              <div className="metric-icon" style={{ color: '#c084fc' }}>
                <Globe size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Registered End-Users</h3>
                <div className="metric-value" style={{ color: 'var(--status-secure)' }}>
                  {Object.values(clientStats).reduce((sum, c) => sum + (c.userCount || 0), 0)}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Total across active databases
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-secure)' }}>
                <Users size={24} />
              </div>
            </div>

            <div className="glass-panel metric-card">
              <div className="metric-info">
                <h3>Audited Assets Count</h3>
                <div className="metric-value" style={{ color: 'var(--status-warning)' }}>
                  {Object.values(clientStats).reduce((sum, c) => sum + (c.assetCount || 0), 0)}
                </div>
                <div className="metric-trend" style={{ color: 'var(--text-secondary)' }}>
                  Certificates, keys, and ciphers
                </div>
              </div>
              <div className="metric-icon" style={{ color: 'var(--status-warning)' }}>
                <Database size={24} />
              </div>
            </div>
          </div>

          {/* List panel (takes full width) */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1rem' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Server size={18} color="var(--accent-cyan)" /> Live Tenant Deployments
            </h3>

            <div style={{ overflowX: 'auto' }}>
              <table className="quark-table">
                <thead>
                  <tr>
                    <th>Client Workspace</th>
                    <th>App Port</th>
                    <th>DB Port</th>
                    <th>Database Stats</th>
                    <th>Status</th>
                    <th style={{ textAlign: 'center' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.map(c => {
                    const stats = clientStats[c.name];
                    return (
                      <tr key={c.name}>
                        <td style={{ fontWeight: 600 }}>
                          <span style={{ color: 'var(--accent-cyan)', textTransform: 'capitalize' }}>{c.name}</span>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 400, marginTop: '0.1rem' }}>
                            Deployed: {new Date(c.createdAt).toLocaleDateString()}
                          </div>
                        </td>
                        <td>
                          <a 
                            href={`${window.location.protocol}//${window.location.hostname}:${c.appPort}`} 
                            target="_blank" 
                            rel="noreferrer" 
                            style={{ color: 'var(--accent-cyan)', textDecoration: 'underline', fontFamily: 'var(--font-mono)' }}
                          >
                            {c.appPort}
                          </a>
                        </td>
                        <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{c.dbPort}</td>
                        <td>
                          <div style={{ fontSize: '0.88rem' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>Users:</span> <strong style={{ color: 'var(--text-primary)' }}>{stats ? stats.userCount : '0'}</strong>
                          </div>
                          <div style={{ fontSize: '0.88rem', marginTop: '0.1rem' }}>
                            <span style={{ color: 'var(--text-secondary)' }}>Keys:</span> <strong style={{ color: 'var(--text-primary)' }}>{stats ? stats.assetCount : '0'}</strong>
                          </div>
                        </td>
                        <td>
                          <span style={{ 
                            color: (stats?.status || c.status) === 'active' ? 'var(--status-secure)' : 'var(--status-vulnerable)',
                            fontWeight: 600,
                            fontSize: '0.85rem',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '0.25rem'
                          }}>
                            <Activity size={12} /> {(stats?.status || c.status).toUpperCase()}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <button 
                            onClick={() => handleDecommission(c.name)}
                            className="btn-secondary" 
                            style={{ 
                              padding: '0.4rem', 
                              color: 'var(--status-vulnerable)', 
                              border: '1px solid rgba(239, 68, 68, 0.2)',
                              background: 'rgba(239, 68, 68, 0.05)'
                            }}
                            title="Decommission Tenant Stack"
                          >
                            <Trash2 size={14} />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {clients.length === 0 && (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                        No active client environments provisioned.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Registered Client Users Table */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1.5rem' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Users size={18} color="var(--accent-cyan)" /> Registered Client Accounts
            </h3>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '-0.5rem' }}>
              Registered accounts waiting for isolated security node provisioning.
            </p>

            <div style={{ overflowX: 'auto' }}>
              <table className="quark-table">
                <thead>
                  <tr>
                    <th>Email Address</th>
                    <th>Registration Date</th>
                    <th>Email Status</th>
                    <th>Orchestration Status</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => {
                    const sanitizedPrefix = u.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
                    const isProvisioned = clients.some(c => c.name === sanitizedPrefix);
                    return (
                      <tr key={u.id}>
                        <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.email}</td>
                        <td style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>
                          {new Date(u.created_at).toLocaleDateString()}
                        </td>
                        <td>
                          <span style={{ 
                            color: u.email_verified ? 'var(--status-secure)' : 'var(--status-warning)',
                            fontWeight: 600,
                            fontSize: '0.85rem'
                          }}>
                            {u.email_verified ? 'VERIFIED' : 'PENDING VERIFICATION'}
                          </span>
                        </td>
                        <td>
                          <span style={{ 
                            color: isProvisioned ? 'var(--status-secure)' : 'var(--status-vulnerable)',
                            fontWeight: 600,
                            fontSize: '0.85rem'
                          }}>
                            {isProvisioned ? 'PROVISIONED' : 'PENDING PROVISIONING'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                  {users.length === 0 && (
                    <tr>
                      <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                        No registered client users found in master database.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}

      {/* 4. Deploy Form Mode */}
      {showOnlyDeployForm && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1.5rem', marginTop: '2rem' }}>
          <div className="glass-panel" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', maxWidth: '650px', width: '100%' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
              <PlusCircle size={18} color="#c084fc" /> Provision New Client Stack
            </h3>

            <form onSubmit={handleProvision} style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="form-group">
                <label style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'block' }}>
                  Select Registered Client Email
                </label>
                <select
                  value={selectedUserEmail}
                  onChange={(e) => {
                    const email = e.target.value;
                    setSelectedUserEmail(email);
                    if (email) {
                      // Derive client name from email prefix (sanitize to alphanumeric lowercase)
                      const prefix = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
                      setNewClientName(prefix);
                    } else {
                      setNewClientName('');
                    }
                  }}
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
                >
                  <option value="">-- Choose a registered user --</option>
                  {users.map(u => (
                    <option key={u.id} value={u.email}>
                      {u.email} ({u.email_verified ? 'Verified' : 'Verification Pending'})
                    </option>
                  ))}
                  {users.length === 0 && (
                    <option disabled value="">No registered users found</option>
                  )}
                </select>
              </div>

              <div className="form-group">
                <label style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'block' }}>
                  Derived Client Name (Alphanumeric only)
                </label>
                <input 
                  type="text" 
                  value={newClientName}
                  onChange={(e) => setNewClientName(e.target.value)}
                  placeholder="Derived automatically from email prefix"
                  required
                  readOnly={!!selectedUserEmail}
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    borderRadius: '6px',
                    background: selectedUserEmail ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.3)',
                    border: '1px solid var(--border-normal)',
                    color: selectedUserEmail ? 'var(--text-secondary)' : 'var(--text-primary)',
                    outline: 'none'
                  }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.25rem' }}>
                <div className="form-group">
                  <label style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'block' }}>
                    Web App Port
                  </label>
                  <input 
                    type="number" 
                    value={newAppPort}
                    onChange={(e) => setNewAppPort(e.target.value)}
                    placeholder="5002"
                    required
                    min="1024"
                    max="65535"
                    style={{
                      width: '100%',
                      padding: '0.75rem 1rem',
                      borderRadius: '6px',
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-primary)',
                      outline: 'none',
                      fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>

                <div className="form-group">
                  <label style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'block' }}>
                    Database Port
                  </label>
                  <input 
                    type="number" 
                    value={newDbPort}
                    onChange={(e) => setNewDbPort(e.target.value)}
                    placeholder="5434"
                    required
                    min="1024"
                    max="65535"
                    style={{
                      width: '100%',
                      padding: '0.75rem 1rem',
                      borderRadius: '6px',
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid var(--border-normal)',
                      color: 'var(--text-primary)',
                      outline: 'none',
                      fontFamily: 'var(--font-mono)'
                    }}
                  />
                </div>
              </div>

              <div className="form-group">
                <label style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'block' }}>
                  Client Gemini API Key (Optional)
                </label>
                <input 
                  type="password" 
                  value={newGeminiKey}
                  onChange={(e) => setNewGeminiKey(e.target.value)}
                  placeholder="Exposes private playbooks if provided"
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

              <button 
                type="submit" 
                disabled={isProvisioning}
                className="btn-primary" 
                style={{ 
                  width: '100%', 
                  padding: '0.85rem', 
                  fontWeight: 600,
                  marginTop: '0.5rem',
                  background: 'linear-gradient(to right, var(--accent-purple), #a855f7)',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: '0.5rem'
                }}
              >
                {isProvisioning ? (
                  <span>Provisioning Containers...</span>
                ) : (
                  <>
                    <PlusCircle size={16} /> Deploy Tenant Stack
                  </>
                )}
              </button>
            </form>

            <div style={{ 
              fontSize: '0.82rem', 
              color: 'var(--text-muted)', 
              background: 'rgba(0,0,0,0.15)', 
              padding: '0.75rem', 
              borderRadius: '6px',
              lineHeight: '1.4',
              marginTop: '0.5rem'
            }}>
              <strong style={{ color: 'var(--accent-cyan)' }}>Deployment Notes:</strong>
              <ul style={{ paddingLeft: '1rem', marginTop: '0.25rem', display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                <li>The client stack will automatically launch isolated containers on the host.</li>
                <li>A private database volume will be mapped for persistent data logs.</li>
                <li>Ensure the selected ports are not currently occupied by other containers or services.</li>
              </ul>
            </div>
          </div>

          {/* SMTP Settings Helper Card */}
          <div style={{ 
            fontSize: '0.82rem', 
            color: 'var(--text-muted)', 
            background: 'rgba(0,0,0,0.15)', 
            padding: '1.25rem', 
            borderRadius: '6px',
            lineHeight: '1.5',
            maxWidth: '650px',
            width: '100%',
            border: '1px solid var(--border-normal)'
          }}>
            <strong style={{ color: 'var(--accent-cyan)', fontSize: '0.9rem', display: 'block', marginBottom: '0.5rem' }}>
              ✉️ System SMTP Email Server Info
            </strong>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
              <div>SMTP_HOST: <span style={{ color: 'var(--text-secondary)' }}>mail.spacemail.com (or local maildev)</span></div>
              <div>SMTP_PORT: <span style={{ color: 'var(--text-secondary)' }}>465 (or local 1025)</span></div>
              <div>SMTP_FROM: <span style={{ color: 'var(--text-secondary)' }}>support@quarkshield.services</span></div>
              <div>SMTP_SECURE: <span style={{ color: 'var(--text-secondary)' }}>true (or local false)</span></div>
            </div>
            <p style={{ marginBottom: '0.5rem' }}>
              <strong>How to get verification and activation emails in your actual inbox:</strong>
              <br />
              Currently, QuarkShield is configured to route SMTP traffic locally to the MailDev mock server. To use your Spaceship (Spacemail) account, edit the environment parameters in your root <code style={{ color: 'var(--accent-purple)' }}>/opt/quantum-rap/docker-compose.yml</code> file on the host:
            </p>
            <pre style={{ 
              background: 'rgba(0,0,0,0.3)', 
              padding: '0.5rem', 
              borderRadius: '4px', 
              fontSize: '0.75rem', 
              overflowX: 'auto',
              color: 'var(--text-secondary)',
              border: '1px solid rgba(255,255,255,0.05)'
            }}>{`environment:
  - SMTP_HOST=mail.spacemail.com
  - SMTP_PORT=465
  - SMTP_SECURE=true
  - SMTP_USER=support@quarkshield.services
  - SMTP_PASSWORD=your_spacemail_password
  - SMTP_FROM=support@quarkshield.services`}</pre>
          </div>
        </div>
      )}
    </>
  );
};
