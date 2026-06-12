import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Users, 
  Database,
  ShieldAlert,
  Layers,
  Globe,
  RefreshCw,
  Lock,
  Unlock,
  Search,
  ChevronUp,
  ChevronDown
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

interface UserInfo {
  id: string;
  email: string;
  role: string;
  email_verified: boolean;
  cmdb_enabled: boolean;
  row_locked: boolean;
  last_login: string | null;
  created_at: string;
}

export const AdminPanel: React.FC = () => {
  const [clients, setClients] = useState<ClientInfo[]>([]);
  const [clientStats, setClientStats] = useState<{ [name: string]: ClientStats }>({});
  const [users, setUsers] = useState<UserInfo[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Fetch client list and users from Express API
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
      
      // Fetch stats for each client
      data.forEach((c: ClientInfo) => {
        fetchStatsForClient(c.name);
      });

      // Fetch users
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
        { 
          id: '1', 
          email: 'democlient@example.com', 
          role: 'user',
          email_verified: true, 
          cmdb_enabled: true,
          row_locked: false,
          last_login: new Date(Date.now() - 600000).toISOString(),
          created_at: new Date(Date.now() - 3600000).toISOString() 
        },
        { 
          id: '2', 
          email: 'pending_client@example.com', 
          role: 'user',
          email_verified: true, 
          cmdb_enabled: false,
          row_locked: false,
          last_login: null,
          created_at: new Date(Date.now() - 1800000).toISOString() 
        },
        { 
          id: '3', 
          email: 'locked_client@example.com', 
          role: 'user',
          email_verified: true, 
          cmdb_enabled: false,
          row_locked: true,
          last_login: new Date(Date.now() - 1200000).toISOString(),
          created_at: new Date(Date.now() - 600000).toISOString() 
        }
      ]);
      if (err.message && err.message.includes('Access Denied')) {
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

  // Handle Inline Client Provisioning (Deploy Tenant)
  const handleDeployInline = async (email: string, namePrefix: string) => {
    setIsRefreshing(true);
    setErrorMessage(null);

    // Calculate ports dynamically
    const appPorts = clients.map((c: ClientInfo) => c.appPort).filter((p: number) => p > 0);
    const dbPorts = clients.map((c: ClientInfo) => c.dbPort).filter((p: number) => p > 0);
    const maxAppPort = appPorts.length > 0 ? Math.max(...appPorts) : 5000;
    const maxDbPort = dbPorts.length > 0 ? Math.max(...dbPorts) : 5432;
    const nextAppPort = maxAppPort + 1;
    const nextDbPort = maxDbPort + 1;

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/admin/clients', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          name: namePrefix,
          appPort: nextAppPort,
          dbPort: nextDbPort,
          geminiApiKey: '',
          email
        })
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to provision client stack.');
      }

      alert(`Success: ${data.message}`);
      fetchClients();
    } catch (err: any) {
      console.error('Provisioning failed:', err);
      setErrorMessage(err.message);
      alert(`Provisioning Error: ${err.message}`);
    } finally {
      setIsRefreshing(false);
    }
  };

  // Handle Client Decommissioning
  const handleDecommission = async (name: string) => {
    const confirm = window.confirm(`WARNING: Are you sure you want to decommission client '${name}'? This will completely terminate all their containers and PERMANENTLY delete their entire database volume.`);
    if (!confirm) return;

    setIsRefreshing(true);
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
    } finally {
      setIsRefreshing(false);
    }
  };

  // Toggle user row lock state
  const handleToggleLock = async (userId: string, currentLocked: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/lock`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ locked: !currentLocked })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle lock.');
      }
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, row_locked: !currentLocked } : u));
    } catch (err: any) {
      console.error('Toggle lock failed:', err);
      alert(`Lock Toggle Error: ${err.message}`);
    }
  };

  // Toggle user CMDB premium feature
  const handleToggleCMDB = async (userId: string, targetEnabled: boolean) => {
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch(`/api/admin/users/${userId}/cmdb`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ enabled: targetEnabled })
      });
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Failed to toggle Crypto CMDB status.');
      }
      alert(data.message);
      
      // Update local state directly for responsive feedback
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, cmdb_enabled: targetEnabled } : u));
    } catch (err: any) {
      console.error('CMDB toggle failed:', err);
      alert(`CMDB Config Error: ${err.message}`);
    }
  };

  // Search and Sort State
  const [searchQuery, setSearchQuery] = useState('');
  const [sortField, setSortField] = useState<'email' | 'row_locked' | 'last_login' | 'status' | 'appPort' | 'userCount'>('email');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');

  const requestSort = (field: typeof sortField) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
  };

  // Filter users based on search query (email or workspace prefix)
  const filteredUsers = users.filter(u => {
    const sanitizedPrefix = u.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
    return u.email.toLowerCase().includes(searchQuery.toLowerCase()) || 
           sanitizedPrefix.includes(searchQuery.toLowerCase());
  });

  // Helper to extract sorting values
  const getSortValue = (u: UserInfo, field: typeof sortField) => {
    const sanitizedPrefix = u.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
    const client = clients.find(c => c.name === sanitizedPrefix);
    const stats = client ? clientStats[client.name] : null;

    switch (field) {
      case 'email':
        return u.email.toLowerCase();
      case 'row_locked':
        return u.row_locked ? 1 : 0;
      case 'last_login':
        return u.last_login ? new Date(u.last_login).getTime() : 0;
      case 'status':
        if (!client) return 0;
        const isOnline = stats ? stats.status === 'active' : client.status === 'active';
        return isOnline ? 2 : 1;
      case 'appPort':
        return client ? client.appPort : 0;
      case 'userCount':
        return stats ? stats.userCount : 0;
      default:
        return '';
    }
  };

  // Sort filtered users
  const sortedUsers = [...filteredUsers].sort((a, b) => {
    const valA = getSortValue(a, sortField);
    const valB = getSortValue(b, sortField);

    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
    return 0;
  });

  const renderSortableHeader = (label: string, field: typeof sortField, style?: React.CSSProperties) => {
    const isActive = sortField === field;
    return (
      <th 
        onClick={() => requestSort(field)} 
        onMouseEnter={(e) => e.currentTarget.style.color = 'var(--accent-cyan)'}
        onMouseLeave={(e) => e.currentTarget.style.color = isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)'}
        style={{ 
          cursor: 'pointer', 
          userSelect: 'none',
          color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
          transition: 'all 0.2s',
          ...style 
        }}
      >
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}>
          <span>{label}</span>
          <span style={{ 
            display: 'inline-flex', 
            alignItems: 'center', 
            color: isActive ? 'var(--accent-cyan)' : 'var(--text-muted)',
            opacity: isActive ? 1 : 0.4,
            transition: 'opacity 0.2s'
          }}>
            {isActive ? (
              sortDirection === 'asc' ? <ChevronUp size={14} /> : <ChevronDown size={14} />
            ) : (
              <ChevronUp size={14} />
            )}
          </span>
        </div>
      </th>
    );
  };

  return (
    <>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Administrative Orchestration Panel</h2>
          <p>Deploy physically isolated container environments, manage configuration locks, and activate premium Crypto CMDB services.</p>
        </div>
        <button 
          className="btn-secondary" 
          onClick={fetchClients}
          disabled={isRefreshing}
          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem' }}
        >
          <RefreshCw size={14} className={isRefreshing ? 'spin' : ''} /> Refresh Registry
        </button>
      </div>

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

      {/* Metrics Grid */}
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
            <h3>Active Server Ports</h3>
            <div className="metric-value" style={{ color: '#c084fc' }}>
              {clients.length > 0 ? `${Math.min(...clients.map(c => c.appPort))}-${Math.max(...clients.map(c => c.appPort))}` : 'None'}
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

      {/* Unified Tenant Management Registry */}
      <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', marginTop: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
              <Users size={18} color="var(--accent-cyan)" /> Administrative Tenant Registry
            </h3>
            <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', margin: 0 }}>
              Manage client user accounts, toggle premium CMDB services, lock/unlock configs, and deploy isolated secure nodes.
            </p>
          </div>
          
          {/* User Search Input */}
          <div style={{ position: 'relative', width: '100%', maxWidth: '300px' }}>
            <Search 
              size={14} 
              style={{ 
                position: 'absolute', 
                left: '10px', 
                top: '50%', 
                transform: 'translateY(-50%)', 
                color: 'var(--text-muted)' 
              }} 
            />
            <input 
              type="text" 
              placeholder="Search email or workspace..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                width: '100%',
                padding: '0.45rem 1rem 0.45rem 2.2rem',
                borderRadius: '6px',
                background: 'rgba(0,0,0,0.3)',
                border: '1px solid var(--border-normal)',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent-cyan)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border-normal)'}
            />
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table className="quark-table">
            <thead>
              <tr>
                {renderSortableHeader('Lock', 'row_locked', { width: '80px', textAlign: 'center' })}
                {renderSortableHeader('User & Workspace', 'email')}
                {renderSortableHeader('Network Channels', 'appPort')}
                {renderSortableHeader('Database Stats', 'userCount')}
                {renderSortableHeader('Last Login', 'last_login')}
                {renderSortableHeader('Orchestration Status', 'status')}
                <th style={{ textAlign: 'center', userSelect: 'none', color: 'var(--text-secondary)' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedUsers.map(u => {
                const sanitizedPrefix = u.email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
                const client = clients.find(c => c.name === sanitizedPrefix);
                const stats = client ? clientStats[client.name] : null;
                const isProvisioned = !!client;
                const isOnline = stats ? stats.status === 'active' : (client ? client.status === 'active' : false);
                
                return (
                  <tr key={u.id} style={{ opacity: u.row_locked ? 0.75 : 1 }}>
                    <td style={{ textAlign: 'center', verticalAlign: 'middle' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                        <input 
                          type="checkbox"
                          checked={u.row_locked}
                          onChange={() => handleToggleLock(u.id, u.row_locked)}
                          style={{ 
                            cursor: 'pointer',
                            width: '16px',
                            height: '16px',
                            accentColor: 'var(--accent-cyan)'
                          }}
                          title={u.row_locked ? "Click to Unlock Row" : "Click to Lock Row"}
                        />
                        {u.row_locked ? (
                          <Lock size={14} style={{ color: 'var(--status-vulnerable)' }} />
                        ) : (
                          <Unlock size={14} style={{ color: 'var(--text-muted)' }} />
                        )}
                      </div>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{u.email}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 400, marginTop: '0.1rem' }}>
                        Workspace: <span style={{ color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)' }}>{sanitizedPrefix}</span>
                      </div>
                    </td>
                    <td>
                      {isProvisioned ? (
                        <div>
                          <div style={{ fontSize: '0.85rem' }}>
                            <span style={{ color: 'var(--text-muted)' }}>App:</span>{' '}
                            <a 
                              href={`${window.location.protocol}//${window.location.hostname}:${client.appPort}`} 
                              target="_blank" 
                              rel="noreferrer" 
                              style={{ color: 'var(--accent-cyan)', textDecoration: 'underline', fontFamily: 'var(--font-mono)' }}
                            >
                              {client.appPort}
                            </a>
                          </div>
                          <div style={{ fontSize: '0.85rem', marginTop: '0.1rem' }}>
                            <span style={{ color: 'var(--text-muted)' }}>DB:</span>{' '}
                            <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{client.dbPort}</span>
                          </div>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem', fontStyle: 'italic' }}>No active ports</span>
                      )}
                    </td>
                    <td>
                      {isProvisioned ? (
                        <div>
                          <div style={{ fontSize: '0.85rem' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Users:</span>{' '}
                            <strong style={{ color: 'var(--text-primary)' }}>{stats ? stats.userCount : '0'}</strong>
                          </div>
                          <div style={{ fontSize: '0.85rem', marginTop: '0.1rem' }}>
                            <span style={{ color: 'var(--text-muted)' }}>Keys:</span>{' '}
                            <strong style={{ color: 'var(--text-primary)' }}>{stats ? stats.assetCount : '0'}</strong>
                          </div>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>-</span>
                      )}
                    </td>
                    <td style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                      {u.last_login ? new Date(u.last_login).toLocaleString() : <span style={{ fontStyle: 'italic', color: 'var(--text-muted)' }}>Never</span>}
                    </td>
                    <td>
                      {isProvisioned ? (
                        <span style={{ 
                          color: isOnline ? 'var(--status-secure)' : 'var(--status-vulnerable)',
                          fontWeight: 600,
                          fontSize: '0.82rem',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: '0.25rem'
                        }}>
                          <Activity size={12} className={isOnline ? 'pulse' : ''} /> {isOnline ? 'ACTIVE' : 'OFFLINE'}
                        </span>
                      ) : (
                        <span style={{ 
                          color: 'var(--status-warning)',
                          fontWeight: 600,
                          fontSize: '0.82rem'
                        }}>
                          PENDING PROVISIONING
                        </span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center' }}>
                        {/* Deploy / Decom Button */}
                        {isProvisioned ? (
                          <button
                            onClick={() => handleDecommission(client.name)}
                            disabled={u.row_locked}
                            className="btn-secondary"
                            style={{
                              padding: '0.4rem 0.8rem',
                              fontSize: '0.8rem',
                              color: u.row_locked ? 'var(--text-muted)' : 'var(--status-vulnerable)',
                              border: '1px solid rgba(239, 68, 68, 0.2)',
                              background: 'rgba(239, 68, 68, 0.05)',
                              cursor: u.row_locked ? 'not-allowed' : 'pointer'
                            }}
                          >
                            Decom Tenant
                          </button>
                        ) : (
                          <button
                            onClick={() => handleDeployInline(u.email, sanitizedPrefix)}
                            disabled={u.row_locked}
                            className="btn-primary"
                            style={{
                              padding: '0.4rem 0.8rem',
                              fontSize: '0.8rem',
                              background: u.row_locked ? 'var(--border-normal)' : 'linear-gradient(to right, var(--accent-purple), #a855f7)',
                              cursor: u.row_locked ? 'not-allowed' : 'pointer'
                            }}
                          >
                            Deploy Tenant
                          </button>
                        )}

                        {/* Enable / Disable CMDB Button */}
                        {u.cmdb_enabled ? (
                          <button
                            onClick={() => handleToggleCMDB(u.id, false)}
                            disabled={u.row_locked}
                            className="btn-secondary"
                            style={{
                              padding: '0.4rem 0.8rem',
                              fontSize: '0.8rem',
                              color: u.row_locked ? 'var(--text-muted)' : 'var(--status-vulnerable)',
                              border: '1px solid rgba(239, 68, 68, 0.2)',
                              background: 'rgba(239, 68, 68, 0.05)',
                              cursor: u.row_locked ? 'not-allowed' : 'pointer'
                            }}
                          >
                            Disable CMDB
                          </button>
                        ) : (
                          <button
                            onClick={() => handleToggleCMDB(u.id, true)}
                            disabled={u.row_locked}
                            className="btn-primary"
                            style={{
                              padding: '0.4rem 0.8rem',
                              fontSize: '0.8rem',
                              background: u.row_locked ? 'var(--border-normal)' : 'linear-gradient(to right, #06b6d4, #0891b2)',
                              cursor: u.row_locked ? 'not-allowed' : 'pointer'
                            }}
                          >
                            Enable CMDB
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {sortedUsers.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                    {users.length === 0 
                      ? "No registered client users found in master database."
                      : "No registered client users matched your search criteria."}
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
