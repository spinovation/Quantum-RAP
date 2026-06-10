import React from 'react';
import { 
  LayoutDashboard, 
  ScanLine, 
  ShieldAlert, 
  CalendarDays, 
  FileCheck, 
  Bot,
  Settings,
  LogOut,
  PlusCircle,
  ShieldAlert as BrandIcon
} from 'lucide-react';

export type TabType = 'overview' | 'scanner' | 'inventory' | 'migration' | 'compliance' | 'ai' | 'admin' | 'deploy';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  vulnerabilityCount: number;
  role: string;
  email: string;
  onLogout: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ 
  activeTab, 
  setActiveTab, 
  vulnerabilityCount,
  role,
  email,
  onLogout
}) => {
  const navItems = [
    { id: 'overview', name: 'Overview', icon: LayoutDashboard },
    { id: 'scanner', name: 'Crypto Scanner', icon: ScanLine },
    { 
      id: 'inventory', 
      name: 'Vulnerability Registry', 
      icon: ShieldAlert,
      badge: vulnerabilityCount > 0 ? vulnerabilityCount : undefined
    },
    { id: 'migration', name: 'Migration Planner', icon: CalendarDays },
    { id: 'compliance', name: 'Compliance & Audit', icon: FileCheck },
    { id: 'ai', name: 'AI Remediation Hub', icon: Bot }
  ];

  // Dynamically append Admin Panel if the logged-in user is platform administrator
  if (role === 'admin') {
    navItems.push({ id: 'admin', name: 'Admin Panel', icon: Settings });
    navItems.push({ id: 'deploy', name: 'Deploy Tenant Stack', icon: PlusCircle });
  }

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-icon">
          <BrandIcon size={20} strokeWidth={2.5} />
        </div>
        <span className="brand-name">QuarkShield</span>
      </div>

      <nav style={{ flexGrow: 1 }}>
        <ul className="nav-links">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <li key={item.id} className="nav-item">
                <button
                  onClick={() => setActiveTab(item.id as TabType)}
                  className={`nav-btn ${activeTab === item.id ? 'active' : ''}`}
                >
                  <Icon />
                  <span style={{ flexGrow: 1 }}>{item.name}</span>
                  {item.badge !== undefined && (
                    <span 
                      className="badge danger" 
                      style={{ 
                        padding: '0.1rem 0.4rem', 
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: '700'
                      }}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="sidebar-footer" style={{ borderTop: '1px solid var(--border-normal)', paddingTop: '1rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 }}>
            <div className="pulse-dot" style={{ flexShrink: 0 }}></div>
            <div style={{ minWidth: 0 }}>
              <div 
                style={{ 
                  fontSize: '0.8rem', 
                  fontWeight: 600, 
                  color: 'var(--text-primary)', 
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}
                title={email}
              >
                {email}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                {role} Node
              </div>
            </div>
          </div>
          <button 
            onClick={onLogout}
            style={{ 
              background: 'none', 
              border: 'none', 
              color: 'var(--text-muted)', 
              cursor: 'pointer',
              display: 'flex',
              padding: '0.35rem',
              borderRadius: '4px',
              transition: 'all 0.2s'
            }}
            onMouseEnter={(e) => e.currentTarget.style.color = 'var(--status-vulnerable)'}
            onMouseLeave={(e) => e.currentTarget.style.color = 'var(--text-muted)'}
            title="Log Out"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </aside>
  );
};
