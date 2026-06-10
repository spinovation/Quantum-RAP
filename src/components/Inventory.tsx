import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  ShieldAlert, 
  ShieldCheck, 
  Info,
  Trash2,
  AlertOctagon,
  X
} from 'lucide-react';
import type { AuditResult } from '../utils/cryptoAuditor';

interface InventoryProps {
  assets: AuditResult[];
  onRemoveAsset: (id: string) => void;
  selectedAsset: AuditResult | null;
  setSelectedAsset: (asset: AuditResult | null) => void;
}

export const Inventory: React.FC<InventoryProps> = ({ 
  assets, 
  onRemoveAsset, 
  selectedAsset, 
  setSelectedAsset 
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  // Open dialog when selectedAsset is set
  useEffect(() => {
    const dialog = document.getElementById('asset-detail-dialog') as HTMLDialogElement;
    if (selectedAsset && dialog) {
      if (!dialog.open) {
        dialog.showModal();
      }
    }
  }, [selectedAsset]);

  const handleCloseDialog = () => {
    const dialog = document.getElementById('asset-detail-dialog') as HTMLDialogElement;
    if (dialog) {
      dialog.close();
    }
    setSelectedAsset(null);
  };

  const handleOpenDialog = (asset: AuditResult) => {
    setSelectedAsset(asset);
  };

  // Filter logic
  const filteredAssets = assets.filter(asset => {
    const matchesSearch = 
      asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.status.toLowerCase().includes(searchTerm.toLowerCase());
      
    const matchesType = typeFilter === 'all' || asset.type === typeFilter;
    
    let matchesStatus = true;
    if (statusFilter === 'vulnerable') {
      matchesStatus = asset.isVulnerable;
    } else if (statusFilter === 'secure') {
      matchesStatus = !asset.isVulnerable;
    }

    return matchesSearch && matchesType && matchesStatus;
  });

  return (
    <>
      <div>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Vulnerability Registry</h2>
        <p>Comprehensive inventory of active cryptographic assets and their quantum risk profiles.</p>
      </div>

      {/* Filter and Search Bar */}
      <div className="glass-panel" style={{ 
        padding: '1rem', 
        display: 'flex', 
        gap: '1rem', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        flexWrap: 'wrap'
      }}>
        {/* Search */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.5rem 1rem', borderRadius: '8px', border: '1px solid var(--border-normal)', flex: 1, minWidth: '240px' }}>
          <Search size={18} color="var(--text-secondary)" />
          <input 
            type="text" 
            placeholder="Search assets, algorithms..." 
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ 
              background: 'transparent', 
              border: 'none', 
              color: 'white', 
              outline: 'none', 
              width: '100%',
              fontFamily: 'var(--font-sans)',
              fontSize: '0.95rem'
            }}
          />
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Filter size={14} color="var(--text-secondary)" />
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Type:</span>
            <select 
              value={typeFilter} 
              onChange={(e) => setTypeFilter(e.target.value)}
              className="chat-text-input" 
              style={{ padding: '0.35rem 0.75rem', fontSize: '0.85rem', width: '150px', background: 'rgba(0,0,0,0.3)' }}
            >
              <option value="all">All Types</option>
              <option value="certificate">Certificates</option>
              <option value="ssh_key">SSH Keys</option>
              <option value="private_key">Private Keys</option>
              <option value="config">Configurations</option>
              <option value="url">Endpoints</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Status:</span>
            <select 
              value={statusFilter} 
              onChange={(e) => setStatusFilter(e.target.value)}
              className="chat-text-input" 
              style={{ padding: '0.35rem 0.75rem', fontSize: '0.85rem', width: '150px', background: 'rgba(0,0,0,0.3)' }}
            >
              <option value="all">All Statuses</option>
              <option value="vulnerable">Quantum Vulnerable</option>
              <option value="secure">Post-Quantum Secure</option>
            </select>
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <div className="table-wrapper">
          <table className="quark-table">
            <thead>
              <tr>
                <th>Asset Name</th>
                <th>Type</th>
                <th>Algorithm</th>
                <th>Key Size</th>
                <th>Severity</th>
                <th>Quantum Status</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id}>
                  <td style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', border: 'none' }}>
                    {asset.isVulnerable ? (
                      <ShieldAlert size={16} color="var(--status-vulnerable)" />
                    ) : (
                      <ShieldCheck size={16} color="var(--status-secure)" />
                    )}
                    <span>{asset.name}</span>
                  </td>
                  <td>
                    <span style={{ textTransform: 'capitalize' }}>
                      {asset.type.replace('_', ' ')}
                    </span>
                  </td>
                  <td>{asset.algorithm}</td>
                  <td>{asset.keySize ? `${asset.keySize}-bit` : 'N/A'}</td>
                  <td>
                    <span className={`badge ${
                      asset.riskLevel === 'critical' ? 'danger' : 
                      asset.riskLevel === 'high' ? 'danger' : 
                      asset.riskLevel === 'medium' ? 'warning' : 
                      asset.riskLevel === 'low' ? 'info' : 'success'
                    }`}>
                      {asset.riskLevel}
                    </span>
                  </td>
                  <td>
                    <span style={{ 
                      color: asset.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)',
                      fontWeight: 500
                    }}>
                      {asset.status}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.5rem' }}>
                      <button 
                        onClick={() => handleOpenDialog(asset)}
                        className="btn-secondary" 
                        style={{ padding: '0.35rem 0.6rem', fontSize: '0.8rem' }}
                      >
                        <Info size={14} /> Audit Details
                      </button>
                      <button 
                        onClick={() => onRemoveAsset(asset.id)}
                        className="btn-secondary" 
                        style={{ padding: '0.35rem', color: 'var(--status-vulnerable)', borderColor: 'rgba(255, 51, 102, 0.15)' }}
                        title="Delete asset"
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredAssets.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                    No assets matched the active filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vulnerability Details Modal using Native HTML5 Dialog */}
      <dialog 
        id="asset-detail-dialog" 
        onClose={handleCloseDialog}
      >
        {selectedAsset && (
          <>
            <div className="dialog-header">
              <h3 className="dialog-title">
                <AlertOctagon size={22} color={selectedAsset.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)'} />
                <span>Cryptographic Audit: {selectedAsset.name}</span>
              </h3>
              <button 
                onClick={handleCloseDialog} 
                style={{ 
                  background: 'none', 
                  border: 'none', 
                  color: 'var(--text-secondary)', 
                  cursor: 'pointer' 
                }}
              >
                <X size={20} />
              </button>
            </div>
            
            <div className="dialog-body">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px', border: '1px solid var(--border-normal)' }}>
                <div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>ALGORITHM TYPE</span>
                  <div style={{ fontWeight: 600 }}>{selectedAsset.algorithm}</div>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>KEY STRENGTH</span>
                  <div style={{ fontWeight: 600 }}>{selectedAsset.keySize ? `${selectedAsset.keySize}-bit` : 'N/A'}</div>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>QUANTUM POSTURE</span>
                  <div style={{ 
                    fontWeight: 700, 
                    color: selectedAsset.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)' 
                  }}>
                    {selectedAsset.status}
                  </div>
                </div>
                <div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>RISK LEVEL</span>
                  <div>
                    <span className={`badge ${selectedAsset.riskLevel === 'critical' || selectedAsset.riskLevel === 'high' ? 'danger' : selectedAsset.riskLevel === 'medium' ? 'warning' : 'success'}`}>
                      {selectedAsset.riskLevel.toUpperCase()}
                    </span>
                  </div>
                </div>
              </div>

              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Asset Summary</h4>
                <p style={{ fontSize: '0.9rem' }}>{selectedAsset.description}</p>
              </div>

              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Quantum Cryptanalysis Details</h4>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedAsset.explainer}
                </p>
              </div>

              <div>
                <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Remediation Strategy</h4>
                <p style={{ fontSize: '0.9rem', color: 'var(--accent-cyan)' }}>{selectedAsset.recommendation}</p>
              </div>

              {selectedAsset.complianceViolations.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--status-vulnerable)', marginBottom: '0.25rem' }}>Compliance Violations</h4>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
                    {selectedAsset.complianceViolations.map((v, i) => (
                      <span key={i} className="badge danger" style={{ fontSize: '0.7rem' }}>{v}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="dialog-actions">
              <button className="btn-secondary" onClick={handleCloseDialog}>Close Diagnostics</button>
            </div>
          </>
        )}
      </dialog>
    </>
  );
};
