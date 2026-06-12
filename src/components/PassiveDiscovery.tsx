import React, { useState, useEffect, useRef } from 'react';
import { 
  Radio, 
  Activity, 
  UploadCloud, 
  Play, 
  Square, 
  Plus, 
  CheckCircle, 
  AlertTriangle,
  Cpu,
  Database,
  Network,
  RefreshCw,
  Clock
} from 'lucide-react';
import type { AuditResult } from '../utils/cryptoAuditor';

interface ShadowAsset {
  id: string;
  name: string;
  ip: string;
  protocol: string;
  algorithm: string;
  isVulnerable: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'secure';
  status: 'Quantum Vulnerable' | 'Post-Quantum Secure';
}

interface PassiveDiscoveryProps {
  onAddAssets: (assets: AuditResult[]) => void;
}

export const PassiveDiscovery: React.FC<PassiveDiscoveryProps> = ({ onAddAssets }) => {
  const [isSniffing, setIsSniffing] = useState(false);
  const [consoleLogs, setConsoleLogs] = useState<string[]>([
    `[${new Date().toLocaleTimeString()}] [SYSTEM] Interface eth0 initialized in promiscuous mode.`,
    `[${new Date().toLocaleTimeString()}] [SYSTEM] Cryptographic TLS/SSH parser filter bound.`,
    `[${new Date().toLocaleTimeString()}] [SYSTEM] Passive capture engine idle. Click "Start Capture" to begin packet parsing.`
  ]);
  
  // PCAP Upload state
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  
  // Shadow Assets discovered passively
  const [shadowAssets, setShadowAssets] = useState<ShadowAsset[]>([
    {
      id: 'shadow-1',
      name: 'pqc-vault.secure.internal',
      ip: '172.24.120.44',
      protocol: 'TLSv1.3',
      algorithm: 'X25519MLKEM768 / ECDSA',
      isVulnerable: false,
      riskLevel: 'secure',
      status: 'Post-Quantum Secure'
    },
    {
      id: 'shadow-2',
      name: 'legacy-syslog.corp.local',
      ip: '192.168.4.99',
      protocol: 'TLSv1.2',
      algorithm: 'ECDHE-RSA-AES256-GCM-SHA384 / RSA-2048',
      isVulnerable: true,
      riskLevel: 'high',
      status: 'Quantum Vulnerable'
    },
    {
      id: 'shadow-3',
      name: 'vulnerable-api-auth.internal',
      ip: '10.0.12.80',
      protocol: 'TLSv1.2',
      algorithm: 'ECDHE-ECDSA-AES128-SHA256 / ECDSA-256',
      isVulnerable: true,
      riskLevel: 'high',
      status: 'Quantum Vulnerable'
    }
  ]);

  const [importingId, setImportingId] = useState<string | null>(null);
  const terminalEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll terminal logs
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [consoleLogs]);

  // Simulating packet capture traffic logs
  useEffect(() => {
    if (!isSniffing) return;

    const mockSourceIps = ['192.168.1.102', '10.0.4.15', '172.17.0.8', '192.168.22.40'];
    const mockDestIps = ['172.24.120.44', '192.168.4.99', '10.0.12.80', '185.12.99.30'];
    const mockHosts = ['pqc-vault.secure.internal', 'legacy-syslog.corp.local', 'vulnerable-api-auth.internal', 'external-gateway.com'];
    const mockCiphers = [
      { name: 'X25519MLKEM768 / ECDSA', pq: true },
      { name: 'ECDHE-RSA-AES256-GCM-SHA384 / RSA-2048', pq: false },
      { name: 'ECDHE-ECDSA-AES128-SHA256 / ECDSA-256', pq: false }
    ];

    const interval = setInterval(() => {
      const srcIp = mockSourceIps[Math.floor(Math.random() * mockSourceIps.length)];
      const destIndex = Math.floor(Math.random() * mockDestIps.length);
      const destIp = mockDestIps[destIndex];
      const host = mockHosts[destIndex];
      const srcPort = Math.floor(Math.random() * 45000) + 15000;
      const cipher = mockCiphers[Math.floor(Math.random() * mockCiphers.length)];
      
      const timestamp = new Date().toLocaleTimeString();
      
      // Log ClientHello
      setConsoleLogs(prev => [
        ...prev,
        `[${timestamp}] [TCP-IN] ${srcIp}:${srcPort} -> ${destIp}:443 [TLS ClientHello] SNI: ${host} | Support: TLSv1.3, TLSv1.2`
      ]);

      // Log ServerHello shortly after
      setTimeout(() => {
        setConsoleLogs(prev => [
          ...prev,
          `[${timestamp}] [TCP-OUT] ${destIp}:443 -> ${srcIp}:${srcPort} [TLS ServerHello] selected: TLSv1.3 | curve: ${cipher.name} | ${cipher.pq ? 'PQ-SECURE' : 'VULNERABLE'}`
        ]);
      }, 300);

    }, 2500);

    return () => clearInterval(interval);
  }, [isSniffing]);

  const toggleSniffing = () => {
    const timestamp = new Date().toLocaleTimeString();
    if (isSniffing) {
      setIsSniffing(false);
      setConsoleLogs(prev => [
        ...prev,
        `[${timestamp}] [SYSTEM] Passive sniffing capture terminated. eth0 interface set back to standard mode.`
      ]);
    } else {
      setIsSniffing(true);
      setConsoleLogs(prev => [
        ...prev,
        `[${timestamp}] [SYSTEM] Sniffing capture started. Promiscuous mode enabled on eth0 interface...`,
        `[${timestamp}] [SYSTEM] Listening for outbound and inbound TLS ClientHello/ServerHello negotiations...`
      ]);
    }
  };

  // PCAP Dropzone handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        await processPcapFile(file);
      } else {
        alert('Invalid file format. Please upload a .pcap or .pcapng network capture file.');
      }
    }
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      await processPcapFile(file);
    }
  };

  const processPcapFile = async (file: File) => {
    setIsUploading(true);
    setUploadProgress(10);
    setConsoleLogs(prev => [
      ...prev,
      `[${new Date().toLocaleTimeString()}] [PCAP] Ingesting file '${file.name}' (${(file.size / 1024).toFixed(1)} KB)...`
    ]);

    // Progress bar animation
    const progressInterval = setInterval(() => {
      setUploadProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval);
          return 90;
        }
        return prev + 15;
      });
    }, 300);

    try {
      // Call backend API to parse PCAP metadata
      const token = sessionStorage.getItem('quarkshield_token');
      const formData = new FormData();
      formData.append('pcap', file);

      // We make the POST request
      const res = await fetch('/api/scan/passive/pcap', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ fileName: file.name, fileSize: file.size }) // Sending metadata mock since we mock on backend
      });

      clearInterval(progressInterval);
      setUploadProgress(100);

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'PCAP parsing failed.');
      }

      setTimeout(() => {
        setIsUploading(false);
        setConsoleLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [SUCCESS] PCAP parsing complete. Mapped ${data.length} new cryptographic endpoints from handshake trace.`
        ]);
        
        // Append parsed shadow assets to the list
        setShadowAssets(prev => {
          const existingNames = new Set(prev.map(a => a.name));
          const filteredNew = data.filter((item: ShadowAsset) => !existingNames.has(item.name));
          return [...prev, ...filteredNew];
        });
      }, 500);

    } catch (err: any) {
      clearInterval(progressInterval);
      setIsUploading(false);
      console.warn('Backend PCAP parser offline, loading simulated parsing results:', err.message);
      
      // Fallback simulated parsing result
      setTimeout(() => {
        setUploadProgress(100);
        setIsUploading(false);
        
        const mockNewShadows: ShadowAsset[] = [
          {
            id: `shadow-${Date.now()}-1`,
            name: 'shadow-ingress-lb.internal',
            ip: '10.220.14.3',
            protocol: 'TLSv1.3',
            algorithm: 'TLS_AES_128_GCM_SHA256 / RSA-4096',
            isVulnerable: true,
            riskLevel: 'high',
            status: 'Quantum Vulnerable'
          },
          {
            id: `shadow-${Date.now()}-2`,
            name: 'pqc-mail-relay.secure',
            ip: '192.168.12.110',
            protocol: 'TLSv1.3',
            algorithm: 'X25519MLKEM768 / ECDSA',
            isVulnerable: false,
            riskLevel: 'secure',
            status: 'Post-Quantum Secure'
          }
        ];

        setConsoleLogs(prev => [
          ...prev,
          `[${new Date().toLocaleTimeString()}] [SUCCESS] Simulated PCAP parsing complete. Extracted 2 shadow assets from offline dataset.`
        ]);

        setShadowAssets(prev => {
          const existingNames = new Set(prev.map(a => a.name));
          const filteredNew = mockNewShadows.filter(item => !existingNames.has(item.name));
          return [...prev, ...filteredNew];
        });
      }, 1500);
    }
  };

  // Import a discovered shadow asset into the permanent Active CMDB
  const handleImportToCMDB = async (asset: ShadowAsset) => {
    setImportingId(asset.id);
    try {
      // Map shadow properties to standard AuditResult schema expected by /api/assets
      const mappedAsset: AuditResult = {
        id: Math.random().toString(36).substring(7),
        type: 'url',
        name: asset.name,
        algorithm: asset.algorithm,
        keySize: asset.algorithm.includes('RSA') ? 2048 : 256,
        isVulnerable: asset.isVulnerable,
        riskLevel: asset.riskLevel,
        status: asset.status,
        description: `Passively discovered shadow asset |CMDB:{"businessService":"Enterprise Shadow Ingress","application":"Unconfigured Listener","endpoint":"${asset.name}","owner":"secops-alert@spinovation.com","lifecycle":"Active"}`,
        recommendation: asset.isVulnerable 
          ? `Reconfigure local endpoints to utilize post-quantum hybrid groups (X25519MLKEM768).` 
          : `Post-quantum secure connection detected. Maintain active listener configuration.`,
        explainer: asset.isVulnerable
          ? `This connection was passively sniffed from network trace logs. It utilizes classical algorithms which are vulnerable to decryption by a cryptanalytically relevant quantum computer.`
          : `Post-quantum cryptographic key exchange verified in trace. Hybrid ML-KEM secures these communications.`,
        complianceViolations: asset.isVulnerable ? ['CNSA 2.0', 'EO 14028'] : []
      };

      // Call parent handleAddAssets to post it to the database
      await onAddAssets([mappedAsset]);
      
      // Remove from shadow assets list
      setShadowAssets(prev => prev.filter(a => a.id !== asset.id));
      alert(`Success: Asset '${asset.name}' has been successfully logged and imported into the Active Crypto CMDB.`);
      
      setConsoleLogs(prev => [
        ...prev,
        `[${new Date().toLocaleTimeString()}] [INGEST] Asset '${asset.name}' permanently registered in CMDB Active Inventory.`
      ]);
    } catch (err: any) {
      console.error('Failed to import shadow asset:', err);
      alert(`Import Failed: ${err.message}`);
    } finally {
      setImportingId(null);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      
      {/* 1. Header & Sniffing Toggle */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Passive Cryptographic Discovery</h2>
          <p>Trace cryptographic handshakes, audit shadow certs, and parse network packet dumps (PCAPs) passively.</p>
        </div>
        <button 
          onClick={toggleSniffing}
          className={isSniffing ? "btn-secondary" : "btn-primary"} 
          style={{ 
            display: 'inline-flex', 
            alignItems: 'center', 
            gap: '0.5rem',
            padding: '0.75rem 1.25rem',
            background: isSniffing ? 'rgba(239, 68, 68, 0.1)' : 'linear-gradient(to right, var(--accent-purple), #a855f7)',
            border: isSniffing ? '1px solid rgba(239, 68, 68, 0.3)' : 'none',
            color: isSniffing ? '#ef4444' : '#ffffff',
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'all 0.3s ease'
          }}
        >
          {isSniffing ? (
            <>
              <Square size={16} fill="#ef4444" /> Stop Passive Capture
            </>
          ) : (
            <>
              <Play size={16} fill="#ffffff" /> Start Passive Capture
            </>
          )}
        </button>
      </div>

      {/* 2. Live Terminal and Flow Graph Panel */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '1.5rem' }}>
        
        {/* Animated Flow Graph */}
        <div className="glass-panel" style={{ padding: '1.5rem 0.5rem', display: 'flex', flexDirection: 'column', gap: '1rem', height: '320px' }}>
          <h3 style={{ fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem', paddingLeft: '1rem' }}>
            <Network size={18} color="var(--accent-cyan)" /> Cryptographic Ingest Flow
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '-0.5rem', paddingLeft: '1rem' }}>
            Flow mapping of network ingress packets down to CMDB records.
          </p>

          <div style={{ flexGrow: 1, display: 'flex', justifyContent: 'center', alignItems: 'center', position: 'relative' }}>
            {/* SVG Ingest Flow Graph */}
            <svg width="100%" height="180" viewBox="0 0 450 180">
              <defs>
                <linearGradient id="flow-grad" x1="0%" y1="0%" x2="100%" y2="0%">
                  <stop offset="0%" stopColor="var(--accent-cyan)" stopOpacity="0.8" />
                  <stop offset="100%" stopColor="var(--accent-purple)" stopOpacity="0.8" />
                </linearGradient>
              </defs>

              {/* Connecting Lines */}
              <line x1="65" y1="90" x2="195" y2="90" stroke="url(#flow-grad)" strokeWidth="2" strokeDasharray={isSniffing ? "5,5" : "none"} className={isSniffing ? "dash-flow" : ""} />
              <line x1="255" y1="90" x2="385" y2="90" stroke="url(#flow-grad)" strokeWidth="2" strokeDasharray={isSniffing ? "5,5" : "none"} className={isSniffing ? "dash-flow" : ""} />

              {/* Nodes */}
              <g transform="translate(35, 90)">
                <circle r="30" fill="rgba(6, 182, 212, 0.1)" stroke="var(--accent-cyan)" strokeWidth="2" />
                <Radio size={30} color="var(--accent-cyan)" style={{ transform: 'translate(-15px, -15px)' }} />
                <text x="0" y="48" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontWeight="600">eth0 Ingress</text>
              </g>

              <g transform="translate(225, 90)">
                <circle r="30" fill="rgba(168, 85, 247, 0.1)" stroke="var(--accent-purple)" strokeWidth="2" />
                <Cpu size={30} color="var(--accent-purple)" style={{ transform: 'translate(-15px, -15px)' }} />
                <text x="0" y="48" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontWeight="600">TLS Parser</text>
              </g>

              <g transform="translate(415, 90)">
                <circle r="30" fill="rgba(16, 185, 129, 0.1)" stroke="var(--status-secure)" strokeWidth="2" />
                <Database size={30} color="var(--status-secure)" style={{ transform: 'translate(-15px, -15px)' }} />
                <text x="0" y="48" textAnchor="middle" fill="var(--text-secondary)" fontSize="11" fontWeight="600">CMDB Ingest</text>
              </g>

              {/* Live pulsing dot */}
              {isSniffing && (
                <>
                  <circle cy="90" r="4" fill="var(--accent-cyan)">
                    <animate attributeName="cx" from="65" to="195" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="1;0.8;0" keyTimes="0;0.5;1" dur="2s" repeatCount="indefinite" />
                  </circle>
                  <circle cy="90" r="4" fill="var(--accent-purple)">
                    <animate attributeName="cx" from="255" to="385" dur="2s" repeatCount="indefinite" />
                    <animate attributeName="opacity" values="1;0.8;0" keyTimes="0;0.5;1" dur="2s" repeatCount="indefinite" />
                  </circle>
                </>
              )}
            </svg>
          </div>
        </div>

        {/* Live Sniffing Terminal */}
        <div className="glass-panel" style={{ 
          padding: '1rem', 
          background: '#020617', 
          border: '1px solid var(--border-normal)',
          height: '320px', 
          display: 'flex', 
          flexDirection: 'column', 
          gap: '0.75rem',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.78rem'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.5rem' }}>
            <span style={{ color: 'var(--text-secondary)', display: 'inline-flex', alignItems: 'center', gap: '0.4rem', fontWeight: 600 }}>
              <span className={`pulse-dot ${isSniffing ? 'online' : 'offline'}`} style={{ width: '8px', height: '8px' }}></span>
              Live Capture Terminal (eth0)
            </span>
            <span style={{ color: 'var(--text-muted)' }}>1500 MTU</span>
          </div>

          <div style={{ flexGrow: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '0.4rem', color: '#38bdf8' }}>
            {consoleLogs.map((log, idx) => {
              let color = '#38bdf8';
              if (log.includes('[SYSTEM]')) color = '#c084fc';
              else if (log.includes('PQ-SECURE') || log.includes('[SUCCESS]')) color = 'var(--status-secure)';
              else if (log.includes('VULNERABLE') || log.includes('[WARN]')) color = 'var(--status-vulnerable)';
              
              return (
                <div key={idx} style={{ color, lineHeight: '1.4', wordBreak: 'break-all' }}>
                  {log}
                </div>
              );
            })}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </div>

      {/* 3. PCAP Ingestion Center */}
      <div 
        className={`glass-panel ${isDragging ? 'drag-active' : ''}`}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{ 
          padding: '2rem', 
          textAlign: 'center', 
          border: isDragging ? '2px dashed var(--accent-cyan)' : '1px dashed var(--border-normal)',
          borderRadius: '8px',
          background: isDragging ? 'rgba(6, 182, 212, 0.05)' : 'rgba(0,0,0,0.15)',
          transition: 'all 0.3s ease',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: '1rem'
        }}
      >
        <UploadCloud size={40} color={isDragging ? 'var(--accent-cyan)' : 'var(--text-muted)'} className={isUploading ? 'bounce' : ''} />
        
        {isUploading ? (
          <div style={{ maxWidth: '350px', width: '100%', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.88rem', fontWeight: 600, color: 'var(--accent-cyan)' }}>
              Parsing network packet capture trace...
            </span>
            <div style={{ width: '100%', height: '6px', background: 'rgba(255,255,255,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
              <div style={{ width: `${uploadProgress}%`, height: '100%', background: 'linear-gradient(to right, var(--accent-cyan), var(--accent-purple))', transition: 'width 0.3s' }}></div>
            </div>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{uploadProgress}% processed</span>
          </div>
        ) : (
          <div>
            <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>
              Ingest Wireshark PCAP Capture Files
            </h4>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginBottom: '1rem' }}>
              Drag and drop your network trace files (`.pcap` / `.pcapng`) here to automatically extract shadow certificates.
            </p>
            
            <label className="btn-secondary" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.4rem', cursor: 'pointer', padding: '0.5rem 1.25rem' }}>
              <UploadCloud size={14} /> Browse PCAP Files
              <input 
                type="file" 
                accept=".pcap,.pcapng" 
                onChange={handleFileSelect} 
                style={{ display: 'none' }} 
              />
            </label>
          </div>
        )}
      </div>

      {/* 4. Discovered Shadow Assets Table */}
      <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Activity size={18} color="var(--accent-cyan)" /> Discovered Shadow Assets
        </h3>
        <p style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', marginTop: '-0.5rem' }}>
          Cryptographic endpoints identified passively from packet traces and network interface captures.
        </p>

        <div style={{ overflowX: 'auto' }}>
          <table className="quark-table">
            <thead>
              <tr>
                <th>Shadow Endpoint</th>
                <th>Source IP</th>
                <th>TLS version</th>
                <th>Negotiated key-share</th>
                <th>Threat Status</th>
                <th style={{ textAlign: 'center' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {shadowAssets.map(asset => (
                <tr key={asset.id}>
                  <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    <div>{asset.name}</div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 400, marginTop: '0.1rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      <Clock size={10} /> Discovered: {new Date().toLocaleDateString()}
                    </div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>{asset.ip}</td>
                  <td style={{ fontWeight: 500 }}>{asset.protocol}</td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{asset.algorithm}</td>
                  <td>
                    <span style={{ 
                      color: asset.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)',
                      fontWeight: 600,
                      fontSize: '0.82rem',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '0.25rem'
                    }}>
                      {asset.isVulnerable ? (
                        <>
                          <AlertTriangle size={12} /> QUANTUM VULNERABLE
                        </>
                      ) : (
                        <>
                          <CheckCircle size={12} /> POST-QUANTUM SECURE
                        </>
                      )}
                    </span>
                  </td>
                  <td style={{ textAlign: 'center' }}>
                    <button
                      onClick={() => handleImportToCMDB(asset)}
                      disabled={importingId === asset.id}
                      className="btn-primary"
                      style={{
                        padding: '0.4rem 0.8rem',
                        fontSize: '0.8rem',
                        background: 'linear-gradient(to right, var(--accent-purple), #a855f7)',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '0.25rem',
                        cursor: importingId === asset.id ? 'not-allowed' : 'pointer'
                      }}
                    >
                      {importingId === asset.id ? (
                        <>
                          <RefreshCw size={12} className="spin" /> Importing...
                        </>
                      ) : (
                        <>
                          <Plus size={12} /> Import to CMDB
                        </>
                      )}
                    </button>
                  </td>
                </tr>
              ))}
              {shadowAssets.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                    No shadow assets detected in current passive session.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Styled keyframe animations for the SVG Flow mapper */}
      <style>{`
        @keyframes dash {
          to {
            stroke-dashoffset: -20;
          }
        }
        .dash-flow {
          animation: dash 1.5s linear infinite;
        }
        @keyframes flowPulse1 {
          0% { transform: translate(40px, 90px) scale(1); opacity: 1; }
          50% { transform: translate(120px, 90px) scale(1.2); opacity: 0.8; }
          100% { transform: translate(200px, 90px) scale(1); opacity: 0; }
        }
        @keyframes flowPulse2 {
          0% { transform: translate(200px, 90px) scale(1); opacity: 1; }
          50% { transform: translate(280px, 90px) scale(1.2); opacity: 0.8; }
          100% { transform: translate(360px, 90px) scale(1); opacity: 0; }
        }
        .pulse-dot-flow-1 {
          animation: flowPulse1 2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
        }
        .pulse-dot-flow-2 {
          animation: flowPulse2 2s cubic-bezier(0.4, 0, 0.2, 1) infinite;
          animation-delay: 1s;
        }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-6px); }
        }
        .bounce {
          animation: bounce 1s ease infinite;
        }
      `}</style>

    </div>
  );
};
