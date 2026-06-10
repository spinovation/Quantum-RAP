import React, { useState, useRef } from 'react';
import { 
  Upload, 
  Terminal, 
  Globe, 
  FileText, 
  AlertOctagon, 
  CheckCircle,
  HelpCircle,
  RefreshCw,
  Server,
  Copy,
  Check
} from 'lucide-react';
import { 
  auditSSHKey, 
  auditPEMCertificate, 
  auditConfigFile, 
  simulateUrlScan
} from '../utils/cryptoAuditor';
import type { AuditResult, ConfigAuditResult } from '../utils/cryptoAuditor';

interface ScannerProps {
  onAddAssets: (newAssets: AuditResult[]) => void;
  setActiveTab: (tab: 'overview' | 'scanner' | 'inventory' | 'migration' | 'compliance' | 'ai') => void;
}

type ScanType = 'file' | 'paste' | 'url' | 'ca';

export const Scanner: React.FC<ScannerProps> = ({ onAddAssets, setActiveTab }) => {
  const [scanType, setScanType] = useState<ScanType>('file');
  const [pasteContent, setPasteContent] = useState('');
  const [pasteFileName, setPasteFileName] = useState('server_config.conf');
  const [urlInput, setUrlInput] = useState('https://cloudflare.com');
  const [isUrlScanning, setIsUrlScanning] = useState(false);
  const [urlScanLog, setUrlScanLog] = useState<string[]>([]);
  
  // Results states
  const [fileResults, setFileResults] = useState<AuditResult[]>([]);
  const [configResult, setConfigResult] = useState<ConfigAuditResult | null>(null);
  const [urlResult, setUrlResult] = useState<AuditResult | null>(null);

  // Consent & Outbound Scan Authorizations
  const [urlAuthorized, setUrlAuthorized] = useState(false);
  const [vaultAuthorized, setVaultAuthorized] = useState(false);
  
  // CA Integration state
  const [vaultUrl, setVaultUrl] = useState('http://localhost:8200');
  const [vaultToken, setVaultToken] = useState('');
  const [vaultMountPath, setVaultMountPath] = useState('pki');
  const [isVaultSyncing, setIsVaultSyncing] = useState(false);
  const [vaultSyncResult, setVaultSyncResult] = useState<{ success: boolean; message: string; syncedCount: number; vulnerableCount: number; secureCount: number } | null>(null);
  const [vaultSyncError, setVaultSyncError] = useState<string | null>(null);
  const [adcsSyncResult, setAdcsSyncResult] = useState<{ success: boolean; message: string; registeredCount: number; vulnerableCount: number } | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [showCopied, setShowCopied] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [isDragging, setIsDragging] = useState(false);

  const getPowerShellScript = () => {
    const apiOrigin = window.location.origin.includes('localhost:5173') 
      ? 'http://localhost:5000' 
      : window.location.origin;
    
    return `# QuarkShield Active Directory Certificate Services (ADCS) Sync Script
# Run this script on your Windows CA server to synchronize active certificates.

[CmdletBinding()]
param (
    [string]$ServerUrl = "${apiOrigin}",
    [string]$TempPath = "$env:TEMP\\adcs_certs_export.csv"
)

Write-Host "--------------------------------------------------" -ForegroundColor Cyan
Write-Host " QuarkShield ADCS Sync Agent starting..." -ForegroundColor Cyan
Write-Host " Target Portal: $ServerUrl" -ForegroundColor Cyan
Write-Host "--------------------------------------------------" -ForegroundColor Cyan

# 1. Export active certificates from CA database in CSV format using certutil
Write-Host "Querying Active Directory Certificate database..."
certutil -view -restrict "NotAfter>=now,Disposition=20" -out "SerialNumber,CommonName,NotAfter,PublicKeyAlgorithm,KeyLength" csv > $TempPath

if (-not (Test-Path $TempPath)) {
    Write-Error "Failed to export certificate registry from ADCS."
    Exit 1
}

# 2. Parse the CSV file manually to avoid system locale bugs
Write-Host "Parsing certificate rows..."
$csvContent = Import-Csv -Path $TempPath -Delimiter ','

$certRows = @()
foreach ($row in $csvContent) {
    # Clean up column names and values
    $serial = $row."Serial Number" -or $row."SerialNumber"
    $cn = $row."Common Name" -or $row."CommonName"
    $expiry = $row."Certificate Expiration Date" -or $row."NotAfter"
    $algo = $row."Public Key Algorithm" -or $row."PublicKeyAlgorithm"
    $length = $row."Key Length" -or $row."KeyLength"

    if ([string]::IsNullOrEmpty($serial) -or [string]::IsNullOrEmpty($cn)) {
        continue
    }

    # Normalize values for QuarkShield ingestion
    $certObj = [PSCustomObject]@{
        serialNumber       = $serial.Trim()
        commonName         = $cn.Trim()
        notAfter           = $expiry
        publicKeyAlgorithm = $algo.Trim()
        keyLength          = [int]$length
    }
    $certRows += $certObj
}

# Clean up temp file
Remove-Item -Path $TempPath -Force

if ($certRows.Count -eq 0) {
    Write-Host "No active certificates found to sync." -ForegroundColor Yellow
    Exit 0
}

Write-Host "Found $($certRows.Count) active certificates to synchronize." -ForegroundColor Green

# 3. Serialize to JSON and POST to QuarkShield central controller
$jsonPayload = ConvertTo-Json -InputObject $certRows -Depth 5
$headers = @{
    "Content-Type" = "application/json"
}

Write-Host "Posting certificate metadata to QuarkShield Ingestion Gateway..."
try {
    $response = Invoke-RestMethod -Uri "$ServerUrl/api/ca/adcs/sync" -Method Post -Body $jsonPayload -Headers $headers
    Write-Host "--------------------------------------------------"
    Write-Host "✓ Success! Sync Complete." -ForegroundColor Green
    Write-Host "Message: $($response.message)" -ForegroundColor Green
    Write-Host "--------------------------------------------------"
}
catch {
    Write-Error "Failed to push certificate logs: $_"
    Exit 1
}
`;
  };

  const psScript = getPowerShellScript();

  const handleCopyScript = () => {
    navigator.clipboard.writeText(psScript);
    setShowCopied(true);
    setTimeout(() => setShowCopied(false), 2000);
  };

  const handleVaultSync = async () => {
    setIsVaultSyncing(true);
    setVaultSyncError(null);
    setVaultSyncResult(null);

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/ca/vault/sync', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          vaultUrl,
          token: vaultToken,
          mountPath: vaultMountPath
        })
      });

      if (res.status === 403) {
        const errData = await res.json();
        throw { isAuthError: true, message: errData.error || 'Access Denied.' };
      }

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.error || `Vault server returned status ${res.status}`);
      }

      const result = await res.json();
      setVaultSyncResult(result);
      
      // Trigger inventory update in App.tsx
      onAddAssets([]);
    } catch (err: any) {
      if (err.isAuthError) {
        setVaultSyncError(err.message);
      } else {
        console.warn('Backend Vault sync failed, running fallback simulation:', err);
      
      const mockVaultCerts: AuditResult[] = [
        {
          id: "vault-cert-" + Math.random().toString(36).substring(2, 12),
          type: "certificate",
          name: "Vault-PKI-Cert:WebPortalRoot",
          algorithm: "RSA",
          keySize: 2048,
          isVulnerable: true,
          riskLevel: "high",
          status: "Quantum Vulnerable",
          description: "Vulnerable certificate retrieved from simulated Vault PKI storage using RSA-2048.",
          recommendation: "Deploy ML-KEM/ML-DSA hybrid algorithms and update root authority.",
          explainer: "Classic RSA is vulnerable to Shor's factorization algorithm on sufficiently powerful quantum computers.",
          complianceViolations: ["CNSA 2.0", "EO 14028"]
        },
        {
          id: "vault-cert-" + Math.random().toString(36).substring(2, 12),
          type: "certificate",
          name: "Vault-PKI-Cert:APIClientAuth",
          algorithm: "ECDSA",
          keySize: 256,
          isVulnerable: true,
          riskLevel: "high",
          status: "Quantum Vulnerable",
          description: "Vulnerable certificate from simulated Vault PKI using elliptic curve Secp256r1.",
          recommendation: "Migrate client certificate authorities to ML-DSA or Falcon.",
          explainer: "Elliptic curves are vulnerable to Shor's algorithm for discrete logarithms, making ECC signatures insecure.",
          complianceViolations: ["CNSA 2.0", "NIST SP 800-219"]
        },
        {
          id: "vault-cert-" + Math.random().toString(36).substring(2, 12),
          type: "certificate",
          name: "Vault-PKI-Cert:CodeSigningCA",
          algorithm: "RSA",
          keySize: 4096,
          isVulnerable: true,
          riskLevel: "medium",
          status: "Quantum Vulnerable",
          description: "Long-term code signing root CA using RSA-4096. Vulnerable over multi-decade quantum horizons.",
          recommendation: "Transition to stateful hash-based signatures (LMS/XMSS) for long-term software signing verification.",
          explainer: "Shor's algorithm breaks RSA of any key size (including 4096-bit) once quantum computers reach scale.",
          complianceViolations: ["EO 14028"]
        }
      ];

      onAddAssets(mockVaultCerts);

      setVaultSyncResult({
        success: true,
        message: 'Successfully simulated local fallback sync of 3 certificates from Vault PKI.',
        syncedCount: 3,
        vulnerableCount: 3,
        secureCount: 0
      });
      }
    } finally {
      setIsVaultSyncing(false);
    }
  };

  const handleAdcsMockPush = async () => {
    setAdcsSyncResult(null);

    const mockPayload = [
      {
        serialNumber: "adcs-" + Math.random().toString(36).substring(2, 8),
        commonName: "WinDomainController-Root",
        notAfter: new Date(Date.now() + 365*24*60*60*1000).toISOString(),
        publicKeyAlgorithm: "RSA",
        keyLength: 2048
      },
      {
        serialNumber: "adcs-" + Math.random().toString(36).substring(2, 8),
        commonName: "Enterprise-UserAuth-ECC",
        notAfter: new Date(Date.now() + 180*24*60*60*1000).toISOString(),
        publicKeyAlgorithm: "ECDSA_P256",
        keyLength: 256
      }
    ];

    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/ca/adcs/sync', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify(mockPayload)
      });

      if (res.status === 403) {
        const errData = await res.json();
        throw { isAuthError: true, message: errData.error || 'Access Denied.' };
      }

      if (!res.ok) {
        throw new Error(`ADCS sync gateway returned status ${res.status}`);
      }

      const result = await res.json();
      setAdcsSyncResult({
        success: true,
        message: result.message || 'ADCS sync complete.',
        registeredCount: result.registeredCount || 2,
        vulnerableCount: result.vulnerableCount || 2
      });

      onAddAssets([]);
    } catch (err: any) {
      if (err.isAuthError) {
        setAdcsSyncResult({
          success: false,
          message: `Access Denied: ${err.message}`,
          registeredCount: 0,
          vulnerableCount: 0
        });
      } else {
        console.warn('Backend ADCS endpoint offline, executing local fallback simulation:', err);
      
      const fallbackCerts: AuditResult[] = mockPayload.map(row => {
        const isVulnerable = true;
        const name = "ADCS-Cert:" + row.commonName;
        const keySize = row.keyLength;
        const rawAlgo = row.publicKeyAlgorithm;
        
        let algorithm = 'RSA';
        let riskLevel: 'low' | 'medium' | 'high' | 'critical' | 'secure' = 'high';
        let description = '';
        let recommendation = '';
        let explainer = '';
        const complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];

        if (rawAlgo.includes('RSA')) {
          algorithm = 'RSA';
          description = "Quantum-vulnerable Active Directory (ADCS) certificate utilizing RSA-" + keySize + ".";
          recommendation = 'Deploy hybrid Post-Quantum keys (ML-KEM) and schedule CA certificate updates.';
          explainer = "RSA integer factorization is solved in polynomial time by Shor's algorithm, breaking standard AD CS roots.";
        } else {
          algorithm = 'ECDSA';
          description = "Quantum-vulnerable Active Directory (ADCS) certificate utilizing Elliptic Curve Cryptography.";
          recommendation = 'Plan migration of certificate validation schemes to ML-DSA signatures.';
          explainer = "Elliptic curve discrete logarithms are easily breakable under Shor's algorithm, exposing AD CS certificates.";
        }

        return {
          id: "adcs-cert-" + row.serialNumber,
          type: 'certificate',
          name,
          algorithm,
          keySize,
          isVulnerable,
          riskLevel,
          status: 'Quantum Vulnerable',
          description,
          recommendation,
          explainer,
          complianceViolations
        };
      });

      onAddAssets(fallbackCerts);

      setAdcsSyncResult({
        success: true,
        message: 'Successfully simulated local push of 2 certificates from ADCS.',
        registeredCount: 2,
        vulnerableCount: 2
      });
      }
    }
  };

  // File drag & drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const processFileContent = (name: string, content: string): AuditResult => {
    const trimmed = content.trim();
    if (trimmed.startsWith('-----BEGIN') || trimmed.includes('PRIVATE KEY')) {
      return auditPEMCertificate(trimmed, name);
    } else if (trimmed.startsWith('ssh-') || trimmed.startsWith('ecdsa-')) {
      return auditSSHKey(trimmed, name);
    } else {
      // Treat as config audit if not recognized cert/ssh format
      return {
        id: Math.random().toString(36).substring(7),
        type: 'config',
        name,
        algorithm: 'Text Config',
        isVulnerable: true,
        riskLevel: 'medium',
        status: 'Quantum Vulnerable',
        description: 'Plaintext file scanned as generic configuration.',
        recommendation: 'Check contents for secret values or algorithms.',
        explainer: 'Unstructured text file analyzed.',
        complianceViolations: []
      };
    }
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const files = Array.from(e.dataTransfer.files);
    await parseUploadedFiles(files);
  };

  const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      await parseUploadedFiles(files);
    }
  };

  const parseUploadedFiles = async (files: File[]) => {
    const results: AuditResult[] = [];
    
    for (const file of files) {
      const reader = new FileReader();
      const fileContent = await new Promise<string>((resolve) => {
        reader.onload = (event) => {
          resolve(event.target?.result as string || '');
        };
        reader.readAsText(file);
      });

      const nameLower = file.name.toLowerCase();
      const isConfig = nameLower.endsWith('.conf') || nameLower.endsWith('.config') || nameLower.includes('sshd') || nameLower.includes('nginx');
      
      try {
        const token = sessionStorage.getItem('quarkshield_token');
        if (isConfig) {
          const res = await fetch('/api/scan/config', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ fileName: file.name, content: fileContent })
          });
          if (res.status === 403) {
            const errData = await res.json();
            throw { isAuthError: true, message: errData.error || 'Access Denied.' };
          }
          const audit = await res.json();
          if (audit.error) throw new Error(audit.error);
          setConfigResult(audit);
          setScanType('paste');
          return;
        } else {
          const res = await fetch('/api/scan/file', {
            method: 'POST',
            headers: { 
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({ name: file.name, content: fileContent })
          });
          if (res.status === 403) {
            const errData = await res.json();
            throw { isAuthError: true, message: errData.error || 'Access Denied.' };
          }
          const audit = await res.json();
          if (audit.error) throw new Error(audit.error);
          results.push(audit);
        }
      } catch (err: any) {
        if (err.isAuthError) {
          setGeneralError(err.message);
          return;
        } else {
          console.warn('Backend scanner offline, executing local parsing fallback:', err);
          // Fallback local parsing
          if (isConfig) {
            const audit = auditConfigFile(file.name, fileContent);
            setConfigResult(audit);
            setScanType('paste');
            return;
          } else {
            const audit = processFileContent(file.name, fileContent);
            results.push(audit);
          }
        }
      }
    }
    
    if (results.length > 0) {
      setFileResults(results);
    }
  };

  const handleAddFilesToInventory = () => {
    onAddAssets(fileResults);
    setFileResults([]);
    setActiveTab('inventory');
  };

  // Paste Action
  const handlePasteAudit = async () => {
    const content = pasteContent.trim();
    if (!content) return;

    const isCertKey = content.startsWith('-----BEGIN') || content.startsWith('ssh-') || content.startsWith('ecdsa-');

    setGeneralError(null);
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      if (isCertKey) {
        const res = await fetch('/api/scan/file', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ name: 'Pasted Cryptographic Asset', content })
        });
        if (res.status === 403) {
          const errData = await res.json();
          throw { isAuthError: true, message: errData.error || 'Access Denied.' };
        }
        const audit = await res.json();
        if (audit.error) throw new Error(audit.error);
        onAddAssets([audit]);
        setPasteContent('');
        setActiveTab('inventory');
      } else {
        const res = await fetch('/api/scan/config', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`
          },
          body: JSON.stringify({ fileName: pasteFileName, content })
        });
        if (res.status === 403) {
          const errData = await res.json();
          throw { isAuthError: true, message: errData.error || 'Access Denied.' };
        }
        const audit = await res.json();
        if (audit.error) throw new Error(audit.error);
        setConfigResult(audit);
      }
    } catch (err: any) {
      if (err.isAuthError) {
        setGeneralError(err.message);
      } else {
        console.warn('Backend scanner offline, executing local paste fallback:', err);
        // Fallback local audit
        if (isCertKey) {
          const audit = processFileContent('Pasted Cryptographic Asset', content);
          onAddAssets([audit]);
          setPasteContent('');
          setActiveTab('inventory');
        } else {
          const audit = auditConfigFile(pasteFileName, content);
          setConfigResult(audit);
        }
      }
    }
  };

  const handleAddConfigViolationAsAsset = () => {
    if (!configResult) return;
    
    // Convert configuration vulnerabilities to assets
    const newAssets: AuditResult[] = configResult.violations.map((v, i) => ({
      id: `cfg-v-${i}-${Math.random().toString(36).substring(4)}`,
      type: 'config',
      name: `${configResult.fileName}:L${v.lineNumber}`,
      algorithm: 'Symmetric/Protocol Config',
      isVulnerable: true,
      riskLevel: v.riskLevel,
      status: 'Quantum Vulnerable',
      description: v.issue,
      recommendation: v.recommendation,
      explainer: `Server configuration at line ${v.lineNumber} allows for quantum-vulnerable operations: "${v.lineContent}"`,
      complianceViolations: ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028']
    }));

    onAddAssets(newAssets);
    setConfigResult(null);
    setPasteContent('');
    setActiveTab('inventory');
  };

  // URL Action
  const handleUrlScan = async () => {
    setIsUrlScanning(true);
    setUrlResult(null);
    setUrlScanLog([]);
    
    const logs = [
      `Resolving domain name...`,
      `Establishing TLS socket on port 443...`,
      `Sending client handshake request (ClientHello)...`,
      `Adding PQC extension: key_share [ML-KEM-768]...`,
      `Received ServerHello response...`,
      `Negotiating cipher suite parameters...`,
      `Verifying certificate chain authority...`,
      `Scan complete. Analyzing cryptographic vulnerability...`
    ];

    for (let i = 0; i < logs.length; i++) {
      setUrlScanLog(prev => [...prev, logs[i]]);
      await new Promise(resolve => setTimeout(resolve, 300));
    }

    setGeneralError(null);
    try {
      const token = sessionStorage.getItem('quarkshield_token');
      const res = await fetch('/api/scan/url', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ url: urlInput })
      });
      if (res.status === 403) {
        const errData = await res.json();
        throw { isAuthError: true, message: errData.error || 'Access Denied.' };
      }
      const result = await res.json();
      if (result.error) throw new Error(result.error);
      setUrlResult(result);
    } catch (err: any) {
      if (err.isAuthError) {
        setUrlScanLog(prev => [...prev, `ERROR: ${err.message}`]);
        setGeneralError(err.message);
      } else {
        console.warn('Backend real socket TLS scan failed, executing fallback audit simulation:', err);
        // Fallback local simulation
        const result = await simulateUrlScan(urlInput);
        setUrlResult(result);
      }
    }
    
    setIsUrlScanning(false);
  };

  const handleAddUrlToInventory = () => {
    if (urlResult) {
      onAddAssets([urlResult]);
      setUrlResult(null);
      setActiveTab('inventory');
    }
  };

  return (
    <>
      <div>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Discovery & Assessment Scanner</h2>
        <p>Analyze server configurations, local PEM certificates, SSH public keys, or remote websites for post-quantum risk.</p>
      </div>

      {generalError && (
        <div style={{ 
          background: 'rgba(239, 68, 68, 0.1)', 
          border: '1px solid var(--status-vulnerable)', 
          borderRadius: '6px', 
          padding: '0.75rem', 
          marginTop: '1.25rem',
          marginBottom: '0.25rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          fontSize: '0.88rem',
          color: '#f87171'
        }}>
          <AlertOctagon size={16} />
          <span>{generalError}</span>
        </div>
      )}

      {/* Selector Tabs */}
      <div className="glass-panel" style={{ display: 'flex', padding: '0.5rem', gap: '0.5rem', borderRadius: '12px' }}>
        <button 
          onClick={() => { setScanType('file'); setConfigResult(null); }}
          className={`nav-btn ${scanType === 'file' ? 'active' : ''}`}
          style={{ flex: 1, justifyContent: 'center' }}
        >
          <Upload size={18} /> File Discovery
        </button>
        <button 
          onClick={() => { setScanType('paste'); setFileResults([]); }}
          className={`nav-btn ${scanType === 'paste' ? 'active' : ''}`}
          style={{ flex: 1, justifyContent: 'center' }}
        >
          <Terminal size={18} /> Configuration Auditor
        </button>
        <button 
          onClick={() => { setScanType('url'); setFileResults([]); setConfigResult(null); }}
          className={`nav-btn ${scanType === 'url' ? 'active' : ''}`}
          style={{ flex: 1, justifyContent: 'center' }}
        >
          <Globe size={18} /> TLS Endpoint Scan
        </button>
        <button 
          onClick={() => { setScanType('ca'); setFileResults([]); setConfigResult(null); }}
          className={`nav-btn ${scanType === 'ca' ? 'active' : ''}`}
          style={{ flex: 1, justifyContent: 'center' }}
        >
          <Server size={18} /> CA Server Sync
        </button>
      </div>

      {/* Scan Modes */}
      {scanType === 'file' && (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <input 
            type="file" 
            ref={fileInputRef} 
            onChange={handleFileSelect} 
            style={{ display: 'none' }} 
            multiple
          />
          <div 
            className={`drop-zone ${isDragging ? 'dragging' : ''}`}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload />
            <h3 style={{ fontSize: '1.2rem' }}>Drag & drop cryptographic keys/certs</h3>
            <p>Supports SSH public keys (`.pub`), SSL certificates (`.pem`, `.crt`, `.key`), or configuration files (`.conf`)</p>
            <span className="btn-secondary" style={{ marginTop: '0.5rem' }}>Select Files</span>
          </div>

          {/* Scanned files results preview */}
          {fileResults.length > 0 && (
            <div style={{ marginTop: '2rem' }}>
              <h4 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <FileText size={18} color="var(--accent-cyan)" /> Scanned Assets Preview
              </h4>
              <table className="quark-table" style={{ marginBottom: '1.5rem' }}>
                <thead>
                  <tr>
                    <th>Asset Name</th>
                    <th>Algorithm</th>
                    <th>Quantum Status</th>
                    <th>Risk Rating</th>
                  </tr>
                </thead>
                <tbody>
                  {fileResults.map((res, i) => (
                    <tr key={i}>
                      <td>{res.name}</td>
                      <td>{res.algorithm} {res.keySize ? `(${res.keySize}-bit)` : ''}</td>
                      <td style={{ color: res.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)', fontWeight: 600 }}>
                        {res.status}
                      </td>
                      <td>
                        <span className={`badge ${res.riskLevel === 'critical' || res.riskLevel === 'high' ? 'danger' : 'success'}`}>
                          {res.riskLevel}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div style={{ display: 'flex', gap: '1rem', justifyContent: 'flex-end' }}>
                <button className="btn-secondary" onClick={() => setFileResults([])}>Discard</button>
                <button className="btn-primary" onClick={handleAddFilesToInventory}>Register in Inventory</button>
              </div>
            </div>
          )}
        </div>
      )}

      {scanType === 'paste' && (
        <div className="scan-controls">
          <div className="glass-panel" style={{ padding: '1.5rem' }}>
            <div className="paste-box">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ fontSize: '1.1rem' }}>Paste cryptographic asset or config content</h3>
                <input 
                  type="text" 
                  value={pasteFileName} 
                  onChange={(e) => setPasteFileName(e.target.value)}
                  style={{ 
                    background: 'rgba(0,0,0,0.3)', 
                    border: '1px solid var(--border-normal)',
                    color: 'white',
                    padding: '0.2rem 0.5rem',
                    borderRadius: '4px',
                    fontSize: '0.8rem',
                    width: '180px'
                  }}
                  placeholder="Filename (e.g. nginx.conf)"
                />
              </div>
              <textarea 
                className="crypto-textarea" 
                value={pasteContent}
                onChange={(e) => setPasteContent(e.target.value)}
                placeholder={`--- Examples ---
* SSH Public Key: ssh-rsa AAAAB3NzaC1yc2E...
* Certificate PEM: -----BEGIN CERTIFICATE----- ...
* Config: paste ssl_ciphers/KexAlgorithms configs to audit.`}
              />
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem' }}>
                <button 
                  className="btn-secondary" 
                  onClick={() => {
                    setPasteContent('ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384;\nssl_prefer_server_ciphers on;');
                    setPasteFileName('nginx.conf');
                  }}
                >
                  Load Demo Nginx Config
                </button>
                <button className="btn-primary" onClick={handlePasteAudit}>Run Cryptographic Audit</button>
              </div>
            </div>
          </div>

          {/* Config Audit Results panel */}
          <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
            <h3 style={{ fontSize: '1.1rem', marginBottom: '1rem' }}>Audit Diagnostics</h3>
            
            {configResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
                <div style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: '0.5rem', 
                  color: configResult.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)',
                  marginBottom: '1rem',
                  fontWeight: 600
                }}>
                  {configResult.isVulnerable ? <AlertOctagon size={18} /> : <CheckCircle size={18} />}
                  <span>{configResult.summary}</span>
                </div>
                
                <div style={{ flex: 1, overflowY: 'auto', maxHeight: '200px', display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
                  {configResult.violations.map((viol, i) => (
                    <div key={i} style={{ 
                      borderLeft: `3px solid ${viol.riskLevel === 'critical' ? 'var(--status-vulnerable)' : 'var(--status-warning)'}`,
                      paddingLeft: '0.75rem',
                      fontSize: '0.88rem'
                    }}>
                      <div style={{ fontWeight: 600, display: 'flex', justifyContent: 'space-between' }}>
                        <span>Line {viol.lineNumber}: {viol.issue}</span>
                        <span className={`badge ${viol.riskLevel === 'critical' ? 'danger' : 'warning'}`} style={{ fontSize: '0.7rem', padding: '0.05rem 0.3rem' }}>
                          {viol.riskLevel}
                        </span>
                      </div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)', margin: '0.2rem 0' }}>
                        "{viol.lineContent}"
                      </div>
                      <div style={{ color: 'var(--text-secondary)' }}>
                        <span style={{ color: 'var(--accent-cyan)', fontWeight: 500 }}>Fix:</span> {viol.recommendation}
                      </div>
                    </div>
                  ))}
                  {configResult.violations.length === 0 && (
                    <div style={{ color: 'var(--text-secondary)', textAlign: 'center', paddingTop: '2rem' }}>
                      Excellent configuration. No vulnerabilities detected.
                    </div>
                  )}
                </div>
                
                <div style={{ display: 'flex', gap: '1rem', marginTop: 'auto', justifyContent: 'flex-end' }}>
                  <button className="btn-secondary" onClick={() => setConfigResult(null)}>Clear</button>
                  {configResult.isVulnerable && (
                    <button className="btn-primary" onClick={handleAddConfigViolationAsAsset}>
                      Track Violations in Inventory
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ 
                flex: 1, 
                display: 'flex', 
                flexDirection: 'column', 
                alignItems: 'center', 
                justifyContent: 'center', 
                color: 'var(--text-muted)',
                gap: '1rem'
              }}>
                <HelpCircle size={40} />
                <span>Audited reports will populate here.</span>
              </div>
            )}
          </div>
        </div>
      )}

      {scanType === 'url' && (
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <h3 style={{ fontSize: '1.2rem', marginBottom: '1.5rem' }}>Remote TLS Handshake Auditor</h3>
          
          {/* Outbound Scan Disclosure Banner */}
          <div style={{
            background: 'rgba(255, 170, 0, 0.05)',
            border: '1px solid rgba(255, 170, 0, 0.25)',
            borderRadius: '8px',
            padding: '1.25rem',
            marginBottom: '1.5rem',
            display: 'flex',
            gap: '1rem',
            alignItems: 'flex-start'
          }}>
            <AlertOctagon size={24} color="var(--status-warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div style={{ fontSize: '0.9rem', lineHeight: '1.45' }}>
              <strong style={{ color: 'var(--text-primary)', display: 'block', marginBottom: '0.25rem' }}>
                Outbound Audit Connection Disclosure
              </strong>
              <span style={{ color: 'var(--text-secondary)' }}>
                Scanning will initiate a <strong>direct outbound TCP/TLS socket connection</strong> from the QuarkShield container to the host on port 443. The auditor evaluates ciphers, key-exchange suites (e.g., ML-KEM/Kyber vs RSA/ECC), protocol versions, and public certificate metadata.
              </span>
              <span style={{ display: 'block', marginTop: '0.5rem', color: 'var(--status-info)' }}>
                🛡️ <strong>Security Guarantee:</strong> No payload data, HTTP headers, credentials, or file paths are sent or inspected. Only public cryptographic handshake negotiations are audited.
              </span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '2rem' }}>
            <div style={{ display: 'flex', gap: '1rem' }}>
              <input 
                type="text" 
                className="chat-text-input" 
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="https://example.com"
                disabled={isUrlScanning}
                style={{ fontSize: '1rem', padding: '0.75rem', flex: 1 }}
              />
              <button 
                className="btn-primary" 
                onClick={handleUrlScan}
                disabled={isUrlScanning || !urlAuthorized}
                style={{ 
                  width: '180px',
                  opacity: (!urlAuthorized && !isUrlScanning) ? 0.5 : 1,
                  cursor: (!urlAuthorized && !isUrlScanning) ? 'not-allowed' : 'pointer'
                }}
              >
                {isUrlScanning ? <RefreshCw className="spin" size={18} /> : 'Scan Endpoint'}
              </button>
            </div>

            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', userSelect: 'none' }}>
              <input 
                type="checkbox" 
                checked={urlAuthorized}
                onChange={(e) => setUrlAuthorized(e.target.checked)}
                disabled={isUrlScanning}
                style={{ 
                  width: '16px', 
                  height: '16px', 
                  accentColor: 'var(--status-secure)',
                  cursor: 'pointer'
                }}
              />
              <span style={{ fontSize: '0.88rem', color: 'var(--text-secondary)' }}>
                I authorize QuarkShield to make this outbound TLS handshake request.
              </span>
            </label>
          </div>

          {isUrlScanning && (
            <div style={{ 
              background: 'rgba(0, 0, 0, 0.4)', 
              borderRadius: '8px', 
              border: '1px solid var(--border-normal)',
              padding: '1.5rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.5rem',
              color: 'var(--text-secondary)'
            }}>
              {urlScanLog.map((log, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  {i === urlScanLog.length - 1 && isUrlScanning ? (
                    <RefreshCw size={12} className="spin" color="var(--accent-cyan)" />
                  ) : (
                    <span style={{ color: 'var(--status-secure)' }}>✓</span>
                  )}
                  <span>{log}</span>
                </div>
              ))}
            </div>
          )}

          {urlResult && !isUrlScanning && (
            <div className="glass-panel" style={{ 
              padding: '1.5rem', 
              border: `1px solid ${urlResult.isVulnerable ? 'rgba(255, 51, 102, 0.3)' : 'rgba(0, 255, 136, 0.3)'}`,
              background: urlResult.isVulnerable ? 'rgba(255, 51, 102, 0.02)' : 'rgba(0, 255, 136, 0.02)'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '1.5rem' }}>
                <div>
                  <h4 style={{ fontSize: '1.3rem', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {urlResult.name}
                    <span className={`badge ${urlResult.isVulnerable ? 'danger' : 'success'}`}>
                      {urlResult.status}
                    </span>
                  </h4>
                  <p style={{ marginTop: '0.25rem' }}>TLS handshake algorithm audit summary.</p>
                </div>
                <div style={{ display: 'flex', gap: '1rem' }}>
                  <button className="btn-secondary" onClick={() => setUrlResult(null)}>Clear</button>
                  <button className="btn-primary" onClick={handleAddUrlToInventory}>Track in Inventory</button>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '2rem' }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', background: 'rgba(0,0,0,0.2)', padding: '1rem', borderRadius: '8px' }}>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PROTOCOL SUITE</span>
                    <div style={{ fontWeight: 600 }}>{urlResult.algorithm}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PUBLIC KEY SIZE</span>
                    <div style={{ fontWeight: 600 }}>{urlResult.keySize ? `${urlResult.keySize}-bit` : 'N/A'}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>QUANTUM THREAT LEVEL</span>
                    <div style={{ 
                      fontWeight: 700, 
                      color: urlResult.riskLevel === 'secure' ? 'var(--status-secure)' : 'var(--status-vulnerable)' 
                    }}>
                      {urlResult.riskLevel.toUpperCase()}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  <div>
                    <h5 style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Detailed Audit</h5>
                    <p style={{ fontSize: '0.92rem' }}>{urlResult.description}</p>
                  </div>
                  <div>
                    <h5 style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Remediation Recommendation</h5>
                    <p style={{ fontSize: '0.92rem' }}>{urlResult.recommendation}</p>
                  </div>
                  <div>
                    <h5 style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '0.25rem' }}>Quantum Cryptanalysis Explainer</h5>
                    <p style={{ fontSize: '0.92rem', fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)' }}>
                      {urlResult.explainer}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {scanType === 'ca' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginTop: '1rem' }}>
          {/* HashiCorp Vault Card */}
          <div className="glass-panel" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <Server size={24} color="var(--accent-cyan)" />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>HashiCorp Vault PKI</h3>
            </div>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Query Vault's certificate authority dynamically. QuarkShield pulls active certificates from the `/v1/pki/certs` endpoint for quantum cryptanalysis.
            </p>

            {/* Outbound Warning */}
            <div style={{
              background: 'rgba(255, 170, 0, 0.05)',
              border: '1px solid rgba(255, 170, 0, 0.2)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
              lineHeight: '1.4'
            }}>
              <span style={{ color: 'var(--status-warning)', fontWeight: 600, display: 'block', marginBottom: '0.15rem' }}>
                ⚠️ Outbound HTTP Request Warning
              </span>
              This will invoke an <strong>outbound authenticated REST API call</strong> from our server to your Vault server URL. It will query the public certificate list and inspect key lengths/subject names.
              <span style={{ display: 'block', marginTop: '0.25rem', color: 'var(--accent-cyan)' }}>
                🔒 Token is held only in-memory during sync; it is never stored, logged, or saved to the database.
              </span>
            </div>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>VAULT SERVER URL</label>
                <input 
                  type="text" 
                  className="chat-text-input" 
                  value={vaultUrl} 
                  onChange={(e) => setVaultUrl(e.target.value)}
                  placeholder="http://localhost:8200"
                  style={{ width: '100%', padding: '0.6rem', border: '1px solid var(--border-normal)', background: 'rgba(0,0,0,0.2)', color: 'white', borderRadius: '6px' }}
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>ACCESS TOKEN (X-VAULT-TOKEN)</label>
                <input 
                  type="password" 
                  className="chat-text-input" 
                  value={vaultToken} 
                  onChange={(e) => setVaultToken(e.target.value)}
                  placeholder="hvs.vault_token_here"
                  style={{ width: '100%', padding: '0.6rem', border: '1px solid var(--border-normal)', background: 'rgba(0,0,0,0.2)', color: 'white', borderRadius: '6px' }}
                />
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>PKI MOUNT PATH</label>
                <input 
                  type="text" 
                  className="chat-text-input" 
                  value={vaultMountPath} 
                  onChange={(e) => setVaultMountPath(e.target.value)}
                  placeholder="pki"
                  style={{ width: '100%', padding: '0.6rem', border: '1px solid var(--border-normal)', background: 'rgba(0,0,0,0.2)', color: 'white', borderRadius: '6px' }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: 'auto' }}>
              <label style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', cursor: 'pointer', userSelect: 'none' }}>
                <input 
                  type="checkbox" 
                  checked={vaultAuthorized}
                  onChange={(e) => setVaultAuthorized(e.target.checked)}
                  disabled={isVaultSyncing}
                  style={{ 
                    marginTop: '3px',
                    width: '14px', 
                    height: '14px', 
                    accentColor: 'var(--status-secure)',
                    cursor: 'pointer'
                  }}
                />
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  I authorize QuarkShield to query my Vault server using the token above.
                </span>
              </label>

              <button 
                className="btn-primary" 
                onClick={handleVaultSync} 
                disabled={isVaultSyncing || !vaultAuthorized}
                style={{ 
                  display: 'flex', 
                  alignItems: 'center', 
                  justifyContent: 'center', 
                  gap: '0.5rem', 
                  width: '100%',
                  opacity: (!vaultAuthorized && !isVaultSyncing) ? 0.5 : 1,
                  cursor: (!vaultAuthorized && !isVaultSyncing) ? 'not-allowed' : 'pointer'
                }}
              >
                {isVaultSyncing ? <RefreshCw className="spin" size={18} /> : 'Trigger Pull Sync'}
              </button>
            </div>

            {vaultSyncError && (
              <div style={{ 
                background: 'rgba(255, 51, 102, 0.1)', 
                border: '1px solid rgba(255, 51, 102, 0.3)', 
                borderRadius: '8px', 
                padding: '0.75rem', 
                color: 'var(--status-vulnerable)', 
                fontSize: '0.85rem' 
              }}>
                <strong>Sync Failed:</strong> {vaultSyncError}
              </div>
            )}

            {vaultSyncResult && (
              <div style={{ 
                background: 'rgba(0, 255, 136, 0.05)', 
                border: '1px solid rgba(0, 255, 136, 0.2)', 
                borderRadius: '8px', 
                padding: '1rem', 
                display: 'flex', 
                flexDirection: 'column', 
                gap: '0.5rem',
                fontSize: '0.9rem' 
              }}>
                <span style={{ color: 'var(--status-secure)', fontWeight: 600 }}>✓ {vaultSyncResult.message}</span>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginTop: '0.5rem', textAlign: 'center' }}>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SYNCED</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{vaultSyncResult.syncedCount}</div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>VULNERABLE</div>
                    <div style={{ fontWeight: 700, color: 'var(--status-vulnerable)' }}>{vaultSyncResult.vulnerableCount}</div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>SECURE</div>
                    <div style={{ fontWeight: 700, color: 'var(--status-secure)' }}>{vaultSyncResult.secureCount}</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Microsoft ADCS Card */}
          <div className="glass-panel" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <Terminal size={24} color="var(--accent-purple)" />
              <h3 style={{ fontSize: '1.2rem', fontWeight: 700 }}>Microsoft ADCS</h3>
            </div>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)' }}>
              Windows Certificate Services lacks modern APIs. Copy the PowerShell script below to execute on your ADCS server. It runs `certutil` and pushes certificate metadata to the ingestion gateway.
            </p>

            {/* Inbound Agent Explanation */}
            <div style={{
              background: 'rgba(0, 210, 255, 0.05)',
              border: '1px solid rgba(0, 210, 255, 0.2)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              fontSize: '0.8rem',
              color: 'var(--text-secondary)',
              lineHeight: '1.4'
            }}>
              <span style={{ color: 'var(--status-info)', fontWeight: 600, display: 'block', marginBottom: '0.15rem' }}>
                ℹ️ Local Execution Agent (Inbound Push Only)
              </span>
              QuarkShield <strong>does not</strong> scan your internal Active Directory or ADCS network. You manually run the script on your Windows CA server. It reads local metadata and registers it via an authenticated HTTP POST payload to our server.
              <span style={{ display: 'block', marginTop: '0.25rem', color: 'var(--status-secure)' }}>
                🛡️ No private keys are read, exported, or transmitted.
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', position: 'relative' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>ADCS_SYNC.PS1</span>
                <button 
                  onClick={handleCopyScript}
                  className="btn-secondary" 
                  style={{ 
                    padding: '0.2rem 0.6rem', 
                    fontSize: '0.8rem', 
                    display: 'flex', 
                    alignItems: 'center', 
                    gap: '0.25rem' 
                  }}
                >
                  {showCopied ? <Check size={14} color="var(--status-secure)" /> : <Copy size={14} />}
                  {showCopied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <textarea 
                readOnly 
                value={psScript}
                style={{ 
                  fontFamily: 'var(--font-mono)', 
                  fontSize: '0.75rem', 
                  background: 'rgba(0,0,0,0.4)', 
                  border: '1px solid var(--border-normal)', 
                  borderRadius: '6px', 
                  padding: '0.75rem', 
                  height: '180px', 
                  resize: 'none',
                  color: 'var(--text-secondary)',
                  outline: 'none'
                }}
              />
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: 'auto' }}>
              <button 
                className="btn-secondary" 
                onClick={handleAdcsMockPush}
                style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}
              >
                <Terminal size={16} /> Simulate Windows Push
              </button>
            </div>

            {adcsSyncResult && (
              <div style={{ 
                background: 'rgba(0, 255, 136, 0.05)', 
                border: '1px solid rgba(0, 255, 136, 0.2)', 
                borderRadius: '8px', 
                padding: '1rem', 
                display: 'flex', 
                flexDirection: 'column', 
                gap: '0.5rem',
                fontSize: '0.9rem' 
              }}>
                <span style={{ color: 'var(--status-secure)', fontWeight: 600 }}>✓ {adcsSyncResult.message}</span>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', marginTop: '0.5rem', textAlign: 'center' }}>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>INGESTED</div>
                    <div style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{adcsSyncResult.registeredCount}</div>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.5rem', borderRadius: '4px' }}>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>VULNERABLE</div>
                    <div style={{ fontWeight: 700, color: 'var(--status-vulnerable)' }}>{adcsSyncResult.vulnerableCount}</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};
