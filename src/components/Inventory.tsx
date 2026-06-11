import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Search, 
  ShieldAlert, 
  ShieldCheck, 
  Info,
  Trash2,
  AlertOctagon,
  X,
  Play,
  Database,
  Layers,
  Globe,
  User,
  Activity
} from 'lucide-react';
import { 
  enrichAssetCMDB
} from '../utils/cryptoAuditor';
import type { 
  AuditResult, 
  EnrichedAuditResult 
} from '../utils/cryptoAuditor';

interface InventoryProps {
  assets: AuditResult[];
  onRemoveAsset: (id: string) => void;
  selectedAsset: AuditResult | null;
  setSelectedAsset: (asset: AuditResult | null) => void;
  onAddAssets?: (assets: AuditResult[]) => void;
}

const DISCOVERY_ASSETS: AuditResult[] = [
  {
    id: 'aws-acm-1',
    type: 'certificate',
    name: 'aws-acm-payment-elb-cert',
    algorithm: 'RSA',
    keySize: 2048,
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    description: 'AWS ACM certificate for payments load balancer. |CMDB:{"businessService":"Transactional Core Payment","application":"PayShield API","endpoint":"api.payments.enterprise.com","owner":"payment-infra@spinovation.com","lifecycle":"Active"}',
    recommendation: 'Request post-quantum hybrid certificate from ACM or associate with Cloudflare proxy enforcing hybrid key exchange.',
    explainer: 'Asymmetric cryptography used in AWS ELB TLS handshakes (RSA) is vulnerable to Shor\'s algorithm.',
    complianceViolations: ['CNSA 2.0', 'EO 14028']
  },
  {
    id: 'azure-kv-1',
    type: 'ssh_key',
    name: 'azure-kv-vm-root-key',
    algorithm: 'RSA',
    keySize: 4096,
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    description: 'Virtual machine administrator access key stored in Azure Key Vault. |CMDB:{"businessService":"Corporate Identity Services","application":"Bastion Gateway","endpoint":"bastion.secure.enterprise.com","owner":"secops@spinovation.com","lifecycle":"Active"}',
    recommendation: 'Rotate VMs to utilize hybrid OpenSSH certificates.',
    explainer: 'RSA-4096 is vulnerable to Shor\'s discrete logarithm calculations.',
    complianceViolations: ['CNSA 2.0']
  },
  {
    id: 'splunk-discovered-1',
    type: 'url',
    name: 'internal-reporting-api',
    algorithm: 'ECDSA',
    keySize: 384,
    isVulnerable: true,
    riskLevel: 'high',
    status: 'Quantum Vulnerable',
    description: 'Discovered via Splunk audit logs analyzing SSL handshakes. |CMDB:{"businessService":"Enterprise Infrastructure","application":"Reporting Engine","endpoint":"reports.internal.enterprise.com","owner":"analytics@spinovation.com","lifecycle":"Active"}',
    recommendation: 'Update endpoint TLS profile to support hybrid ML-KEM exchange.',
    explainer: 'ECDSA P-384 discrete logarithms can be completely solved by Shor\'s algorithm.',
    complianceViolations: ['CNSA 2.0']
  },
  {
    id: 'servicenow-tracked-1',
    type: 'config',
    name: 'kubernetes-ingress-routing',
    algorithm: 'SHA1',
    isVulnerable: true,
    riskLevel: 'critical',
    status: 'Quantum Vulnerable',
    description: 'Kubernetes routing config utilizing weak hash algorithms. |CMDB:{"businessService":"Transactional Core Payment","application":"PayShield API","endpoint":"api.payments.enterprise.com","owner":"k8s-admin@spinovation.com","lifecycle":"Active"}',
    recommendation: 'Update ingress controller config map to enforce SHA-256 for integrity checks.',
    explainer: 'SHA1 references in configurations are vulnerable to collision attacks and quantum Grover speedup.',
    complianceViolations: ['NIST SP 800-131A']
  }
];

export const Inventory: React.FC<InventoryProps> = ({ 
  assets, 
  onRemoveAsset, 
  selectedAsset, 
  setSelectedAsset,
  onAddAssets
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [serviceFilter, setServiceFilter] = useState('all');
  const [lifecycleFilter, setLifecycleFilter] = useState('all');

  // Discovery simulation states
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [discoveryLogs, setDiscoveryLogs] = useState<string[]>([]);
  const [selectedConnector, setSelectedConnector] = useState('aws');
  const logTerminalRef = useRef<HTMLDivElement>(null);

  // Parse and enrich all assets with CMDB metadata
  const enrichedAssets = useMemo(() => {
    return assets.map(asset => enrichAssetCMDB(asset));
  }, [assets]);

  // Unique filters lists
  const businessServices = useMemo(() => {
    const services = enrichedAssets.map(a => a.businessService);
    return Array.from(new Set(services)).filter(Boolean);
  }, [enrichedAssets]);

  // Default the graph service filter to the first available service (or "Transactional Core Payment" if present)
  const [graphService, setGraphService] = useState('Transactional Core Payment');
  
  useEffect(() => {
    if (businessServices.length > 0 && !businessServices.includes(graphService)) {
      setGraphService(businessServices[0]);
    }
  }, [businessServices, graphService]);

  // Filtered Assets
  const filteredAssets = useMemo(() => {
    return enrichedAssets.filter(asset => {
      const matchesSearch = 
        asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.businessService.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.application.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.owner.toLowerCase().includes(searchTerm.toLowerCase());
        
      const matchesType = typeFilter === 'all' || asset.type === typeFilter;
      
      let matchesStatus = true;
      if (statusFilter === 'vulnerable') {
        matchesStatus = asset.isVulnerable;
      } else if (statusFilter === 'secure') {
        matchesStatus = !asset.isVulnerable;
      }

      const matchesService = serviceFilter === 'all' || asset.businessService === serviceFilter;
      const matchesLifecycle = lifecycleFilter === 'all' || asset.lifecycle === lifecycleFilter;

      return matchesSearch && matchesType && matchesStatus && matchesService && matchesLifecycle;
    });
  }, [enrichedAssets, searchTerm, typeFilter, statusFilter, serviceFilter, lifecycleFilter]);

  // Sync scroll on logs terminal
  useEffect(() => {
    if (logTerminalRef.current) {
      logTerminalRef.current.scrollTop = logTerminalRef.current.scrollHeight;
    }
  }, [discoveryLogs]);

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

  // Run Metadata Discovery Scan Simulation
  const triggerDiscovery = () => {
    if (isDiscovering) return;
    setIsDiscovering(true);
    setDiscoveryLogs([]);

    const connectorNames: Record<string, string> = {
      aws: 'AWS ACM & ELB API Connector',
      azure: 'Azure Key Vault & ARM API Connector',
      gcp: 'GCP Certificate Manager & Load Balancer API',
      k8s: 'Kubernetes Ingress & Secrets Mesh Controller',
      splunk: 'Splunk SIEM API Logs Analyzer',
      defender: 'Microsoft Defender Endpoint API Core',
      crowdstrike: 'CrowdStrike Falcon Threat Intelligence',
      qualys: 'Qualys VMDR Vuln Sync Client',
      tenable: 'Tenable SecurityCenter API Ingestion',
      workday: 'Workday HR Directory Owner Mapper',
      sharepoint: 'SharePoint Document Dependency Crawler',
      servicenow: 'ServiceNow CMDB Dependency Syncer'
    };

    const targetConnector = connectorNames[selectedConnector] || 'API Cloud Connector';
    const nowStr = new Date().toLocaleTimeString();

    // Custom logs based on selected connector
    let scanLog = `[${nowStr}] [SCAN] Querying active resource configurations. Ingesting schema descriptors...`;
    let correlationLog = `[${nowStr}] [CORRELATE] Resolving ownership records from Active Directory & ServiceNow service catalogs...`;

    if (selectedConnector === 'workday') {
      scanLog = `[${nowStr}] [WORKDAY-SYNC] Fetching organizational hierarchy and manager profiles...`;
      correlationLog = `[${nowStr}] [IDENTITY-MAP] Linking cryptosystem owners to Workday cost-centers and Slack handles...`;
    } else if (selectedConnector === 'sharepoint') {
      scanLog = `[${nowStr}] [SP-CRAWL] Parsing SharePoint document libraries for SSL/TLS configuration spreadsheets...`;
      correlationLog = `[${nowStr}] [DOC-CORRELATE] Mapping SharePoint asset registers to discovered endpoints...`;
    } else if (selectedConnector === 'defender') {
      scanLog = `[${nowStr}] [DEFENDER-SCAN] Extracting network connection logs and handshake telemetry from endpoints...`;
      correlationLog = `[${nowStr}] [POLICY] Identifying TLS versions and cipher suites in active use by endpoints...`;
    } else if (selectedConnector === 'crowdstrike') {
      scanLog = `[${nowStr}] [FALCON-INTEL] Querying Falcon network traffic metadata for legacy SSL handshakes...`;
      correlationLog = `[${nowStr}] [ZERO-TRUST] Mapping encryption tunnels to domain controllers...`;
    } else if (selectedConnector === 'qualys' || selectedConnector === 'tenable') {
      const toolName = selectedConnector === 'qualys' ? 'Qualys' : 'Tenable';
      scanLog = `[${nowStr}] [${toolName.toUpperCase()}-INGEST] Fetching active host vulnerabilities and SSL/TLS scan results...`;
      correlationLog = `[${nowStr}] [VULN-MATCH] Cross-referencing host CVEs with quantum-vulnerable configurations...`;
    }

    const logs = [
      `[${nowStr}] [CMDB-INIT] Initializing metadata-first discovery connector: ${targetConnector}...`,
      `[${nowStr}] [AUTH] Authenticating session tokens with OAuth2 credential stores...`,
      scanLog,
      `[${nowStr}] [GDPR-CHECK] GDPR compliance filter activated: Raw payloads, logs and user inputs are discarded.`,
      `[${nowStr}] [METADATA-FIRST] Extracting cryptographic parameters (TLS profiles, key rings, algorithms, owners)...`,
      correlationLog,
      `[${nowStr}] [PARSE] Discovered 4 cryptographic assets mapped to enterprise dependencies.`,
      `[${nowStr}] [SYNC] Registering assets into postgres database...`,
      `[${nowStr}] [SUCCESS] Metadata sync finished. 4 new assets imported into Crypto CMDB.`
    ];

    let currentLogIndex = 0;
    const interval = setInterval(() => {
      if (currentLogIndex < logs.length) {
        setDiscoveryLogs(prev => [...prev, logs[currentLogIndex]]);
        currentLogIndex++;
      } else {
        clearInterval(interval);
        setIsDiscovering(false);
        if (onAddAssets) {
          onAddAssets(DISCOVERY_ASSETS);
        }
      }
    }, 600);
  };

  // Compute SVG nodes and links for the SVG dependency mapper
  const svgGraph = useMemo(() => {
    const serviceAssets = enrichedAssets.filter(a => a.businessService === graphService);
    if (serviceAssets.length === 0) return null;

    // We want unique nodes for each level:
    // Level 0: Business Service (1 node)
    // Level 1: Application (unique apps)
    // Level 2: Endpoint (unique endpoints)
    // Level 3: Asset (unique asset names)
    // Level 4: Algorithm (unique algorithms)

    const uniqueApps = Array.from(new Set(serviceAssets.map(a => a.application)));
    const uniqueEndpoints = Array.from(new Set(serviceAssets.map(a => a.endpoint)));
    const uniqueNames = Array.from(new Set(serviceAssets.map(a => a.name)));
    const uniqueAlgs = Array.from(new Set(serviceAssets.map(a => a.algorithm)));

    const width = 850;
    const height = 280;

    // X coordinates for the 5 levels
    const xPositions = [50, 230, 420, 610, 780];

    // Compute Y positions
    const getY = (index: number, count: number) => {
      if (count === 1) return height / 2;
      const step = (height - 60) / (count - 1);
      return 30 + index * step;
    };

    // Construct nodes
    const nodes: Array<{
      id: string;
      label: string;
      x: number;
      y: number;
      col: number;
      type: string;
      isVulnerable: boolean;
      originalAsset?: EnrichedAuditResult;
    }> = [];

    // Level 0 node
    const serviceVulnerable = serviceAssets.some(a => a.isVulnerable);
    nodes.push({
      id: `service-${graphService}`,
      label: graphService,
      x: xPositions[0],
      y: height / 2,
      col: 0,
      type: 'service',
      isVulnerable: serviceVulnerable
    });

    // Level 1: Applications
    uniqueApps.forEach((app, i) => {
      const appVulnerable = serviceAssets.filter(a => a.application === app).some(a => a.isVulnerable);
      nodes.push({
        id: `app-${app}`,
        label: app,
        x: xPositions[1],
        y: getY(i, uniqueApps.length),
        col: 1,
        type: 'app',
        isVulnerable: appVulnerable
      });
    });

    // Level 2: Endpoints
    uniqueEndpoints.forEach((end, i) => {
      const endVulnerable = serviceAssets.filter(a => a.endpoint === end).some(a => a.isVulnerable);
      nodes.push({
        id: `end-${end}`,
        label: end,
        x: xPositions[2],
        y: getY(i, uniqueEndpoints.length),
        col: 2,
        type: 'endpoint',
        isVulnerable: endVulnerable
      });
    });

    // Level 3: Assets
    uniqueNames.forEach((name, i) => {
      const matchingAsset = serviceAssets.find(a => a.name === name);
      nodes.push({
        id: `asset-${name}`,
        label: name,
        x: xPositions[3],
        y: getY(i, uniqueNames.length),
        col: 3,
        type: 'asset',
        isVulnerable: matchingAsset?.isVulnerable || false,
        originalAsset: matchingAsset
      });
    });

    // Level 4: Algorithms
    uniqueAlgs.forEach((alg, i) => {
      const algVulnerable = serviceAssets.filter(a => a.algorithm === alg).some(a => a.isVulnerable);
      nodes.push({
        id: `alg-${alg}`,
        label: alg,
        x: xPositions[4],
        y: getY(i, uniqueAlgs.length),
        col: 4,
        type: 'alg',
        isVulnerable: algVulnerable
      });
    });

    // Helper to find node by ID
    const findNode = (id: string) => nodes.find(n => n.id === id);

    // Construct links based on actual assets
    const links: Array<{
      source: typeof nodes[0];
      target: typeof nodes[0];
      isVulnerable: boolean;
    }> = [];

    serviceAssets.forEach(asset => {
      const nService = findNode(`service-${graphService}`);
      const nApp = findNode(`app-${asset.application}`);
      const nEnd = findNode(`end-${asset.endpoint}`);
      const nAsset = findNode(`asset-${asset.name}`);
      const nAlg = findNode(`alg-${asset.algorithm}`);

      if (nService && nApp) {
        if (!links.some(l => l.source.id === nService.id && l.target.id === nApp.id)) {
          links.push({ source: nService, target: nApp, isVulnerable: asset.isVulnerable });
        }
      }
      if (nApp && nEnd) {
        if (!links.some(l => l.source.id === nApp.id && l.target.id === nEnd.id)) {
          links.push({ source: nApp, target: nEnd, isVulnerable: asset.isVulnerable });
        }
      }
      if (nEnd && nAsset) {
        if (!links.some(l => l.source.id === nEnd.id && l.target.id === nAsset.id)) {
          links.push({ source: nEnd, target: nAsset, isVulnerable: asset.isVulnerable });
        }
      }
      if (nAsset && nAlg) {
        if (!links.some(l => l.source.id === nAsset.id && l.target.id === nAlg.id)) {
          links.push({ source: nAsset, target: nAlg, isVulnerable: asset.isVulnerable });
        }
      }
    });

    return { nodes, links, width, height };
  }, [enrichedAssets, graphService]);

  return (
    <>
      <div style={{ marginBottom: '1.5rem' }}>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem', background: 'linear-gradient(135deg, #00f3ff 0%, #a855f7 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
          Crypto Asset CMDB
        </h2>
        <p style={{ color: 'var(--text-secondary)' }}>
          Enterprise System of Record: Mapped dependencies, ownership alignment, and cryptographic lifecycle state.
        </p>
      </div>

      {/* Row 1: Discovery Connectors and SVG Dependency Graph */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'minmax(300px, 1fr) minmax(450px, 2fr)', 
        gap: '1.5rem', 
        marginBottom: '1.5rem',
        alignItems: 'stretch'
      }}>
        {/* Discovery Panel */}
        <div className="glass-panel" style={{ 
          padding: '1.25rem', 
          display: 'flex', 
          flexDirection: 'column', 
          justifyContent: 'space-between',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-normal)'
        }}>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem', color: '#ffffff' }}>
              <Database size={18} color="var(--accent-cyan)" />
              <span>Metadata-First Discovery Center</span>
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.4' }}>
              Connect agentless API resource descriptors to sync cryptographic inventory. Ingests metadata only (GDPR compliant).
            </p>

            {/* Select connector */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
                Select Active Cloud / SIEM Source
              </label>
              <select 
                value={selectedConnector} 
                onChange={(e) => setSelectedConnector(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.5rem', fontSize: '0.9rem', width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: '#ffffff' }}
              >
                <option value="aws">AWS ACM & ELB APIs (Tier 1)</option>
                <option value="azure">Azure Key Vault & Resource APIs (Tier 1)</option>
                <option value="gcp">GCP Certificate Manager & Load Balancer (Tier 1)</option>
                <option value="k8s">Kubernetes TLS Secrets & Service Mesh (Tier 1)</option>
                <option value="splunk">Splunk SIEM API Logs (Tier 2)</option>
                <option value="defender">Microsoft Defender for Endpoint (Tier 2)</option>
                <option value="crowdstrike">CrowdStrike Falcon Insight (Tier 2)</option>
                <option value="qualys">Qualys VMDR Scanning (Tier 2)</option>
                <option value="tenable">Tenable SecurityCenter (Tier 2)</option>
                <option value="workday">Workday HR Identity Catalog (Tier 2)</option>
                <option value="sharepoint">SharePoint Document Assets (Tier 2)</option>
                <option value="servicenow">ServiceNow CMDB Service Catalog (Tier 2)</option>
              </select>
            </div>

            <button 
              onClick={triggerDiscovery}
              disabled={isDiscovering}
              className="btn-primary" 
              style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem', padding: '0.65rem' }}
            >
              <Play size={15} />
              <span>{isDiscovering ? 'Running API Metadata Sync...' : 'Trigger Metadata Discovery'}</span>
            </button>
          </div>

          {/* Simulated Logs Terminal */}
          <div style={{ marginTop: '1rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Discovery Logs</span>
              {isDiscovering && <div className="pulse-dot"></div>}
            </div>
            <div 
              ref={logTerminalRef}
              style={{ 
                height: '110px', 
                background: '#090a0f', 
                border: '1px solid var(--border-normal)', 
                borderRadius: '6px', 
                padding: '0.5rem', 
                fontFamily: 'monospace', 
                fontSize: '0.75rem', 
                color: '#39ff14', 
                overflowY: 'auto',
                whiteSpace: 'pre-line',
                lineHeight: '1.4'
              }}
            >
              {discoveryLogs.length === 0 ? (
                <span style={{ color: 'var(--text-muted)' }}>Idle. Click "Trigger Metadata Discovery" to run agentless cloud discovery.</span>
              ) : (
                discoveryLogs.join('\n')
              )}
            </div>
          </div>
        </div>

        {/* SVG Dependency Mapper */}
        <div className="glass-panel" style={{ 
          padding: '1.25rem', 
          background: 'var(--bg-card)', 
          border: '1px solid var(--border-normal)',
          display: 'flex',
          flexDirection: 'column'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#ffffff', margin: 0 }}>
              <Layers size={18} color="var(--accent-purple)" />
              <span>Cryptographic Dependency Graph</span>
            </h3>
            
            {/* Graph Service Selector */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Service Context:</span>
              <select 
                value={graphService} 
                onChange={(e) => setGraphService(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem', background: 'rgba(0,0,0,0.3)', width: '180px' }}
              >
                {businessServices.map((service) => (
                  <option key={service} value={service}>{service}</option>
                ))}
              </select>
            </div>
          </div>

          <div style={{ 
            flexGrow: 1, 
            background: 'rgba(0, 0, 0, 0.25)', 
            border: '1px solid var(--border-normal)', 
            borderRadius: '6px', 
            position: 'relative', 
            minHeight: '230px',
            overflow: 'auto'
          }}>
            {svgGraph ? (
              <svg 
                viewBox={`0 0 ${svgGraph.width} ${svgGraph.height}`} 
                style={{ width: '100%', minWidth: '780px', height: '100%', display: 'block' }}
              >
                {/* Draw Links */}
                {svgGraph.links.map((link, i) => {
                  const dPath = `M ${link.source.x} ${link.source.y} C ${(link.source.x + link.target.x) / 2} ${link.source.y}, ${(link.source.x + link.target.x) / 2} ${link.target.y}, ${link.target.x} ${link.target.y}`;
                  return (
                    <path 
                      key={i} 
                      d={dPath} 
                      fill="none" 
                      stroke={link.isVulnerable ? '#ef4444' : '#10b981'} 
                      strokeWidth={1.5}
                      strokeOpacity={link.isVulnerable ? 0.6 : 0.4}
                      style={{ transition: 'all 0.2s' }}
                    />
                  );
                })}

                {/* Draw Nodes */}
                {svgGraph.nodes.map((node) => {
                  const rectW = node.type === 'service' ? 120 : node.type === 'app' ? 110 : node.type === 'endpoint' ? 120 : 100;
                  const rectH = 32;
                  
                  return (
                    <g 
                      key={node.id} 
                      transform={`translate(${node.x - rectW/2}, ${node.y - rectH/2})`}
                      style={{ cursor: node.originalAsset ? 'pointer' : 'default' }}
                      onClick={() => {
                        if (node.originalAsset) {
                          handleOpenDialog(node.originalAsset);
                        }
                      }}
                    >
                      <rect 
                        width={rectW} 
                        height={rectH} 
                        rx={6} 
                        fill={node.originalAsset ? 'var(--bg-card)' : 'rgba(20,20,30,0.85)'}
                        stroke={node.isVulnerable ? 'rgba(239, 68, 68, 0.7)' : 'rgba(16, 185, 129, 0.7)'}
                        strokeWidth={1.5}
                        style={{
                          filter: node.isVulnerable 
                            ? 'drop-shadow(0px 0px 3px rgba(239, 68, 68, 0.2))' 
                            : 'drop-shadow(0px 0px 3px rgba(16, 185, 129, 0.2))'
                        }}
                      />
                      <text 
                        x={rectW / 2} 
                        y={rectH / 2 + 4} 
                        fill="#ffffff"
                        fontSize={8.5} 
                        fontWeight={node.originalAsset ? '700' : '500'}
                        textAnchor="middle"
                        style={{ pointerEvents: 'none', userSelect: 'none' }}
                      >
                        {node.label.length > 20 ? node.label.substring(0, 18) + '...' : node.label}
                      </text>
                    </g>
                  );
                })}
              </svg>
            ) : (
              <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No dependency graph assets found. Trigger discovery above.
              </div>
            )}
            
            {/* Column labels */}
            <div style={{ position: 'absolute', bottom: 5, left: 0, right: 0, display: 'flex', justifyContent: 'space-between', padding: '0 1rem', pointerEvents: 'none', fontSize: '0.65rem', color: 'var(--text-muted)', fontWeight: 'bold', textTransform: 'uppercase' }}>
              <span>Service</span>
              <span>Application</span>
              <span>Endpoint</span>
              <span>Asset</span>
              <span>Algorithm</span>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: Search, Filters, and Table */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem', 
        background: 'var(--bg-card)', 
        border: '1px solid var(--border-normal)',
        marginBottom: '1.5rem'
      }}>
        {/* Header Search & Filtering */}
        <div style={{ 
          display: 'flex', 
          gap: '1rem', 
          alignItems: 'center', 
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          marginBottom: '1rem'
        }}>
          {/* Search bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.45rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-normal)', flex: 1, minWidth: '220px' }}>
            <Search size={16} color="var(--text-secondary)" />
            <input 
              type="text" 
              placeholder="Search CMDB (ciphers, services, owners...)" 
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{ 
                background: 'transparent', 
                border: 'none', 
                color: 'white', 
                outline: 'none', 
                width: '100%',
                fontFamily: 'var(--font-sans)',
                fontSize: '0.9rem'
              }}
            />
          </div>

          {/* Filters array */}
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {/* Service Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Service:</span>
              <select 
                value={serviceFilter} 
                onChange={(e) => setServiceFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem', width: '130px', background: 'rgba(0,0,0,0.3)' }}
              >
                <option value="all">All Services</option>
                {businessServices.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>

            {/* Type Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Type:</span>
              <select 
                value={typeFilter} 
                onChange={(e) => setTypeFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem', width: '110px', background: 'rgba(0,0,0,0.3)' }}
              >
                <option value="all">All Types</option>
                <option value="certificate">Certificates</option>
                <option value="ssh_key">SSH Keys</option>
                <option value="private_key">Private Keys</option>
                <option value="config">Configurations</option>
                <option value="url">Endpoints</option>
              </select>
            </div>

            {/* Status Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Status:</span>
              <select 
                value={statusFilter} 
                onChange={(e) => setStatusFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem', width: '110px', background: 'rgba(0,0,0,0.3)' }}
              >
                <option value="all">All Postures</option>
                <option value="vulnerable">Vulnerable</option>
                <option value="secure">PQC Secure</option>
              </select>
            </div>

            {/* Lifecycle Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Lifecycle:</span>
              <select 
                value={lifecycleFilter} 
                onChange={(e) => setLifecycleFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.25rem 0.5rem', fontSize: '0.8rem', width: '110px', background: 'rgba(0,0,0,0.3)' }}
              >
                <option value="all">All States</option>
                <option value="Active">Active</option>
                <option value="Migrating">Migrating</option>
                <option value="Remediated">Remediated</option>
              </select>
            </div>
          </div>
        </div>

        {/* Table representation of assets */}
        <div style={{ overflowX: 'auto' }}>
          <table className="quark-table">
            <thead>
              <tr>
                <th>Business Service</th>
                <th>Application</th>
                <th>Endpoint</th>
                <th>Cryptographic Asset</th>
                <th>Algorithm</th>
                <th>Risk</th>
                <th>Owner</th>
                <th>Lifecycle</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredAssets.map((asset) => (
                <tr key={asset.id} style={{ borderBottom: '1px solid var(--border-normal)' }}>
                  <td style={{ fontWeight: 600, color: '#ffffff' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <Layers size={13} color="var(--text-secondary)" />
                      <span>{asset.businessService}</span>
                    </div>
                  </td>
                  <td>{asset.application}</td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontFamily: 'monospace', fontSize: '0.8rem', color: 'var(--accent-cyan)' }}>
                      <Globe size={12} />
                      <span>{asset.endpoint}</span>
                    </div>
                  </td>
                  <td style={{ fontWeight: 500 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      {asset.isVulnerable ? (
                        <ShieldAlert size={14} color="var(--status-vulnerable)" />
                      ) : (
                        <ShieldCheck size={14} color="var(--status-secure)" />
                      )}
                      <span>{asset.name}</span>
                    </div>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.85rem' }}>
                      {asset.algorithm} {asset.keySize ? `(${asset.keySize}-bit)` : ''}
                    </span>
                  </td>
                  <td>
                    <span className={`badge ${
                      asset.riskLevel === 'critical' ? 'danger' : 
                      asset.riskLevel === 'high' ? 'danger' : 
                      asset.riskLevel === 'medium' ? 'warning' : 'success'
                    }`} style={{ fontSize: '0.7rem' }}>
                      {asset.riskLevel}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                      <User size={12} />
                      <span>{asset.owner}</span>
                    </div>
                  </td>
                  <td>
                    <span style={{ 
                      fontSize: '0.75rem', 
                      fontWeight: 600, 
                      color: asset.lifecycle === 'Remediated' ? 'var(--status-secure)' : 
                             asset.lifecycle === 'Migrating' ? 'var(--status-warning)' : 'var(--text-muted)'
                    }}>
                      {asset.lifecycle}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: '0.4rem' }}>
                      <button 
                        onClick={() => handleOpenDialog(asset)}
                        className="btn-secondary" 
                        style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.2rem' }}
                      >
                        <Info size={12} /> Detail
                      </button>
                      <button 
                        onClick={() => onRemoveAsset(asset.id)}
                        className="btn-secondary" 
                        style={{ padding: '0.25rem', color: 'var(--status-vulnerable)', borderColor: 'rgba(255, 51, 102, 0.15)' }}
                        title="Delete asset"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredAssets.length === 0 && (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2.5rem' }}>
                    No CMDB assets matched the active filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Upgraded Audit Details Modal */}
      <dialog 
        id="asset-detail-dialog" 
        onClose={handleCloseDialog}
        style={{
          width: '650px',
          maxWidth: '90%',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-normal)',
          borderRadius: '8px',
          boxShadow: '0 10px 40px rgba(0,0,0,0.6)',
          padding: 0
        }}
      >
        {selectedAsset && (() => {
          const enriched = enrichAssetCMDB(selectedAsset);
          return (
            <div style={{ color: '#ffffff' }}>
              <div className="dialog-header" style={{ borderBottom: '1px solid var(--border-normal)', padding: '1.25rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 className="dialog-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', margin: 0, fontSize: '1.2rem', fontWeight: 700 }}>
                  <AlertOctagon size={20} color={enriched.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)'} />
                  <span>Asset Profile: {enriched.name}</span>
                </h3>
                <button 
                  onClick={handleCloseDialog} 
                  style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
                >
                  <X size={18} />
                </button>
              </div>
              
              <div className="dialog-body" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '1.2rem', maxHeight: '70vh', overflowY: 'auto' }}>
                {/* CMDB Context Mapping card */}
                <div style={{ 
                  background: 'rgba(0,0,0,0.25)', 
                  border: '1px solid var(--border-normal)', 
                  borderRadius: '6px', 
                  padding: '1rem',
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '0.75rem',
                  fontSize: '0.85rem'
                }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Business Service Context</span>
                    <div style={{ fontWeight: 600, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <Layers size={13} />
                      {enriched.businessService}
                    </div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Target System Application</span>
                    <div style={{ fontWeight: 600, color: '#ffffff' }}>{enriched.application}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Network Endpoint URI</span>
                    <div style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{enriched.endpoint}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Assigned Business Owner</span>
                    <div style={{ fontWeight: 600, color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                      <User size={13} />
                      {enriched.owner}
                    </div>
                  </div>
                </div>

                {/* Tech Specs */}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem', padding: '0.75rem', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.05)' }}>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>CIPHER & DEP</span>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{enriched.algorithm}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>BIT LENGTH</span>
                    <div style={{ fontWeight: 600, fontSize: '0.9rem' }}>{enriched.keySize ? `${enriched.keySize}-bit` : 'N/A'}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>LIFECYCLE STATUS</span>
                    <div style={{ 
                      fontWeight: 700, 
                      fontSize: '0.9rem',
                      color: enriched.lifecycle === 'Remediated' ? 'var(--status-secure)' : 
                             enriched.lifecycle === 'Migrating' ? 'var(--status-warning)' : 'var(--text-muted)'
                    }}>
                      {enriched.lifecycle}
                    </div>
                  </div>
                </div>

                {/* Details */}
                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.25rem' }}>Asset Description</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0 }}>{enriched.description}</p>
                </div>

                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.25rem' }}>Quantum Attack Vector (Shor's/Grover's)</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>{enriched.explainer}</p>
                </div>

                {/* What Breaks on Migration */}
                <div style={{ padding: '0.75rem', background: enriched.isVulnerable ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.08)', borderRadius: '6px', border: enriched.isVulnerable ? '1px solid rgba(239, 68, 68, 0.2)' : '1px solid rgba(16, 185, 129, 0.2)' }}>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: enriched.isVulnerable ? 'var(--status-vulnerable)' : 'var(--status-secure)', marginBottom: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                    <Activity size={14} />
                    <span>Migration Fallout & Impact Summary</span>
                  </h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
                    {enriched.isVulnerable ? (
                      `Migrating this asset to ML-KEM/ML-DSA will break legacy client API consumers that do not support lattice-based key exchanges. Estimated engineering rotation effort: Medium (24-48 hours deployment timeline).`
                    ) : (
                      `No compatibility impacts. This asset is already running post-quantum signatures and operates in secure hybrid mode.`
                    )}
                  </p>
                </div>

                {/* Recommendation */}
                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.25rem' }}>Action Playbook</h4>
                  <p style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', margin: 0 }}>{enriched.recommendation}</p>
                </div>

                {enriched.complianceViolations.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--status-vulnerable)', marginBottom: '0.3rem' }}>Compliance Failures</h4>
                    <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                      {enriched.complianceViolations.map((v, i) => (
                        <span key={i} className="badge danger" style={{ fontSize: '0.65rem' }}>{v}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="dialog-actions" style={{ borderTop: '1px solid var(--border-normal)', padding: '1rem', display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
                <button className="btn-secondary" onClick={handleCloseDialog} style={{ padding: '0.5rem 1rem' }}>Close Diagnostics</button>
              </div>
            </div>
          );
        })()}
      </dialog>
    </>
  );
};
