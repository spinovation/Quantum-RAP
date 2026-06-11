import React, { useState, useEffect, useMemo } from 'react';
import { 
  Calculator, 
  ListTodo,
  Sparkles,
  Play,
  AlertTriangle,
  CheckCircle2,
  Ticket,
  FileJson,
  X,
  Layers,
  ArrowRight
} from 'lucide-react';
import { calculateMoscaRisk } from '../utils/moscaMath';
import type { MoscaResult } from '../utils/moscaMath';

interface Milestone {
  id: string;
  quarter: string;
  title: string;
  description: string;
  completed: boolean;
}

interface MigrationTarget {
  id: string;
  title: string;
  assetName: string;
  currentAlgo: string;
  targetAlgo: string;
  businessService: string;
  application: string;
  endpoint: string;
  owner: string;
  riskLevel: 'critical' | 'high' | 'medium';
  impactPercent: number;
  warnings: string[];
  remediationSteps: string[];
  jiraPayload: any;
  snowPayload: any;
}

const MIGRATION_TARGETS: MigrationTarget[] = [
  {
    id: 'target-1',
    title: 'Migrate Core TLS Ingress (production-ingress-wildcard)',
    assetName: 'production-ingress-wildcard',
    currentAlgo: 'RSA-2048',
    targetAlgo: 'ML-KEM-768 (Kyber)',
    businessService: 'Transactional Core Payment',
    application: 'PayShield API',
    endpoint: 'api.payments.enterprise.com',
    owner: 'sridhargs@spinovation.com',
    riskLevel: 'high',
    impactPercent: 18,
    warnings: [
      '18% of legacy Android/iOS SDK API clients will fail TLS handshake due to older OpenSSL versions (< 3.2) lacking ML-KEM support.',
      'Corporate proxies and firewalls that intercept TLS decrypt-and-inspect will block the hybrid handshake until updated with ML-KEM parsers.'
    ],
    remediationSteps: [
      'Deploy a dual-certificate server configuration (hybrid RSA-2048 alongside ML-KEM-768) to support legacy endpoints during the transition.',
      'Initiate client-side SDK rollouts pushing OpenSSL 3.3 compatible builds to mobile device fleets.',
      'Configure F5 VIP profile to enforce fallback options to classical suites if lattice key exchanges fail.'
    ],
    jiraPayload: {
      update: {},
      fields: {
        project: { key: 'PQC' },
        summary: 'PQC Migration: production-ingress-wildcard (RSA-2048 -> ML-KEM-768)',
        issuetype: { name: 'Epic' },
        description: 'Critical post-quantum migration required for production-ingress-wildcard.\n\nContext:\n- Business Service: Transactional Core Payment\n- Application: PayShield API\n- Owner: sridhargs@spinovation.com\n- Legacy Client Fallout: 18% affected.\n\nPlease follow the attached action playbook for dual-certificate configuration.',
        priority: { name: 'High' },
        labels: ['PQC-Migration', 'Crypto-Agility', 'Kyber-ML-KEM']
      }
    },
    snowPayload: {
      short_description: 'PQC Vulnerability: Upgrade production-ingress-wildcard to ML-KEM-768',
      description: 'Automated remediation alert from QuarkShield Crypto CMDB.\n\nCryptographic asset is vulnerable to Shor\'s algorithm.\nSystem: PayShield API\nCMDB Target: api.payments.enterprise.com\nUrgency: High',
      urgency: '2',
      impact: '2',
      priority: '2',
      assignment_group: 'Crypto Agility Operations Group',
      cmdb_ci: 'api.payments.enterprise.com',
      u_fallback_plan: 'Dual Certificate Deployment (RSA + ML-KEM)'
    }
  },
  {
    id: 'target-2',
    title: 'Decommission Obsolete Client Certs (legacy-api-client-cert)',
    assetName: 'legacy-api-client-cert',
    currentAlgo: 'RSA-1024',
    targetAlgo: 'ML-KEM-1024 / RSA-4096 Hybrid',
    businessService: 'External API Gateway',
    application: 'Legacy Partner Client',
    endpoint: 'legacy.partner.api.com',
    owner: 'partnerships@spinovation.com',
    riskLevel: 'critical',
    impactPercent: 45,
    warnings: [
      '45% of third-party partner applications utilize legacy integration libraries that do not support modern key exchange parameters.',
      'Classically insecure RSA-1024 poses immediate risk of factoring from state-level actors using classical clusters today.'
    ],
    remediationSteps: [
      'Issue deprecation warnings to all partner endpoints consuming legacy.partner.api.com.',
      'Mandate upgrade of partner SDKs to supported Java 17 / BouncyCastle PQC modules.',
      'Revoke RSA-1024 certificates on the API Gateway by the end of Q3.'
    ],
    jiraPayload: {
      update: {},
      fields: {
        project: { key: 'PQC' },
        summary: 'PQC Emergency: Revoke RSA-1024 Client Certificates',
        issuetype: { name: 'Epic' },
        description: 'CRITICAL threat: RSA-1024 is vulnerable classically and quantum-wise.\n\nContext:\n- Business Service: External API Gateway\n- Application: Legacy Partner Client\n- Owner: partnerships@spinovation.com\n- Legacy Client Fallout: 45% affected.',
        priority: { name: 'Highest' },
        labels: ['PQC-Emergency', 'Revocation', 'RSA-1024']
      }
    },
    snowPayload: {
      short_description: 'PQC Critical Incident: Decommission RSA-1024 client certificates',
      description: 'Automated remediation alert from QuarkShield Crypto CMDB.\n\nCryptographic asset is critically vulnerable.\nSystem: Legacy Partner Client\nCMDB Target: legacy.partner.api.com\nUrgency: Critical',
      urgency: '1',
      impact: '1',
      priority: '1',
      assignment_group: 'Security Incident Response',
      cmdb_ci: 'legacy.partner.api.com',
      u_fallback_plan: 'Deprecate endpoint and route traffic to v2 Gateway'
    }
  },
  {
    id: 'target-3',
    title: 'Migrate Database Backup Signing Key (database-backup-sign-key)',
    assetName: 'database-backup-sign-key',
    currentAlgo: 'RSA-4096',
    targetAlgo: 'ML-DSA-65 (Dilithium)',
    businessService: 'Transactional Core Payment',
    application: 'PayShield Database',
    endpoint: 'db-primary.payments.internal',
    owner: 'db-admin@spinovation.com',
    riskLevel: 'high',
    impactPercent: 0,
    warnings: [
      'No active clients are affected (offline backups only).',
      'Historical backup signatures will remain vulnerable to offline key forgery unless re-signed using ML-DSA.'
    ],
    remediationSteps: [
      'Update database backup signing engine configuration to utilize ML-DSA-65.',
      'Establish a background task to re-sign historical audit log bundles from 2024-2026.',
      'Configure key rotation policy in Vault for ML-DSA keys.'
    ],
    jiraPayload: {
      update: {},
      fields: {
        project: { key: 'PQC' },
        summary: 'PQC Migration: database-backup-sign-key to ML-DSA-65',
        issuetype: { name: 'Task' },
        description: 'Post-quantum signature migration required for backup signing engine.\n\nContext:\n- Business Service: Transactional Core Payment\n- Application: PayShield Database\n- Owner: db-admin@spinovation.com\n- Downstream fallout: 0% affected.',
        priority: { name: 'Medium' },
        labels: ['PQC-Migration', 'Database-Backups', 'ML-DSA']
      }
    },
    snowPayload: {
      short_description: 'PQC Task: Transition database backup signing to ML-DSA-65',
      description: 'Automated tracking ticket from QuarkShield CMDB.\n\nSystem: PayShield Database\nCMDB Target: db-primary.payments.internal\nUrgency: Medium',
      urgency: '3',
      impact: '3',
      priority: '3',
      assignment_group: 'DB Operations',
      cmdb_ci: 'db-primary.payments.internal',
      u_fallback_plan: 'None required (Offline backups)'
    }
  }
];

export const MigrationPlanner: React.FC = () => {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<'simulator' | 'mosca' | 'roadmap'>('simulator');

  // Simulator state
  const [selectedTargetId, setSelectedTargetId] = useState(MIGRATION_TARGETS[0].id);
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationLogs, setSimulationLogs] = useState<string[]>([]);
  const [simulationReport, setSimulationReport] = useState<MigrationTarget | null>(null);

  // Ticketing state
  const [ticketModal, setTicketModal] = useState<{
    open: boolean;
    type: 'jira' | 'servicenow';
    payload: any;
  }>({ open: false, type: 'jira', payload: null });

  // Mosca state
  const [shelfLife, setShelfLife] = useState(10); // S
  const [migrationTime, setMigrationTime] = useState(5); // Y
  const [collapseTime, setCollapseTime] = useState(12); // Z
  const [riskResult, setRiskResult] = useState<MoscaResult | null>(null);

  // Roadmap state
  const [milestones, setMilestones] = useState<Milestone[]>([
    {
      id: 'm1',
      quarter: 'Q1-Q2 2026',
      title: 'Cryptographic Discovery & Inventory',
      description: 'Catalog all public certificates, private keys, SSH configurations, and API ciphers across internal networks using QuarkShield scanners.',
      completed: true
    },
    {
      id: 'm2',
      quarter: 'Q3-Q4 2026',
      title: 'Data Classification & Mosca Assessment',
      description: 'Assess data storage shelf-life requirements and prioritize legacy databases containing sensitive PII for early post-quantum transition.',
      completed: false
    },
    {
      id: 'm3',
      quarter: 'Q1-Q4 2027',
      title: 'Hybrid Key Exchange Pilots',
      description: 'Enable hybrid TLS exchanges (ECDH + ML-KEM) in developer ingress endpoints. Pilot hybrid sntrup761 ssh credentials for admin channels.',
      completed: false
    },
    {
      id: 'm4',
      quarter: 'Q1-Q4 2028',
      title: 'Core Cryptographic Migration',
      description: 'Decommission legacy RSA-1024 and Triple DES ciphers. Re-key root certificate authorities using ML-DSA (Dilithium) standards.',
      completed: false
    },
    {
      id: 'm5',
      quarter: '2029-2030',
      title: 'Full Quantum-Resistant Posture',
      description: 'Enforce native PQC standard signatures on firmware updates, APIs, and microservices. Achieve 100% compliance across CNSA 2.0 timelines.',
      completed: false
    }
  ]);

  // Mosca calculation
  useEffect(() => {
    const result = calculateMoscaRisk(shelfLife, migrationTime, collapseTime);
    setRiskResult(result);
  }, [shelfLife, migrationTime, collapseTime]);

  const toggleMilestone = (id: string) => {
    setMilestones(prev => 
      prev.map(m => m.id === id ? { ...m, completed: !m.completed } : m)
    );
  };

  const selectedTarget = useMemo(() => {
    return MIGRATION_TARGETS.find(t => t.id === selectedTargetId) || MIGRATION_TARGETS[0];
  }, [selectedTargetId]);

  // Run Impact analysis simulation
  const runImpactAnalysis = () => {
    setIsSimulating(true);
    setSimulationReport(null);
    setSimulationLogs([]);

    const logs = [
      `[14:02:40] [SIMULATOR] Parsing dependency maps for service: ${selectedTarget.businessService}...`,
      `[14:02:41] [CLIENT-SCAN] Querying active connection records over past 30 days...`,
      `[14:02:41] [FALLOUT] Evaluating client TLS/SSH negotiation capability limits...`,
      `[14:02:42] [ANALYZING] Simulating ML-KEM parameter support on OpenSSL/BouncyCastle client targets...`,
      `[14:02:43] [COMPLETED] Impact report generated successfully.`
    ];

    let index = 0;
    const interval = setInterval(() => {
      if (index < logs.length) {
        setSimulationLogs(prev => [...prev, logs[index]]);
        index++;
      } else {
        clearInterval(interval);
        setIsSimulating(false);
        setSimulationReport(selectedTarget);
      }
    }, 500);
  };

  const triggerTicketGeneration = (type: 'jira' | 'servicenow') => {
    const payload = type === 'jira' ? selectedTarget.jiraPayload : selectedTarget.snowPayload;
    setTicketModal({
      open: true,
      type,
      payload
    });
  };

  return (
    <>
      <div style={{ marginBottom: '1.5rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem', background: 'linear-gradient(135deg, #00f3ff 0%, #a855f7 100%)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Migration & Impact Planner
          </h2>
          <p style={{ color: 'var(--text-secondary)' }}>
            Examine what breaks if you transition endpoints to post-quantum standards, configure timelines, and automate tickets.
          </p>
        </div>

        {/* Tabs navigation */}
        <div style={{ display: 'flex', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', borderRadius: '8px', padding: '0.25rem' }}>
          <button 
            onClick={() => setActiveTab('simulator')} 
            className={`btn-secondary ${activeTab === 'simulator' ? 'active' : ''}`}
            style={{ padding: '0.45rem 1rem', fontSize: '0.85rem', border: 'none', background: activeTab === 'simulator' ? 'var(--bg-card)' : 'transparent' }}
          >
            "What Breaks?" Simulator
          </button>
          <button 
            onClick={() => setActiveTab('mosca')} 
            className={`btn-secondary ${activeTab === 'mosca' ? 'active' : ''}`}
            style={{ padding: '0.45rem 1rem', fontSize: '0.85rem', border: 'none', background: activeTab === 'mosca' ? 'var(--bg-card)' : 'transparent' }}
          >
            Mosca Assessment
          </button>
          <button 
            onClick={() => setActiveTab('roadmap')} 
            className={`btn-secondary ${activeTab === 'roadmap' ? 'active' : ''}`}
            style={{ padding: '0.45rem 1rem', fontSize: '0.85rem', border: 'none', background: activeTab === 'roadmap' ? 'var(--bg-card)' : 'transparent' }}
          >
            PQC Transition Roadmap
          </button>
        </div>
      </div>

      {activeTab === 'simulator' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Main Simulator Panel */}
          <div className="glass-panel" style={{ padding: '1.25rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem', color: '#ffffff' }}>
              <Layers size={18} color="var(--accent-cyan)" />
              <span>Cryptographic Migration Impact Simulator</span>
            </h3>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr min-content', gap: '1rem', alignItems: 'flex-end', marginBottom: '1rem' }}>
              <div style={{ flexGrow: 1 }}>
                <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
                  Target Cryptographic Migration Profile
                </label>
                <select 
                  value={selectedTargetId} 
                  onChange={(e) => {
                    setSelectedTargetId(e.target.value);
                    setSimulationReport(null);
                    setSimulationLogs([]);
                  }}
                  className="chat-text-input" 
                  style={{ padding: '0.6rem', fontSize: '0.9rem', width: '100%', background: 'rgba(0,0,0,0.3)', color: '#ffffff' }}
                >
                  {MIGRATION_TARGETS.map(t => (
                    <option key={t.id} value={t.id}>{t.title}</option>
                  ))}
                </select>
              </div>

              <button 
                onClick={runImpactAnalysis}
                disabled={isSimulating}
                className="btn-primary" 
                style={{ height: '38px', padding: '0 1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', whiteSpace: 'nowrap' }}
              >
                <Play size={14} />
                <span>{isSimulating ? 'Analyzing Fallout...' : 'Run Impact Analysis'}</span>
              </button>
            </div>

            {/* Sim Logs */}
            {simulationLogs.length > 0 && (
              <div style={{ 
                background: '#090a0f', 
                border: '1px solid var(--border-normal)', 
                borderRadius: '6px', 
                padding: '0.6rem 0.8rem', 
                fontFamily: 'monospace', 
                fontSize: '0.75rem', 
                color: '#00f3ff', 
                maxHeight: '120px',
                overflowY: 'auto',
                marginBottom: '1rem'
              }}>
                {simulationLogs.map((log, i) => (
                  <div key={i}>{log}</div>
                ))}
              </div>
            )}
          </div>

          {/* Simulation Report */}
          {simulationReport && (
            <div style={{ 
              display: 'grid', 
              gridTemplateColumns: '2fr 1fr', 
              gap: '1.5rem', 
              alignItems: 'stretch'
            }}>
              {/* Left Column: Warnings and Remediation */}
              <div className="glass-panel" style={{ padding: '1.25rem', background: 'var(--bg-card)', border: '1px solid var(--border-normal)' }}>
                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--status-vulnerable)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <AlertTriangle size={16} />
                  <span>Client Compatibility & Migration Fallout ({simulationReport.impactPercent}% Affected)</span>
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
                  {simulationReport.warnings.map((warn, i) => (
                    <div 
                      key={i} 
                      style={{ 
                        background: 'rgba(239, 68, 68, 0.06)', 
                        border: '1px solid rgba(239, 68, 68, 0.15)', 
                        borderRadius: '6px', 
                        padding: '0.75rem 1rem', 
                        fontSize: '0.88rem', 
                        color: 'var(--text-primary)',
                        lineHeight: '1.4'
                      }}
                    >
                      {warn}
                    </div>
                  ))}
                </div>

                <h4 style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--status-secure)', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <CheckCircle2 size={16} />
                  <span>Remediation Roadmap & Action Steps</span>
                </h4>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                  {simulationReport.remediationSteps.map((step, i) => (
                    <div 
                      key={i} 
                      style={{ 
                        display: 'flex', 
                        alignItems: 'flex-start', 
                        gap: '0.5rem', 
                        fontSize: '0.88rem', 
                        color: 'var(--text-secondary)',
                        lineHeight: '1.4'
                      }}
                    >
                      <ArrowRight size={14} color="var(--accent-cyan)" style={{ marginTop: '0.2rem', flexShrink: 0 }} />
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Downstream Specs & Ticketing */}
              <div className="glass-panel" style={{ 
                padding: '1.25rem', 
                background: 'var(--bg-card)', 
                border: '1px solid var(--border-normal)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between'
              }}>
                <div>
                  <h4 style={{ fontSize: '0.95rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.75rem', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.4rem' }}>
                    Impact Specifications
                  </h4>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem', fontSize: '0.82rem', marginBottom: '1.5rem' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Business Service Context:</span>
                      <div style={{ fontWeight: 600, color: '#ffffff' }}>{simulationReport.businessService}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Target Application:</span>
                      <div style={{ fontWeight: 600, color: '#ffffff' }}>{simulationReport.application}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Network Endpoint:</span>
                      <div style={{ fontWeight: 600, color: 'var(--accent-cyan)', fontFamily: 'monospace' }}>{simulationReport.endpoint}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Assigned Owner:</span>
                      <div style={{ fontWeight: 600, color: 'var(--text-secondary)' }}>{simulationReport.owner}</div>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Migration Profile:</span>
                      <div style={{ fontWeight: 600, color: 'var(--status-warning)' }}>
                        {simulationReport.currentAlgo} ➔ {simulationReport.targetAlgo}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Ticketing integrations */}
                <div>
                  <h4 style={{ fontSize: '0.9rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.5rem' }}>
                    Ticketing Workflow integrations
                  </h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                    <button 
                      onClick={() => triggerTicketGeneration('jira')}
                      className="btn-secondary" 
                      style={{ width: '100%', padding: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem', fontSize: '0.85rem' }}
                    >
                      <Ticket size={14} color="var(--accent-purple)" />
                      <span>Export JIRA Epic Payload</span>
                    </button>
                    <button 
                      onClick={() => triggerTicketGeneration('servicenow')}
                      className="btn-secondary" 
                      style={{ width: '100%', padding: '0.5rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.4rem', fontSize: '0.85rem' }}
                    >
                      <FileJson size={14} color="var(--accent-cyan)" />
                      <span>Export ServiceNow Incident</span>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'mosca' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '1.15rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Calculator size={18} color="var(--accent-cyan)" /> Mosca's Theorem Risk Assessment
          </h3>
          
          <div className="mosca-calculator">
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <label>Data Shelf-Life ($S$): {shelfLife} years</label>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Security lifespan of stored data</span>
                </div>
                <input 
                  type="range" 
                  min="1" 
                  max="30" 
                  value={shelfLife} 
                  onChange={(e) => setShelfLife(Number(e.target.value))}
                  style={{ accentColor: 'var(--accent-cyan)' }}
                />
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <label>Migration Time ($Y$): {migrationTime} years</label>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Years needed to transition infrastructure</span>
                </div>
                <input 
                  type="range" 
                  min="1" 
                  max="15" 
                  value={migrationTime} 
                  onChange={(e) => setMigrationTime(Number(e.target.value))}
                  style={{ accentColor: 'var(--accent-purple)' }}
                />
              </div>

              <div className="form-group">
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <label>Collapse Time ($Z$): {collapseTime} years</label>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Projected time until a CRQC is developed</span>
                </div>
                <input 
                  type="range" 
                  min="5" 
                  max="40" 
                  value={collapseTime} 
                  onChange={(e) => setCollapseTime(Number(e.target.value))}
                  style={{ accentColor: 'var(--status-vulnerable)' }}
                />
              </div>
            </div>

            {/* Mosca Calculator Output */}
            {riskResult && (
              <div className="mosca-results">
                <div style={{ textAlign: 'center' }}>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Risk Urgency Profile
                  </span>
                  <div className={`mosca-score-glowing ${riskResult.isThreatened ? 'risk' : 'safe'}`}>
                    {riskResult.priorityScore}
                    <span style={{ fontSize: '1.2rem', fontWeight: 500 }}>/100</span>
                  </div>
                  <div style={{ marginTop: '0.5rem' }}>
                    <span className={`badge ${
                      riskResult.riskLevel === 'critical' || riskResult.riskLevel === 'high' ? 'danger' : 
                      riskResult.riskLevel === 'medium' ? 'warning' : 'success'
                    }`}>
                      {riskResult.riskLevel.toUpperCase()} THREAT STATUS
                    </span>
                  </div>
                </div>

                <div style={{ width: '100%', borderTop: '1px solid var(--border-normal)', paddingTop: '1rem', fontSize: '0.9rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Inequality ($S + Y &gt; Z$):</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: riskResult.isThreatened ? 'var(--status-vulnerable)' : 'var(--status-secure)' }}>
                      {shelfLife} + {migrationTime} {riskResult.isThreatened ? '>' : '≤'} {collapseTime}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>Security Margin:</span>
                    <span style={{ 
                      fontWeight: 600, 
                      color: riskResult.isThreatened ? 'var(--status-vulnerable)' : 'var(--status-secure)' 
                    }}>
                      {riskResult.margin > 0 ? `+${riskResult.margin} Years Buffer` : `${riskResult.margin} Years Deficit`}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {riskResult && (
            <div style={{ 
              marginTop: '1.5rem', 
              padding: '1rem', 
              borderRadius: '8px', 
              background: 'rgba(0,0,0,0.15)',
              borderLeft: `3px solid ${
                riskResult.riskLevel === 'critical' ? 'var(--status-vulnerable)' : 
                riskResult.riskLevel === 'high' ? 'var(--status-vulnerable)' : 
                riskResult.riskLevel === 'medium' ? 'var(--status-warning)' : 'var(--status-secure)'
              }`,
              fontSize: '0.92rem'
            }}>
              <div style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
                Mosca Formula Assessment:
              </div>
              <p style={{ marginBottom: '0.5rem' }}>{riskResult.assessmentSummary}</p>
              <div style={{ color: 'var(--accent-cyan)' }}>
                <span style={{ fontWeight: 600 }}>Action Required:</span> {riskResult.recommendation}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'roadmap' && (
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
            <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <ListTodo size={18} color="var(--accent-cyan)" /> PQC Transition Roadmap
            </h3>
            <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
              <Sparkles size={12} color="var(--status-secure)" /> Check boxes to mark operational task completion.
            </span>
          </div>

          <div className="roadmap-timeline">
            {milestones.map((milestone) => (
              <div 
                key={milestone.id} 
                className={`timeline-node ${milestone.completed ? 'completed' : 'future'}`}
              >
                <div className="glass-panel" style={{ 
                  padding: '1rem 1.25rem', 
                  borderLeft: milestone.completed ? '2px solid var(--status-secure)' : '1px solid var(--border-normal)',
                  marginLeft: '0.5rem'
                }}>
                  <div className="timeline-header">
                    <span className="timeline-quarter" style={{ color: milestone.completed ? 'var(--status-secure)' : 'var(--accent-cyan)' }}>
                      {milestone.quarter}
                    </span>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                      <input 
                        type="checkbox" 
                        checked={milestone.completed} 
                        onChange={() => toggleMilestone(milestone.id)}
                        style={{ 
                          width: '16px', 
                          height: '16px', 
                          accentColor: 'var(--status-secure)',
                          cursor: 'pointer'
                        }}
                      />
                      <span style={{ fontSize: '0.8rem', color: milestone.completed ? 'var(--status-secure)' : 'var(--text-secondary)' }}>
                        {milestone.completed ? 'Completed' : 'Pending'}
                      </span>
                    </label>
                  </div>
                  <h4 className="timeline-title" style={{ 
                    color: milestone.completed ? 'var(--text-primary)' : 'var(--text-secondary)',
                    marginTop: '0.25rem'
                  }}>
                    {milestone.title}
                  </h4>
                  <p className="timeline-desc" style={{ marginTop: '0.25rem' }}>
                    {milestone.description}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Ticket Payload Modal */}
      {ticketModal.open && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(0,0,0,0.6)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          zIndex: 1000
        }}>
          <div className="glass-panel" style={{
            width: '520px',
            maxWidth: '90%',
            background: 'var(--bg-card)',
            border: '1px solid var(--border-normal)',
            borderRadius: '8px',
            padding: '1.25rem',
            color: '#ffffff'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.5rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.4rem', margin: 0 }}>
                <Ticket size={16} color="var(--accent-cyan)" />
                <span>Exported {ticketModal.type === 'jira' ? 'JIRA Epic' : 'ServiceNow Incident'} Payload</span>
              </h3>
              <button 
                onClick={() => setTicketModal({ open: false, type: 'jira', payload: null })}
                style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>

            <div style={{ marginBottom: '1rem' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--status-secure)', display: 'block', marginBottom: '0.5rem', fontWeight: 600 }}>
                ✓ Connector payload compiled successfully. Ready for REST API push.
              </span>
              <div style={{ 
                background: '#090a0f', 
                border: '1px solid var(--border-normal)', 
                borderRadius: '6px', 
                padding: '0.75rem', 
                maxHeight: '220px', 
                overflowY: 'auto'
              }}>
                <pre style={{ 
                  margin: 0, 
                  fontFamily: 'monospace', 
                  fontSize: '0.75rem', 
                  color: '#39ff14', 
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all'
                }}>
                  {JSON.stringify(ticketModal.payload, null, 2)}
                </pre>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.5rem' }}>
              <button 
                className="btn-secondary" 
                onClick={() => setTicketModal({ open: false, type: 'jira', payload: null })}
                style={{ padding: '0.45rem 1rem', fontSize: '0.85rem' }}
              >
                Close View
              </button>
              <button 
                className="btn-primary" 
                onClick={() => {
                  alert(`${ticketModal.type === 'jira' ? 'JIRA Epic' : 'ServiceNow Incident'} successfully published to integration webhook!`);
                  setTicketModal({ open: false, type: 'jira', payload: null });
                }}
                style={{ padding: '0.45rem 1rem', fontSize: '0.85rem' }}
              >
                Publish Ticket
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
