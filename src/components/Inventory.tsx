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
  Activity,
  FileSpreadsheet,
  Download
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

const getMockLogsForSource = (source: string, date: string): string[] => {
  const timestamp = date === '2026-06-11' ? '14:02' : date === '2026-06-10' ? '10:15' : '11:40';
  
  const commonPrefix = [
    `[${timestamp}:10] [CMDB-INIT] Initializing cryptographic sync for source '${source.toUpperCase()}'...`,
    `[${timestamp}:12] [AUTH] Authenticating credentials against enterprise credential vault...`,
  ];

  const gdprLog = `[${timestamp}:14] [GDPR-CHECK] GDPR compliance filter activated: Raw payloads, logs and user inputs are discarded.`;
  
  let specificLogs: string[] = [];
  
  switch (source) {
    case 'aws':
      specificLogs = [
        `[${timestamp}:15] [AWS-SCAN] Syncing ACM certificates, ELB targets, API Gateways, IAM SSH keys & Secrets Manager ciphers...`,
        `[${timestamp}:18] [METADATA-FIRST] Extracting cryptographic parameters (TLS profiles, key size, algorithms, owners)...`,
        `[${timestamp}:20] [AWS-MATCH] Correlating EC2 load balancers with active AWS ACM private keys...`,
        `[${timestamp}:22] [PARSE] Discovered 1 cryptographic asset mapped to transactional pay services.`,
      ];
      break;
    case 'azure':
      specificLogs = [
        `[${timestamp}:15] [AZURE-SYNC] Querying Key Vault secrets, ARM template parameters and Azure Graph API active users...`,
        `[${timestamp}:18] [METADATA-FIRST] Extracting active certificate keys and SSH credentials...`,
        `[${timestamp}:20] [AZURE-MATCH] Mapping Azure Active Directory identities to Key Vault secrets...`,
        `[${timestamp}:22] [PARSE] Extracted application context 'bastion-gateway' and tenant metadata.`,
      ];
      break;
    case 'gcp':
      specificLogs = [
        `[${timestamp}:15] [GCP-SYNC] Fetching GCP Certificate Manager descriptors and HTTPS Load Balancer targets...`,
        `[${timestamp}:18] [METADATA-FIRST] Reading SSL profiles and frontend target configuration...`,
        `[${timestamp}:20] [GCP-MATCH] Cross-referencing GCP target pools with active SSL bindings...`,
        `[${timestamp}:22] [PARSE] Found 1 target endpoint using RSA-2048 SSL certificate.`,
      ];
      break;
    case 'k8s':
      specificLogs = [
        `[${timestamp}:15] [K8S-SCAN] Querying K8s TLS Secrets, Ingress controller routes (Nginx/Traefik) and Istio Service Mesh configs...`,
        `[${timestamp}:18] [METADATA-FIRST] Ingesting TLS Secrets namespace metadata (Owner, Application name)...`,
        `[${timestamp}:20] [K8S-MATCH] Mapping service-to-service mutual TLS (mTLS) cipher restrictions...`,
        `[${timestamp}:22] [PARSE] Parsed Traefik ingress configuration mapping endpoints to service namespaces.`,
      ];
      break;
    case 'f5':
      specificLogs = [
        `[${timestamp}:15] [F5-INGEST] Loading ClientSSL/ServerSSL profiles, virtual server VIP definitions and Big-IP certificates...`,
        `[${timestamp}:18] [METADATA-FIRST] Collecting local SSL profile parameters...`,
        `[${timestamp}:20] [F5-MAP] Pinpointing legacy virtual IP (VIP) profiles enforcing RSA key exchanges...`,
        `[${timestamp}:22] [PARSE] Located obsolete virtual server profile utilizing weak SHA-1 hash algorithm.`,
      ];
      break;
    case 'paloalto':
      specificLogs = [
        `[${timestamp}:15] [PAN-CRAWL] Extracting GlobalProtect VPN gateway profiles, IPSec tunnels and active client certificates...`,
        `[${timestamp}:18] [METADATA-FIRST] Ingesting VPN security profile configuration parameters...`,
        `[${timestamp}:20] [PAN-MATCH] Identifying legacy IKE phase 1/2 proposals using weak Diffie-Hellman groups...`,
        `[${timestamp}:22] [PARSE] Found active VPN profile utilizing vulnerable RSA-2048 key exchange.`,
      ];
      break;
    case 'cisco':
      specificLogs = [
        `[${timestamp}:15] [CISCO-CRAWL] Fetching AnyConnect VPN profiles, ASA cryptomaps and ISAKMP parameters...`,
        `[${timestamp}:18] [METADATA-FIRST] Extracting TLS and cipher configurations from ASA routers...`,
        `[${timestamp}:20] [CISCO-MATCH] Auditing Cisco client profile SSL cipher suites for Grover threat compliance...`,
        `[${timestamp}:22] [PARSE] Core security gateway mapped to business service 'Enterprise Infrastructure'.`,
      ];
      break;
    case 'splunk':
      specificLogs = [
        `[${timestamp}:15] [SPLUNK-INGEST] Connecting to Splunk Search API as user 'secops_auditor'...`,
        `[${timestamp}:17] [SPLUNK-QUERY] Executing search: 'index="ia" sourcetype="syslog:tls" | table dest_ip, ssl_cipher, ssl_version'...`,
        `[${timestamp}:19] [METADATA-FIRST] Extracting cryptographic endpoints and TLS ciphers from raw Splunk index...`,
        `[${timestamp}:22] [PARSE] Correlation complete. Found 1 vulnerable cipher event in splunk TLS audits.`,
      ];
      break;
    case 'defender':
      specificLogs = [
        `[${timestamp}:15] [DEFENDER-SCAN] Extracting network connection logs and handshake telemetry from endpoints...`,
        `[${timestamp}:18] [METADATA-FIRST] Scanning client endpoint registry for active TLS certificates...`,
        `[${timestamp}:20] [POLICY] Identifying TLS versions and cipher suites in active use by endpoints...`,
        `[${timestamp}:22] [PARSE] Located 5 hosts running outdated local root certificates.`,
      ];
      break;
    case 'crowdstrike':
      specificLogs = [
        `[${timestamp}:15] [FALCON-INTEL] Querying Falcon network traffic metadata for legacy SSL handshakes...`,
        `[${timestamp}:18] [METADATA-FIRST] Pulling cryptographic cipher usage records across remote workspace hosts...`,
        `[${timestamp}:20] [ZERO-TRUST] Mapping encryption tunnels to active domain controllers...`,
        `[${timestamp}:22] [PARSE] Synced 2 endpoints using TLS 1.0 connections from legacy systems.`,
      ];
      break;
    case 'qualys':
      specificLogs = [
        `[${timestamp}:15] [QUALYS-INGEST] Fetching active host vulnerabilities and SSL/TLS scan results...`,
        `[${timestamp}:18] [METADATA-FIRST] Importing Qualys VMDR asset lists and vulnerability indices...`,
        `[${timestamp}:20] [VULN-MATCH] Running configuration parsing on host SSL endpoints...`,
        `[${timestamp}:22] [PARSE] Ingested 1 network asset with critical SSL vulnerability reports.`,
      ];
      break;
    case 'tenable':
      specificLogs = [
        `[${timestamp}:15] [TENABLE-INGEST] Ingesting Nessus SSL scan profiles and active network asset inventories...`,
        `[${timestamp}:18] [METADATA-FIRST] Resolving key strength metrics and encryption algorithms...`,
        `[${timestamp}:20] [VULN-MATCH] Running vulnerability mapping for outdated public keys...`,
        `[${timestamp}:22] [PARSE] 1 active SSH credential identified as using quantum-vulnerable algorithms.`,
      ];
      break;
    case 'workday':
      specificLogs = [
        `[${timestamp}:15] [WORKDAY-SYNC] Fetching organizational hierarchy and manager profiles...`,
        `[${timestamp}:18] [METADATA-FIRST] Retrieving email handles and team alignment lists...`,
        `[${timestamp}:20] [IDENTITY-MAP] Linking cryptosystem owners to Workday cost-centers and Slack handles...`,
        `[${timestamp}:22] [PARSE] Owner attributes matched for active inventory items.`,
      ];
      break;
    case 'sharepoint':
      specificLogs = [
        `[${timestamp}:15] [SP-CRAWL] Parsing SharePoint document libraries for SSL/TLS configuration spreadsheets...`,
        `[${timestamp}:18] [METADATA-FIRST] Ingesting spreadsheet tables mapping assets to business owners...`,
        `[${timestamp}:20] [DOC-CORRELATE] Mapping SharePoint asset registers to discovered endpoints...`,
        `[${timestamp}:22] [PARSE] Synced legacy certificate profiles from spreadsheet records.`,
      ];
      break;
    case 'servicenow':
      specificLogs = [
        `[${timestamp}:15] [SN-SYNC] Querying Configuration Items (CIs) from ServiceNow Service Catalog...`,
        `[${timestamp}:18] [METADATA-FIRST] Mapping CI business services, applications, and support groups...`,
        `[${timestamp}:20] [SN-MAPPING] Synchronizing business owners, application names, and support group tables...`,
        `[${timestamp}:22] [PARSE] ServiceNow asset configuration sync complete.`,
      ];
      break;
    default:
      specificLogs = [
        `[${timestamp}:15] [GENERIC-SYNC] Syncing data with source ${source}...`,
        `[${timestamp}:18] [METADATA-FIRST] Ingesting metadata descriptors...`,
        `[${timestamp}:22] [SUCCESS] Sync session finished successfully.`,
      ];
  }

  const successLogs = [
    `[${timestamp}:24] [SYNC] Registering assets into postgres database...`,
    `[${timestamp}:25] [SUCCESS] Synchronized log stream for ${source.toUpperCase()} completed successfully.`
  ];

  return [...commonPrefix, gdprLog, ...specificLogs, ...successLogs];
};

const getDiscoveryAssetsForSource = (source: string): AuditResult[] => {
  const timestamp = Date.now().toString(36);
  
  switch (source) {
    case 'aws':
      return [
        {
          id: `aws-acm-${timestamp}-1`,
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
        }
      ];
    case 'azure':
      return [
        {
          id: `azure-kv-${timestamp}-1`,
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
        }
      ];
    case 'gcp':
      return [
        {
          id: `gcp-cert-${timestamp}-1`,
          type: 'certificate',
          name: 'gcp-load-balancer-ssl-cert',
          algorithm: 'ECDSA',
          keySize: 256,
          isVulnerable: true,
          riskLevel: 'high',
          status: 'Quantum Vulnerable',
          description: 'GCP external HTTPS load balancer SSL certificate binding. |CMDB:{"businessService":"External API Gateway","application":"Customer Portal","endpoint":"portal.enterprise.com","owner":"gcp-team@spinovation.com","lifecycle":"Active"}',
          recommendation: 'Enable Google Cloud Certificate Manager hybrid post-quantum TLS options.',
          explainer: 'ECDSA elliptic curves are completely broken by quantum Shor\'s algorithm.',
          complianceViolations: ['CNSA 2.0']
        }
      ];
    case 'k8s':
      return [
        {
          id: `k8s-secret-${timestamp}-1`,
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
    case 'f5':
      return [
        {
          id: `f5-vip-${timestamp}-1`,
          type: 'certificate',
          name: 'f5-bigip-external-vip-cert',
          algorithm: 'RSA',
          keySize: 2048,
          isVulnerable: true,
          riskLevel: 'high',
          status: 'Quantum Vulnerable',
          description: 'ClientSSL profile certificate loaded on external F5 BIG-IP LTM. |CMDB:{"businessService":"Transactional Core Payment","application":"External Checkout Gateway","endpoint":"checkout.payments.com","owner":"netops-f5@spinovation.com","lifecycle":"Active"}',
          recommendation: 'Configure F5 SSL profile to support quantum-safe hybrid key exchange suites.',
          explainer: 'F5 client-side SSL handshakes using RSA-2048 are vulnerable to retrospective decryption (SNDL).',
          complianceViolations: ['CNSA 2.0', 'EO 14028']
        }
      ];
    case 'paloalto':
      return [
        {
          id: `pan-vpn-${timestamp}-1`,
          type: 'certificate',
          name: 'palo-alto-globalprotect-vpn-cert',
          algorithm: 'ECDSA',
          keySize: 384,
          isVulnerable: true,
          riskLevel: 'high',
          status: 'Quantum Vulnerable',
          description: 'SSL Client VPN authentication profile certificate on Palo Alto gateway. |CMDB:{"businessService":"Corporate Identity Services","application":"GlobalProtect VPN","endpoint":"vpn.corp.enterprise.com","owner":"secops@spinovation.com","lifecycle":"Active"}',
          recommendation: 'Upgrade tunnel profiles to support Post-Quantum Hybrid IPSec VPN exchange.',
          explainer: 'ECDSA keys used to sign VPN certificates can be broken by Shor\'s algorithm, compromising tunnel credentials.',
          complianceViolations: ['CNSA 2.0']
        }
      ];
    case 'cisco':
      return [
        {
          id: `cisco-vpn-${timestamp}-1`,
          type: 'certificate',
          name: 'cisco-asa-anyconnect-ssl-cert',
          algorithm: 'RSA',
          keySize: 2048,
          isVulnerable: true,
          riskLevel: 'high',
          status: 'Quantum Vulnerable',
          description: 'Secure remote access certificate deployed on Cisco ASA cluster. |CMDB:{"businessService":"Corporate Identity Services","application":"AnyConnect VPN Gateway","endpoint":"vpn-secondary.corp.com","owner":"netops-cisco@spinovation.com","lifecycle":"Active"}',
          recommendation: 'Transition to hybrid TLS or upgrade client profile configurations to support quantum-safe ciphers.',
          explainer: 'RSA key exchanges are vulnerable to decryption by a quantum computer running Shor\'s algorithm.',
          complianceViolations: ['CNSA 2.0']
        }
      ];
    case 'splunk':
      return [
        {
          id: `splunk-discovered-${timestamp}-1`,
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
        }
      ];
    case 'servicenow':
      return [
        {
          id: `servicenow-tracked-${timestamp}-1`,
          type: 'config',
          name: 'legacy-api-client-cert',
          algorithm: 'RSA',
          keySize: 1024,
          isVulnerable: true,
          riskLevel: 'critical',
          status: 'Quantum Vulnerable',
          description: 'ServiceNow Catalog Tracked Configuration Item: microservice communication certificate. |CMDB:{"businessService":"External API Gateway","application":"Legacy Partner Client","endpoint":"legacy.partner.api.com","owner":"partnerships@spinovation.com","lifecycle":"Active"}',
          recommendation: 'Revoke and replace immediately. RSA-1024 is vulnerable classically and critically vulnerable quantum-wise.',
          explainer: 'RSA-1024 is at active risk of classical factorization and requires a fraction of the quantum capacity to break compared to RSA-2048.',
          complianceViolations: ['NIST SP 800-131A', 'CNSA 2.0', 'EO 14028']
        }
      ];
    default:
      return [
        {
          id: `gen-discover-${timestamp}-1`,
          type: 'certificate',
          name: `${source}-discovered-endpoint-key`,
          algorithm: 'RSA',
          keySize: 2048,
          isVulnerable: true,
          riskLevel: 'high',
          status: 'Quantum Vulnerable',
          description: `Asset discovered via active ${source} crawler integrations. |CMDB:{"businessService":"Enterprise Infrastructure","application":"Core Routing","endpoint":"${source}-sync.internal","owner":"secops@spinovation.com","lifecycle":"Active"}`,
          recommendation: 'Rotate to post-quantum hybrid algorithm.',
          explainer: 'RSA key exchanges can be solved in polynomial time by Shor\'s algorithm.',
          complianceViolations: ['CNSA 2.0']
        }
      ];
  }
};

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

  // Discovery panel state
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [liveDiscoveryLogs, setLiveDiscoveryLogs] = useState<string[]>([]);
  const [selectedSource, setSelectedSource] = useState('aws');
  const [discoveredAssets, setDiscoveredAssets] = useState<AuditResult[]>([]);
  const liveTerminalRef = useRef<HTMLDivElement>(null);

  // History selectors state
  const [selectedAuditDate, setSelectedAuditDate] = useState('2026-06-11');
  const [logCategory, setLogCategory] = useState<'api' | 'integration'>('api');
  const [selectedAuditApiTopic, setSelectedAuditApiTopic] = useState<string>('all');
  const [selectedAuditIntegrationSource, setSelectedAuditIntegrationSource] = useState<string>('all');

  // Historical raw logs database (mapped by Date ➔ Source)
  const [syncLogsRegistry, setSyncLogsRegistry] = useState<Record<string, Record<string, string[]>>>({
    '2026-06-11': {
      aws: [
        `[14:02:15] [CMDB-INIT] Initializing metadata discovery: AWS ACM, ELB, API Gateway, IAM, Secrets Manager...`,
        `[14:02:16] [AUTH] Authenticating session tokens with OAuth2 credential stores...`,
        `[14:02:17] [AWS-SCAN] Syncing ACM certificates, ELB targets, API Gateways, IAM SSH keys & Secrets Manager ciphers...`,
        `[14:02:17] [GDPR-CHECK] GDPR compliance filter activated: Raw payloads, logs and user inputs are discarded.`,
        `[14:02:18] [METADATA-FIRST] Extracting cryptographic parameters (TLS profiles, key rings, algorithms, owners)...`,
        `[14:02:19] [AWS-MATCH] Correlating EC2 load balancers with active AWS ACM private keys...`,
        `[14:02:20] [PARSE] Discovered 1 cryptographic asset mapped to transactional pay services.`,
        `[14:02:20] [SYNC] Registering assets into postgres database...`,
        `[14:02:21] [SUCCESS] Metadata sync finished. 1 new asset imported into Crypto CMDB.`
      ],
      splunk: [
        `[13:10:02] [CMDB-INIT] Initializing integration sync: Splunk SIEM API Logs Analyzer...`,
        `[13:10:03] [AUTH] Authenticating as Splunk user 'secops_auditor'...`,
        `[13:10:04] [SPLUNK-INGEST] Connecting to Splunk Search API endpoint...`,
        `[13:10:04] [SPLUNK-QUERY] Executing search: 'index="ia" sourcetype="syslog:tls" | table dest_ip, ssl_cipher, ssl_version'...`,
        `[13:10:05] [GDPR-CHECK] GDPR compliance filter activated: Raw user payloads discarded.`,
        `[13:10:06] [METADATA-FIRST] Extracted 1 vulnerable cipher endpoint from syslog logs.`,
        `[13:10:07] [SUCCESS] Ingested 1 asset from Splunk 'ia' index log audit.`
      ]
    },
    '2026-06-10': {
      servicenow: [
        `[09:15:30] [CMDB-INIT] Initializing integration sync: ServiceNow CMDB Service Catalog...`,
        `[09:15:31] [AUTH] Authenticating ServiceNow API token...`,
        `[09:15:32] [SN-SYNC] Querying Configuration Items (CIs) from ServiceNow Service Catalog...`,
        `[09:15:32] [GDPR-CHECK] GDPR compliance filter activated: No personal data ingested.`,
        `[09:15:33] [METADATA-FIRST] Extracting operational owners and system descriptions...`,
        `[09:15:34] [SN-MAPPING] Synchronizing business owners, application names, and support group tables...`,
        `[09:15:35] [SUCCESS] ServiceNow asset configuration sync complete.`
      ]
    }
  });

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

  // Filtered Assets for Table
  const filteredAssets = useMemo(() => {
    return enrichedAssets.filter(asset => {
      // 1. Search filter
      const matchesSearch = 
        asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.algorithm.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.businessService.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.application.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.endpoint.toLowerCase().includes(searchTerm.toLowerCase()) ||
        asset.owner.toLowerCase().includes(searchTerm.toLowerCase());
        
      // 2. Type filter
      const matchesType = typeFilter === 'all' || asset.type === typeFilter;
      
      // 3. Posture Status filter
      let matchesStatus = true;
      if (statusFilter === 'vulnerable') {
        matchesStatus = asset.isVulnerable;
      } else if (statusFilter === 'secure') {
        matchesStatus = !asset.isVulnerable;
      }

      // 4. Business Service filter
      const matchesService = serviceFilter === 'all' || asset.businessService === serviceFilter;
      
      // 5. Lifecycle filter
      const matchesLifecycle = lifecycleFilter === 'all' || asset.lifecycle === lifecycleFilter;

      // 6. Historical Source Filter
      let matchesAuditSource = true;
      const activeSource = logCategory === 'api' ? selectedAuditApiTopic : selectedAuditIntegrationSource;
      
      if (activeSource !== 'all') {
        const sourceNormalized = activeSource.toLowerCase();
        if (sourceNormalized === 'aws') {
          matchesAuditSource = asset.id.includes('aws') || asset.name.includes('aws') || asset.id === 'inv-1';
        } else if (sourceNormalized === 'azure') {
          matchesAuditSource = asset.id.includes('azure') || asset.name.includes('azure') || asset.id === 'inv-4';
        } else if (sourceNormalized === 'gcp') {
          matchesAuditSource = asset.id.includes('gcp') || asset.name.includes('gcp');
        } else if (sourceNormalized === 'k8s') {
          matchesAuditSource = asset.id.includes('k8s') || asset.name.includes('k8s');
        } else if (sourceNormalized === 'f5') {
          matchesAuditSource = asset.id.includes('f5') || asset.name.includes('f5');
        } else if (sourceNormalized === 'paloalto') {
          matchesAuditSource = asset.id.includes('paloalto') || asset.name.includes('paloalto');
        } else if (sourceNormalized === 'cisco') {
          matchesAuditSource = asset.id.includes('cisco') || asset.name.includes('cisco');
        } else if (sourceNormalized === 'splunk') {
          matchesAuditSource = asset.id.includes('splunk') || asset.name.includes('splunk') || asset.id === 'inv-3';
        } else if (sourceNormalized === 'defender') {
          matchesAuditSource = asset.id.includes('defender') || asset.name.includes('defender');
        } else if (sourceNormalized === 'crowdstrike') {
          matchesAuditSource = asset.id.includes('crowdstrike') || asset.name.includes('crowdstrike');
        } else if (sourceNormalized === 'qualys') {
          matchesAuditSource = asset.id.includes('qualys') || asset.name.includes('qualys');
        } else if (sourceNormalized === 'tenable') {
          matchesAuditSource = asset.id.includes('tenable') || asset.name.includes('tenable');
        } else if (sourceNormalized === 'workday') {
          matchesAuditSource = asset.id.includes('workday') || asset.name.includes('workday');
        } else if (sourceNormalized === 'sharepoint') {
          matchesAuditSource = asset.id.includes('sharepoint') || asset.name.includes('sharepoint');
        } else if (sourceNormalized === 'servicenow') {
          matchesAuditSource = asset.id.includes('servicenow') || asset.name.includes('servicenow') || asset.id === 'inv-5';
        } else {
          matchesAuditSource = asset.name.toLowerCase().includes(sourceNormalized) || asset.id.includes(sourceNormalized);
        }
      } else {
        // If activeSource is 'all', filter by the active logCategory
        const apiSources = ['aws', 'azure', 'gcp', 'k8s', 'f5', 'paloalto', 'cisco'];
        const partnerSources = ['splunk', 'defender', 'crowdstrike', 'qualys', 'tenable', 'workday', 'sharepoint', 'servicenow'];
        if (logCategory === 'api') {
          matchesAuditSource = apiSources.some(src => asset.id.includes(src) || asset.name.toLowerCase().includes(src)) || asset.id === 'inv-1' || asset.id === 'inv-4';
        } else {
          matchesAuditSource = partnerSources.some(src => asset.id.includes(src) || asset.name.toLowerCase().includes(src)) || asset.id === 'inv-3' || asset.id === 'inv-5' || asset.id === 'inv-2';
        }
      }

      return matchesSearch && matchesType && matchesStatus && matchesService && matchesLifecycle && matchesAuditSource;
    });
  }, [enrichedAssets, searchTerm, typeFilter, statusFilter, serviceFilter, lifecycleFilter, logCategory, selectedAuditApiTopic, selectedAuditIntegrationSource]);

  // Sync scroll on logs terminal
  useEffect(() => {
    if (liveTerminalRef.current) {
      liveTerminalRef.current.scrollTop = liveTerminalRef.current.scrollHeight;
    }
  }, [liveDiscoveryLogs]);

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
    setLiveDiscoveryLogs([]);
    setDiscoveredAssets([]);

    // Get realistic logs based on date 2026-06-11 and selectedSource
    const logs = getMockLogsForSource(selectedSource, '2026-06-11');
    const newAssets = getDiscoveryAssetsForSource(selectedSource);

    let currentLogIndex = 0;
    const interval = setInterval(() => {
      if (currentLogIndex < logs.length) {
        setLiveDiscoveryLogs(prev => [...prev, logs[currentLogIndex]]);
        currentLogIndex++;
      } else {
        clearInterval(interval);
        setIsDiscovering(false);
        setDiscoveredAssets(newAssets);
        
        // Save the run to our historical logs database registry
        setSyncLogsRegistry(prev => ({
          ...prev,
          '2026-06-11': {
            ...(prev['2026-06-11'] || {}),
            [selectedSource]: logs
          }
        }));

        // Set selectors to view the newly ingested logs
        setSelectedAuditDate('2026-06-11');
        
        const apiSources = ['aws', 'azure', 'gcp', 'k8s', 'f5', 'paloalto', 'cisco'];
        if (apiSources.includes(selectedSource)) {
          setLogCategory('api');
          setSelectedAuditApiTopic(selectedSource);
        } else {
          setLogCategory('integration');
          setSelectedAuditIntegrationSource(selectedSource);
        }

        if (onAddAssets) {
          onAddAssets(newAssets);
        }
      }
    }, 250);
  };

  const handleExportCSV = () => {
    const headers = [
      'Business Service',
      'Application',
      'Endpoint',
      'Asset Name',
      'Type',
      'Algorithm',
      'Key Size',
      'Risk Level',
      'Owner',
      'Lifecycle State',
      'Posture Status'
    ];
    
    const rows = filteredAssets.map(asset => [
      `"${asset.businessService.replace(/"/g, '""')}"`,
      `"${asset.application.replace(/"/g, '""')}"`,
      `"${asset.endpoint.replace(/"/g, '""')}"`,
      `"${asset.name.replace(/"/g, '""')}"`,
      `"${asset.type.replace(/"/g, '""')}"`,
      `"${asset.algorithm.replace(/"/g, '""')}"`,
      asset.keySize ? `${asset.keySize}` : 'N/A',
      `"${asset.riskLevel.replace(/"/g, '""')}"`,
      `"${asset.owner.replace(/"/g, '""')}"`,
      `"${asset.lifecycle.replace(/"/g, '""')}"`,
      `"${asset.status.replace(/"/g, '""')}"`
    ]);
    
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', `quarkshield_crypto_cmdb_export_${new Date().toISOString().split('T')[0]}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleExportAuditTrail = () => {
    const activeSource = logCategory === 'api' ? selectedAuditApiTopic : selectedAuditIntegrationSource;
    const dateStr = selectedAuditDate;
    const fileName = `quarkshield_${activeSource}_audit_trail_${dateStr}.log`;
    const content = activeHistoricalLogs.join('\n');
    
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', fileName);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Compute SVG nodes and links for the SVG dependency mapper
  const svgGraph = useMemo(() => {
    const serviceAssets = enrichedAssets.filter(a => a.businessService === graphService);
    if (serviceAssets.length === 0) return null;

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

  // Selected historical sync log text resolver
  const activeHistoricalLogs = useMemo(() => {
    const activeSource = logCategory === 'api' ? selectedAuditApiTopic : selectedAuditIntegrationSource;
    if (activeSource === 'all') {
      return [`[INFO] Select a specific ${logCategory === 'api' ? 'API Discovery Topic' : 'Other Internal Source'} to view its raw sync console logs.`];
    }
    const dateRegistry = syncLogsRegistry[selectedAuditDate];
    if (dateRegistry && dateRegistry[activeSource]) {
      return dateRegistry[activeSource];
    }
    return getMockLogsForSource(activeSource, selectedAuditDate);
  }, [syncLogsRegistry, selectedAuditDate, logCategory, selectedAuditApiTopic, selectedAuditIntegrationSource]);

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
        gridTemplateColumns: 'minmax(300px, 15fr) minmax(450px, 22fr)', 
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
              <span>Metadata Discovery & Integrations</span>
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: '1.4' }}>
              Connect agentless APIs and other internal systems to sync cryptographic inventory. Ingests metadata only (GDPR compliant).
            </p>

            {/* Select connector */}
            <div style={{ marginBottom: '1rem' }}>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '0.4rem', textTransform: 'uppercase' }}>
                Select Active Integration / API Source
              </label>
              <select 
                value={selectedSource} 
                onChange={(e) => setSelectedSource(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.5rem', fontSize: '0.9rem', width: '100%', background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border-normal)', color: '#ffffff' }}
              >
                <optgroup label="Direct Cloud & Network API Connectors" style={{ background: 'var(--bg-card)', color: 'var(--accent-cyan)' }}>
                  <option value="aws" style={{ color: '#ffffff' }}>AWS: ACM, ELB, API Gateway, IAM, Secrets Manager</option>
                  <option value="azure" style={{ color: '#ffffff' }}>Azure: Graph API, Key Vault, Azure Resource Manager</option>
                  <option value="gcp" style={{ color: '#ffffff' }}>GCP: Certificates, Load Balancers</option>
                  <option value="k8s" style={{ color: '#ffffff' }}>Kubernetes: TLS Secrets, Ingress Controllers, Service Mesh</option>
                  <option value="f5" style={{ color: '#ffffff' }}>F5: SSL Profiles, VIPs, Certificates</option>
                  <option value="paloalto" style={{ color: '#ffffff' }}>Palo Alto: VPNs, Certificates</option>
                  <option value="cisco" style={{ color: '#ffffff' }}>Cisco: VPN Infrastructure</option>
                </optgroup>
                <optgroup label="Other Internal Sources" style={{ background: 'var(--bg-card)', color: 'var(--accent-purple)' }}>
                  <option value="splunk" style={{ color: '#ffffff' }}>Splunk: Connect as Splunk User & query 'ia' index</option>
                  <option value="defender" style={{ color: '#ffffff' }}>Microsoft Defender: Extract active endpoint host certs</option>
                  <option value="crowdstrike" style={{ color: '#ffffff' }}>CrowdStrike: Sync endpoint KEX ciphers from Falcon</option>
                  <option value="qualys" style={{ color: '#ffffff' }}>Qualys: Sync discovered host SSL configurations</option>
                  <option value="tenable" style={{ color: '#ffffff' }}>Tenable: Ingest Nessus SSL scan profiles</option>
                  <option value="workday" style={{ color: '#ffffff' }}>Workday: Sync directory names & owner identities</option>
                  <option value="sharepoint" style={{ color: '#ffffff' }}>SharePoint: Parse asset inventory documents</option>
                  <option value="servicenow" style={{ color: '#ffffff' }}>ServiceNow: Get configuration items & create tickets</option>
                </optgroup>
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
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>Live Sync Output</span>
              {isDiscovering && <div className="pulse-dot"></div>}
            </div>
            <div 
              ref={liveTerminalRef}
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
              {liveDiscoveryLogs.length === 0 ? (
                <span style={{ color: 'var(--text-muted)' }}>Idle. Click "Trigger Metadata Discovery" to execute live cloud scan.</span>
              ) : (
                liveDiscoveryLogs.join('\n')
              )}
            </div>
          </div>

          {/* Recently Discovered Assets list */}
          {!isDiscovering && liveDiscoveryLogs.length > 0 && discoveredAssets.length > 0 && (
            <div style={{ marginTop: '1rem', animation: 'fadeIn 0.3s' }}>
              <span style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', marginBottom: '0.4rem' }}>
                Discovered Cryptographic Assets ({discoveredAssets.length})
              </span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '180px', overflowY: 'auto' }}>
                {discoveredAssets.map((asset) => {
                  const enriched = enrichAssetCMDB(asset);
                  return (
                    <div key={asset.id} style={{ 
                      display: 'flex', 
                      justifyContent: 'space-between', 
                      alignItems: 'center', 
                      background: 'rgba(255,255,255,0.02)', 
                      border: '1px solid var(--border-normal)', 
                      borderRadius: '4px', 
                      padding: '0.4rem 0.6rem',
                      fontSize: '0.8rem'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        {enriched.isVulnerable ? (
                          <ShieldAlert size={12} color="var(--status-vulnerable)" />
                        ) : (
                          <ShieldCheck size={12} color="var(--status-secure)" />
                        )}
                        <span style={{ color: '#ffffff', fontWeight: 500 }}>{enriched.name}</span>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{enriched.algorithm}</span>
                        <span className={`badge ${
                          enriched.riskLevel === 'critical' || enriched.riskLevel === 'high' ? 'danger' : 'warning'
                        }`} style={{ fontSize: '0.65rem', padding: '0.1rem 0.3rem' }}>
                          {enriched.riskLevel}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
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

      {/* Row 2: Historic logs and Ingested data results */}
      <div className="glass-panel" style={{ 
        padding: '1.25rem', 
        background: 'var(--bg-card)', 
        border: '1px solid var(--border-normal)',
        marginBottom: '1.5rem'
      }}>
        <div style={{ borderBottom: '1px solid var(--border-normal)', paddingBottom: '0.75rem', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 600, color: '#ffffff', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity size={18} color="var(--accent-cyan)" />
            <span>CMDB Dependency Registry</span>
          </h3>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
            Select sync dates, API topics (metadata), or imported integration data to inspect stored raw console logs and matching records.
          </p>
        </div>

        {/* Filters and Date/Source selectors */}
        <div style={{ 
          display: 'flex', 
          flexDirection: 'column',
          gap: '1rem', 
          marginBottom: '1rem',
          background: 'rgba(255,255,255,0.01)',
          padding: '1rem',
          borderRadius: '8px',
          border: '1px solid var(--border-normal)'
        }}>
          {/* Top Row: Date Selection & Categories Toggle */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
              {/* Date Selection */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <span style={{ fontSize: '0.8rem', color: '#ffffff', fontWeight: 600 }}>Sync Date:</span>
                <select 
                  value={selectedAuditDate} 
                  onChange={(e) => setSelectedAuditDate(e.target.value)}
                  className="chat-text-input" 
                  style={{ padding: '0.4rem 0.6rem', fontSize: '0.85rem', width: '160px', background: 'rgba(0,0,0,0.3)', color: '#ffffff' }}
                >
                  <option value="2026-06-11">2026-06-11 (Today)</option>
                  <option value="2026-06-10">2026-06-10</option>
                  <option value="2026-06-09">2026-06-09</option>
                </select>
              </div>

              {/* Log Category Selector Buttons (Tab-like) */}
              <div style={{ display: 'flex', background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '2px', border: '1px solid var(--border-normal)' }}>
                <button
                  onClick={() => setLogCategory('api')}
                  style={{
                    padding: '0.4rem 0.85rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    background: logCategory === 'api' ? 'var(--accent-cyan)' : 'transparent',
                    color: logCategory === 'api' ? '#000000' : 'var(--text-secondary)',
                    transition: 'all 0.2s'
                  }}
                >
                  API Discovery Sources
                </button>
                <button
                  onClick={() => setLogCategory('integration')}
                  style={{
                    padding: '0.4rem 0.85rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    borderRadius: '4px',
                    border: 'none',
                    cursor: 'pointer',
                    background: logCategory === 'integration' ? 'var(--accent-purple)' : 'transparent',
                    color: logCategory === 'integration' ? '#ffffff' : 'var(--text-secondary)',
                    transition: 'all 0.2s'
                  }}
                >
                  Other Internal Sources
                </button>
              </div>
            </div>

            {/* Ingested Records Search Bar */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0,0,0,0.3)', padding: '0.45rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-normal)', width: '280px' }}>
              <Search size={15} color="var(--text-secondary)" />
              <input 
                type="text" 
                placeholder="Search matching records..." 
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ 
                  background: 'transparent', 
                  border: 'none', 
                  color: 'white', 
                  outline: 'none', 
                  width: '100%',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.85rem'
                }}
              />
            </div>
          </div>

          {/* Bottom Row: Conditional Selectors for specific sources */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap', borderTop: '1px solid rgba(255,255,255,0.05)', paddingTop: '0.75rem' }}>
            {logCategory === 'api' ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', width: '100%' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 600 }}>API Discovery Topic:</span>
                <select 
                  value={selectedAuditApiTopic} 
                  onChange={(e) => setSelectedAuditApiTopic(e.target.value)}
                  className="chat-text-input" 
                  style={{ padding: '0.4rem 0.6rem', fontSize: '0.85rem', width: '320px', background: 'rgba(0,0,0,0.3)', color: '#ffffff' }}
                >
                  <option value="all">All API Topics (Full API Ingestion)</option>
                  <option value="aws">AWS: ACM, ELB, API Gateway, IAM, Secrets Manager</option>
                  <option value="azure">Azure: Graph API, Key Vault, Azure Resource Manager</option>
                  <option value="gcp">GCP: Certificates, Load Balancers</option>
                  <option value="k8s">Kubernetes: TLS Secrets, Ingress Controllers, Service Mesh</option>
                  <option value="f5">F5: SSL Profiles, VIPs, Certificates</option>
                  <option value="paloalto">Palo Alto: VPNs, Certificates</option>
                  <option value="cisco">Cisco: VPN Infrastructure</option>
                </select>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '1rem' }}>
                  Queries direct cloud/network metadata discovery logs.
                </span>
              </div>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', width: '100%' }}>
                <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', fontWeight: 600 }}>Other Internal Source:</span>
                <select 
                  value={selectedAuditIntegrationSource} 
                  onChange={(e) => setSelectedAuditIntegrationSource(e.target.value)}
                  className="chat-text-input" 
                  style={{ padding: '0.4rem 0.6rem', fontSize: '0.85rem', width: '320px', background: 'rgba(0,0,0,0.3)', color: '#ffffff' }}
                >
                  <option value="all">All Internal Sources (Full Ingestion)</option>
                  <option value="splunk">Splunk: Connect as Splunk User & query 'ia' index</option>
                  <option value="defender">Microsoft Defender: Extract active endpoint host certs</option>
                  <option value="crowdstrike">CrowdStrike: Sync endpoint KEX ciphers from Falcon</option>
                  <option value="qualys">Qualys: Sync discovered host SSL configurations</option>
                  <option value="tenable">Tenable: Ingest Nessus SSL scan profiles</option>
                  <option value="workday">Workday: Sync directory names & owner identities</option>
                  <option value="sharepoint">SharePoint: Parse asset inventory documents</option>
                  <option value="servicenow">ServiceNow: Get configuration items & create tickets</option>
                </select>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginLeft: '1rem' }}>
                  Queries other internal security and catalog inventory records.
                </span>
              </div>
            )}
          </div>
        </div>

        {/* Stored Raw Log Terminal Console */}
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
              Sync Console logs (Audit Trail)
            </span>
            <button 
              onClick={handleExportAuditTrail}
              className="btn-secondary"
              style={{ 
                padding: '0.15rem 0.5rem', 
                fontSize: '0.7rem', 
                display: 'inline-flex', 
                alignItems: 'center', 
                gap: '0.25rem',
                borderColor: 'rgba(0, 243, 255, 0.25)',
                color: 'var(--accent-cyan)'
              }}
              title="Export raw sync audit trail to file"
            >
              <Download size={11} />
              <span>Export Audit Trail</span>
            </button>
          </div>
          <div 
            style={{ 
              height: '110px', 
              background: '#090a0f', 
              border: '1px solid var(--border-normal)', 
              borderRadius: '6px', 
              padding: '0.5rem 0.8rem', 
              fontFamily: 'monospace', 
              fontSize: '0.75rem', 
              color: '#00f3ff', 
              overflowY: 'auto',
              whiteSpace: 'pre-line',
              lineHeight: '1.4'
            }}
          >
            {activeHistoricalLogs.join('\n')}
          </div>
        </div>

        {/* Filters Array for Table */}
        <div style={{ 
          display: 'flex', 
          gap: '0.75rem', 
          alignItems: 'center', 
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          marginBottom: '0.75rem',
          padding: '0.5rem',
          background: 'rgba(255,255,255,0.02)',
          borderRadius: '4px',
          border: '1px solid rgba(255,255,255,0.05)'
        }}>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            {/* Service Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Service:</span>
              <select 
                value={serviceFilter} 
                onChange={(e) => setServiceFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.2rem 0.4rem', fontSize: '0.75rem', width: '120px', background: 'rgba(0,0,0,0.3)' }}
              >
                <option value="all">All Services</option>
                {businessServices.map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>

            {/* Type Filter */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Type:</span>
              <select 
                value={typeFilter} 
                onChange={(e) => setTypeFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.2rem 0.4rem', fontSize: '0.75rem', width: '100px', background: 'rgba(0,0,0,0.3)' }}
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
              <span style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Status:</span>
              <select 
                value={statusFilter} 
                onChange={(e) => setStatusFilter(e.target.value)}
                className="chat-text-input" 
                style={{ padding: '0.2rem 0.4rem', fontSize: '0.75rem', width: '100px', background: 'rgba(0,0,0,0.3)' }}
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

            {/* Export CSV Button */}
            <button 
              onClick={handleExportCSV}
              className="btn-secondary"
              style={{ 
                padding: '0.25rem 0.65rem', 
                fontSize: '0.8rem', 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.3rem',
                borderColor: 'rgba(0, 243, 255, 0.3)',
                color: 'var(--accent-cyan)'
              }}
              title="Export filtered records to CSV"
            >
              <FileSpreadsheet size={13} />
              <span>Export CSV</span>
            </button>
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
