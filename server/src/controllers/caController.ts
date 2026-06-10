import { Request, Response } from 'express';
import pool from '../config/db';
import { auditPEMCertificate, AuditResult } from '../utils/cryptoAuditor';

// Helper: Query DB to register a single AuditResult
const saveAssetToDb = async (asset: AuditResult): Promise<void> => {
  const queryText = `
    INSERT INTO assets (
      id, type, name, algorithm, key_size, hash_algorithm, 
      is_vulnerable, risk_level, status, description, 
      recommendation, explainer, compliance_violations
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
    ON CONFLICT (id) DO UPDATE SET 
      name = EXCLUDED.name,
      algorithm = EXCLUDED.algorithm,
      key_size = EXCLUDED.key_size,
      is_vulnerable = EXCLUDED.is_vulnerable,
      risk_level = EXCLUDED.risk_level,
      status = EXCLUDED.status,
      description = EXCLUDED.description,
      recommendation = EXCLUDED.recommendation,
      explainer = EXCLUDED.explainer,
      compliance_violations = EXCLUDED.compliance_violations;
  `;

  const values = [
    asset.id,
    asset.type,
    asset.name,
    asset.algorithm,
    asset.keySize || null,
    asset.hashAlgorithm || null,
    asset.isVulnerable,
    asset.riskLevel,
    asset.status,
    asset.description,
    asset.recommendation,
    asset.explainer,
    asset.complianceViolations || [],
  ];

  await pool.query(queryText, values);
};

// POST /api/ca/vault/sync
export const syncVaultCertificates = async (req: Request, res: Response) => {
  try {
    const { vaultUrl, token, mountPath } = req.body;
    if (!vaultUrl || !token) {
      return res.status(400).json({ error: 'Missing Vault parameters (vaultUrl, token).' });
    }

    const pkiMount = mountPath || 'pki';
    const cleanUrl = vaultUrl.replace(/\/$/, '');

    // 1. Fetch certificate serial numbers list from Vault PKI
    const listUrl = `${cleanUrl}/v1/${pkiMount}/certs`;
    console.log(`Vault Sync: Fetching cert serials from ${listUrl}`);
    
    const listRes = await fetch(listUrl, {
      method: 'GET',
      headers: {
        'X-Vault-Token': token,
        'Accept': 'application/json'
      }
    });

    if (!listRes.ok) {
      const errText = await listRes.text();
      return res.status(listRes.status).json({ error: `Vault error: ${errText}` });
    }

    const listData: any = await listRes.json();
    const serials: string[] = listData?.data?.keys || [];

    if (serials.length === 0) {
      return res.json({ success: true, message: 'No certificates found in Vault PKI engine.', syncedCount: 0 });
    }

    let syncedCount = 0;
    let vulnerableCount = 0;
    let secureCount = 0;

    // 2. Fetch and audit each certificate PEM
    for (const serial of serials.slice(0, 30)) { // Limit to 30 certs for demo safety
      const certUrl = `${cleanUrl}/v1/${pkiMount}/cert/${serial}`;
      const certRes = await fetch(certUrl, {
        method: 'GET',
        headers: {
          'X-Vault-Token': token,
          'Accept': 'application/json'
        }
      });

      if (certRes.ok) {
        const certData: any = await certRes.json();
        const certPem = certData?.data?.certificate;
        if (certPem) {
          const name = `Vault-PKI-Cert:${serial.substring(0, 8)}`;
          const audit = auditPEMCertificate(certPem, name);
          
          // Force asset ID mapping
          audit.id = `vault-cert-${serial}`;
          
          await saveAssetToDb(audit);
          syncedCount++;
          if (audit.isVulnerable) {
            vulnerableCount++;
          } else {
            secureCount++;
          }
        }
      }
    }

    res.json({
      success: true,
      message: `Successfully synced ${syncedCount} certificates from Vault PKI.`,
      syncedCount,
      vulnerableCount,
      secureCount
    });

  } catch (err: any) {
    console.error('Error syncing Vault certificates:', err);
    res.status(500).json({ error: `Sync failed: ${err.message}` });
  }
};

// Interface for ADCS post payload
interface ADCSCertRow {
  serialNumber: string;
  commonName: string;
  notAfter: string;
  publicKeyAlgorithm: string;
  keyLength: number;
}

// POST /api/ca/adcs/sync
export const syncADCSCertificates = async (req: Request, res: Response) => {
  try {
    const certs: ADCSCertRow[] = req.body;
    if (!Array.isArray(certs)) {
      return res.status(400).json({ error: 'Expected JSON array of certificate rows.' });
    }

    let registeredCount = 0;
    let vulnerableCount = 0;

    for (const row of certs) {
      if (!row.serialNumber || !row.commonName) continue;

      const serial = row.serialNumber.trim();
      const name = `ADCS-Cert:${row.commonName}`;
      const keySize = Number(row.keyLength) || 2048;
      const rawAlgo = row.publicKeyAlgorithm || 'RSA';

      // Audit decision logic
      let algorithm = 'RSA';
      let isVulnerable = true;
      let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure' = 'high';
      let description = '';
      let recommendation = '';
      let explainer = '';
      const complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];

      const algoUpper = rawAlgo.toUpperCase();
      if (stringsContains(algoUpper, 'RSA')) {
        algorithm = 'RSA';
        if (keySize < 2048) {
          riskLevel = 'critical';
        }
        description = `Quantum-vulnerable Active Directory (ADCS) certificate utilizing RSA-${keySize}.`;
        recommendation = 'Deploy hybrid Post-Quantum keys (ML-KEM) and schedule CA certificate updates.';
        explainer = "RSA integer factorization is solved in polynomial time by Shor's algorithm, breaking standard AD CS roots.";
      } else if (stringsContains(algoUpper, 'EC') || stringsContains(algoUpper, 'ECDSA')) {
        algorithm = 'ECDSA / ECDH';
        description = `Quantum-vulnerable Active Directory (ADCS) certificate utilizing Elliptic Curve Cryptography.`;
        recommendation = 'Plan migration of certificate validation schemes to ML-DSA signatures.';
        explainer = "Elliptic curve discrete logarithms are easily breakable under Shor's algorithm, exposing AD CS certificates.";
      } else {
        algorithm = rawAlgo;
        description = `Generic vulnerable ADCS certificate using algorithm: ${rawAlgo}.`;
        recommendation = 'Transition certificate to post-quantum module-lattices.';
        explainer = "Assume any classical algorithm is vulnerable to Shor's solvers.";
      }

      const status = 'Quantum Vulnerable';
      vulnerableCount++;

      const audit: AuditResult = {
        id: `adcs-cert-${serial}`,
        type: 'certificate',
        name,
        algorithm,
        keySize,
        isVulnerable,
        riskLevel,
        status,
        description,
        recommendation,
        explainer,
        complianceViolations,
      };

      await saveAssetToDb(audit);
      registeredCount++;
    }

    res.status(201).json({
      success: true,
      message: `Successfully parsed and registered ${registeredCount} certificates from Windows ADCS.`,
      registeredCount,
      vulnerableCount
    });

  } catch (err: any) {
    console.error('Error synchronizing ADCS certificates:', err);
    res.status(500).json({ error: `Failed to import ADCS certificate data: ${err.message}` });
  }
};

// Helper: case-insensitive string contains
function stringsContains(str: string, search: string): boolean {
  return str.indexOf(search) !== -1;
}
