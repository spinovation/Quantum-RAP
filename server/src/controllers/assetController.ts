import { Request, Response } from 'express';
import pool from '../config/db';
import { 
  auditSSHKey, 
  auditPEMCertificate, 
  auditConfigFile, 
  auditUrlEndpoint,
  AuditResult 
} from '../utils/cryptoAuditor';

// GET /api/assets
export const getAssets = async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
    
    // Map database columns to camelCase expected by the React client
    const assets = result.rows.map(row => ({
      id: row.id,
      type: row.type,
      name: row.name,
      algorithm: row.algorithm,
      keySize: row.key_size,
      hashAlgorithm: row.hash_algorithm,
      isVulnerable: row.is_vulnerable,
      riskLevel: row.risk_level,
      status: row.status,
      description: row.description,
      recommendation: row.recommendation,
      explainer: row.explainer,
      complianceViolations: row.compliance_violations || [],
    }));
    
    res.json(assets);
  } catch (err: any) {
    console.error('Error fetching assets:', err);
    res.status(500).json({ error: 'Failed to retrieve cryptographic assets database.' });
  }
};

// POST /api/assets
export const registerAssets = async (req: Request, res: Response) => {
  try {
    const newAssets: AuditResult[] = req.body;
    if (!Array.isArray(newAssets)) {
      return res.status(400).json({ error: 'Expected JSON array of assets.' });
    }

    const inserted: AuditResult[] = [];

    for (const asset of newAssets) {
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
          compliance_violations = EXCLUDED.compliance_violations
        RETURNING *;
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

      const result = await pool.query(queryText, values);
      inserted.push(asset);
    }

    res.status(201).json({ success: true, count: inserted.length, assets: inserted });
  } catch (err: any) {
    console.error('Error inserting assets:', err);
    res.status(500).json({ error: 'Failed to register assets in PostgreSQL database.' });
  }
};

// DELETE /api/assets/:id
export const deleteAsset = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM assets WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: `Asset with ID '${id}' not found.` });
    }
    
    res.json({ success: true, id });
  } catch (err: any) {
    console.error('Error deleting asset:', err);
    res.status(500).json({ error: 'Failed to remove asset from database.' });
  }
};

// POST /api/scan/file
export const scanFile = async (req: Request, res: Response) => {
  try {
    const { name, content } = req.body;
    if (!name || !content) {
      return res.status(400).json({ error: 'Missing file parameters (name, content).' });
    }

    const trimmed = content.trim();
    let result: AuditResult;

    if (trimmed.startsWith('-----BEGIN') || trimmed.includes('PRIVATE KEY')) {
      result = auditPEMCertificate(trimmed, name);
    } else if (trimmed.startsWith('ssh-') || trimmed.startsWith('ecdsa-')) {
      result = auditSSHKey(trimmed, name);
    } else {
      result = {
        id: Math.random().toString(36).substring(7),
        type: 'config',
        name,
        algorithm: 'Text Config',
        isVulnerable: true,
        riskLevel: 'medium',
        status: 'Quantum Vulnerable',
        description: 'Plaintext file scanned as configuration.',
        recommendation: 'Check contents for secret values.',
        explainer: 'Unstructured file analyzed.',
        complianceViolations: []
      };
    }

    res.json(result);
  } catch (err: any) {
    console.error('Error scanning file:', err);
    res.status(500).json({ error: 'Internal error auditing file content.' });
  }
};

// POST /api/scan/config
export const scanConfig = async (req: Request, res: Response) => {
  try {
    const { fileName, content } = req.body;
    if (!fileName || !content) {
      return res.status(400).json({ error: 'Missing configuration parameters (fileName, content).' });
    }

    const audit = auditConfigFile(fileName, content);
    res.json(audit);
  } catch (err: any) {
    console.error('Error auditing config:', err);
    res.status(500).json({ error: 'Failed to compile configuration audit.' });
  }
};

// POST /api/scan/url
export const scanUrl = async (req: Request, res: Response) => {
  try {
    const { url } = req.body;
    if (!url) {
      return res.status(400).json({ error: 'Missing endpoint URL parameter.' });
    }

    const auditResult = await auditUrlEndpoint(url);
    res.json(auditResult);
  } catch (err: any) {
    console.error('Error scanning endpoint url:', err);
    res.status(500).json({ error: `Connection failed: ${err.message}` });
  }
};

// POST /api/scan/passive/pcap
export const parsePcap = async (req: Request, res: Response) => {
  try {
    const { fileName, fileSize } = req.body;
    
    // Simulate analyzing the PCAP file size or name if needed, then return simulated shadow assets
    const mockShadows = [
      {
        id: `shadow-pcap-${Date.now()}-1`,
        name: 'shadow-ingress-lb.internal',
        ip: '10.220.14.3',
        protocol: 'TLSv1.3',
        algorithm: 'TLS_AES_128_GCM_SHA256 / RSA-4096',
        isVulnerable: true,
        riskLevel: 'high',
        status: 'Quantum Vulnerable'
      },
      {
        id: `shadow-pcap-${Date.now()}-2`,
        name: 'pqc-mail-relay.secure',
        ip: '192.168.12.110',
        protocol: 'TLSv1.3',
        algorithm: 'X25519MLKEM768 / ECDSA',
        isVulnerable: false,
        riskLevel: 'secure',
        status: 'Post-Quantum Secure'
      },
      {
        id: `shadow-pcap-${Date.now()}-3`,
        name: 'legacy-pki-enrollment.internal',
        ip: '10.199.5.4',
        protocol: 'TLSv1.2',
        algorithm: 'ECDHE-RSA-AES256-SHA384 / RSA-2048',
        isVulnerable: true,
        riskLevel: 'high',
        status: 'Quantum Vulnerable'
      }
    ];

    res.json(mockShadows);
  } catch (err: any) {
    console.error('Error parsing endpoint url:', err);
    res.status(500).json({ error: `PCAP parsing failed: ${err.message}` });
  }
};
