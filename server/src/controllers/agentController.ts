import { Request, Response } from 'express';
import pool from '../config/db';
import crypto from 'crypto';
import path from 'path';
import fs from 'fs';

// GET /api/scan/agent/connectors
export const getConnectors = async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT id, name, status, last_sync as "lastSync", created_at as "createdAt" FROM connectors ORDER BY name ASC');
    res.json(result.rows);
  } catch (err: any) {
    console.error('Error fetching connectors:', err);
    res.status(500).json({ error: 'Failed to retrieve agent connectors from database.' });
  }
};

// POST /api/scan/agent/connectors
export const registerConnector = async (req: Request, res: Response) => {
  try {
    const { name } = req.body;
    if (!name) {
      return res.status(400).json({ error: 'Connector name is required.' });
    }

    const id = crypto.randomUUID();
    const token = `qsc_${crypto.randomBytes(24).toString('hex')}`;

    const queryText = `
      INSERT INTO connectors (id, name, token, status)
      VALUES ($1, $2, $3, 'offline')
      RETURNING id, name, token, status, created_at as "createdAt";
    `;
    const result = await pool.query(queryText, [id, name, token]);
    res.status(201).json(result.rows[0]);
  } catch (err: any) {
    console.error('Error registering connector:', err);
    if (err.code === '23505') {
      return res.status(400).json({ error: 'A connector with this name already exists.' });
    }
    res.status(500).json({ error: 'Failed to register connector in database.' });
  }
};

// DELETE /api/scan/agent/connectors/:id
export const deleteConnector = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const result = await pool.query('DELETE FROM connectors WHERE id = $1 RETURNING id', [id]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Connector not found.' });
    }
    res.json({ success: true, id });
  } catch (err: any) {
    console.error('Error deleting connector:', err);
    res.status(500).json({ error: 'Failed to delete connector from database.' });
  }
};

// GET /api/scan/agent/script
export const getConnectorScript = async (req: Request, res: Response) => {
  try {
    const scriptPath = path.join(__dirname, '../assets/quarkshield-connector.py');
    if (fs.existsSync(scriptPath)) {
      res.setHeader('Content-Type', 'text/plain');
      res.sendFile(scriptPath);
    } else {
      res.status(404).send('Connector script not found on server.');
    }
  } catch (err: any) {
    console.error('Error serving connector script:', err);
    res.status(500).send('Failed to serve script.');
  }
};

// POST /api/scan/agent/ingest
export const ingestConnectorData = async (req: Request, res: Response) => {
  try {
    const token = req.headers['x-connector-token'] as string;
    if (!token) {
      return res.status(401).json({ error: 'Unauthorized: X-Connector-Token header is missing.' });
    }

    // Validate token
    const connectorResult = await pool.query('SELECT * FROM connectors WHERE token = $1', [token]);
    if (connectorResult.rowCount === 0) {
      return res.status(401).json({ error: 'Unauthorized: Invalid connector token.' });
    }
    const connector = connectorResult.rows[0];

    const { hostname, os, assets } = req.body;
    if (!hostname || !Array.isArray(assets)) {
      return res.status(400).json({ error: 'Malformed payload: expected hostname and assets array.' });
    }

    // Update connector status and last sync timestamp
    await pool.query('UPDATE connectors SET status = $1, last_sync = CURRENT_TIMESTAMP WHERE id = $2', ['online', connector.id]);

    const inserted: any[] = [];

    for (const rawAsset of assets) {
      // 1. Generate unique deterministic ID based on hostname, type, and filepath (from description)
      const uniqueString = `${connector.name}-${rawAsset.type}-${rawAsset.name}-${rawAsset.description}`;
      const id = 'agent-' + crypto.createHash('sha256').update(uniqueString).digest('hex').substring(0, 26);

      let isVulnerable = false;
      let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure' = 'low';
      let status: 'Quantum Vulnerable' | 'Quantum Mapped' | 'Post-Quantum Secure' = 'Quantum Mapped';
      let recommendation = '';
      let explainer = '';
      let complianceViolations: string[] = [];

      // Determine audit metrics based on asset properties
      if (rawAsset.type === 'private_key') {
        const size = rawAsset.key_size || 2048;
        const algo = (rawAsset.algorithm || '').toUpperCase();

        if (algo.includes('RSA') && size < 2048) {
          isVulnerable = true;
          riskLevel = 'critical';
          status = 'Quantum Vulnerable';
          recommendation = 'Delete this key immediately. Generate a Post-Quantum digital signature key (ML-DSA) or at minimum a secure classical key (RSA-3072/4096).';
          explainer = 'Short key sizes can be cracked classically, and all classical key exchanges are broken by Shor\'s algorithm.';
          complianceViolations = ['NIST SP 800-57', 'CNSA 2.0', 'EO 14028'];
        } else if (algo.includes('RSA') && size >= 2048) {
          isVulnerable = true;
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Migrate to a Post-Quantum signature standard (ML-DSA) before the CNSA 2.0 timeline enforcement.';
          explainer = 'RSA signatures are mathematically vulnerable to integer factorization on quantum computing platforms.';
          complianceViolations = ['CNSA 2.0', 'NIST SP 800-219'];
        } else if (algo.includes('ECDSA') || algo.includes('EC')) {
          isVulnerable = true;
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Transition to ML-DSA/Dilithium algorithms.';
          explainer = 'Elliptic curves are vulnerable to Shor\'s algorithm for discrete logarithms.';
          complianceViolations = ['CNSA 2.0'];
        } else if (algo.includes('ML-DSA') || algo.includes('DILITHIUM')) {
          isVulnerable = false;
          riskLevel = 'secure';
          status = 'Post-Quantum Secure';
          recommendation = 'None. Active post-quantum cryptographic algorithm verified.';
          explainer = 'Approved ML-DSA lattice-based algorithm is mathematically resilient against quantum cryptanalysis.';
        }
      } else if (rawAsset.type === 'certificate') {
        const size = rawAsset.key_size || 2048;
        const hash = (rawAsset.hash_algorithm || '').toUpperCase();
        const algo = (rawAsset.algorithm || '').toUpperCase();

        if (hash === 'MD5' || hash === 'SHA-1' || size < 2048) {
          isVulnerable = true;
          riskLevel = 'critical';
          status = 'Quantum Vulnerable';
          recommendation = 'Revoke and replace this certificate immediately. Ensure the new certificate uses SHA-256 (or higher) and RSA >= 3072 or ML-DSA.';
          explainer = 'Obsolete hash functions (MD5/SHA-1) suffer from collision vulnerabilities. Key sizes < 2048 bits fail to meet current classical security minimums.';
          complianceViolations = ['CAB Forum', 'NIST SP 800-52', 'CNSA 2.0'];
        } else if (algo.includes('RSA') || algo.includes('ECDSA') || algo.includes('EC')) {
          isVulnerable = true;
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Prepare certificate authority pipeline to issue Post-Quantum certificates (ML-DSA signatures).';
          explainer = 'Classical certificate signatures will be easily forgeable by quantum computers running Shor\'s algorithm.';
          complianceViolations = ['CNSA 2.0'];
        } else if (algo.includes('ML-DSA')) {
          isVulnerable = false;
          riskLevel = 'secure';
          status = 'Post-Quantum Secure';
          recommendation = 'None. Certificate is signed with a FIPS-compliant post-quantum algorithm.';
          explainer = 'Uses state-of-the-art lattice cryptography for signature validation.';
        }
      } else if (rawAsset.type === 'cipher') {
        isVulnerable = rawAsset.is_vulnerable || false;
        if (isVulnerable) {
          riskLevel = 'high';
          status = 'Quantum Vulnerable';
          recommendation = 'Update configuration files to disable outdated ciphers (RC4, 3DES, MD5) and legacy protocols (TLS 1.0, 1.1).';
          explainer = 'Legacy configurations are vulnerable to classical downgrade attacks and lack forward secrecy.';
          complianceViolations = ['PCI-DSS', 'NIST SP 800-52'];
        } else {
          isVulnerable = false;
          riskLevel = 'low';
          status = 'Quantum Mapped';
          recommendation = 'Configure hybrid post-quantum key exchange groups (e.g. X25519MLKEM768).';
          explainer = 'Configuration uses strong classical TLS ciphers but lacks post-quantum key exchange.';
          complianceViolations = [];
        }
      }

      // 2. Prepare description with Business context & metadata
      // Inject standard business service metadata if matching path is found
      let bizService = "General Corporate Host";
      let appName = "Local System Settings";
      let endpointStr = hostname;

      if (rawAsset.description.includes('/etc/nginx') || rawAsset.description.includes('/var/www')) {
        bizService = "Customer Web Presence";
        appName = "Production Web Host";
        endpointStr = `${hostname}.local`;
      } else if (rawAsset.description.includes('/etc/ssh') || rawAsset.description.includes('id_rsa')) {
        bizService = "Administrative Operations";
        appName = "Secure SSH Node";
      }

      const cmdbMetadata = `|CMDB:{"businessService":"${bizService}","application":"${appName}","endpoint":"${endpointStr}"}`;
      const finalDescription = `${rawAsset.description} ${cmdbMetadata}`;

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
          hash_algorithm = EXCLUDED.hash_algorithm,
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
        id,
        rawAsset.type,
        rawAsset.name,
        rawAsset.algorithm || 'Unknown',
        rawAsset.key_size || null,
        rawAsset.hash_algorithm || null,
        isVulnerable,
        riskLevel,
        status,
        finalDescription,
        recommendation,
        explainer,
        complianceViolations
      ];

      await pool.query(queryText, values);
      inserted.push({ id, name: rawAsset.name, type: rawAsset.type });
    }

    res.status(201).json({
      success: true,
      connector: connector.name,
      processedCount: inserted.length,
      assets: inserted
    });

  } catch (err: any) {
    console.error('Error in agent ingestion:', err);
    res.status(500).json({ error: 'Failed to process agent ingestion telemetry.' });
  }
};
