import { Request, Response } from 'express';
import pool from '../config/db';
import { evaluateCompliance } from '../utils/regoEvaluator';

// GET /api/compliance
export const getComplianceReport = async (req: Request, res: Response) => {
  try {
    const result = await pool.query('SELECT * FROM assets');
    
    // Normalize db fields to match React client expected camelCase fields
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

    const report = evaluateCompliance(assets);
    res.json(report);
  } catch (err: any) {
    console.error('Error compiling compliance report:', err);
    res.status(500).json({ error: `Compliance compilation failed: ${err.message}` });
  }
};
