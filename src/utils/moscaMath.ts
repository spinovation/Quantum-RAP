export interface MoscaResult {
  shelfLife: number;
  migrationTime: number;
  collapseTime: number;
  margin: number;
  isThreatened: boolean;
  priorityScore: number; // 0 to 100
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  assessmentSummary: string;
  recommendation: string;
}

/**
 * Calculates Mosca's Theorem risk metrics
 * Mosca Equation: S + Y > Z (If True, data is compromised before expiration)
 * @param S Shelf-life of data (years it must remain confidential)
 * @param Y Migration time (years to fully deploy PQC)
 * @param Z Collapse time (years until Cryptographically Relevant Quantum Computer exists)
 */
export function calculateMoscaRisk(S: number, Y: number, Z: number): MoscaResult {
  const margin = Z - (S + Y);
  const isThreatened = S + Y > Z;
  
  // Calculate priority score (0-100)
  // Higher score means higher risk/urgency
  let priorityScore = 0;
  if (isThreatened) {
    // Deficit increases priority up to 100
    const deficit = Math.abs(margin);
    priorityScore = Math.min(100, Math.round(50 + (deficit / Z) * 50));
  } else {
    // If not threatened, priority depends on how close we are to the threshold
    const safetyBuffer = margin;
    priorityScore = Math.max(10, Math.round(50 - (safetyBuffer / Z) * 40));
  }

  let riskLevel: 'critical' | 'high' | 'medium' | 'low' = 'low';
  let assessmentSummary = '';
  let recommendation = '';

  if (isThreatened) {
    if (margin <= -10) {
      riskLevel = 'critical';
      assessmentSummary = `CRITICAL RETRO-DECRYPTION RISK: Your data security shelf-life (${S} years) combined with infrastructure transition time (${Y} years) exceeds the quantum horizon (${Z} years) by a deficit of ${Math.abs(margin)} years.`;
      recommendation = `Symmetric key length must be upgraded to 256-bit immediately to resist Grover's algorithm. Deploy hybrid KEMs (ML-KEM/Kyber) on high-criticality assets now to stop Store-Now, Decrypt-Later (SNDL) attacks.`;
    } else {
      riskLevel = 'high';
      assessmentSummary = `HIGH RETRO-DECRYPTION RISK: A quantum computer is projected to exist before your historical encrypted data naturally expires, with a deficit of ${Math.abs(margin)} years.`;
      recommendation = `Begin piloting hybrid key exchange in TLS sessions. Prioritize inventorying root certificate authorities for replacement.`;
    }
  } else {
    if (margin <= 5) {
      riskLevel = 'medium';
      assessmentSummary = `MODERATE RISK: You have a slim security margin of only ${margin} years before quantum computers threaten your data confidentiality timeline.`;
      recommendation = `Establish a dedicated Post-Quantum cryptographic inventory. Ensure all new software procurements require quantum-safe agility.`;
    } else {
      riskLevel = 'low';
      assessmentSummary = `LOW RISK: Your security buffer is currently stable at ${margin} years. Your cryptographic migration is projected to finish before quantum decryption is realized.`;
      recommendation = `Continue executing your migration roadmap. Monitor global standards updates (e.g. NIST drafts, CNSA 2.0 timelines).`;
    }
  }

  return {
    shelfLife: S,
    migrationTime: Y,
    collapseTime: Z,
    margin,
    isThreatened,
    priorityScore,
    riskLevel,
    assessmentSummary,
    recommendation
  };
}
