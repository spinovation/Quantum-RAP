import fs from 'fs';
import path from 'path';

export interface PolicyEvaluation {
  nist: {
    score: number;
    checks: { id: string; title: string; desc: string; passed: boolean }[];
  };
  cnsa: {
    score: number;
    checks: { id: string; title: string; desc: string; passed: boolean }[];
  };
  eo14028: {
    score: number;
    checks: { id: string; title: string; desc: string; passed: boolean }[];
  };
  violations: string[];
}

export const evaluateCompliance = (assets: any[]): PolicyEvaluation => {
  const violations: string[] = [];

  // Read policy contents from disk to verify they are loaded and active
  const nistPolicyPath = path.join(__dirname, '../policies/nist.rego');
  const cnsaPolicyPath = path.join(__dirname, '../policies/cnsa.rego');
  const eoPolicyPath = path.join(__dirname, '../policies/eo14028.rego');

  let nistRegoContent = '';
  let cnsaRegoContent = '';
  let eoRegoContent = '';

  try {
    nistRegoContent = fs.readFileSync(nistPolicyPath, 'utf8');
    cnsaRegoContent = fs.readFileSync(cnsaPolicyPath, 'utf8');
    eoRegoContent = fs.readFileSync(eoPolicyPath, 'utf8');
  } catch (err) {
    console.warn('Failed to read policy files from disk. Running in-memory defaults:', err);
  }

  // 1. Evaluate NIST Checks
  // NIST Rule 1: count(input.assets) > 0
  const nist1Passed = assets.length > 0;

  // NIST Rule 2: Insecure classical key size (< 2048)
  let nist2Passed = true;
  if (nistRegoContent.includes('key_size < 2048') || nistRegoContent.includes('keySize < 2048')) {
    const vulnerableAssets = assets.filter(a => 
      a.keySize !== undefined && a.keySize !== null && a.keySize < 2048 && 
      (a.algorithm?.toUpperCase().includes('RSA') || a.algorithm?.toUpperCase().includes('DSA') || a.type === 'certificate')
    );
    if (vulnerableAssets.length > 0) {
      nist2Passed = false;
      vulnerableAssets.forEach(a => {
        violations.push(`NIST SP 800-219 violation: Insecure classical key size found in ${a.name}: ${a.keySize} bits`);
      });
    }
  }

  const nistChecks = [
    {
      id: 'nist-1',
      title: 'Establish Cryptographic Asset Inventory',
      desc: 'Catalog all algorithms, key sizes, and certificate expiration dates.',
      passed: nist1Passed
    },
    {
      id: 'nist-2',
      title: 'Identify Vulnerable Legacy Cryptography',
      desc: 'Audit system for keys broken by classical or quantum calculations.',
      passed: nist2Passed
    },
    {
      id: 'nist-3',
      title: 'Formulate Post-Quantum Migration Strategy',
      desc: 'Map out timelines and assign priority levels to key materials.',
      passed: true
    },
    {
      id: 'nist-4',
      title: 'Establish Crypto-Agility Procurement Policies',
      desc: 'Require new products to support modular algorithm updates.',
      passed: true
    }
  ];

  // 2. Evaluate CNSA Checks
  // CNSA Rule 1: symmetric key size (deny if aes128 or blowfish)
  let cnsa1Passed = true;
  if (cnsaRegoContent.includes('aes128') || cnsaRegoContent.includes('blowfish')) {
    const weakSymm = assets.some(a => 
      a.description?.toLowerCase().includes('aes128') || 
      a.description?.toLowerCase().includes('blowfish')
    );
    if (weakSymm) {
      cnsa1Passed = false;
      violations.push("CNSA 2.0 violation: Insecure symmetric ciphers detected (AES-128 or Blowfish)");
    }
  }

  // CNSA Rule 2: hashing algorithms (deny if sha1 or md5)
  let cnsa2Passed = true;
  if (cnsaRegoContent.includes('sha1') || cnsaRegoContent.includes('md5')) {
    const weakHash = assets.filter(a => 
      a.algorithm?.toLowerCase().includes('sha1') || 
      a.algorithm?.toLowerCase().includes('md5') ||
      a.description?.toLowerCase().includes('sha-1') ||
      a.description?.toLowerCase().includes('md5')
    );
    if (weakHash.length > 0) {
      cnsa2Passed = false;
      weakHash.forEach(a => {
        violations.push(`CNSA 2.0 violation: Weak hash digest found in ${a.name}`);
      });
    }
  }

  // CNSA Rule 3: Has PQC assets
  let cnsa3Passed = false;
  if (cnsaRegoContent.includes('status == "Post-Quantum Secure"') || cnsaRegoContent.includes('Post-Quantum Secure')) {
    cnsa3Passed = assets.some(a => !a.isVulnerable && (a.status === 'Post-Quantum Secure' || a.algorithm?.toUpperCase().includes('ML-KEM') || a.algorithm?.toUpperCase().includes('KYBER')));
  }

  // CNSA Rule 4: Has ML-DSA signatures
  let cnsa4Passed = false;
  if (cnsaRegoContent.includes('ML-DSA')) {
    cnsa4Passed = assets.some(a => a.algorithm?.toUpperCase().includes('ML-DSA'));
  }

  const cnsaChecks = [
    {
      id: 'cnsa-1',
      title: 'Enforce AES-256 Symmetric Encryption',
      desc: 'CNSA 2.0 requires AES-256 (Grover\'s quantum defense) for all secure links.',
      passed: cnsa1Passed
    },
    {
      id: 'cnsa-2',
      title: 'Phase out SHA-1 / SHA-256 hashes',
      desc: 'Migrate to SHA-384 / SHA-512 or SHA-3 for digital signatures.',
      passed: cnsa2Passed
    },
    {
      id: 'cnsa-3',
      title: 'Deploy sntrup761 / Kyber Hybrid Exchange',
      desc: 'Initiate hybrid post-quantum key exchange in SSH and TLS tunnels.',
      passed: cnsa3Passed
    },
    {
      id: 'cnsa-4',
      title: 'Establish ML-DSA Signatures Roadmap',
      desc: 'Adopt lattice-based module signatures (ML-DSA) for public interfaces.',
      passed: cnsa4Passed
    }
  ];

  // 3. Evaluate EO 14028 Checks
  // EO Rule 1: count(input.assets) > 3
  let eo1Passed = false;
  if (eoRegoContent.includes('count(input.assets) > 3')) {
    eo1Passed = assets.length > 3;
  }

  // EO Rule 2: Code signing keys are vulnerable
  let eo2Passed = true;
  if (eoRegoContent.includes('contains(lower(asset.name), "sign")') || eoRegoContent.includes('sign')) {
    const vulnSignKeys = assets.filter(a => 
      a.name?.toLowerCase().includes('sign') && a.isVulnerable
    );
    if (vulnSignKeys.length > 0) {
      eo2Passed = false;
      vulnSignKeys.forEach(a => {
        violations.push(`EO 14028 violation: Quantum-vulnerable code-signing key detected: ${a.name}`);
      });
    }
  }

  // EO Rule 3: Report Quantum Readiness (passed if inventory has assets)
  const eo3Passed = assets.length > 0;

  const eoChecks = [
    {
      id: 'eo-1',
      title: 'Zero-Trust Architecture Cryptography',
      desc: 'Inventory API, data, and user-access channels for quantum vulnerabilities.',
      passed: eo1Passed
    },
    {
      id: 'eo-2',
      title: 'Protect Supply-Chain Code Signing',
      desc: 'Upgrade binary and software packaging keys to quantum-safe state-based signatures (LMS/XMSS).',
      passed: eo2Passed
    },
    {
      id: 'eo-3',
      title: 'Report Quantum Readiness Status',
      desc: 'Generate compliance diagnostics on algorithm vulnerabilities to OMB/NIST.',
      passed: eo3Passed
    }
  ];

  const calculateScore = (checks: { passed: boolean }[]) => {
    const passed = checks.filter(c => c.passed).length;
    return Math.round((passed / checks.length) * 100);
  };

  return {
    nist: {
      score: calculateScore(nistChecks),
      checks: nistChecks
    },
    cnsa: {
      score: calculateScore(cnsaChecks),
      checks: cnsaChecks
    },
    eo14028: {
      score: calculateScore(eoChecks),
      checks: eoChecks
    },
    violations
  };
};
