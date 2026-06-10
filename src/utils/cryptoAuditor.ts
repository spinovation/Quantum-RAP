export interface AuditResult {
  id: string;
  type: 'certificate' | 'ssh_key' | 'private_key' | 'config' | 'url';
  name: string;
  algorithm: string;
  keySize?: number;
  hashAlgorithm?: string;
  isVulnerable: boolean;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure';
  status: 'Quantum Vulnerable' | 'Quantum Mapped' | 'Post-Quantum Secure';
  description: string;
  recommendation: string;
  explainer: string;
  complianceViolations: string[];
}

export interface LineViolation {
  lineNumber: number;
  lineContent: string;
  issue: string;
  riskLevel: 'critical' | 'high' | 'medium';
  recommendation: string;
}

export interface ConfigAuditResult {
  fileName: string;
  isVulnerable: boolean;
  violations: LineViolation[];
  summary: string;
  recommendation: string;
}

// Helper: Estimate RSA key size from base64 length in SSH public keys
function estimateRsaKeySize(base64Str: string): number {
  const byteLen = (base64Str.length * 3) / 4;
  if (byteLen > 500) return 4096;
  if (byteLen > 250) return 2048;
  return 1024;
}

/**
 * Audits an SSH public key string (e.g. ssh-rsa AAAAB3...)
 */
export function auditSSHKey(keyString: string, label = 'SSH Public Key'): AuditResult {
  const cleanKey = keyString.trim();
  const parts = cleanKey.split(/\s+/);
  
  if (parts.length < 2) {
    return {
      id: Math.random().toString(36).substring(7),
      type: 'ssh_key',
      name: label,
      algorithm: 'Unknown',
      isVulnerable: true,
      riskLevel: 'critical',
      status: 'Quantum Vulnerable',
      description: 'Invalid or malformed SSH public key format.',
      recommendation: 'Ensure key is in format: "ssh-rsa <base64> [comment]".',
      explainer: 'Malformed key headers cannot be audited for cryptography.',
      complianceViolations: ['RFC 4253']
    };
  }

  const keyType = parts[0];
  const base64Data = parts[1];
  const comment = parts.slice(2).join(' ') || 'Unnamed Asset';
  
  let algorithm = 'Unknown';
  let keySize: number | undefined = undefined;
  let isVulnerable = true;
  let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure' = 'high';
  let description = '';
  let recommendation = '';
  let explainer = '';
  let complianceViolations: string[] = [];

  switch (keyType) {
    case 'ssh-rsa':
      algorithm = 'RSA';
      keySize = estimateRsaKeySize(base64Data);
      isVulnerable = true;
      riskLevel = keySize < 2048 ? 'critical' : 'high';
      description = `Vulnerable SSH public key utilizing the RSA-${keySize} algorithm.`;
      recommendation = `Replace with a Post-Quantum digital signature key (e.g. ML-DSA) or at minimum a hybrid key (e.g. sntrup761x25519-sha512@openssh.com).`;
      explainer = `RSA relies on the mathematical difficulty of integer factorization. Shor's algorithm on a quantum computer can factor RSA integers in polynomial time ($O(n^3)$), completely breaking RSA encryption and signatures of any key size.`;
      complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];
      break;

    case 'ssh-dss':
      algorithm = 'DSA';
      keySize = 1024;
      isVulnerable = true;
      riskLevel = 'critical';
      description = 'Legacy SSH public key using the highly insecure DSA algorithm.';
      recommendation = 'Delete this key immediately. Replace with post-quantum equivalents (ML-DSA).';
      explainer = 'DSA is classically insecure and completely broken by Shor\'s algorithm for discrete logarithms on a quantum computer.';
      complianceViolations = ['NIST SP 800-131A', 'CNSA 2.0', 'EO 14028'];
      break;

    case 'ecdsa-sha2-nistp256':
    case 'ecdsa-sha2-nistp384':
    case 'ecdsa-sha2-nistp521':
      algorithm = 'ECDSA';
      keySize = keyType.includes('nistp256') ? 256 : keyType.includes('nistp384') ? 384 : 521;
      isVulnerable = true;
      riskLevel = 'high';
      description = `Elliptic Curve Digital Signature Algorithm (ECDSA) public key on NIST curve P-${keySize}.`;
      recommendation = `Replace with a NIST-approved post-quantum signature algorithm (ML-DSA/Dilithium) to ensure quantum resistance.`;
      explainer = `Elliptic Curve Cryptography (ECC) relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP). Shor's algorithm breaks ECDLP even faster than RSA, rendering all standard ECC curves completely vulnerable to quantum decryption.`;
      complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];
      break;

    case 'ssh-ed25519':
      algorithm = 'Ed25519';
      keySize = 256;
      isVulnerable = true;
      riskLevel = 'high'; // High because it's vulnerable to Shor's, even though it's classically preferred
      description = 'Modern classical Elliptic Curve Signature (Ed25519) public key.';
      recommendation = 'Deploy hybrid post-quantum wrappers or plan direct migration to ML-DSA.';
      explainer = 'While Ed25519 offers excellent classical performance and security, it uses elliptic curves and is entirely vulnerable to quantum discrete logarithm solvers (Shor\'s algorithm).';
      complianceViolations = ['CNSA 2.0', 'NIST SP 800-219'];
      break;

    // Post-quantum or hybrid (OpenSSH support)
    case 'sntrup761x25519-sha512@openssh.com':
      algorithm = 'sntrup761-x25519 (Hybrid)';
      keySize = 858; // sntrup761 key length plus x25519
      isVulnerable = false;
      riskLevel = 'secure';
      description = 'Quantum-safe hybrid key exchange algorithm combining Streamlined NTRU Prime 761 and Curve25519.';
      recommendation = 'Maintain deployment. This represents the current gold-standard for OpenSSH hybrid PQC transition.';
      explainer = 'This is a hybrid algorithm. Even if NTRU is broken, Curve25519 secures it classically; if Curve25519 is broken by a quantum computer, the Streamlined NTRU Prime lattice-based algorithm protects the session.';
      complianceViolations = [];
      break;

    default:
      if (keyType.toLowerCase().includes('ml-dsa') || keyType.toLowerCase().includes('dilithium')) {
        algorithm = 'ML-DSA';
        isVulnerable = false;
        riskLevel = 'secure';
        description = 'NIST Standard Post-Quantum Digital Signature Algorithm (ML-DSA).';
        recommendation = 'Secure. Keep monitored.';
        explainer = 'ML-DSA is based on the hardness of lattice problems (specifically Module Learning With Errors - M-LWE), which are currently resistant to both classical and quantum algorithms.';
        complianceViolations = [];
      } else {
        algorithm = keyType;
        isVulnerable = true;
        riskLevel = 'medium';
        description = `Custom or unidentified SSH key algorithm: ${keyType}.`;
        recommendation = 'Review key specifications and migrate to ML-DSA.';
        explainer = 'Unrecognized asymmetric cryptosystems should be assumed vulnerable to quantum Shor\'s solver unless verified as lattice-based or hash-based signature schemes.';
        complianceViolations = ['NIST SP 800-219'];
      }
  }

  return {
    id: Math.random().toString(36).substring(7),
    type: 'ssh_key',
    name: comment,
    algorithm,
    keySize,
    isVulnerable,
    riskLevel,
    status: isVulnerable ? 'Quantum Vulnerable' : 'Post-Quantum Secure',
    description,
    recommendation,
    explainer,
    complianceViolations
  };
}

/**
 * Audits a raw PEM certificate or public/private key file
 */
export function auditPEMCertificate(pemString: string, label = 'PEM Certificate'): AuditResult {
  const cleanPem = pemString.trim();
  let algorithm = 'Unknown';
  let keySize = 2048;
  let isVulnerable = true;
  let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'secure' = 'high';
  let description = '';
  let recommendation = '';
  let explainer = '';
  let complianceViolations: string[] = [];
  let type: 'certificate' | 'private_key' = 'certificate';

  if (cleanPem.includes('PRIVATE KEY')) {
    type = 'private_key';
  }

  // Parse details using regex heuristics over base64 string
  if (cleanPem.includes('BEGIN CERTIFICATE') || cleanPem.includes('BEGIN PUBLIC KEY') || cleanPem.includes('BEGIN PRIVATE KEY') || cleanPem.includes('BEGIN RSA')) {
    // Check if it's RSA or EC
    const base64Body = cleanPem.replace(/-----BEGIN[^-]+-----/, '').replace(/-----END[^-]+-----/, '').replace(/\s+/g, '');
    
    // Simple heuristics based on length and patterns:
    if (cleanPem.includes('RSA') || base64Body.length > 500) {
      algorithm = 'RSA';
      keySize = base64Body.length > 1000 ? 4096 : base64Body.length > 600 ? 2048 : 1024;
      isVulnerable = true;
      riskLevel = keySize < 2048 ? 'critical' : 'high';
      description = `Quantum-vulnerable ${type === 'private_key' ? 'Private Key' : 'TLS Certificate'} utilizing the RSA-${keySize} algorithm.`;
      recommendation = `Migrate to a Post-Quantum Key Encapsulation (ML-KEM/Kyber) for encryption, and ML-DSA (Dilithium) for authentication/signatures.`;
      explainer = `Shor's algorithm can easily factor large integers in polynomial time. A cryptanalyst with a Cryptographically Relevant Quantum Computer (CRQC) can decrypt historical traffic captured today (Store Now, Decrypt Later - SNDL).`;
      complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];
    } else {
      // Assume Elliptic Curve
      algorithm = 'ECDSA / ECDH';
      keySize = base64Body.length > 300 ? 384 : 256;
      isVulnerable = true;
      riskLevel = 'high';
      description = `Quantum-vulnerable Elliptic Curve ${type === 'private_key' ? 'Key' : 'Certificate'} (likely NIST P-${keySize} or Curve25519).`;
      recommendation = `Replace certificate with a hybrid TLS certificate (e.g. ML-KEM + ECDH) and migrate root authorities to ML-DSA.`;
      explainer = `Elliptic Curve discrete logarithms are highly susceptible to Shor's algorithm. Because EC keys are smaller, they actually require fewer qubits to break than RSA keys of equivalent classical strength.`;
      complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];
    }
  } else {
    // Malformed PEM
    return {
      id: Math.random().toString(36).substring(7),
      type: 'certificate',
      name: label,
      algorithm: 'Unknown',
      isVulnerable: true,
      riskLevel: 'critical',
      status: 'Quantum Vulnerable',
      description: 'The uploaded file is not a valid PEM encoded asset.',
      recommendation: 'Please upload files beginning with "-----BEGIN CERTIFICATE-----" or similar headers.',
      explainer: 'Failed to verify file encoding.',
      complianceViolations: ['RFC 7468']
    };
  }

  return {
    id: Math.random().toString(36).substring(7),
    type,
    name: label,
    algorithm,
    keySize,
    isVulnerable,
    riskLevel,
    status: isVulnerable ? 'Quantum Vulnerable' : 'Post-Quantum Secure',
    description,
    recommendation,
    explainer,
    complianceViolations
  };
}

/**
 * Audits a server configuration file (Nginx, Apache, OpenSSH)
 */
export function auditConfigFile(fileName: string, content: string): ConfigAuditResult {
  const lines = content.split('\n');
  const violations: LineViolation[] = [];
  let isVulnerable = false;
  
  const lowerName = fileName.toLowerCase();
  
  if (lowerName.includes('nginx') || content.includes('ssl_ciphers') || content.includes('ssl_protocols')) {
    // Nginx Config Auditor
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const cleanLine = line.trim();
      
      // Check for TLS protocols
      if (cleanLine.startsWith('ssl_protocols')) {
        if (cleanLine.includes('TLSv1.0') || cleanLine.includes('TLSv1.1')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'Obsolete TLS versions (TLSv1.0/TLSv1.1) enabled.',
            riskLevel: 'critical',
            recommendation: 'Remove TLSv1 and TLSv1.1. Force TLSv1.3 and TLSv1.2 (for legacy backup).'
          });
        }
        if (!cleanLine.includes('TLSv1.3')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'TLSv1.3 is not explicitly enabled. TLSv1.3 is required for early adoption of post-quantum cipher suites.',
            riskLevel: 'high',
            recommendation: 'Update protocols to: "ssl_protocols TLSv1.2 TLSv1.3;"'
          });
        }
      }

      // Check for ciphers
      if (cleanLine.startsWith('ssl_ciphers')) {
        // Look for weak ciphers
        if (cleanLine.includes('RC4') || cleanLine.includes('3DES') || cleanLine.includes('DES') || cleanLine.includes('MD5')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'Classically broken symmetric algorithms (RC4, 3DES, MD5) enabled.',
            riskLevel: 'critical',
            recommendation: 'Replace cipher suite with modern, AEAD-only symmetric ciphers.'
          });
        }
        
        // Standard ciphers that aren't hybrid post-quantum
        if (!cleanLine.includes('X25519MLKEM768') && !cleanLine.includes('Kyber')) {
          // It's not necessarily "critical" classically, but it's quantum-vulnerable key exchange
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'No Post-Quantum key exchange (ML-KEM / Kyber) enabled in Nginx ssl_ciphers.',
            riskLevel: 'medium',
            recommendation: 'Deploy Open Quantum Safe (OQS) Nginx module and enable PQ/classical hybrids like "X25519+MLKEM768" or "secp384r1+MLKEM1024".'
          });
        }
      }
    });
  } else if (lowerName.includes('ssh') || content.includes('KexAlgorithms') || content.includes('Ciphers')) {
    // OpenSSH Config Auditor
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const cleanLine = line.trim();
      
      if (cleanLine.startsWith('KexAlgorithms')) {
        if (cleanLine.includes('diffie-hellman-group1-sha1') || cleanLine.includes('diffie-hellman-group14-sha1')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'SHA-1 based Diffie-Hellman Key Exchange enabled.',
            riskLevel: 'critical',
            recommendation: 'Remove diffie-hellman-group1-sha1 immediately.'
          });
        }
        
        if (!cleanLine.includes('sntrup761x25519-sha512@openssh.com')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'Post-Quantum Key Exchange (sntrup761x25519) is not enabled.',
            riskLevel: 'medium',
            recommendation: 'Prepend "sntrup761x25519-sha512@openssh.com" to your KexAlgorithms parameter.'
          });
        }
      }

      if (cleanLine.startsWith('Ciphers')) {
        if (cleanLine.includes('3des-cbc') || cleanLine.includes('blowfish-cbc') || cleanLine.includes('aes128-cbc')) {
          isVulnerable = true;
          violations.push({
            lineNumber: lineNum,
            lineContent: cleanLine,
            issue: 'Weak symmetric ciphers or CBC modes enabled.',
            riskLevel: 'high',
            recommendation: 'Enforce AES-GCM or Chacha20-Poly1305. Prefer 256-bit modes (e.g. aes256-gcm@openssh.com) to mitigate Grover\'s search threat.'
          });
        }
      }
    });
  } else {
    // Generic Config Audit
    lines.forEach((line, index) => {
      const lineNum = index + 1;
      const cleanLine = line.trim().toLowerCase();
      
      if (cleanLine.includes('sha1') || cleanLine.includes('md5')) {
        isVulnerable = true;
        violations.push({
          lineNumber: lineNum,
          lineContent: line,
          issue: 'Reference to weak hash algorithms (MD5/SHA1) detected.',
          riskLevel: 'high',
          recommendation: 'Migrate to SHA-256, SHA-384, SHA-512, or SHA-3.'
        });
      }
      if (cleanLine.includes('rsa1024') || cleanLine.includes('rsa-1024') || (cleanLine.includes('rsa') && cleanLine.includes('1024'))) {
        isVulnerable = true;
        violations.push({
          lineNumber: lineNum,
          lineContent: line,
          issue: '1024-bit RSA key reference found (critically broken classically and quantum).',
          riskLevel: 'critical',
          recommendation: 'Upgrade to post-quantum signatures (ML-DSA) or at minimum RSA-4096.'
        });
      }
    });
  }

  const summary = isVulnerable 
    ? `Discovered ${violations.length} cryptography-related vulnerabilites in ${fileName}.`
    : `No obvious quantum-vulnerable configurations found in ${fileName}.`;

  const recommendation = isVulnerable
    ? `Update the configuration file to enforce post-quantum algorithms (like ML-KEM/Kyber or hybrid key exchanges) and disable obsolete ciphers/protocols.`
    : `Maintain the current configuration. Set up monitoring to audit for future compliance overrides.`;

  return {
    fileName,
    isVulnerable,
    violations,
    summary,
    recommendation
  };
}

/**
 * Simulates checking a URL's TLS configuration for post-quantum capability
 */
export async function simulateUrlScan(url: string): Promise<AuditResult> {
  // Simulate network delay
  await new Promise(resolve => setTimeout(resolve, 1500));
  
  const domain = url.replace(/https?:\/\//, '').split('/')[0];
  
  // Decide results based on domain name (making it reactive to user inputs!)
  let algorithm = 'RSA-2048';
  let keySize = 2048;
  let isVulnerable = true;
  let riskLevel: 'critical' | 'high' | 'medium' | 'secure' = 'high';
  let status: 'Quantum Vulnerable' | 'Quantum Mapped' | 'Post-Quantum Secure' = 'Quantum Vulnerable';
  let description = '';
  let recommendation = '';
  let explainer = '';
  const complianceViolations = ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028'];

  if (domain.includes('cloudflare.com') || domain.includes('google.com')) {
    // Cloudflare and Google deploy hybrid X25519 + ML-KEM-768!
    algorithm = 'ML-KEM-768 / X25519 (Hybrid)';
    keySize = 768;
    isVulnerable = false;
    riskLevel = 'secure';
    status = 'Post-Quantum Secure';
    description = `Secure TLS handshake establishing a Post-Quantum Kyber/ML-KEM hybrid exchange with ${domain}.`;
    recommendation = `Excellent setup. Target server supports modern PQ ciphers natively. Keep monitored.`;
    explainer = `The handshake utilizes ML-KEM-768 (Module Lattice-based Key Encapsulation Mechanism) combined with Curve25519. This hybrid model protects against retro-decryption attacks by quantum adversaries while ensuring classical security standards.`;
    complianceViolations.length = 0; // No violations
  } else if (domain.includes('nist.gov') || domain.includes('gov')) {
    algorithm = 'ECDSA P-384 / SHA-384';
    keySize = 384;
    isVulnerable = true;
    riskLevel = 'high';
    status = 'Quantum Mapped'; // Under CNSA timeline
    description = `Quantum-vulnerable Elliptic Curve exchange (P-384) with ${domain}.`;
    recommendation = `Configure server to support post-quantum key exchange (ML-KEM-768) alongside standard ECDH.`;
    explainer = `While complying with current CNSA 1.0 government standards, P-384 elliptic curve discrete logarithms can be completely solved by Shor's algorithm on a quantum computer, breaking the confidentiality of the session.`;
    complianceViolations.push('CNSA 2.0 (Transition phase)');
  } else {
    // Default standard website
    algorithm = 'RSA-2048 / SHA-256';
    keySize = 2048;
    isVulnerable = true;
    riskLevel = 'high';
    status = 'Quantum Vulnerable';
    description = `Vulnerable RSA-2048 SSL certificate on host ${domain}.`;
    recommendation = `Replace current RSA certificate with a hybrid certificate, or configure the webserver to accept post-quantum key-exchange client requests (Chrome/Firefox Kyber standard).`;
    explainer = `RSA-2048 provides 112 bits of classical security, but zero quantum security. An adversary recording this handshake can decrypt it once a quantum computer with ~4000 logical qubits becomes available.`;
  }

  return {
    id: Math.random().toString(36).substring(7),
    type: 'url',
    name: domain,
    algorithm,
    keySize,
    isVulnerable,
    riskLevel,
    status,
    description,
    recommendation,
    explainer,
    complianceViolations
  };
}

/**
 * Returns a list of default mock assets for the inventory if none have been scanned yet
 */
export function getDefaultInventory(): AuditResult[] {
  return [
    {
      id: 'inv-1',
      type: 'certificate',
      name: 'production-ingress-wildcard',
      algorithm: 'RSA',
      keySize: 2048,
      isVulnerable: true,
      riskLevel: 'high',
      status: 'Quantum Vulnerable',
      description: 'Production ingress TLS certificate utilizing RSA-2048.',
      recommendation: 'Replace with a hybrid TLS certificate (ML-KEM + Classical).',
      explainer: 'RSA relies on integer factorization, which Shor\'s algorithm solves in $O(n^3)$ polynomial time. This exposes historical sessions to retro-decryption (SNDL threat).',
      complianceViolations: ['CNSA 2.0', 'NIST SP 800-219', 'EO 14028']
    },
    {
      id: 'inv-2',
      type: 'ssh_key',
      name: 'ci-cd-deployment-key',
      algorithm: 'Ed25519',
      keySize: 256,
      isVulnerable: true,
      riskLevel: 'high',
      status: 'Quantum Vulnerable',
      description: 'SSH deploy key used in GitHub actions pipeline.',
      recommendation: 'Upgrade OpenSSH on target servers and transition key to hybrid lattice-based algorithm.',
      explainer: 'Ed25519 is classically secure but uses elliptic curves. Elliptic curve discrete logarithms are easily computed on a quantum computer running Shor\'s algorithm.',
      complianceViolations: ['CNSA 2.0']
    },
    {
      id: 'inv-3',
      type: 'private_key',
      name: 'database-backup-sign-key',
      algorithm: 'RSA',
      keySize: 4096,
      isVulnerable: true,
      riskLevel: 'high',
      status: 'Quantum Vulnerable',
      description: 'Signing key for database backup integrity checks.',
      recommendation: 'Migrate integrity checks to post-quantum signatures (ML-DSA / Dilithium).',
      explainer: 'RSA-4096 signatures can be forged by a quantum computer that extracts the private signing key from the public key, enabling backdoors in historical backups.',
      complianceViolations: ['EO 14028']
    },
    {
      id: 'inv-4',
      type: 'ssh_key',
      name: 'admin-bastion-key-pqc',
      algorithm: 'sntrup761-x25519 (Hybrid)',
      keySize: 858,
      isVulnerable: false,
      riskLevel: 'secure',
      status: 'Post-Quantum Secure',
      description: 'Root access bastion key matching CNSA 2.0 standards.',
      recommendation: 'Maintain. This key is fully post-quantum compliant.',
      explainer: 'Streamlined NTRU Prime protects this session from quantum cryptanalysis. Even if quantum computers emerge, the lattice-based mathematics remain secure.',
      complianceViolations: []
    },
    {
      id: 'inv-5',
      type: 'certificate',
      name: 'legacy-api-client-cert',
      algorithm: 'RSA',
      keySize: 1024,
      isVulnerable: true,
      riskLevel: 'critical',
      status: 'Quantum Vulnerable',
      description: 'Obsolete client-certificate used by legacy microservices.',
      recommendation: 'Revoke and replace immediately. RSA-1024 is vulnerable classically and critically vulnerable quantum-wise.',
      explainer: 'RSA-1024 is at active risk of classical factorization and requires a fraction of the quantum capacity to break compared to RSA-2048.',
      complianceViolations: ['NIST SP 800-131A', 'CNSA 2.0', 'EO 14028']
    }
  ];
}
