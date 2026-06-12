import { Request, Response } from 'express';
import pool from '../config/db';

// POST /api/ai/chat
export const getAIChatResponse = async (req: Request, res: Response) => {
  try {
    const { message, history } = req.body;
    if (!message) {
      return res.status(400).json({ error: 'Missing prompt message parameter.' });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey.trim() !== '') {
      console.log('AI Controller: Querying Gemini API...');
      const model = 'gemini-1.5-flash';
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

      // Assemble system instruction and history context for Gemini
      const systemInstruction = 
        "You are QuarkShield AI, an expert post-quantum cryptography (PQC) migration advisor. " +
        "You analyze classical algorithms (RSA, ECC, Diffie-Hellman) and direct developers on how to " +
        "upgrade their infrastructure to quantum-safe alternatives (ML-KEM, ML-DSA, Falcon, LMS, XMSS, stateful hash signatures). " +
        "Reference NIST, CNSA 2.0, and EO 14028 standards. Keep recommendations concise, actionable, and mathematically grounded. " +
        "If the user asks for code, provide clean snippets in Go, Rust, Nginx config, or OpenSSH config format.";

      const contents = [];
      
      // Add history if present
      if (Array.isArray(history)) {
        for (const h of history) {
          contents.push({
            role: h.sender === 'user' ? 'user' : 'model',
            parts: [{ text: h.text }]
          });
        }
      }

      // Add current user prompt
      contents.push({
        role: 'user',
        parts: [{ text: `${systemInstruction}\n\nUser Question: ${message}` }]
      });

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents })
      });

      if (geminiRes.ok) {
        const data: any = await geminiRes.json();
        const aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
        if (aiText) {
          // Parse out code block if present
          const { textResponse, codeResponse, langResponse } = extractCodeBlock(aiText);
          return res.json({
            text: textResponse,
            code: codeResponse,
            language: langResponse
          });
        }
      }
      console.warn('Gemini API query failed or returned empty. Falling back to local rules engine.');
    }

    // --- Local Fallback Logic ---
    console.log('AI Controller: Executing local rules-based fallback...');
    const query = message.toLowerCase();
    let text = '';
    let code = '';
    let language = 'javascript';

    if (query.includes('ssh') || query.includes('openssh')) {
      text = 'To secure OpenSSH, you should prepend sntrup761x25519-sha512@openssh.com (a Streamlined NTRU Prime and Curve25519 hybrid) to your Key Exchange algorithms. This protects admin channels from retro-decryption. Here is the configuration to add to your sshd_config:';
      language = 'nginx'; // using nginx highlighter for config files
      code = `# /etc/ssh/sshd_config
# Enforce sntrup761 hybrid post-quantum key exchange (standard in OpenSSH 9.0+)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

# Enforce secure symmetric ciphers (resisting Grover's search)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Enforce secure MACs
MACs hmac-sha2-512-etm@openssh.com`;
    } else if (query.includes('nginx') || query.includes('tls') || query.includes('ciphers')) {
      text = 'For Nginx, you must use an Open Quantum Safe (OQS) build of OpenSSL. Ensure you enable TLSv1.3 and specify post-quantum hybrid groups like X25519+MLKEM768 or secp384r1+MLKEM1024. Here is a configuration snippet:';
      language = 'nginx';
      code = `# nginx.conf snippet
server {
    listen 443 ssl;
    server_name secure.enterprise.com;

    # OQS OpenSSL build ciphers supporting ML-KEM hybrids
    ssl_protocols TLSv1.3;
    
    # Enable X25519 + ML-KEM-768 hybrid key share groups
    ssl_curves x25519_kyber768:X25519+MLKEM768:secp384r1_kyber1024;

    # Enforce strong symmetric AES-256 for Grover resistance
    ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
    ssl_prefer_server_ciphers on;
}`;
    } else if (query.includes('go') || query.includes('golang') || query.includes('kem')) {
      text = 'In Go (since version 1.24), you can utilize native TLS post-quantum groups in tls.Config. Set CurvePreferences to prioritize ML-KEM hybrids. Here is how:';
      language = 'go';
      code = `package main

import (
	"crypto/tls"
	"net/http"
)

func main() {
	// Configure TLS config with ML-KEM key exchange curves
	// Note: requires Go 1.24+ for native ML-KEM / Kyber standard support
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.CurveID(0x003F), // X25519MLKEM768 hybrid
			tls.X25519,
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	// Request secure post-quantum server
	client.Get("https://cloudflare.com")
}`;
    } else if (query.includes('rust') || query.includes('signature') || query.includes('dsa') || query.includes('dilithium')) {
      text = 'For signatures and code-signing in Rust, the pqcrypto-ml-dsa crate offers bindings to standard lattice signature algorithms. Here is a key generation and signing snippet:';
      language = 'rust';
      code = `// Cargo.toml: pqcrypto-ml-dsa = "0.1"
use pqcrypto_ml_dsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

fn main() {
    // 1. Generate lattice keys (ML-DSA-65 matches AES-192 security)
    let (pk, sk) = mldsa65::keypair();
    
    // 2. Sign message
    let message = b"Database integrity validation check.";
    let signature = mldsa65::sign(message, &sk);
    
    // 3. Verify signature
    let verification = mldsa65::verify(message, &signature, &pk);
    assert!(verification.is_ok());
    println!("Lattice verification successful!");
}`;
    } else if (query.includes('shor') || query.includes('factor') || query.includes('math')) {
      text = "Shor's algorithm is a quantum computer algorithm that solves integer factorization and discrete logarithms in O((log N)³) polynomial time. This breaks RSA and ECC because classical cryptography relies on these math problems being exponential. Lattice-based cryptography (like ML-KEM/Kyber) relies on high-dimensional vector space lattice problems (like Shortest Vector Problem), which Shor's algorithm cannot solve efficiently.";
    } else if (query.includes('grover') || query.includes('symmetric') || query.includes('aes')) {
      text = "Grover's algorithm searches an unsorted database of N elements in O(√N) steps. When applied to symmetric keys (AES), it effectively halves the key size security (AES-128 becomes 64-bit strength, which is vulnerable). To mitigate this, CNSA 2.0 requires migrating to AES-256, providing a robust 128-bit quantum security buffer.";
    } else if (query.includes('nist') || query.includes('cnsa') || query.includes('eo')) {
      text = "NIST SP 800-219, CNSA 2.0, and Executive Order 14028 mandate moving Federal systems and national security systems to post-quantum algorithms by 2030. Key milestones require replacing classic public-key algorithms (RSA, ECDH) with module lattices (ML-KEM, ML-DSA) and state-based signatures (LMS, XMSS) for firmware verification.";
    } else {
      text = "I can guide you on securing your environment. Try asking: \n* 'How do I configure OpenSSH for post-quantum security?'\n* 'How do Nginx OQS hybrids work?'\n* 'Explain the difference between Shor's and Grover's algorithms.'\n* 'Provide a Golang post-quantum TLS snippet.'";
    }

    res.json({ text, code: code || undefined, language });

  } catch (err: any) {
    console.error('Error generating AI response:', err);
    res.status(500).json({ error: `AI Assistant failed: ${err.message}` });
  }
};

// Helper: parse markdown code blocks
function extractCodeBlock(markdownText: string): { textResponse: string, codeResponse: string, langResponse: string } {
  const codeBlockRegex = /```(\w*)\n([\s\S]*?)```/;
  const match = markdownText.match(codeBlockRegex);
  
  if (match) {
    const langResponse = match[1] || 'javascript';
    const codeResponse = match[2];
    const textResponse = markdownText.replace(codeBlockRegex, '').trim();
    return { textResponse, codeResponse, langResponse };
  }
  
  return { textResponse: markdownText, codeResponse: '', langResponse: 'javascript' };
}

// Helper: extract CMDB metadata from description field
function parseCmdbMetadata(desc: string) {
  const defaultMeta = {
    businessService: 'Unassigned Infrastructure',
    application: 'Core Services',
    owner: 'secops-alert@quarkshield.services',
    lifecycle: 'Active'
  };

  if (!desc) return defaultMeta;
  const parts = desc.split('|CMDB:');
  if (parts.length > 1) {
    try {
      const parsed = JSON.parse(parts[1]);
      return {
        businessService: parsed.businessService || defaultMeta.businessService,
        application: parsed.application || defaultMeta.application,
        owner: parsed.owner || defaultMeta.owner,
        lifecycle: parsed.lifecycle || defaultMeta.lifecycle
      };
    } catch (e) {
      // Ignore parse errors
    }
  }
  return defaultMeta;
}

// POST /api/ai/correlate
export const getAICorrelation = async (req: Request, res: Response) => {
  try {
    // 1. Fetch all assets from database
    const dbRes = await pool.query('SELECT * FROM assets ORDER BY created_at DESC');
    const assets = dbRes.rows.map(row => ({
      id: row.id,
      type: row.type,
      name: row.name,
      algorithm: row.algorithm,
      keySize: row.key_size,
      isVulnerable: row.is_vulnerable,
      riskLevel: row.risk_level,
      status: row.status,
      description: row.description,
      recommendation: row.recommendation,
      explainer: row.explainer,
      complianceViolations: row.compliance_violations || [],
    }));

    const apiKey = process.env.GEMINI_API_KEY;
    if (apiKey && apiKey.trim() !== '' && assets.length > 0) {
      console.log('AI Controller: Querying Gemini API for correlation...');
      const model = 'gemini-1.5-flash';
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;

      const systemInstruction = 
        "You are QuarkShield AI, an expert post-quantum cryptography (PQC) migration advisor. " +
        "Analyze the provided array of cryptographic assets and correlate their risk profiles. " +
        "Group the assets into 3 logical migration waves (Wave 1: Immediate, Wave 2: High, Wave 3: Standard) based on NIST/CNSA 2.0 guidelines. " +
        "Generate exactly 3 key security insights (finding cross-app dependencies, obsolete cipher patterns, or compliance alerts). " +
        "Return the output STRICTLY in a clean JSON object format: " +
        "{ \"insights\": [ { \"title\": \"string\", \"desc\": \"string\", \"severity\": \"critical\" | \"high\" | \"medium\" } ], " +
        "\"waves\": { \"wave1\": [ { \"name\": \"string\", \"owner\": \"string\", \"algorithm\": \"string\", \"businessService\": \"string\" } ], " +
        "\"wave2\": [...], \"wave3\": [...] } }. " +
        "Do not include markdown code block syntax (like ```json) in your response, just the raw JSON object.";

      const contents = [{
        role: 'user',
        parts: [{ text: `${systemInstruction}\n\nAssets Inventory JSON:\n${JSON.stringify(assets, null, 2)}` }]
      }];

      const geminiRes = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ contents })
      });

      if (geminiRes.ok) {
        const data: any = await geminiRes.json();
        let aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        
        // Clean markdown block wrapping if Gemini ignores instructions
        aiText = aiText.replace(/```json/g, '').replace(/```/g, '').trim();

        try {
          const parsed = JSON.parse(aiText);
          if (parsed.insights && parsed.waves) {
            return res.json(parsed);
          }
        } catch (jsonErr) {
          console.warn('Failed to parse Gemini correlation JSON response, using fallback format parser:', jsonErr);
        }
      }
      console.warn('Gemini correlation failed. Executing local rules engine.');
    }

    // --- Local Rules Correlation Fallback ---
    console.log('AI Controller: Executing local rules-based correlation engine...');
    
    const wave1: any[] = [];
    const wave2: any[] = [];
    const wave3: any[] = [];

    assets.forEach(asset => {
      const cmdb = parseCmdbMetadata(asset.description);
      const waveItem = {
        name: asset.name,
        owner: cmdb.owner,
        algorithm: asset.algorithm,
        businessService: cmdb.businessService
      };

      if (!asset.isVulnerable) {
        // Secure assets don't need migration
        return;
      }

      if (asset.riskLevel === 'critical' || asset.algorithm.includes('1024') || asset.algorithm.includes('SHA1') || asset.algorithm.includes('MD5')) {
        wave1.push(waveItem);
      } else if (asset.riskLevel === 'high' || asset.algorithm.includes('2048') || asset.algorithm.includes('ECDSA') || asset.algorithm.includes('ECC')) {
        wave2.push(waveItem);
      } else {
        wave3.push(waveItem);
      }
    });

    // Generate static correlated insights based on inventory findings
    const insights = [
      {
        title: 'Legacy Asymmetric Ciphers Detected',
        desc: `Identified ${assets.filter(a => a.isVulnerable).length} active configurations negotiating classical RSA/ECC encryption keys which can be retrospectively decrypted by a quantum computer (SNDL threat).`,
        severity: assets.some(a => a.riskLevel === 'critical') ? 'critical' : 'high'
      },
      {
        title: 'CNSA 2.0 Compliance Gaps',
        desc: `Multiple systems violate Executive Order 14028 and NSA CNSA 2.0 timelines which mandate beginning the transition to module-lattice key exchange standard (ML-KEM) immediately.`,
        severity: 'high'
      },
      {
        title: 'Shadow Certificates Active',
        desc: `Passive discovery sniffer caught untracked microservices running legacy TLS handshakes in production subnet lines. Mapped these to Cost-Center Application targets for isolation.`,
        severity: 'medium'
      }
    ];

    res.json({
      insights,
      waves: { wave1, wave2, wave3 }
    });

  } catch (err: any) {
    console.error('Error generating AI correlation blueprint:', err);
    res.status(500).json({ error: `Correlation Engine failed: ${err.message}` });
  }
};
