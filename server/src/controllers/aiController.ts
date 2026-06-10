import { Request, Response } from 'express';

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
