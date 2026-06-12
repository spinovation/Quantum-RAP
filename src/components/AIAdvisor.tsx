import React, { useState, useRef, useEffect } from 'react';
import { 
  Bot, 
  Send, 
  Copy, 
  Terminal, 
  Code,
  Check,
  Server
} from 'lucide-react';

interface ChatMessage {
  sender: 'user' | 'ai';
  text: string;
  code?: string;
  language?: string;
}

interface Playbook {
  id: string;
  title: string;
  description: string;
  category: 'config' | 'code';
  icon: React.ComponentType<any>;
  code: string;
  language: string;
}

export const AIAdvisor: React.FC = () => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'ai',
      text: 'Hello, I am QuarkShield AI, your Post-Quantum Cryptographic Remediation Advisor. I can generate quantum-safe configurations, draft language snippets, and guide your infrastructure transition. Ask me a question or click a playbook on the right!'
    }
  ]);
  const [inputText, setInputText] = useState('');
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('ssh');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  
  const chatHistoryRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (chatHistoryRef.current) {
      chatHistoryRef.current.scrollTop = chatHistoryRef.current.scrollHeight;
    }
  }, [messages]);

  const playbooks: Playbook[] = [
    {
      id: 'ssh',
      title: 'OpenSSH Post-Quantum config',
      description: 'Enforce Streamlined NTRU Prime hybrid key exchange in sshd_config.',
      category: 'config',
      icon: Terminal,
      language: 'nginx',
      code: `# /etc/ssh/sshd_config
# Enforce sntrup761 hybrid post-quantum key exchange (standard in OpenSSH 9.0+)
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org

# Enforce secure symmetric ciphers (resisting Grover's search)
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com

# Enforce secure MACs
MACs hmac-sha2-512-etm@openssh.com`
    },
    {
      id: 'nginx',
      title: 'Nginx OQS (Open Quantum Safe) TLS',
      description: 'Configure Nginx with OQS library for hybrid ML-KEM/Kyber TLS 1.3.',
      category: 'config',
      icon: Server,
      language: 'nginx',
      code: `# nginx.conf snippet
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
}`
    },
    {
      id: 'go',
      title: 'Go (Golang) ML-KEM exchange',
      description: 'Configure standard Go tls.Config with ML-KEM post-quantum curves.',
      category: 'code',
      icon: Code,
      language: 'go',
      code: `package main

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
}`
    },
    {
      id: 'rust',
      title: 'Rust ML-DSA key generation',
      description: 'Generate keys and sign messages using Rust module-lattice cryptography.',
      category: 'code',
      icon: Code,
      language: 'rust',
      code: `// Cargo.toml: pqcrypto-ml-dsa = "0.1"
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
}`
    }
  ];

  const handleSend = async (customText?: any) => {
    const text = (typeof customText === 'string' ? customText : inputText).trim();
    if (!text) return;

    const userMsg: ChatMessage = { sender: 'user', text };
    const updatedMessages = [...messages, userMsg];
    setMessages(updatedMessages);
    
    if (typeof customText !== 'string') {
      setInputText('');
    }

    // Add temporary loading indicator bubble
    const loadingMsg: ChatMessage = { sender: 'ai', text: 'Typing...' };
    setMessages(prev => [...prev, loadingMsg]);

    try {
      const chatHistory = updatedMessages.slice(-10);
      const token = sessionStorage.getItem('quarkshield_token');

      const res = await fetch('/api/ai/chat', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ message: text, history: chatHistory })
      });

      if (res.status === 403) {
        const errData = await res.json();
        throw { isAuthError: true, message: errData.error || 'Access Denied.' };
      }

      if (!res.ok) {
        throw new Error(`AI Gateway responded with status ${res.status}`);
      }

      const data = await res.json();
      
      setMessages(prev => {
        const filtered = prev.filter(m => m.text !== 'Typing...');
        return [...filtered, {
          sender: 'ai',
          text: data.text || 'No response generated.',
          code: data.code,
          language: data.language || 'javascript'
        }];
      });

    } catch (err: any) {
      if (err.isAuthError) {
        setMessages(prev => {
          const filtered = prev.filter(m => m.text !== 'Typing...');
          return [...filtered, {
            sender: 'ai',
            text: `⚠️ Access Denied: ${err.message}`
          }];
        });
      } else {
        console.warn('Backend AI route failed, executing local rules-based fallback:', err);
      
      setTimeout(() => {
        let aiText = '';
        let aiCode = '';
        let aiLang = 'javascript';
        
        const query = text.toLowerCase();
        
        if (query.includes('ssh') || query.includes('openssh')) {
          aiText = 'To secure OpenSSH, you should prepend sntrup761x25519-sha512@openssh.com (a Streamlined NTRU Prime and Curve25519 hybrid) to your Key Exchange algorithms. This protects admin channels from retro-decryption. Here is the configuration to add:';
          aiCode = playbooks[0].code;
          aiLang = 'nginx';
        } else if (query.includes('nginx') || query.includes('tls') || query.includes('ciphers')) {
          aiText = 'For Nginx, you must use an Open Quantum Safe (OQS) build of OpenSSL. Ensure you enable TLSv1.3 and specify post-quantum hybrid groups like X25519+MLKEM768 or secp384r1+MLKEM1024. Here is a configuration snippet:';
          aiCode = playbooks[1].code;
          aiLang = 'nginx';
        } else if (query.includes('go') || query.includes('golang') || query.includes('kem')) {
          aiText = 'In Go (since version 1.24), you can utilize native TLS post-quantum groups in tls.Config. Set CurvePreferences to prioritize ML-KEM hybrids. Here is how:';
          aiCode = playbooks[2].code;
          aiLang = 'go';
        } else if (query.includes('rust') || query.includes('signature') || query.includes('dsa') || query.includes('dilithium')) {
          aiText = 'For signatures and code-signing in Rust, the pqcrypto-ml-dsa crate offers bindings to standard lattice signature algorithms. Here is a key generation and signing snippet:';
          aiCode = playbooks[3].code;
          aiLang = 'rust';
        } else if (query.includes('shor') || query.includes('factor') || query.includes('math')) {
          aiText = "Shor's algorithm is a quantum computer algorithm that solves integer factorization and discrete logarithms in O((log N)³) polynomial time. This breaks RSA and ECC because classical cryptography relies on these math problems being exponential. Lattice-based cryptography (like ML-KEM/Kyber) relies on high-dimensional vector space lattice problems (like Shortest Vector Problem), which Shor's algorithm cannot solve efficiently.";
        } else if (query.includes('grover') || query.includes('symmetric') || query.includes('aes')) {
          aiText = "Grover's algorithm searches an unsorted database of N elements in O(√N) steps. When applied to symmetric keys (AES), it effectively halves the key size security (AES-128 becomes 64-bit strength, which is vulnerable). To mitigate this, CNSA 2.0 requires migrating to AES-256, providing a robust 128-bit quantum security buffer.";
        } else {
          aiText = "I can guide you on securing your environment. Try asking: \n* 'How do I configure OpenSSH for post-quantum security?'\n* 'How do Nginx OQS hybrids work?'\n* 'Explain the difference between Shor's and Grover's algorithms.'\n* 'Provide a Golang post-quantum TLS snippet.'";
        }

        setMessages(prev => {
          const filtered = prev.filter(m => m.text !== 'Typing...');
          return [...filtered, {
            sender: 'ai',
            text: aiText,
            code: aiCode || undefined,
            language: aiLang
          }];
        });
      }, 500);
      }
    }
  };

  const handleCopy = (codeText: string, id: string) => {
    navigator.clipboard.writeText(codeText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Mount effect to check for preloaded remediation advice query from other tabs (e.g. CMDB Correlation blueprint)
  useEffect(() => {
    const preloadedQuery = sessionStorage.getItem('preloaded_advisor_query');
    if (preloadedQuery) {
      sessionStorage.removeItem('preloaded_advisor_query');
      handleSend(preloadedQuery);
    }
  }, []);

  const activePlaybook = playbooks.find(p => p.id === selectedPlaybookId) || playbooks[0];

  return (
    <>
      <div>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>AI Remediation Hub</h2>
        <p>Interactive post-quantum remediation playbooks and virtual security advisor.</p>
      </div>

      <div className="ai-advisor-layout">
        {/* Chat Console */}
        <div className="chat-console">
          <div className="panel-header" style={{ background: 'rgba(0,0,0,0.1)' }}>
            <h3 style={{ fontSize: '1.05rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Bot size={18} color="var(--accent-cyan)" /> Virtual Cryptography Advisor
            </h3>
            <span style={{ fontSize: '0.75rem', color: 'var(--status-secure)' }}>● Online</span>
          </div>

          <div className="chat-history" ref={chatHistoryRef}>
            {messages.map((msg, i) => (
              <div key={i} className={`chat-bubble ${msg.sender}`}>
                <div style={{ whiteSpace: 'pre-line' }}>{msg.text}</div>
                {msg.code && (
                  <div style={{ marginTop: '0.75rem', position: 'relative' }}>
                    <div className="code-viewer">
                      <button 
                        className="code-copy-btn"
                        onClick={() => handleCopy(msg.code!, `msg-c-${i}`)}
                      >
                        {copiedId === `msg-c-${i}` ? <Check size={12} /> : <Copy size={12} />}
                      </button>
                      <pre><code>{msg.code}</code></pre>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="chat-input-area">
            <input 
              type="text" 
              className="chat-text-input" 
              placeholder="Ask how to migrate keys, secure ciphers, or code PQC..." 
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            />
            <button className="btn-primary" style={{ padding: '0.75rem' }} onClick={handleSend}>
              <Send size={18} />
            </button>
          </div>
        </div>

        {/* Playbook Pane */}
        <div className="playbook-pane">
          <h3 style={{ fontSize: '1.1rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Terminal size={18} color="var(--accent-cyan)" /> Post-Quantum Playbooks
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1.5rem' }}>
            {playbooks.map(playbook => {
              const Icon = playbook.icon;
              return (
                <div 
                  key={playbook.id} 
                  onClick={() => setSelectedPlaybookId(playbook.id)}
                  className={`glass-panel playbook-card ${selectedPlaybookId === playbook.id ? 'active' : ''}`}
                  style={{ 
                    borderLeft: selectedPlaybookId === playbook.id ? '3px solid var(--accent-cyan)' : '1px solid var(--border-normal)',
                    background: selectedPlaybookId === playbook.id ? 'var(--bg-card-hover)' : 'var(--bg-card)'
                  }}
                >
                  <div className="playbook-header">
                    <Icon size={16} />
                    <span className="playbook-title">{playbook.title}</span>
                    <span className="badge info" style={{ fontSize: '0.65rem', padding: '0.05rem 0.3rem', marginLeft: 'auto' }}>
                      {playbook.category}
                    </span>
                  </div>
                  <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>{playbook.description}</p>
                </div>
              );
            })}
          </div>

          {/* Active Playbook Code Viewer */}
          <div className="glass-panel" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.85rem', fontWeight: 600 }}>Active Workspace Snippet</span>
              <button 
                className="btn-secondary" 
                style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', gap: '0.25rem' }}
                onClick={() => handleCopy(activePlaybook.code, 'pbc')}
              >
                {copiedId === 'pbc' ? (
                  <>
                    <Check size={12} color="var(--status-secure)" /> Copied!
                  </>
                ) : (
                  <>
                    <Copy size={12} /> Copy Code
                  </>
                )}
              </button>
            </div>
            
            <div className="code-viewer" style={{ maxHeight: '320px' }}>
              <pre><code>{activePlaybook.code}</code></pre>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};
