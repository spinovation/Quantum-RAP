# QuarkShield User Operations Guide
### Post-Quantum Risk Management & Migration Guide

Welcome to **QuarkShield**, your dedicated post-quantum security assessment portal. This guide outlines the purpose, step-by-step usage, and expected results for each of the core modules in your private environment.

---

## 1. Cryptographic Scan Terminal (Crypto Scanner)

The scan terminal allows security administrators to ingest, inspect, and audit cryptographic assets across files, configurations, and remote domain handshakes.

### A. File Discovery (Public Keys & Certificates)
*   **How to Use:**
    1. Navigate to the **Crypto Scanner** tab in the sidebar.
    2. Click **Scan File / Key** and drop an SSH public key file (e.g., `id_rsa.pub`, `id_ed25519.pub`) or a PEM/DER X.509 certificate file into the upload zone. Alternatively, paste the raw string directly into the text editor.
    3. Click **Discover Cryptographic Assets**.
*   **Expected Results:**
    *   **RSA / DSA / ECDSA:** Categorized as **Legacy (Vulnerable)**. The scanner extracts key sizes (e.g., 2048-bit, 4096-bit) and curves (e.g., P-256) and logs a critical Shor's vulnerability warning.
    *   **Ed25519:** Categorized as **Pre-Quantum secure (High Strength)**, suitable for temporary use but requiring eventual PQC planning.
    *   **ML-KEM / ML-DSA:** Categorized as **Post-Quantum Secure**.

### B. Configuration Linting (Server Audit)
*   **How to Use:**
    1. Click **Scan Configuration File**.
    2. Upload an active server configuration file, such as an Nginx configuration (`nginx.conf`) or an OpenSSH daemon config (`sshd_config`).
    3. Click **Execute Configuration Lint**.
*   **Expected Results:**
    *   Line-by-line inspection of enabled ciphers, key exchange algorithms (KEX), and protocol versions.
    *   Highlights insecure protocols (e.g., TLS 1.0, TLS 1.1) and legacy ciphers (e.g., `ecdhe-rsa-aes128-sha`).
    *   Suggests replacements like hybrid KEX (e.g., `x25519-kyber-512`) and secure parameters.

### C. Live Remote Handshake (TLS Endpoint Scan)
*   **How to Use:**
    1. Click **Scan TLS Endpoint**.
    2. Enter a target domain URL (e.g., `https://google.com` or `https://quarkshield.services`).
    3. Click **Initiate Secure Handshake**.
*   **Expected Results:**
    *   Establishes a real TLS socket connection to inspect the certificate chain and negotiated parameters.
    *   Returns the active Cipher Suite, Key Share, and SSL Protocol Version.
    *   Fails over to a simulated PQC hybrid handshake if the remote host doesn't support ML-KEM key shares natively.

---

## 2. Vulnerability Registry (Asset Inventory)

The registry acts as the single source of truth for all audited public keys, certificates, server configurations, and domains.

### A. Registry Architecture & Data Flow
*   **Data Storage:** All cryptographic asset metadata is stored inside a private, physically isolated PostgreSQL database (`assets` table) unique to your organization's tenant stack.
*   **Search Mechanics:** When you type in the search bar, the UI performs a real-time, client-side search across your inventory. Search queries match against the asset's **Name**, **Algorithm Suite**, and **Quantum Posture Status**.
*   **Bootstrapping:** If your inventory is empty upon initialization, the registry automatically bootstraps a default mock inventory of common enterprise assets so you have actionable examples to explore right away.

### B. Outbound Scan Consent & Safety Guarantee
QuarkShield is designed with strict boundaries to protect internal corporate environments:
*   **No Background Scanning:** There are **zero automated backend scripts, crawlers, or silent background scanner daemons** running on our platform. The database only updates when you explicitly trigger a scan or push certificate data.
*   **Outbound Activity Disclosures:**
    *   **TLS Endpoint Scanner:** Establishes a direct outbound TCP/TLS socket connection from the QuarkShield server to your specified host on port 443. It performs a standard TLS client handshake to negotiate cipher ciphers and check cert expiration. No HTTP headers or request bodies are sent, and no application payload data is read.
    *   **HashiCorp Vault PKI Sync:** Makes a secure outbound HTTP GET call to your Vault REST endpoint carrying your secret token. It fetches the certificate serial list and parses certificate PEM values. The Vault token is processed strictly in-memory during sync and is **never** saved to our database or logged.
    *   **Microsoft ADCS Sync:** Uses an **inbound-only push architecture**. QuarkShield does *not* contact your Active Directory or CA server. Instead, you run the provided PowerShell script locally to read CA metadata, which then posts an authenticated JSON payload to our server.
*   **Manual Consent Checks:** To prevent accidental network triggers, outbound requests (TLS Scans and Vault Syncs) are gated behind an **Explicit Consent Checkbox** (e.g., *'I authorize QuarkShield to make this outbound TLS handshake request'*). Trigger buttons remain disabled until checked.

### C. Usage & Expected Results
*   **How to Use:**
    1. Navigate to the **Overview** page for a high-level summary of your readiness ratio, algorithm distribution, and key-strength breakdowns.
    2. Go to the **Asset Inventory** tab in the sidebar.
    3. Use the search bar to filter assets by name, host, or algorithm (e.g., "RSA").
    4. Click the filter badges to narrow down by risk level (**Critical**, **High**, **Medium**, **Secure**).
    5. Click the **View Analysis** link on any asset row.
*   **Expected Results:**
    *   An interactive modal drawer opens containing a detailed mathematical explanation of why the asset is vulnerable:
        *   **Shor's Algorithm:** Describes how a quantum computer factorizes integers (RSA) or solves discrete logarithms (ECDSA) in polynomial time ($O(n^3)$).
        *   **Grover's Algorithm:** Explains the square-root speedup ($O(\sqrt{N})$) that reduces symmetric encryption and hash strengths (requiring upgrades to SHA-3 or larger parameters).
    *   Specific remediation steps customized for that asset's type.

---

## 3. Mosca's Migration Planner

The planner maps your organization's security timeline based on **Mosca’s Theorem** to determine your risk horizon.

### A. Mosca's Horizon Slider
*   **How to Use:**
    1. Navigate to the **Migration Planner** tab in the sidebar.
    2. Adjust the three parameters:
        *   **Data Shelf-Life ($S$):** How many years your ingested/archived data must remain secure (e.g., 10 years for compliance).
        *   **Transition Time ($Y$):** How many years it will take your enterprise to completely upgrade to post-quantum standards (e.g., 5 years).
        *   **Quantum Horizon ($Z$):** How many years before a Cryptanalytically Relevant Quantum Computer (CRQC) is built (standard estimates range from 8 to 15 years).
*   **Expected Results:**
    *   **If $S + Y > Z$:** The system displays a **Quantum Risk Threat** warning. This indicates your data will be exposed to "harvest-now, decrypt-later" attacks before your systems are upgraded.
    *   **If $S + Y \le Z$:** The system displays **Systems Secure**, indicating your migration plan is safe.

### B. Transition Roadmap
*   **How to Use:**
    1. Review the dynamic milestone roadmap below the slider.
    2. Check off migration milestones as they are completed:
        *   *Phase 1:* Cryptographic Asset Discovery (Scans complete)
        *   *Phase 2:* OPA Policy Alignment (CNSA 2.0 Audits)
        *   *Phase 3:* Hybrid Protocol Piloting (Nginx & SSH tests)
        *   *Phase 4:* Complete Post-Quantum Deployment (ML-KEM enforcement)
*   **Expected Results:**
    *   Saves checkbox states in your portal session.
    *   Dynamically recalculates remaining roadmap tasks and updates your organizational migration progress gauge.

---

## 4. Compliance & Audit

This module automatically audits all items in your Asset Inventory against international cryptographic transition standards using an Open Policy Agent (OPA) engine.

*   **How to Use:**
    1. Navigate to the **Compliance & Audit** tab in the sidebar.
    2. Review the compliance scores and checklist gauges.
*   **Expected Results:**
    *   **Compliance Scores:** Displays percentage bars evaluating your assets against:
        *   **NIST SP 800-219:** Guidelines for planning migration to Post-Quantum Cryptography.
        *   **CNSA 2.0:** Commercial National Security Algorithm Suite requirements (enforcing ML-KEM/ML-DSA).
        *   **Executive Order 14028:** US federal mandate to migrate systems to quantum-resistant standards.
    *   **Exception Log:** Lists all specific database assets violating these standards, along with the precise policy rule breached (e.g., *"Rule: RSA key size < 3072 bits is prohibited"*).

---

## 5. AI Remediation Hub

The AI Hub leverages Google Gemini to provide customized cryptographic fixes, patch scripts, and quantum-safe configurations.

*   **How to Use:**
    1. Navigate to the **AI Remediation Hub** tab in the sidebar.
    2. Type a question or paste a legacy configuration block into the console prompt (e.g., *"Provide a quantum-safe sshd_config"* or *"How do I upgrade my Nginx cipher suite to support Kyber?"*).
    3. Click **Generate Remediation Plan**.
*   **Expected Results:**
    *   Returns step-by-step upgrade scripts.
    *   Outputs copy-pasteable configuration files with syntax highlighting.
    *   Includes a local rules-based fallback engine that resolves ciphers and parameters instantly if the connection to Google Gemini is offline.

---

## Support & Inquiries

For any questions, troubleshooting, or custom configuration queries, please reply directly to your provisioning email or contact our support team at:
*   **Email:** [support@quarkshield.services](mailto:support@quarkshield.services)
*   **Display Name:** Support Quarkshield

*QuarkShield is committed to securing your digital assets ahead of the quantum revolution.*
