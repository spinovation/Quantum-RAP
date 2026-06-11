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

## 2. Crypto Asset CMDB

The **Crypto CMDB** serves as your enterprise system of record for cryptographic assets, identifying ownership, system dependencies, risk profiles, and lifecycle states.

### A. CMDB Architecture & Dependency Mapping
*   **Data Model Structure**: Mapped as `Business Service ➔ Application ➔ Endpoint ➔ Cryptographic Asset ➔ Algorithm`.
*   **Multiple-Dependency Relations**: Multiple certificates, signing keys, and configurations can map to a single Business Service or Endpoint (e.g. `Transactional Core Payment` utilizes both the wildcard ingress certificate `production-ingress-wildcard` and the backup signing key `database-backup-sign-key`). This models realistic hierarchical systems where multiple credentials protect the same endpoints.
*   **Identity Alignment**: Assets are linked to cost-center owners (e.g., `payment-infra@spinovation.com` or `it-ops@spinovation.com`) to coordinate rotation schedules.
*   **Lifecycle Tracking**: Tracks transition states for each asset: `Active` (unmitigated), `Migrating` (hybrid tests running), or `Remediated` (fully post-quantum compliant).

### B. Agentless Metadata Discovery (Tiers 1 & 2)
*   **Tier 1 Discovery (API-Based)**: Connects directly to cloud infrastructure providers and services (AWS ACM/ELB/APIGW/IAM/SecretsManager, Azure Graph/KeyVault/ARM, GCP Certificates/LBs, Kubernetes TLS/Ingress/Mesh, F5 SSL/VIPs, Palo Alto VPNs, Cisco VPNs).
*   **Tier 2 Discovery (Existing Tool Integrations)**: Syncs with security tools (Splunk, Microsoft Defender, CrowdStrike, Qualys, Tenable, Workday, SharePoint, and ServiceNow).
*   **Live Status**: All Tier 1 and 2 discovery components are **fully live**. Refreshing your browser allows you to select any connector on the discovery board and click **Trigger Metadata Discovery** to run real-time audits.
*   **GDPR Compliance**: To prevent data privacy exposures, the CMDB implements a **Metadata-First** ingestion pattern. Only structural cryptographic details (algorithms, sizes, names) are collected—raw logs, user activities, and payloads are discarded.

---

## 3. Migration & Impact Planner

The **Migration & Impact** module combines Mosca's Theorem with a downstream simulator to predict migration fallout.

### A. "What Breaks?" Impact Simulator
*   **How to Use**:
    1. Select a migration profile (e.g. migrating your core TLS ingress from RSA-2048 to ML-KEM-768).
    2. Click **Run Impact Analysis**.
*   **Expected Results**:
    *   **Downstream Service Impact**: Displays the specific applications and owner contacts affected.
    *   **Fallout Warnings**: Flags client incompatibility percentages (e.g. identifying that legacy mobile client libraries will fail TLS handshakes if ML-KEM is enforced).
    *   **Action Playbooks**: Lists step-by-step mitigation instructions (e.g. implementing hybrid dual-cert setups).
    *   **Ticketing Integrations**: Generates JIRA Epic or ServiceNow Incident payloads carrying priority, ownership, and CMDB CI mapping keys.

### B. Mosca's Horizon Calculator
*   **How to Use**:
    1. Navigate to the **Mosca Assessment** sub-tab.
    2. Adjust the sliders for Data Shelf-Life ($S$), Migration Time ($Y$), and Quantum Collapse Time ($Z$).
*   **Expected Results**:
    *   **If $S + Y > Z$**: Flags a threatened status indicating the systems are susceptible to retro-decryption (Harvest Now, Decrypt Later).
    *   **If $S + Y \le Z$**: Confirms the transition buffer is secure.

### C. Transition Roadmap
*   *Phase 1:* Cryptographic Asset Discovery (Scans complete)
*   *Phase 2:* OPA Policy Alignment (CNSA 2.0 Audits)
*   *Phase 3:* Hybrid Protocol Piloting (Nginx & SSH tests)
*   *Phase 4:* Complete Post-Quantum Deployment (ML-KEM enforcement)
*   **Expected Results**:
    *   Checkbox states are preserved in your session and dynamically update the readiness gauges.
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
