package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type AuditResult struct {
	ID                   string   `json:"id"`
	Type                 string   `json:"type"`
	Name                 string   `json:"name"`
	Algorithm            string   `json:"algorithm"`
	KeySize              int      `json:"keySize,omitempty"`
	HashAlgorithm        string   `json:"hashAlgorithm,omitempty"`
	IsVulnerable         bool     `json:"isVulnerable"`
	RiskLevel            string   `json:"riskLevel"`
	Status               string   `json:"status"`
	Description          string   `json:"description"`
	Recommendation       string   `json:"recommendation"`
	Explainer            string   `json:"explainer"`
	ComplianceViolations []string `json:"complianceViolations"`
}

type LineViolation struct {
	LineNumber  int    `json:"lineNumber"`
	LineContent string `json:"lineContent"`
	Issue       string `json:"issue"`
	RiskLevel   string `json:"riskLevel"`
	Fix         string `json:"fix"`
}

type ConfigAuditResult struct {
	FileName       string          `json:"fileName"`
	IsVulnerable   bool            `json:"isVulnerable"`
	Violations     []LineViolation `json:"violations"`
	Summary        string          `json:"summary"`
	Recommendation string          `json:"recommendation"`
}

func generateID() string {
	rand.Seed(time.Now().UnixNano())
	chars := "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 8)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func estimateRsaKeySize(base64Data string) int {
	// Heuristics based on base64 character count
	charCount := len(base64Data)
	if charCount > 650 {
		return 4096
	}
	if charCount > 340 {
		return 2048
	}
	return 1024
}

// AuditSSHKey audits public SSH key strings
func AuditSSHKey(keyString string, label string) AuditResult {
	clean := strings.TrimSpace(keyString)
	parts := strings.Fields(clean)

	if len(parts) < 2 {
		return AuditResult{
			ID:             generateID(),
			Type:           "ssh_key",
			Name:           label,
			Algorithm:      "Unknown",
			IsVulnerable:   true,
			RiskLevel:      "critical",
			Status:         "Quantum Vulnerable",
			Description:    "Invalid or malformed SSH public key format.",
			Recommendation: "Ensure key is formatted as '<key-type> <base64> [comment]'.",
			Explainer:      "Failed to parse public key fields.",
		}
	}

	keyType := parts[0]
	base64Data := parts[1]
	comment := label
	if len(parts) > 2 {
		comment = strings.Join(parts[2:], " ")
	}

	algorithm := "Unknown"
	keySize := 0
	isVulnerable := true
	riskLevel := "high"
	description := ""
	recommendation := ""
	explainer := ""
	complianceViolations := []string{}

	switch keyType {
	case "ssh-rsa":
		algorithm = "RSA"
		keySize = estimateRsaKeySize(base64Data)
		isVulnerable = true
		if keySize < 2048 {
			riskLevel = "critical"
		} else {
			riskLevel = "high"
		}
		description = fmt.Sprintf("Vulnerable SSH public key utilizing the RSA-%d algorithm.", keySize)
		recommendation = "Replace with a Post-Quantum signature key (e.g. ML-DSA) or hybrid exchange wrapper."
		explainer = "RSA depends on prime factorization. Shor's algorithm running on a quantum computer solves integer factorization in cubic time, breaking RSA of any bit strength."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-219", "EO 14028"}

	case "ssh-dss":
		algorithm = "DSA"
		keySize = 1024
		isVulnerable = true
		riskLevel = "critical"
		description = "Legacy SSH public key using the insecure DSA algorithm."
		recommendation = "Delete this key immediately. Replace with post-quantum standards (ML-DSA)."
		explainer = "DSA is classically broken and completely vulnerable to Shor's algorithm solving discrete logarithms."
		complianceViolations = []string{"NIST SP 800-131A", "CNSA 2.0", "EO 14028"}

	case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521":
		algorithm = "ECDSA"
		if strings.Contains(keyType, "nistp256") {
			keySize = 256
		} else if strings.Contains(keyType, "nistp384") {
			keySize = 384
		} else {
			keySize = 521
		}
		isVulnerable = true
		riskLevel = "high"
		description = fmt.Sprintf("Vulnerable Elliptic Curve signature (ECDSA) public key on curve P-%d.", keySize)
		recommendation = "Upgrade to post-quantum signature schemes (ML-DSA / Dilithium) to block quantum decryption."
		explainer = "Elliptic curves rely on the discrete log problem. Shor's algorithm breaks elliptic curves even faster than RSA due to smaller key parameters."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-219", "EO 14028"}

	case "ssh-ed25519":
		algorithm = "Ed25519"
		keySize = 256
		isVulnerable = true
		riskLevel = "high"
		description = "Vulnerable modern classical Elliptic Curve Signature (Ed25519) public key."
		recommendation = "Plan migration to ML-DSA or deploy hybrid post-quantum wrappers."
		explainer = "Although Ed25519 is classically secure, the elliptic curve discrete logarithm problem is easily solved by a quantum computer running Shor's algorithm."
		complianceViolations = []string{"CNSA 2.0", "NIST SP 800-219"}

	case "sntrup761x25519-sha512@openssh.com":
		algorithm = "sntrup761-x25519 (Hybrid)"
		keySize = 858
		isVulnerable = false
		riskLevel = "secure"
		description = "Quantum-safe hybrid key exchange key combining Streamlined NTRU Prime 761 and Curve25519."
		recommendation = "Maintain deployment. Fully compliant with OpenSSH hybrid post-quantum standards."
		explainer = "Lattice-based NTRU Prime secures the exchange from quantum analysis; Curve25519 provides classical assurance."
		complianceViolations = []string{}

	default:
		if strings.Contains(strings.ToLower(keyType), "ml-dsa") || strings.Contains(strings.ToLower(keyType), "dilithium") {
			algorithm = "ML-DSA"
			isVulnerable = false;
			riskLevel = "secure"
			description = "NIST Standard Post-Quantum Digital Signature Algorithm (ML-DSA)."
			recommendation = "Secure. Keep monitored."
			explainer = "ML-DSA lattice schemes are secure against both classical and quantum algorithms."
			complianceViolations = []string{}
		} else {
			algorithm = keyType
			isVulnerable = true
			riskLevel = "medium"
			description = fmt.Sprintf("Unrecognized key type: %s.", keyType)
			recommendation = "Verify key specifications and migrate to ML-DSA."
			explainer = "Assume any classical asymmetric key type is quantum-vulnerable unless mathematically proven otherwise."
			complianceViolations = []string{"NIST SP 800-219"}
		}
	}

	status := "Quantum Vulnerable"
	if !isVulnerable {
		status = "Post-Quantum Secure"
	}

	return AuditResult{
		ID:                   generateID(),
		Type:                 "ssh_key",
		Name:                 comment,
		Algorithm:            algorithm,
		KeySize:              keySize,
		IsVulnerable:         isVulnerable,
		RiskLevel:            riskLevel,
		Status:               status,
		Description:          description,
		Recommendation:       recommendation,
		Explainer:            explainer,
		ComplianceViolations: complianceViolations,
	}
}

// AuditPEMCertificate audits raw PEM file blocks (certificates and keys)
func AuditPEMCertificate(pemString string, label string) AuditResult {
	block, _ := pem.Decode([]byte(pemString))
	if block == nil {
		return AuditResult{
			ID:             generateID(),
			Type:           "certificate",
			Name:           label,
			Algorithm:      "Unknown",
			IsVulnerable:   true,
			RiskLevel:      "critical",
			Status:         "Quantum Vulnerable",
			Description:    "Failed to decode PEM certificate body. Check headers.",
			Recommendation: "Verify PEM syntax includes '-----BEGIN CERTIFICATE-----'.",
			Explainer:      "Malformed file encoding.",
		}
	}

	assetType := "certificate"
	if strings.Contains(block.Type, "PRIVATE KEY") {
		assetType = "private_key"
	}

	algorithm := "RSA"
	keySize := 2048
	isVulnerable := true
	riskLevel := "high"
	description := ""
	recommendation := ""
	explainer := ""
	complianceViolations := []string{"CNSA 2.0", "NIST SP 800-219", "EO 14028"}

	// Native x509 certificate parsing
	if block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			// Extract parameters natively
			switch cert.PublicKeyAlgorithm {
			case x509.RSA:
				algorithm = "RSA"
				if rsaKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
					keySize = rsaKey.N.BitLen()
				}
				if keySize < 2048 {
					riskLevel = "critical"
				}
			case x509.ECDSA:
				algorithm = "ECDSA"
				if ecdsaKey, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
					keySize = ecdsaKey.Params().BitSize
				}
			default:
				algorithm = cert.PublicKeyAlgorithm.String()
			}
			description = fmt.Sprintf("Quantum-vulnerable TLS certificate utilizing the %s-%d algorithm.", algorithm, keySize)
		}
	}

	if description == "" {
		// Heuristics fallback for key files
		base64Len := len(block.Bytes)
		if strings.Contains(block.Type, "RSA") || base64Len > 400 {
			algorithm = "RSA"
			if base64Len > 800 {
				keySize = 4096
			} else if base64Len > 250 {
				keySize = 2048
			} else {
				keySize = 1024
			}
			if keySize < 2048 {
				riskLevel = "critical"
			}
			description = fmt.Sprintf("Quantum-vulnerable RSA-%d %s file.", keySize, strings.ToLower(block.Type))
		} else {
			algorithm = "ECDSA / ECDH"
			keySize = 256
			description = fmt.Sprintf("Quantum-vulnerable Elliptic Curve %s file.", strings.ToLower(block.Type))
		}
	}

	recommendation = "Upgrade to post-quantum signature certificates (ML-DSA) and hybrid KEMs."
	explainer = "Shor's algorithm breaks integer factoring and elliptic curve discrete logarithms. Adversaries can record TLS handshakes today and decrypt them post-quantum."

	status := "Quantum Vulnerable"
	if !isVulnerable {
		status = "Post-Quantum Secure"
	}

	return AuditResult{
		ID:                   generateID(),
		Type:                 assetType,
		Name:                 label,
		Algorithm:            algorithm,
		KeySize:              keySize,
		IsVulnerable:         isVulnerable,
		RiskLevel:            riskLevel,
		Status:               status,
		Description:          description,
		Recommendation:       recommendation,
		Explainer:            explainer,
		ComplianceViolations: complianceViolations,
	}
}

// AuditConfigFile audits server configuration files for protocols
func AuditConfigFile(fileName string, content string) ConfigAuditResult {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var violations []LineViolation
	isVulnerable := false
	lineNum := 0

	lowerName := strings.ToLower(fileName)
	isNginx := strings.Contains(lowerName, "nginx") || strings.Contains(content, "ssl_ciphers") || strings.Contains(content, "ssl_protocols")
	isSSH := strings.Contains(lowerName, "ssh") || strings.Contains(content, "KexAlgorithms") || strings.Contains(content, "Ciphers")

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if isNginx {
			if strings.HasPrefix(line, "ssl_protocols") {
				if strings.Contains(line, "TLSv1.0") || strings.Contains(line, "TLSv1.1") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Obsolete TLS versions (TLSv1.0/1.1) enabled.",
						RiskLevel:   "critical",
						Fix:         "Force TLSv1.3 and TLSv1.2 only.",
					})
				}
				if !strings.Contains(line, "TLSv1.3") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "TLSv1.3 is not explicitly enabled. TLSv1.3 is required for post-quantum curves.",
						RiskLevel:   "high",
						Fix:         "Update protocols to: 'ssl_protocols TLSv1.2 TLSv1.3;'",
					})
				}
			}

			if strings.HasPrefix(line, "ssl_ciphers") {
				if strings.Contains(line, "RC4") || strings.Contains(line, "3DES") || strings.Contains(line, "MD5") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Classically broken algorithms (RC4, 3DES, MD5) enabled.",
						RiskLevel:   "critical",
						Fix:         "Replace with modern AEAD-only ciphers.",
					})
				}
				if !strings.Contains(line, "X25519MLKEM768") && !strings.Contains(line, "Kyber") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "No Post-Quantum key exchange curves (ML-KEM / Kyber) enabled.",
						RiskLevel:   "medium",
						Fix:         "Prepend PQ hybrid curves (e.g. X25519+MLKEM768) to curves registry.",
					})
				}
			}
		} else if isSSH {
			if strings.HasPrefix(line, "KexAlgorithms") {
				if strings.Contains(line, "diffie-hellman-group1-sha1") || strings.Contains(line, "diffie-hellman-group14-sha1") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Weak Diffie-Hellman ciphers with SHA-1 enabled.",
						RiskLevel:   "critical",
						Fix:         "Decommission SHA-1 Diffie-Hellman algorithms.",
					})
				}
				if !strings.Contains(line, "sntrup761x25519") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Post-Quantum KEX (sntrup761x25519-sha512) is not enabled.",
						RiskLevel:   "medium",
						Fix:         "Prepend 'sntrup761x25519-sha512@openssh.com' to KexAlgorithms.",
					})
				}
			}
			if strings.HasPrefix(line, "Ciphers") {
				if strings.Contains(line, "3des-cbc") || strings.Contains(line, "blowfish-cbc") {
					isVulnerable = true
					violations = append(violations, LineViolation{
						LineNumber:  lineNum,
						LineContent: line,
						Issue:       "Weak symmetric CBC ciphers enabled.",
						RiskLevel:   "high",
						Fix:         "Restrict ciphers to AES-GCM and Chacha20-Poly1305.",
					})
				}
			}
		} else {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "sha1") || strings.Contains(lineLower, "md5") {
				isVulnerable = true
				violations = append(violations, LineViolation{
					LineNumber:  lineNum,
					LineContent: line,
					Issue:       "Insecure hash reference (SHA-1 / MD5) detected.",
					RiskLevel:   "high",
					Fix:         "Migrate hashing to SHA-256 or SHA-3.",
				})
			}
		}
	}

	summary := fmt.Sprintf("No obvious quantum-vulnerable configurations found in %s.", fileName)
	recommend := "Maintain config."
	if isVulnerable {
		summary = fmt.Sprintf("Discovered %d vulnerabilities in config %s.", len(violations), fileName)
		recommend = "Update configuration parameters to enforce post-quantum algorithms."
	}

	return ConfigAuditResult{
		FileName:       fileName,
		IsVulnerable:   isVulnerable,
		Violations:     violations,
		Summary:        summary,
		Recommendation: recommend,
	}
}
