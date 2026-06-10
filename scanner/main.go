package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	// 1. Define Command-Line Flags
	pathFlag := flag.String("path", ".", "Local directory path to scan")
	serverFlag := flag.String("server", "http://localhost:5000", "QuarkShield central server URL")
	registerFlag := flag.Bool("register", false, "Register findings directly in the central database")
	outputFlag := flag.String("output", "", "Output file path to save JSON scan report")
	flag.StringVar(pathFlag, "p", ".", "Local directory path to scan (shorthand)")
	flag.StringVar(serverFlag, "s", "http://localhost:5000", "QuarkShield central server URL (shorthand)")
	flag.BoolVar(registerFlag, "r", false, "Register findings in database (shorthand)")
	flag.StringVar(outputFlag, "o", "", "Output JSON file (shorthand)")
	flag.Parse()

	targetPath, err := filepath.Abs(*pathFlag)
	if err != nil {
		fmt.Printf("Error resolving path: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("--------------------------------------------------\n")
	fmt.Printf(" QuarkShield CLI Scanner - Crawling Path:\n %s\n", targetPath)
	fmt.Printf("--------------------------------------------------\n")

	var assets []AuditResult
	var configViolations []AuditResult
	scannedFilesCount := 0

	// 2. Crawl the target directory recursively
	err = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip files with permission errors
		}
		if d.IsDir() {
			// Skip hidden directories like .git or node_modules
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "dist" {
				return filepath.SkipDir
			}
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Skip huge files to avoid memory overhead
		if info.Size() > 2*1024*1024 { // 2MB limit
			return nil
		}

		scannedFilesCount++

		// Read file content
		contentBytes, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(contentBytes)
		fileName := filepath.Base(path)

		// Heuristic sorting based on file headers
		trimmed := strings.TrimSpace(content)
		if strings.HasPrefix(trimmed, "-----BEGIN") {
			// PEM certificate or private key
			audit := AuditPEMCertificate(content, fileName)
			assets = append(assets, audit)
			fmt.Printf("[CERT/KEY] Found: %s (%s, Vulnerable: %v)\n", fileName, audit.Algorithm, audit.IsVulnerable)
		} else if strings.HasPrefix(trimmed, "ssh-") || strings.HasPrefix(trimmed, "ecdsa-") {
			// SSH Public Key
			audit := AuditSSHKey(content, fileName)
			assets = append(assets, audit)
			fmt.Printf("[SSH KEY]  Found: %s (%s, Vulnerable: %v)\n", fileName, audit.Algorithm, audit.IsVulnerable)
		} else if strings.HasSuffix(fileName, ".conf") || strings.HasSuffix(fileName, ".config") || strings.Contains(fileName, "sshd_config") || strings.Contains(fileName, "nginx.conf") {
			// Configuration File Auditor
			audit := AuditConfigFile(fileName, content)
			if audit.IsVulnerable {
				fmt.Printf("[CONFIG]   Vulnerable settings in: %s (%d warnings)\n", fileName, len(audit.Violations))
				// Convert configuration violations into assets for tracking
				for i, v := range audit.Violations {
					configViolations = append(configViolations, AuditResult{
						ID:                   fmt.Sprintf("cli-cfg-%s-%d", generateID(), i),
						Type:                 "config",
						Name:                 fmt.Sprintf("%s:Line %d", fileName, v.LineNumber),
						Algorithm:            "Symmetric/Protocol Config",
						IsVulnerable:         true,
						RiskLevel:            v.RiskLevel,
						Status:               "Quantum Vulnerable",
						Description:          v.Issue,
						Recommendation:       v.Fix,
						Explainer:            fmt.Sprintf("Server configuration at line %d permits: \"%s\"", v.LineNumber, v.LineContent),
						ComplianceViolations: []string{"CNSA 2.0", "NIST SP 800-219", "EO 14028"},
					})
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directories: %v\n", err)
		os.Exit(1)
	}

	// Merge config findings into inventory list
	allFindings := append(assets, configViolations...)

	fmt.Printf("--------------------------------------------------\n")
	fmt.Printf(" Scan Summary:\n")
	fmt.Printf(" - Scanned Files: %d\n", scannedFilesCount)
	fmt.Printf(" - Crypto Assets Found: %d\n", len(assets))
	fmt.Printf(" - Configuration Vulnerabilities: %d\n", len(configViolations))
	fmt.Printf("--------------------------------------------------\n")

	if len(allFindings) == 0 {
		fmt.Println("No cryptographic credentials or configuration issues found.")
		return
	}

	// 3. Output logic
	// Write JSON to output file if specified
	if *outputFlag != "" {
		jsonData, err := json.MarshalIndent(allFindings, "", "  ")
		if err != nil {
			fmt.Printf("Failed to format JSON output: %v\n", err)
		} else {
			err = os.WriteFile(*outputFlag, jsonData, 0644)
			if err != nil {
				fmt.Printf("Failed to write report to %s: %v\n", *outputFlag, err)
			} else {
				fmt.Printf("Report successfully saved to %s\n", *outputFlag)
			}
		}
	} else if !*registerFlag {
		// Default: Output a clean JSON layout to terminal
		jsonData, _ := json.MarshalIndent(allFindings, "", "  ")
		fmt.Println(string(jsonData))
	}

	// Register with database if flag set
	if *registerFlag {
		fmt.Printf("Connecting to QuarkShield server at %s...\n", *serverFlag)
		err = RegisterAssets(*serverFlag, allFindings)
		if err != nil {
			fmt.Printf("❌ Failed to register findings with server: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Success! Registered %d findings in database.\n", len(allFindings))
	}
}
