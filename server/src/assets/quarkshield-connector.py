#!/usr/bin/env python3
# QuarkShield Tier 4 Lightweight Discovery Connector
# Usage: python3 quarkshield-connector.py --token <token> --host <portal_url> [--path <scan_path>]

import os
import sys
import json
import re
import socket
import platform
import subprocess
import urllib.request
from datetime import datetime

# Default paths to scan if no custom path is provided
DEFAULT_SCAN_PATHS = [
    '/etc/ssl/certs',
    '/etc/nginx',
    '/etc/apache2',
    '/etc/ssh',
    '/var/www',
    '.' # current directory fallback
]

def parse_cert_with_openssl(file_path):
    """Parses certificate file details using the system openssl CLI if available."""
    try:
        cmd = ['openssl', 'x509', '-in', file_path, '-text', '-noout']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        
        algorithm = "RSA"
        key_size = 2048
        hash_algo = "SHA-256"
        name = os.path.basename(file_path)
        
        # Determine Algorithm Type
        if "rsaEncryption" in output or "RSA" in output:
            algorithm = "RSA"
        elif "id-ecPublicKey" in output or "ECDSA" in output:
            algorithm = "ECDSA"
        elif "ML-KEM" in output or "kyber" in output.lower():
            algorithm = "ML-KEM-768"
            
        # Determine Key Size
        match = re.search(r'Public-Key:\s*\((\d+)\s*bit\)', output)
        if match:
            key_size = int(match.group(1))
            
        # Determine Signature Hash Algorithm
        match = re.search(r'Signature Algorithm:\s*([a-zA-Z0-9]+)', output)
        if match:
            sig_algo = match.group(1).lower()
            if "sha1" in sig_algo:
                hash_algo = "SHA-1"
            elif "sha256" in sig_algo:
                hash_algo = "SHA-256"
            elif "sha384" in sig_algo:
                hash_algo = "SHA-384"
            elif "sha512" in sig_algo:
                hash_algo = "SHA-512"
            elif "md5" in sig_algo:
                hash_algo = "MD5"
                
        # Extract Common Name (CN)
        match = re.search(r'Subject:.*?CN\s*=\s*([^,\/\n]+)', output)
        if match:
            name = match.group(1).strip()
            
        return {
            "name": name,
            "type": "certificate",
            "algorithm": f"{algorithm}-{key_size}" if algorithm == "RSA" else algorithm,
            "key_size": key_size,
            "hash_algorithm": hash_algo,
            "description": f"File: {file_path}. Common Name: {name}. Ingested via local Tier 4 agent scan."
        }
    except Exception:
        # Fallback to simple parser if openssl fails
        return parse_cert_fallback(file_path)

def parse_cert_fallback(file_path):
    """Simple regex fallback parser if OpenSSL CLI is not available."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        if "BEGIN CERTIFICATE" in content:
            return {
                "name": os.path.basename(file_path),
                "type": "certificate",
                "algorithm": "RSA-2048",  # Default fallback assumption
                "key_size": 2048,
                "hash_algorithm": "SHA-256",
                "description": f"File: {file_path} (Parsed via regex fallback)."
            }
    except Exception:
        pass
    return None

def parse_key_with_openssl(file_path):
    """Parses private key file details using openssl CLI."""
    try:
        cmd = ['openssl', 'pkey', '-in', file_path, '-text', '-noout']
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        output = result.stdout
        
        algorithm = "RSA"
        key_size = 2048
        
        if "Private-Key: (" in output:
            match = re.search(r'Private-Key:\s*\((\d+)\s*bit\)', output)
            if match:
                key_size = int(match.group(1))
                
        if "EC Private-Key:" in output or "id-ecPublicKey" in output:
            algorithm = "ECDSA"
        elif "RSA Private-Key:" in output:
            algorithm = "RSA"
            
        return {
            "name": f"Private Key ({os.path.basename(file_path)})",
            "type": "private_key",
            "algorithm": f"{algorithm}-{key_size}" if algorithm == "RSA" else algorithm,
            "key_size": key_size,
            "description": f"File: {file_path}. Private Key parameters detected locally."
        }
    except Exception:
        # Fallback: check text markers
        return parse_key_fallback(file_path)

def parse_key_fallback(file_path):
    """Fallback checks for private keys based on file headers."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        if "BEGIN PRIVATE KEY" in content or "BEGIN RSA PRIVATE KEY" in content:
            return {
                "name": f"Private Key ({os.path.basename(file_path)})",
                "type": "private_key",
                "algorithm": "RSA-2048",
                "key_size": 2048,
                "description": f"File: {file_path} (Identified via PEM headers)."
            }
    except Exception:
        pass
    return None

def scan_configs(file_path):
    """Scans config files like nginx.conf or sshd_config for cipher definitions."""
    try:
        with open(file_path, 'r', errors='ignore') as f:
            lines = f.readlines()
            
        assets = []
        for i, line in enumerate(lines):
            # Check Nginx Cipher Configuration
            if "ssl_ciphers" in line and not line.strip().startswith("#"):
                match = re.search(r'ssl_ciphers\s+[\'"]?([^\'";]+)', line)
                if match:
                    ciphers = match.group(1)
                    # Check for obsolete ciphers in configuration
                    is_vulnerable = any(x in ciphers for x in ["RC4", "3DES", "MD5", "DES", "WEAK"])
                    assets.append({
                        "name": f"Nginx SSL Ciphers (Line {i+1})",
                        "type": "cipher",
                        "algorithm": "SSL-Config",
                        "description": f"Config: {file_path}. Configured Ciphers: {ciphers[:60]}...",
                        "is_vulnerable": is_vulnerable
                    })
            # Check SSH Key Exchange Algorithms
            if "KexAlgorithms" in line and not line.strip().startswith("#"):
                match = re.search(r'KexAlgorithms\s+([^\s;]+)', line)
                if match:
                    kex = match.group(1)
                    is_vulnerable = any(x in kex for x in ["sha1", "diffie-hellman-group1-sha1"])
                    assets.append({
                        "name": f"SSH Key Exchange (Line {i+1})",
                        "type": "cipher",
                        "algorithm": "SSH-Kex-Config",
                        "description": f"Config: {file_path}. Configured Kex: {kex[:60]}...",
                        "is_vulnerable": is_vulnerable
                    })
        return assets
    except Exception:
        return []

def scan_directory(path):
    """Recursively scans a directory for cryptographic files and server configurations."""
    assets = []
    if not os.path.exists(path):
        return assets
        
    print(f"Scanning directory: {path}...")
    for root, _, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip massive node_modules or system files to avoid performance bloat
            if any(x in file_path for x in ['node_modules', '.git', '/proc', '/sys', '/dev']):
                continue
                
            # 1. Parse Certificate Files
            if file.endswith(('.crt', '.pem', '.der')):
                cert = parse_cert_with_openssl(file_path)
                if cert:
                    assets.append(cert)
                    
            # 2. Parse Private Key Files
            elif file.endswith(('.key', 'id_rsa', 'id_dsa', 'id_ecdsa')):
                key = parse_key_with_openssl(file_path)
                if key:
                    assets.append(key)
                    
            # 3. Scan Web / SSH Server Configuration Ciphers
            elif file in ('nginx.conf', 'sshd_config') or file.endswith(('.conf', 'sites-enabled')):
                config_assets = scan_configs(file_path)
                if config_assets:
                    assets.extend(config_assets)
                    
    return assets

def main():
    import argparse
    parser = argparse.ArgumentParser(description="QuarkShield Discovery Connector")
    parser.add_argument("--token", required=True, help="Connector authentication token")
    parser.add_argument("--host", required=True, help="QuarkShield portal API host url (e.g. http://5.161.249.16:5000)")
    parser.add_argument("--path", help="Custom directory path to scan")
    
    args = parser.parse_args()
    
    # Resolve host URL format
    host_url = args.host.rstrip('/')
    if not host_url.startswith(('http://', 'https://')):
        host_url = f"https://{host_url}"
        
    # Gather system/host details
    hostname = socket.gethostname()
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    
    print("======================================================")
    print("🚀 QuarkShield Tier 4 Discovery Scan Initiated")
    print(f"Host: {hostname} ({os_info})")
    print(f"Time: {datetime.now().isoformat()}")
    print("======================================================")
    
    # Execute Scan
    scan_paths = [args.path] if args.path else DEFAULT_SCAN_PATHS
    all_assets = []
    
    for path in scan_paths:
        if path and os.path.exists(path):
            all_assets.extend(scan_directory(path))
            
    # Remove duplicates based on path descriptions
    unique_assets = []
    seen_descriptions = set()
    for asset in all_assets:
        desc = asset.get("description", "")
        if desc not in seen_descriptions:
            seen_descriptions.add(desc)
            unique_assets.append(asset)
            
    print(f"\nScan complete! Identified {len(unique_assets)} cryptographic configuration and asset profiles.")
    
    # Package payload
    payload = {
        "hostname": hostname,
        "os": os_info,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "assets": unique_assets
    }
    
    # Push Ingestion Payload (Outbound-only via HTTPS/HTTP POST)
    endpoint = f"{host_url}/api/scan/agent/ingest"
    print(f"Pushing data outbound to portal: {endpoint}...")
    
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode('utf-8'),
        headers={
            'Content-Type': 'application/json',
            'X-Connector-Token': args.token
        },
        method='POST'
    )
    
    try:
        # Create relaxed context for testing local/self-signed SSL endpoints if necessary
        import ssl
        context = ssl._create_unverified_context()
        
        with urllib.request.urlopen(req, context=context) as response:
            res_data = response.read().decode('utf-8')
            print("\n✓ Success! Telemetry successfully synced with CMDB registry.")
            print("Server Response:", res_data)
            
    except Exception as e:
        print(f"\n❌ Error pushing scan results to portal: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
