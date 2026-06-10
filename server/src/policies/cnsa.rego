package compliance.cnsa

default allow = false

# Rule: Deny weak hashing digests (MD5, SHA-1)
deny[msg] {
    asset := input.assets[_]
    contains(lower(asset.algorithm), "sha1")
    msg := sprintf("CNSA 2.0 violation: Weak hash digest SHA-1 in asset %v", [asset.name])
}

deny[msg] {
    asset := input.assets[_]
    contains(lower(asset.algorithm), "md5")
    msg := sprintf("CNSA 2.0 violation: Deprecated MD5 hash in asset %v", [asset.name])
}

# Rule: Deny weak symmetric algorithms
deny[msg] {
    asset := input.assets[_]
    contains(lower(asset.description), "aes128")
    msg := sprintf("CNSA 2.0 violation: Insecure symmetric AES-128 in configuration %v", [asset.name])
}

deny[msg] {
    asset := input.assets[_]
    contains(lower(asset.description), "blowfish")
    msg := sprintf("CNSA 2.0 violation: Insecure symmetric Blowfish in configuration %v", [asset.name])
}

# Rule: Check if we have hybrid post-quantum assets (passed if exists)
has_pqc {
    asset := input.assets[_]
    asset.is_vulnerable == false
    asset.status == "Post-Quantum Secure"
}

# Rule: Check if we have ML-DSA signatures in place
has_mldsa {
    asset := input.assets[_]
    contains(asset.algorithm, "ML-DSA")
}
