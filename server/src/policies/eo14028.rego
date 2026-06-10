package compliance.eo14028

default allow = false

# Rule: Deny vulnerable code signing assets
deny[msg] {
    asset := input.assets[_]
    contains(lower(asset.name), "sign")
    asset.is_vulnerable == true
    msg := sprintf("EO 14028 violation: Quantum-vulnerable code-signing key detected in asset %v", [asset.name])
}

# Rule: Verify zero-trust crypto density (requires at least 4 cataloged assets)
has_zero_trust {
    count(input.assets) > 3
}
