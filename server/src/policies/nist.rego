package compliance.nist

default allow = false

# Rule: Verify we have an inventory of cryptographic assets
has_inventory {
    count(input.assets) > 0
}

# Rule: Deny weak RSA/DSA keys (size < 2048)
deny[msg] {
    asset := input.assets[_]
    asset.type == "certificate"
    asset.key_size < 2048
    msg := sprintf("Insecure classical certificate key size found in %v: %v bits", [asset.name, asset.key_size])
}

deny[msg] {
    asset := input.assets[_]
    asset.algorithm == "RSA"
    asset.key_size < 2048
    msg := sprintf("Insecure RSA key size found in %v: %v bits", [asset.name, asset.key_size])
}
