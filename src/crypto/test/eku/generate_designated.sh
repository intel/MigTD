#!/usr/bin/env bash
# Generate the "designated MigTD signer purpose" EKU fixtures used to cover
# `crypto::extract_single_leaf_eku_oid_der` selecting the dedicated OID
#   1.3.6.1.4.1.311.76.59.1.43
# from a leaf that may co-assert other purposes.
#
# The leaf is ECDSA P-384 / SHA-384 signed by a self-signed root (CA:TRUE),
# matching the algorithms accepted by the crypto crate. The fixture is a
# leaf-first PEM chain (leaf + root).
set -euo pipefail
cd "$(dirname "$0")"

SIGNER_OID="1.3.6.1.4.1.311.76.59.1.43"   # dedicated MigTD policy-signer purpose
CODESIGN_OID="1.3.6.1.5.5.7.3.3"          # id-kp-codeSigning (co-asserted purpose)
DAYS=36500

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

openssl ecparam -name secp384r1 -genkey -noout -out "$TMP/root.key"
cat > "$TMP/root.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
prompt = no
[dn]
O = MigTD Test
CN = MigTD Designated EKU Root
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF
openssl req -x509 -new -key "$TMP/root.key" -sha384 -days "$DAYS" \
  -config "$TMP/root.cnf" -out "$TMP/root.pem"

gen_leaf() {
  local out="$1" cn="$2" eku="$3"
  openssl ecparam -name secp384r1 -genkey -noout -out "$TMP/leaf.key"
  cat > "$TMP/leaf.cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
O = MigTD Test
CN = $cn
EOF
  openssl req -new -key "$TMP/leaf.key" -sha384 -config "$TMP/leaf.cnf" -out "$TMP/leaf.csr"
  printf 'basicConstraints = critical, CA:FALSE\nextendedKeyUsage = %s\n' "$eku" > "$TMP/leaf.ext"
  openssl x509 -req -in "$TMP/leaf.csr" -CA "$TMP/root.pem" -CAkey "$TMP/root.key" \
    -CAcreateserial -sha384 -days "$DAYS" -extfile "$TMP/leaf.ext" -out "$TMP/leaf.pem"
  cat "$TMP/leaf.pem" "$TMP/root.pem" > "$out"
}

# Designated OID co-asserted with an unrelated code-signing purpose.
gen_leaf signer_designated_multi.pem "MigTD Designated Multi" "$CODESIGN_OID,$SIGNER_OID"

echo "Generated:"
printf '  %-28s ' "signer_designated_multi.pem"
openssl x509 -in signer_designated_multi.pem -noout -ext extendedKeyUsage 2>/dev/null |
  tail -1 | sed 's/^ *//'
