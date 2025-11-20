#!/bin/bash
set -e

# Set output directory
OUTPUT_DIR="key"
mkdir -p "$OUTPUT_DIR"

# 1. Create the Root CA Key and Certificate
openssl ecparam -name secp384r1 -genkey -noout -out "$OUTPUT_DIR/ca.key"
if [ ! -s "$OUTPUT_DIR/ca.key" ]; then
	echo "Error: Root CA key ($OUTPUT_DIR/ca.key) was not generated successfully." >&2
	exit 1
fi
openssl req -x509 -new -nodes -key "$OUTPUT_DIR/ca.key" -sha384 -days 3650 -out "$OUTPUT_DIR/root_ca.crt" -subj "/C=US/ST=CA/L=Santa Clara/O=MigTD Issuer/CN=MigTD Root CA"

# 2. Create the Intermediate CA Key and Certificate
openssl ecparam -name secp384r1 -genkey -noout -out "$OUTPUT_DIR/intermediate_ca.key"
if [ ! -s "$OUTPUT_DIR/intermediate_ca.key" ]; then
	echo "Error: Intermediate CA key ($OUTPUT_DIR/intermediate_ca.key) was not generated successfully." >&2
	exit 1
fi
openssl req -new -nodes -key "$OUTPUT_DIR/intermediate_ca.key" -sha384 -out "$OUTPUT_DIR/intermediate_ca.csr" -subj "/C=US/ST=CA/L=Santa Clara/O=MigTD Intermediate Issuer/CN=MigTD Intermediate CA"
openssl x509 -req -in "$OUTPUT_DIR/intermediate_ca.csr" -CA "$OUTPUT_DIR/root_ca.crt" -CAkey "$OUTPUT_DIR/ca.key" -CAcreateserial -sha384 -days 1825 -out "$OUTPUT_DIR/intermediate_ca.crt"

# 3. Create the End-Entity (Server/Client) Key and Certificate
openssl ecparam -name secp384r1 -genkey -noout -out "$OUTPUT_DIR/issuer.key"
if [ ! -s "$OUTPUT_DIR/issuer.key" ]; then
	echo "Error: End-Entity key ($OUTPUT_DIR/issuer.key) was not generated successfully." >&2
	exit 1
fi
openssl req -new -nodes -key "$OUTPUT_DIR/issuer.key" -sha384 -out "$OUTPUT_DIR/issuer.csr" -subj "/C=US/ST=CA/L=Santa Clara/O=MigTD Issuer/CN=MigTD Info Issuer"
openssl x509 -req -in "$OUTPUT_DIR/issuer.csr" -CA "$OUTPUT_DIR/intermediate_ca.crt" -CAkey "$OUTPUT_DIR/intermediate_ca.key" -CAcreateserial -sha384 -days 365 -out "$OUTPUT_DIR/issuer.crt"

# 4. Concat them into cert chain
cat "$OUTPUT_DIR/issuer.crt" "$OUTPUT_DIR/intermediate_ca.crt" "$OUTPUT_DIR/root_ca.crt" > "$OUTPUT_DIR/migtd_issuer_chain.pem"

# 5. Convert issuer key to PKCS8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in "$OUTPUT_DIR/issuer.key" -out "$OUTPUT_DIR/issuer_pkcs8.key"

if [ ! -s "$OUTPUT_DIR/issuer_pkcs8.key" ]; then
	echo "Error: PKCS8 key ($OUTPUT_DIR/issuer_pkcs8.key) was not generated successfully." >&2
	exit 1
fi
echo "Certificate chain and keys generated successfully in $OUTPUT_DIR."