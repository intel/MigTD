#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause-Patent
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: $0 <test-ca-cert.pem> <test-ca-key.pem> <output-crl.pem>" >&2
    exit 1
fi

# Only for freshly generated test CAs; never replace a deployment's revocation list.
temp_dir=$(mktemp -d)
trap 'rm -f "$temp_dir/index" "$temp_dir/crlnumber" "$temp_dir/crlnumber.old" "$temp_dir/crlnumber.new"; rmdir "$temp_dir"' EXIT
: > "$temp_dir/index"
printf '01\n' > "$temp_dir/crlnumber"

openssl ca -gencrl -batch -cert "$1" -keyfile "$2" -out "$3" \
    -md sha384 -crldays 365 -config /dev/stdin <<EOF
[ca]
default_ca = test_ca
[test_ca]
database = $temp_dir/index
crlnumber = $temp_dir/crlnumber
EOF
