#!/bin/sh
# Regenerate the PBES2 fixtures with the openssl CLI (3.x).
#
# rsa_pkcs8.pem / ec_pkcs8.pem are unencrypted PKCS#8 keys. The *_enc
# files are the same keys wrapped as RFC 5958 EncryptedPrivateKeyInfo
# with PBES2/PBKDF2 under the password "correct horse battery staple".
set -eu
cd "$(dirname "$0")"

PASSWORD="correct horse battery staple"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out rsa_pkcs8.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 \
    -in rsa_pkcs8.pem -out rsa_enc.pem -passout "pass:$PASSWORD"
openssl pkcs8 -topk8 -v2 aes-128-cbc -v2prf hmacWithSHA512 \
    -in rsa_pkcs8.pem -out rsa_enc_aes128_sha512.pem -passout "pass:$PASSWORD"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out ec_pkcs8.pem
openssl pkcs8 -topk8 -v2 aes-256-cbc -v2prf hmacWithSHA256 \
    -in ec_pkcs8.pem -out ec_enc.pem -passout "pass:$PASSWORD"
openssl pkcs8 -topk8 -v2 aes-192-cbc -v2prf hmacWithSHA224 \
    -in ec_pkcs8.pem -out ec_enc_aes192_sha224.pem -passout "pass:$PASSWORD"
openssl pkcs8 -topk8 -v2 aes-256-cbc \
    -in ec_pkcs8.pem -out ec_enc_default_prf.pem -passout "pass:$PASSWORD"
