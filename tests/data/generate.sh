#!/usr/bin/env bash
# Regenerate the X.509 test fixtures. Requires the openssl CLI (3.x).
# All keys and certificates are throwaway test material, never used
# for anything but the test suite.
set -euo pipefail
cd "$(dirname "$0")"

rm -f -- ./*.pem ./*.csr ./*.srl ./*.der ./*.ext 2>/dev/null || true

ca_ext() {
    # $1 = pathlen value or empty
    if [ -n "$1" ]; then
        printf 'basicConstraints=critical,CA:true,pathlen:%s\n' "$1"
    else
        printf 'basicConstraints=critical,CA:true\n'
    fi
    printf 'keyUsage=critical,keyCertSign,cRLSign\n'
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid\n'
}

leaf_ext() {
    printf 'basicConstraints=critical,CA:false\n'
    printf 'keyUsage=critical,digitalSignature\n'
    printf 'subjectKeyIdentifier=hash\n'
    printf 'authorityKeyIdentifier=keyid\n'
}

mkroot() { # $1 = prefix, $2 = subject CN, rest = keygen args
    local prefix="$1" cn="$2"
    shift 2
    openssl req -x509 -newkey "$@" -keyout "${prefix}_key.pem" \
        -out "${prefix}.pem" -days 3650 -nodes \
        -subj "/C=US/O=Quad4/CN=${cn}" \
        -addext "basicConstraints=critical,CA:true" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -addext "issuerAltName=DNS:ca.example.com" 2>/dev/null
}

mkcsr() { # $1 = prefix, $2 = subject CN, rest = keygen args
    local prefix="$1" cn="$2"
    shift 2
    openssl req -newkey "$@" -nodes -keyout "${prefix}_key.pem" \
        -out "${prefix}.csr" -subj "/C=US/O=Quad4/CN=${cn}" 2>/dev/null
}

sign() { # $1 = csr prefix, $2 = out cert, $3 = ca prefix, $4 = serial, $5 = extfile
    openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3_key.pem" \
        -set_serial "$4" -days 825 -out "$2" -extfile "$5" 2>/dev/null
}

# --- RSA-2048 root, intermediate, leaf -------------------------------

mkroot rsa_root "PureCrypt Test RSA Root" rsa:2048

mkcsr rsa_inter "PureCrypt Test RSA Intermediate" rsa:2048
ca_ext 1 > ca.ext
sign rsa_inter rsa_inter.pem rsa_root 2001 ca.ext

mkcsr rsa_leaf "cn-fallback.invalid" rsa:2048
cat > leaf_full.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=DNS:www.example.com,DNS:*.example.com,DNS:example.org,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1,email:admin@example.com,URI:https://example.com/,RID:1.2.3.4
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
certificatePolicies=2.23.140.1.2.1
EOF
sign rsa_leaf rsa_leaf.pem rsa_inter 3001 leaf_full.ext

# Leaf with no SAN at all, exercises the CN fallback.
mkcsr rsa_leaf_nosan "legacy.example.com" rsa:2048
leaf_ext > leaf_min.ext
sign rsa_leaf_nosan rsa_leaf_nosan.pem rsa_inter 3002 leaf_min.ext

# Intermediate with pathlen:0 plus a sub CA below it, exercises the
# path length constraint failure.
mkcsr rsa_inter_p0 "PureCrypt Pathlen Zero CA" rsa:2048
ca_ext 0 > ca_p0.ext
sign rsa_inter_p0 rsa_inter_p0.pem rsa_root 2003 ca_p0.ext

mkcsr rsa_subca "PureCrypt Sub CA" rsa:2048
sign rsa_subca rsa_subca.pem rsa_inter_p0 2004 ca.ext

mkcsr rsa_subleaf "subleaf.example.com" rsa:2048
sign rsa_subleaf rsa_subleaf.pem rsa_subca 2005 leaf_min.ext

# Leaf whose keyUsage lacks digitalSignature.
mkcsr rsa_leaf_nods "nods.example.com" rsa:2048
cat > leaf_nods.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,keyEncipherment
EOF
sign rsa_leaf_nods rsa_leaf_nods.pem rsa_inter 3003 leaf_nods.ext

# A certificate with serial number zero, which RFC 5280 forbids.
mkcsr zero_serial "zero.example.com" rsa:2048
openssl x509 -req -in zero_serial.csr -CA rsa_root.pem \
    -CAkey rsa_root_key.pem -set_serial 0 -days 825 \
    -out zero_serial.pem -extfile leaf_min.ext 2>/dev/null

# Self-signed cert with no basicConstraints at all, plus a leaf it
# issued. The issuer must fail the cA=TRUE requirement. A minimal
# openssl config is used because the system config injects
# basicConstraints CA:true into every self-signed cert.
printf '[req]\ndistinguished_name=dn\n[dn]\n' > min.cnf
openssl req -x509 -newkey rsa:2048 -keyout plain_root_key.pem \
    -out plain_root.pem -days 3650 -nodes \
    -subj "/C=US/O=Quad4/CN=PureCrypt Not A CA" \
    -addext "keyUsage=critical,digitalSignature" \
    -config min.cnf 2>/dev/null
mkcsr plain_leaf "plain.example.com" rsa:2048
sign plain_leaf plain_leaf.pem plain_root 2101 leaf_min.ext

# Self-signed CA whose keyUsage lacks keyCertSign, plus its leaf.
openssl req -x509 -newkey rsa:2048 -keyout ku_root_key.pem \
    -out ku_root.pem -days 3650 -nodes \
    -subj "/C=US/O=Quad4/CN=PureCrypt No CertSign CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,digitalSignature,cRLSign" 2>/dev/null
mkcsr ku_leaf "ku.example.com" rsa:2048
sign ku_leaf ku_leaf.pem ku_root 2201 leaf_min.ext

# --- EC P-256 root and leaf ------------------------------------------

mkroot ec_root "PureCrypt Test EC Root" ec -pkeyopt ec_paramgen_curve:P-256

mkcsr ec_leaf "ec.example.com" ec -pkeyopt ec_paramgen_curve:P-256
cat > ec_leaf.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ec.example.com
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
sign ec_leaf ec_leaf.pem ec_root 4001 ec_leaf.ext

# --- Ed25519 root and leaf --------------------------------------------

mkroot ed25519_root "PureCrypt Test Ed25519 Root" ed25519

mkcsr ed25519_leaf "ed.example.com" ed25519
cat > ed_leaf.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
subjectAltName=DNS:ed.example.com
EOF
sign ed25519_leaf ed25519_leaf.pem ed25519_root 5001 ed_leaf.ext

# --- Expired chain: real certs with dates entirely in the past --------
# openssl req -x509 cannot set dates, so the root is self-signed through
# openssl x509 -req -signkey which does accept -not_before/-not_after.

openssl req -newkey rsa:2048 -nodes -keyout expired_root_key.pem \
    -out expired_root.csr -subj "/C=US/O=Quad4/CN=PureCrypt Expired Root" \
    2>/dev/null
ca_ext "" > expired_root.ext
openssl x509 -req -in expired_root.csr -signkey expired_root_key.pem \
    -set_serial 6000 -not_before 20190101000000Z \
    -not_after 20291231235959Z -out expired_root.pem \
    -extfile expired_root.ext 2>/dev/null

mkcsr expired_leaf "expired.example.com" rsa:2048
leaf_ext > expired.ext
openssl x509 -req -in expired_leaf.csr -CA expired_root.pem \
    -CAkey expired_root_key.pem -set_serial 6001 \
    -not_before 20200101000000Z -not_after 20201231235959Z \
    -out expired_leaf.pem -extfile expired.ext 2>/dev/null

# --- Leaf under an untrusted root -------------------------------------

mkroot untrusted_root "PureCrypt Untrusted Root" rsa:2048
mkcsr untrusted_leaf "untrusted.example.com" rsa:2048
sign untrusted_leaf untrusted_leaf.pem untrusted_root 7001 leaf_min.ext

# --- Leaf with a critical unknown extension ----------------------------

mkcsr critext_leaf "crit.example.com" rsa:2048
cat > critext.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
subjectAltName=DNS:crit.example.com
1.3.6.1.4.1.55555.1=critical,DER:05:00
EOF
sign critext_leaf critext_leaf.pem rsa_root 7002 critext.ext

# --- Leaf signed with RSASSA-PSS ---------------------------------------

mkcsr pss_leaf "pss.example.com" rsa:2048
openssl x509 -req -in pss_leaf.csr -CA rsa_root.pem \
    -CAkey rsa_root_key.pem -set_serial 8001 -days 825 -sha256 \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -sigopt rsa_mgf1_md:sha256 \
    -out pss_leaf.pem -extfile leaf_min.ext 2>/dev/null

# --- Leaf with a critical SAN -------------------------------------------

mkcsr critsan_leaf "critsan.example.com" rsa:2048
cat > critsan.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
subjectAltName=critical,DNS:critsan.example.com,DNS:www.critsan.example.com
EOF
sign critsan_leaf critsan_leaf.pem rsa_root 7003 critsan.ext

# --- Version-1 anchor and its leaf --------------------------------------
# openssl 3.x always emits v3, so the v1 root is crafted with this
# package: the v3 cert is rebuilt without version or extensions and
# re-signed with purecrypt.rsa. openssl verify still accepts it.

openssl req -x509 -newkey rsa:2048 -nodes -keyout v1_root_key.pem \
    -out v1_root.pem -days 3650 \
    -subj "/C=US/O=Quad4/CN=PureCrypt V1 Root" 2>/dev/null
python3 - <<'PYEOF'
import sys
sys.path.insert(0, "../../src")
from purecrypt import asn1
from purecrypt.pem import decode_pem, encode_pem
from purecrypt.rsa import RSAPrivateKey

label, cert_der = decode_pem(open("v1_root.pem").read())
key = RSAPrivateKey.from_pem(open("v1_root_key.pem").read())
top = asn1.sequence_value(asn1.decode(cert_der))
tbs = asn1.sequence_value(top[0])
assert tbs[0].tag == 0xA0
body = tbs[1:7]
tbs_v1 = asn1.encode_sequence(*(asn1.encode_tlv(n.tag, n.content) for n in body))
sig = key.sign_v15(tbs_v1, "sha256")
alg = asn1.encode_tlv(tbs[2].tag, tbs[2].content)
cert = asn1.encode_sequence(tbs_v1, alg, asn1.encode_bit_string(sig))
open("v1_root.pem", "w").write(encode_pem("CERTIFICATE", cert))
PYEOF

mkcsr v1_leaf "v1.example.com" rsa:2048
cat > v1leaf.ext <<'EOF'
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature
subjectAltName=DNS:v1.example.com
EOF
sign v1_leaf v1_leaf.pem v1_root 7004 v1leaf.ext

# --- Leaf signed with sha1WithRSAEncryption ----------------------------

mkcsr sha1_leaf "sha1.example.com" rsa:2048
openssl x509 -req -in sha1_leaf.csr -CA rsa_root.pem \
    -CAkey rsa_root_key.pem -set_serial 9001 -days 825 -sha1 \
    -out sha1_leaf.pem -extfile leaf_min.ext 2>/dev/null

# --- Bundles and DER copies ---------------------------------------------

cat rsa_leaf.pem rsa_inter.pem rsa_root.pem > bundle.pem
openssl x509 -in rsa_root.pem -outform der -out rsa_root.der
openssl x509 -in rsa_leaf.pem -outform der -out rsa_leaf.der

rm -f -- ./*.csr ./*.srl ./*.ext ./min.cnf

echo "fixtures generated"
