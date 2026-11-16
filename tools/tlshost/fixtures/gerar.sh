#!/bin/sh
# Regera as chaves e os certificados de teste do `tlshost` (T-654, T-657).
# São chaves DE TESTE, sem valor: ficam no repositório de propósito, para o
# servidor de host e o `netcli` terem sempre o mesmo certificado (o `pin` da
# imagem de teste é o SHA-256 do SPKI de `p256.der`). Regerar muda as
# assinaturas e o `pin`; os testes leem os certificados daqui.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
cd "$tmp"
cat > ext.cnf <<'CNF'
[leaf]
basicConstraints=CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:tls.optimus.test
CNF
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -sha256 -days 36500 -subj "/C=BR/O=Optimus Teste/CN=CA TLS Teste" \
  -addext "basicConstraints=critical,CA:true,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out ca.pem
leaf() { # nome série comando-de-chave...
  n=$1 ser=$2; shift 2
  "$@"
  openssl req -new -key "$n.key" -subj "/CN=tls.optimus.test" -out "$n.csr"
  openssl x509 -req -in "$n.csr" -CA ca.pem -CAkey ca.key -sha256 -days 36500 -set_serial "$ser" \
    -extfile ext.cnf -extensions leaf -out "$n.pem"
}
leaf p256 0x201 openssl ecparam -name prime256v1 -genkey -noout -out p256.key
leaf rsa 0x202 openssl genrsa -out rsa.key 2048
leaf ed25519 0x203 openssl genpkey -algorithm ed25519 -out ed25519.key
openssl x509 -in ca.pem -outform DER -out "$here/ca.der"
for n in p256 rsa ed25519; do
  openssl x509 -in "$n.pem" -outform DER -out "$here/$n.der"
  openssl pkcs8 -topk8 -nocrypt -in "$n.key" -outform DER -out "$here/$n.key.der"
done
# OCSP do `p256`: bom e revogado (série 0201), assinados pela CA.
exp=$(date -u -d '+36500 days' +%y%m%d%H%M%SZ)
rev=$(date -u -d '-1 day' +%y%m%d%H%M%SZ)
printf 'V\t%s\t\t0201\tunknown\t/CN=a\n' "$exp" > good.idx
printf 'R\t%s\t%s,keyCompromise\t0201\tunknown\t/CN=a\n' "$exp" "$rev" > rev.idx
openssl ocsp -issuer ca.pem -cert p256.pem -no_nonce -reqout req.der
openssl ocsp -index good.idx -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin req.der -respout "$here/staple-bom.der" -ndays 3650
openssl ocsp -index rev.idx -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin req.der -respout "$here/staple-revogado.der" -ndays 3650
