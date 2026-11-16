#!/bin/sh
# Regera os certificados e as respostas OCSP `ocsp-*.der` (T-655) com o
# OpenSSL 3.0. Usa um diretório temporário e descarta as chaves; as
# assinaturas e os instantes mudam a cada execução, então os testes de
# `src/ocsp_tests.rs` (`THIS_UPDATE`, `REVOKED_AT`, `SEM_NEXT_UPDATE`) têm
# de acompanhar os novos `thisUpdate` (veja `openssl ocsp -respin ... -resp_text`).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
cd "$tmp"
cat > ext.cnf <<'CNF'
[leaf]
basicConstraints=CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ocsp.optimus.test
[leafms]
basicConstraints=CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:ocsp.optimus.test
tlsfeature=status_request
[resp]
basicConstraints=CA:false
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
CNF
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -new -x509 -key ca.key -sha256 -days 3650 -subj "/C=BR/O=Optimus Teste/CN=CA OCSP" \
  -addext "basicConstraints=critical,CA:true,pathlen:0" -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out ca.pem
# nome:série:extensão. 0101 bom, 0102 revogado, 0103 fora do índice, 0104 must-staple.
for n in bom:0x101:leaf revogado:0x102:leaf ms:0x104:leafms desconhecido:0x103:leaf; do
  IFS=: read -r name ser ext <<EOF2
$n
EOF2
  openssl ecparam -name prime256v1 -genkey -noout -out "$name.key"
  openssl req -new -key "$name.key" -subj "/CN=ocsp.optimus.test" -out "$name.csr"
  openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -sha256 -days 365 -set_serial "$ser" \
    -extfile ext.cnf -extensions "$ext" -out "$name.pem"
done
# Respondedor delegado pela CA e um estranho.
openssl ecparam -name prime256v1 -genkey -noout -out resp.key
openssl req -new -key resp.key -subj "/CN=Respondedor OCSP" -out resp.csr
openssl x509 -req -in resp.csr -CA ca.pem -CAkey ca.key -sha256 -days 365 -set_serial 0x900 \
  -extfile ext.cnf -extensions resp -out resp.pem
openssl ecparam -name prime256v1 -genkey -noout -out outro.key
openssl req -new -x509 -key outro.key -sha256 -days 365 -subj "/CN=Outro" -out outro.pem
# Índice do respondedor (subjects distintos, que o OpenSSL exige).
rev=$(date -u -d '-1 day' +%y%m%d%H%M%SZ)
exp=$(date -u -d '+365 days' +%y%m%d%H%M%SZ)
printf 'V\t%s\t\t0101\tunknown\t/CN=ocsp1\nR\t%s\t%s,keyCompromise\t0102\tunknown\t/CN=ocsp2\nV\t%s\t\t0104\tunknown\t/CN=ocsp3\n' \
  "$exp" "$exp" "$rev" "$exp" > index.txt
resp() { # saída cert assinante chave opções...
  out=$1 cert=$2 sc=$3 sk=$4; shift 4
  openssl ocsp -issuer ca.pem -cert "$cert" -no_nonce -reqout req.der
  openssl ocsp -index index.txt -CA ca.pem -rsigner "$sc" -rkey "$sk" -reqin req.der -respout "$out" "$@"
}
resp ocsp-resp-bom.der bom.pem ca.pem ca.key -ndays 3650
resp ocsp-resp-revogado.der revogado.pem ca.pem ca.key -ndays 3650
resp ocsp-resp-ms.der ms.pem ca.pem ca.key -ndays 3650
resp ocsp-resp-delegada.der bom.pem resp.pem resp.key -ndays 3650
resp ocsp-resp-desconhecido.der desconhecido.pem ca.pem ca.key -ndays 3650
resp ocsp-resp-curta.der bom.pem ca.pem ca.key -nmin 60
resp ocsp-resp-estranho.der bom.pem outro.pem outro.key -ndays 3650 -resp_no_certs
resp ocsp-resp-sem-next.der bom.pem ca.pem ca.key
openssl x509 -in ca.pem -outform DER -out ocsp-ca.der
for n in bom revogado ms desconhecido; do openssl x509 -in "$n.pem" -outform DER -out "ocsp-folha-$n.der"; done
openssl x509 -in resp.pem -outform DER -out ocsp-respondedor.der
cp ocsp-*.der "$here/"
