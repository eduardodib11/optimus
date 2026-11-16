# Certificados de teste do `ox509`

Usados pelos testes de `src/tests.rs` e como semente do fuzzing
(`fuzz/ox509/seeds/cert/`). São dados públicos, sem chave privada.

| Arquivo | Origem |
|---|---|
| `isrg-root-x1.der` | Raiz ISRG Root X1 (RSA 4096), <https://letsencrypt.org/certs/isrgrootx1.der>; SHA-256 `96bcec06…bddf08c6`. Está no conjunto da Mozilla. |
| `isrg-root-x2.der` | Raiz ISRG Root X2 (ECDSA P-384), <https://letsencrypt.org/certs/isrg-root-x2.der>. |
| `le-r11.der` | Intermediária R11 da Let's Encrypt (RSA, emitida pela X1). |
| `le-e7.der` | Intermediária E7 da Let's Encrypt (P-384, emitida pela X2). |
| `teste-*.der` | Gerados com OpenSSL 3.0 e `gerar.cnf` (2026-11-16), validade a partir dessa data. |

As cadeias `teste-*`:

- `teste-root` (P-256, ECDSA SHA-256) → `teste-int` (RSA 2048, `pathlen:0`) → `teste-leaf` (P-256, assinada com RSA-PSS SHA-256; SAN com DNS, curinga, IPv4 e IPv6; `must-staple`).
- `teste-edca` (Ed25519, `nameConstraints`) → `teste-edleaf` (Ed25519, `casa.lan`).

Casos ruins da validação (T-651), com as mesmas chaves:

- `teste-int` → `teste-int2` (CA) → `teste-leaf2`: estoura o `pathlen:0` da `teste-int`.
- `teste-int` → `teste-cliente`: só `clientAuth`.
- `teste-leaf` → `teste-vitima`: emitido por uma folha, que não é CA.
- `teste-edca` → `teste-edmau` (excluído), `teste-edfora` (fora do permitido) e `teste-edcuringa` (curinga e IP dentro do permitido).

Para regerar (as chaves são descartadas; as assinaturas mudam):

```sh
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req -new -x509 -key root.key -sha256 -days 7300 -subj "/C=BR/O=Optimus Teste/CN=Raiz P-256" \
  -extensions root -config <(cat /etc/ssl/openssl.cnf gerar.cnf) -out root.pem
openssl genrsa -out int.key 2048
openssl req -new -key int.key -subj "/C=BR/O=Optimus Teste/CN=Intermediaria RSA" -out int.csr
openssl x509 -req -in int.csr -CA root.pem -CAkey root.key -sha256 -days 3650 -set_serial 0x1002 \
  -extfile gerar.cnf -extensions int -out int.pem
openssl ecparam -name prime256v1 -genkey -noout -out leaf.key
openssl req -new -key leaf.key -subj "/CN=optimus.test" -out leaf.csr
openssl x509 -req -in leaf.csr -CA int.pem -CAkey int.key -sha256 -sigopt rsa_padding_mode:pss \
  -sigopt rsa_pss_saltlen:digest -days 365 -set_serial 0x00d1 -extfile gerar.cnf -extensions leaf -out leaf.pem
openssl genpkey -algorithm ed25519 -out ed.key
openssl req -new -x509 -key ed.key -days 7300 -subj "/CN=Raiz Ed25519" -extensions edca \
  -config <(cat /etc/ssl/openssl.cnf gerar.cnf) -out edca.pem
openssl genpkey -algorithm ed25519 -out edl.key
openssl req -new -key edl.key -subj "/CN=casa.lan" -out edl.csr
openssl x509 -req -in edl.csr -CA edca.pem -CAkey ed.key -days 365 -set_serial 7 \
  -extfile gerar.cnf -extensions edleaf -out edleaf.pem
openssl ecparam -name prime256v1 -genkey -noout -out int2.key
openssl req -new -key int2.key -subj "/C=BR/O=Optimus Teste/CN=Intermediaria 2" -out int2.csr
openssl x509 -req -in int2.csr -CA int.pem -CAkey int.key -sha256 -days 3650 -set_serial 0x2002 \
  -extfile gerar.cnf -extensions int2 -out int2.pem
openssl ecparam -name prime256v1 -genkey -noout -out leaf2.key
openssl req -new -key leaf2.key -subj "/CN=fundo.optimus.test" -out leaf2.csr
openssl x509 -req -in leaf2.csr -CA int2.pem -CAkey int2.key -sha256 -days 365 -set_serial 0x22 \
  -extfile gerar.cnf -extensions leaf2 -out leaf2.pem
openssl x509 -req -in leaf.csr -CA int.pem -CAkey int.key -sha256 -days 365 -set_serial 0x33 \
  -extfile gerar.cnf -extensions cliente -out cliente.pem
openssl req -new -key leaf2.key -subj "/CN=vitima.optimus.test" -out vit.csr
openssl x509 -req -in vit.csr -CA leaf.pem -CAkey leaf.key -sha256 -days 365 -set_serial 0x44 \
  -extfile gerar.cnf -extensions vitima -out vitima.pem
for x in edmau edfora edcuringa; do
  openssl x509 -req -in edl.csr -CA edca.pem -CAkey ed.key -days 365 -set_serial 0x55 \
    -extfile gerar.cnf -extensions $x -out $x.pem
done
for f in root int leaf edca edleaf int2 leaf2 cliente vitima edmau edfora edcuringa; do
  openssl x509 -in $f.pem -outform der -out teste-$f.der
done
```

Conferido também contra as 119 raízes do conjunto da Mozilla (via
`cacert.pem` do curl, 2026-11-16): todas são lidas; 4 têm assinatura ou
chave fora da ADR 0071 e saem como `Unsupported`.
