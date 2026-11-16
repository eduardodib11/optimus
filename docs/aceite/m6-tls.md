# Aceite do TLS no M6: interoperabilidade e casos de recusa (T-657)

O cliente TLS 1.3 do `tlsd` (`lib/otls`, com o verificador do `optcrypt`) foi
testado contra um servidor independente: o `rustls` 0.23 com `aws-lc-rs`, que
fala o grupo híbrido `X25519MLKEM768` (`tools/tlshost`). O OpenSSL 3.5 do
backlog não está nos *runners* do CI (Ubuntu 24.04 traz o 3.0, sem o grupo), e
o `tlshost` cobre o mesmo papel (ADR 0070, item 12) com os casos de recusa à
mão.

Os testes rodam em `cargo xtask test unit` (e `all`): o cliente fala com o
servidor por um soquete de verdade, no host (`tools/tlshost/tests/interop.rs`).
Os certificados são de teste e ficam em `tools/tlshost/fixtures` (`gerar.sh`).

| Caso | Servidor | Esperado | Teste |
|---|---|---|---|
| Handshake híbrido e GET, folha ECDSA P-256, RSA 2048 (PSS) e Ed25519 | TLS 1.3, `X25519MLKEM768` | conecta; o servidor registra `kx=X25519MLKEM768` | `handshake_hibrido_com_cada_tipo_de_chave` |
| Cada suíte do ADR 0070, item 3 | só ChaCha20-Poly1305, só AES-256-GCM (onde há AES-NI) | conecta com a suíte do servidor | `cada_suite_das_duas` |
| 1 MiB de dados e `KeyUpdate` do servidor | TLS 1.3 | corpo íntegro; troca de chaves sem perder dado | `um_mebibyte_e_troca_de_chaves` |
| Servidor só TLS 1.2 | TLS 1.2 | recusado (`protocol_version`, alerta 70 do servidor; `Tls12Only` se ele respondesse como 1.2) | `servidor_so_com_tls12_e_recusado` |
| Servidor sem o grupo híbrido (ADR 0070, item 4) | TLS 1.3, só `x25519` | recusado (`handshake_failure`, alerta 40 do servidor) | `servidor_sem_o_grupo_hibrido_e_recusado` |
| Nome errado | folha para `tls.optimus.test` | `NameMismatch` | `nome_raiz_e_pin` |
| Raiz desconhecida | idem | `UnknownIssuer` | `nome_raiz_e_pin` |
| `pin` certo, errado e de outra folha | idem | passa sem raízes; `BadCertificate` nos outros dois | `nome_raiz_e_pin` |
| OCSP bom, e com `Require` | OCSP grampeado bom | conecta; `Ocsp::Good` | `ocsp_grampeado` |
| OCSP revogado | OCSP grampeado revogado | recusado: `Revoked` (alerta 44) | `ocsp_grampeado` |
| Sem OCSP | sem grampo | conecta com `Ocsp::Absent`; recusado com `Require` (`StapleRequired`) | `ocsp_grampeado` |
| OCSP de outro certificado | grampo da folha P-256 numa folha RSA | ignorado por padrão (`NoMatch`); recusado com `Require` | `ocsp_grampeado` |
| Servidor pede certificado ao cliente | `client_auth` | o cliente manda `Certificate` vazio; o servidor encerra com `certificate_required` (116) | `servidor_que_pede_certificado_ao_cliente` |

Os casos de mensagens malformadas (`ServerHello` com extensão repetida, HRR,
`CertificateVerify` e `Finished` errados, registros truncados) ficam nos testes
do próprio `otls` (`client_tests`, `msg_tests`) e no fuzz do handshake
(T-658), onde o servidor de teste é escrito para errar de propósito.
