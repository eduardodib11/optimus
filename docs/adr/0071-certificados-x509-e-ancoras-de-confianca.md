# ADR 0071: Certificados X.509 e âncoras de confiança

- Status: aceita (modo autônomo de Eduardo, 2026-11-16), aguardando a revisão dele
- Data: 2026-11-16
- Origem: backlog do M6, T-605 (SDD v1.0, seção 10.3)
- Relaciona-se com: ADR 0004, 0017, 0018 (assinaturas híbridas do sistema), 0070 (`tlsd`)

## Contexto

O SDD pede parser X.509 próprio sob fuzzing, raízes na imagem de sistema e revogação por OCSP stapling e CRLite. Ele não diz quais algoritmos de assinatura de certificado são aceitos. A web pública usa sobretudo ECDSA P-256, RSA e, raramente, Ed25519; sem eles o `tlsd` só falaria com servidores próprios. A assinatura híbrida Ed25519 + ML-DSA-65 da ADR 0018 é do **sistema** (imagem, pacotes, atualizações), não dos certificados da web, que ainda não têm cadeia pós-quântica.

## Decisão

1. **Algoritmos de certificado aceitos no M6** (só **verificação**): ECDSA com P-256 e SHA-256 ou SHA-384, RSA-PSS e RSA PKCS#1 v1.5 com módulos de 2048 a 4096 bits e SHA-256, SHA-384 ou SHA-512, e Ed25519. P-384 e P-521 ficam de fora por ora. O `CertificateVerify` do TLS aceita `ecdsa_secp256r1_sha256`, `rsa_pss_rsae_sha256/384` e `ed25519`.
2. **Verificação em `optcrypt`, assinatura não.** ECDSA e RSA entram só para verificar (menos código sensível); Ed25519 entra com verificação e assinatura, porque a ADR 0018 também precisa dele.
3. **Parser DER próprio** em `lib/ox509`: alocação limitada, profundidade máxima, comprimentos de acordo com o DER estrito (sem BER), `no_std`, sem `unsafe`. Campos que o `tlsd` não usa são pulados com validação de limites. Alvo de fuzzing obrigatório.
4. **Validação de cadeia.** Assinatura de cada elo, validade com a hora do `timed` (ADR 0070, item 9), `basicConstraints` e profundidade, `keyUsage`, `extKeyUsage serverAuth`, `nameConstraints`, nome do servidor por `subjectAltName` (sem usar o CN) e rejeição de extensões críticas desconhecidas. Cadeia máxima de 8 certificados.
5. **Âncoras.** Um conjunto de raízes (DER, com hash fixo) vai na imagem de sistema, dentro do volume imutável, assinado com o restante (ADR 0015 e 0018). No M6 o conjunto vem de um arquivo do repositório, `data/trust/roots.der`, gerado por ferramenta de host a partir do conjunto público do projeto Mozilla com licença MPL-2.0, com uma nota de origem; o `xtask` confere o hash. O usuário não adiciona raízes por conta própria no M6.
6. **Revogação.** OCSP stapling: se o servidor mandar a resposta, o `tlsd` valida (assinatura, validade, certificado) e rejeita certificados revogados; sem resposta, o comportamento depende da política (padrão: aceitar sem grampo, com aviso no log, o que é o que os navegadores fazem para certificados sem `must-staple`; com `must-staple`, exigir). CRLite depende do canal de atualização do `updated` (marco posterior) e **não** entra no M6; fica registrado como pendência de Gate 3.
7. **Sem AIA, sem busca por rede.** O `tlsd` não busca certificados intermediários nem OCSP por conta própria; usa só o que o servidor entrega.
8. **Fixação.** Chaves públicas fixadas (`pin`) pulam a cadeia e só conferem a chave (ADR 0070, item 7).

## Alternativas consideradas

- Só Ed25519 e ECDSA: simplifica, mas deixa de fora a maior parte da web (RSA é mais da metade das raízes). Rejeitada.
- Delegar a verificação ao servidor ou ao SO anfitrião: contraria o princípio local por padrão.
- Aceitar certificados sem verificação de nome por padrão: rejeitada (ADR 0070, item 7).

## Consequências

- O `optcrypt` ganha ECDSA P-256 (verificação), RSA (verificação) e Ed25519, todos com o rito de aceite da ADR 0053 (vetores oficiais, Wycheproof, tempo constante onde há segredo).
- Nova crate `lib/ox509`, com alvo de fuzzing e testes com cadeias reais e malformadas.
- O arquivo de raízes entra na verificação do `cargo xtask check`.
- Qualquer mudança no que está acima exige ADR nova.

## Notas de implementação (T-655)

- **Perfil do OCSP.** O cliente oferece `status_request` (RFC 6066, seção 8) e lê a resposta na extensão do `CertificateEntry` da folha. `ox509::ocsp::validate` confere, nesta ordem: `successful` e `id-pkix-ocsp-basic`; a assinatura, pela chave do emissor da folha ou de um respondedor delegado (certificado do próprio emissor, com `id-kp-OCSPSigning`, na validade); uma resposta única para o **número de série** da folha; `thisUpdate` (folga de 5 min) e `nextUpdate` (sem ele, a resposta vale 7 dias).
- **Sem SHA-1.** O `CertID` leva *hashes* do nome e da chave do emissor, quase sempre SHA-1. Como o signatário já foi provado emissor (ou delegado dele), o número de série basta para saber de qual certificado se fala; o `optcrypt` não ganha SHA-1.
- **Política.** Revogação provada recusa sempre (alerta 44). Resposta que não vale (assinatura errada, vencida, `unknown`, mal formada) conta como ausente: sem `must-staple` nem `OcspPolicy::Require` a conexão segue e o motivo fica em `Client::ocsp()` para o `logd`; com um dos dois, é erro (alerta 113 para resposta inválida e 42 para ausente). Um atacante no caminho poderia só retirar a resposta, então tratar a inválida como ausente não perde nada.
- **Pin.** O modo `pin` não tem cadeia e não confere revogação.
