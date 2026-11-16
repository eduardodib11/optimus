# ADR 0070: `tlsd`: sessões TLS 1.3 e isolamento de chaves

- Status: aceita; revisada e aprovada pelo Eduardo em 2026-11-16 (T-606)
- Data: 2026-11-16
- Origem: backlog do M6, T-604 (SDD v1.0, seção 10.3)
- Relaciona-se com: ADR 0004 (cripto verificada), 0017 (TLS 1.3 híbrido), 0053 (cripto de volume), 0068 (`netd`), 0071 (certificados)

## Contexto

A ADR 0017 fixa TLS 1.3 só, com X25519+ML-KEM-768, AES-256-GCM e ChaCha20-Poly1305, e diz que chaves de sessão nunca saem do `tlsd`. Falta definir a interface com os clientes, as suítes e extensões aceitas, e o que o `optcrypt` precisa ter antes.

## Decisão

1. **O `tlsd` é cliente do `netd`.** O cliente comum abre a sessão no `tlsd` (`optimus.net.Tls@1`), que abre o socket no `netd` com o `NetAccess` do próprio cliente (ADR 0068, item 3: o `tlsd` não amplia a política). O `tlsd` mesmo recebe só o necessário para fazer o que o cliente pediu, por endpoint derivado.
2. **Texto claro por anéis.** O cliente liga dois anéis SPSC de bytes ao `tlsd` (como o socket do `netd`); o `tlsd` cifra e decifra, e o `netd` só vê registros TLS. Nem o `netd` nem o cliente veem segredos de tráfego, chaves ou o estado do handshake.
3. **Versão e suítes.** Só TLS 1.3 (RFC 8446). Suítes: `TLS_AES_256_GCM_SHA384` e `TLS_CHACHA20_POLY1305_SHA256`. `TLS_AES_128_GCM_SHA256` fica de fora (o SDD só lista as duas). Um servidor que só fala TLS 1.2 dá erro `Tls12Only` ao cliente (ADR 0017).
4. **Troca de chaves.** O cliente oferece `X25519MLKEM768` primeiro e `X25519` puro depois, só se a política do cliente permitir (por padrão, **não**: queda para clássico é decisão explícita visível, não um *downgrade* silencioso). Grupos NIST (secp256r1) não são oferecidos.
5. **Sem 0-RTT e sem retomada de sessão no M6.** A retomada (PSK) entra depois, em ADR própria, junto do armazenamento de tíquetes.
6. **Assinaturas aceitas** e **confiança**: ADR 0071.
7. **Nome do servidor** (SNI) e verificação do nome são obrigatórios; o cliente passa o nome e não pode desligar a verificação. Existe um modo `pin` (hash da chave pública) para o `updated` (SDD 10.4), declarado no manifesto.
8. **Servidor.** O `tlsd` servidor (para o Cockpit remoto do perfil Server) fica fora do M6; a máquina de estados do handshake nasce separada do papel (cliente ou servidor) para não precisar de reescrita.
9. **Tempo de validade.** O `tlsd` lê a hora do `timed`. Sem hora de parede confiável (relógio ainda não sincronizado), a validação de validade falha de forma fechada (`ClockUnsynced`), e o erro aparece ao usuário.
10. **`optcrypt` primeiro.** Ordem: SHA-384 e SHA-512 com HMAC e HKDF; X25519; ML-KEM-768; só depois o handshake. Cada primitiva traz propriedades verificáveis no padrão da ADR 0053 (vetores oficiais, Wycheproof, tempo constante, sem `Debug` de segredo, cobertura ≥ 80 %). A origem é código verificado e adaptado (ADR 0004).
11. **Erros.** O `tlsd` nunca devolve ao cliente o motivo detalhado de um erro de decifração (evita oráculos); o motivo vai para o `logd`.
12. **Fuzzing e interoperabilidade.** O parser de mensagens do handshake e o de certificados têm alvos de fuzzing. A interoperabilidade é testada contra um servidor TLS 1.3 do host (OpenSSL 3.5 ou posterior, que já oferece o grupo híbrido) pelo cenário de integração.

## Alternativas consideradas

- TLS como biblioteca no processo do cliente: as chaves ficariam no espaço de cada app. Rejeitada (ADR 0017).
- Oferecer também secp256r1: amplia compatibilidade, mas é mais código a verificar, e o SDD pede X25519+ML-KEM. Rejeitada.
- Retomada de sessão agora: aumenta superfície e estado persistente sem ser necessária ao Gate 2. Adiada.

## Consequências

- O `lib/optcrypt` cresce (SHA-384/512, X25519, ML-KEM-768) com o rito de aceite da ADR 0053.
- O aceite de ponta a ponta do M6 depende de OpenSSL 3.5 ou posterior no ambiente de CI (ou de um servidor TLS de host próprio em `tools/`).
- Qualquer mudança no que está acima exige ADR nova.
