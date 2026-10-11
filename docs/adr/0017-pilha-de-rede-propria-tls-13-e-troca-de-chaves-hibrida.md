# ADR 0017: Pilha de rede própria, só TLS 1.3 e troca de chaves híbrida

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 10, 13.2 e 13.3
- Relaciona-se com: ADR 0003 (tudo do zero), ADR 0004 (cripto verificada),
  ADR 0011 (sem root), ADR 0018 (assinaturas híbridas)

## Contexto

A rede é a maior superfície de ataque remoto. Num microkernel, uma pilha no
kernel colocaria parsers de pacotes, TCP e DNS dentro da base de confiança.
Ao mesmo tempo, tráfego gravado hoje pode ser decifrado no futuro por um
computador quântico ("guardar agora, decifrar depois"), e a ADR 0003 proíbe
importar uma pilha pronta para a imagem.

## Decisão

- A pilha inteira (Ethernet, IPv4/IPv6, TCP, UDP, DNS) roda no processo `netd`,
  em espaço de usuário, com anéis de pacotes sem cópia entre driver e `netd`.
- A rede é negada por padrão: entrada bloqueada e saída só com a capability
  `NetAccess`, que lista destinos, portas e protocolo por processo.
- O `tlsd` implementa só TLS 1.3, com troca de chaves híbrida X25519+ML-KEM-768
  e cifras AES-256-GCM e ChaCha20-Poly1305. Chaves de sessão nunca saem dele.
- Parser X.509 próprio sob fuzzing contínuo; raízes confiáveis na imagem;
  revogação por OCSP stapling e CRLite.

## Alternativas

- **Pilha no kernel:** menos trocas de contexto, mas um bug num parser de rede
  vira comprometimento do kernel. Contraria a ADR 0001.
- **Aceitar TLS 1.2:** amplia a compatibilidade, mas traz renegociação, suítes
  sem sigilo futuro e downgrade. Mais código, mais ataque; rejeitado.
- **Só clássico (X25519):** maduro, mas não protege tráfego gravado contra o
  adversário quântico futuro.
- **Só pós-quântico (ML-KEM):** jovem; uma falha no esquema ou na implementação
  deixaria a sessão sem proteção. O híbrido só cai se os dois caírem.

## Consequências

- Servidores que só falam TLS 1.2 ficam inacessíveis; o erro aparece ao usuário.
- O handshake fica cerca de 1,1 KiB maior por causa do ML-KEM-768.
- Um `netd` tomado não ganha acesso ao kernel nem às chaves do `tlsd`.
- Desempenho de rede depende de IPC e anéis eficientes (ADRs 0001 e 0007).
