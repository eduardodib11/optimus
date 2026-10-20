# ADR 0018: Assinaturas híbridas Ed25519 + ML-DSA-65

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 5.1, 13.3, 13.4 e 14.5
- Relaciona-se com: ADR 0004 (cripto verificada), ADR 0005 (optboot),
  ADR 0015 (imagem imutável), ADR 0017 (troca de chaves híbrida)

## Contexto

Boot, imagem de sistema, pacotes, modelos e atualizações dependem de
assinaturas. Uma imagem assinada hoje pode continuar em uso por anos, e chaves
de projeto são difíceis de trocar em máquinas já instaladas. Um adversário com
computador quântico capaz de forjar Ed25519 poderia publicar atualização falsa.
Os esquemas pós-quânticos são padronizados (FIPS 204), mas ainda têm pouco
histórico de uso e análise.

## Decisão

- Toda assinatura do sistema é dupla: Ed25519 e ML-DSA-65. A verificação só
  aceita se as duas forem válidas.
- Vale para o kernel ELF e o bootfs (verificados pelo `optboot`), a imagem `.osi`,
  os pacotes `.opk`, os modelos `.omdl`, as atualizações `.oupd` e os manifestos
  de serviço (`.oman`).
- No M3 a verificação fica provisória (ADR 0034, item 10): o manifesto vale pelo
  hash do bootfs conferido pelo `optboot`. A promoção para a assinatura dupla é
  obrigatória antes da primeira imagem distribuída.
- A raiz fica offline em dois tokens de hardware; chaves de release são
  intermediárias com validade de 1 ano, rotacionadas no estilo TUF.

## Alternativas

- **Só Ed25519:** assinaturas de 64 bytes e verificação rápida, mas sem defesa
  contra forja quântica durante a vida útil das imagens.
- **Só ML-DSA-65:** resiste ao ataque quântico, mas uma falha no esquema ou na
  implementação ainda nova anularia toda a cadeia de confiança.
- **SLH-DSA (hash):** segurança conservadora, mas assinaturas de 8 a 50 KiB e
  assinatura lenta; caro demais para pacotes e deltas.
- **RSA-4096:** maior e mais lento que Ed25519, e igualmente quebrável.

## Consequências

- Cada assinatura ocupa cerca de 3,3 KiB; chaves públicas, cerca de 2 KiB.
- O `optboot` carrega dois verificadores, ambos da `optcrypt` (ADR 0004).
- Se um dos algoritmos for quebrado, o par restante segura a cadeia até a troca.
- Ferramentas de build e assinatura offline precisam suportar os dois esquemas.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- Incluídos os manifestos de serviço no escopo da assinatura.
- Registrada a verificação provisória do M3 (ADR 0034).
