# ADR 0015: Imagem de sistema imutável, verificada por Merkle, em slots A/B

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 5.1, 5.5, 7.3, 9.1, 9.2 e 14.5
- Relaciona-se com: ADR 0005 (optboot), ADR 0014 (OptFS), ADR 0018 (assinaturas)

## Contexto

O RF-12 pede atualização atômica, assinada e com rollback em até um boot
(RNF-06). Se os arquivos do sistema podem ser alterados em repouso, um invasor
deixa código persistente que sobrevive a reinícios. Atualizar arquivo por arquivo
também deixa a máquina inutilizável se a energia cair no meio.

## Decisão

- O disco tem dois slots de sistema, `sys-a` e `sys-b` (1 GiB cada; 384 MiB no
  Lite), e kernel e bootfs de cada slot ficam na ESP.
- A imagem (`.osi`) é um OptFS somente leitura com árvore de Merkle SHA-256 sobre
  blocos de 4 KiB. A raiz está no manifesto do slot, com assinatura híbrida.
  Cada leitura verifica o caminho até a raiz; bloco divergente gera erro de E/S
  e alerta, nunca dado corrompido.
- O sistema nunca escreve na imagem em uso. O `updated` grava a nova imagem no
  slot inativo (deltas `.oupd`, metadados no estilo TUF, contador anti-rollback),
  verifica e troca o slot ativo na variável UEFI e no TPM.
- Se o slot ativo falhar três vezes sem marcar sucesso, o `optboot` volta ao
  outro slot; se ambos falharem, inicia o `rescue` a partir do bootfs.

## Alternativas

- **Sistema mutável com gerenciador de pacotes (apt, dnf, pacman):** flexível,
  mas o estado diverge entre máquinas, a atualização não é atômica e nada impede
  alterar binários em repouso.
- **Snapshots do sistema de arquivos para rollback (estilo btrfs/snapper):**
  dão rollback, mas a raiz continua gravável e sem verificação por bloco.
- **Imagem única com verificação, sem A/B (dm-verity sem slots):** protege em
  repouso, mas a atualização precisa de um modo especial e não tem volta fácil.
- **Árvore de objetos versionada (estilo OSTree):** atualização atômica com
  menos espaço, porém sem verificação de cada bloco lido.

## Consequências

- Mudança de sistema só por atualização assinada; o resto fica no volume de dados.
- O disco reserva espaço para duas imagens, o que pesa no perfil Lite.
- O fluxo A/B é modelado em TLA+ e testado com rollback no CI.
