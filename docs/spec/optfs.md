# Layout em bytes do OptFS

Fonte: ADR 0052. Este arquivo e `lib/optfs-format` precisam concordar; divergir da ADR exige ADR nova. Inteiros em little-endian. Bloco de 4 KiB.

## Regiões da partição

| Bloco | Conteúdo |
|---|---|
| 0 | Cabeçalho do volume (ADR 0053); cópia no último bloco |
| 1, 4 a 15 | Reservados |
| 2, 3 | Superblocos A e B (o txg `t` grava em `2 + t % 2`) |
| 16 em diante | Área alocável, em grupos de 32 768 blocos (128 MiB) |

## Ponteiro de bloco (72 bytes)

| Deslocamento | Tam. | Campo |
|---|---|---|
| 0 | 8 | `endereço` |
| 8 | 8 | `nascimento` (txg) |
| 16 | 4 | `tamanho_lógico` (até 131 072) |
| 20 | 4 | `tamanho_físico` (múltiplo de 4096, até 131 072) |
| 24 | 4 | `tipo`: bits 0–7 nível, 8–15 bloco (0 nó, 1 dados, 2 mapa de bits), 16–23 compressão (0 nenhuma, 1 LZ4), 24–31 integridade (0 hash, 1 AEAD) |
| 28 | 12 | `nonce` (AEAD: época `u32` e contador `u64`; hash: zero) |
| 40 | 32 | `autenticação` (AEAD: tag de 16 bytes e 16 zeros; hash: SHA-256) |

O ponteiro nulo é todo zero.

## Superbloco (um bloco)

| Deslocamento | Tam. | Campo |
|---|---|---|
| 0 | 8 | `OPTFSSB1` |
| 8 | 4 | versão (1) |
| 12 | 4 | reservado (0) |
| 16 | 16 | UUID do volume |
| 32 | 8 | txg |
| 40 | 4 | modo de integridade (0 hash, 1 AEAD) |
| 44 | 4 | reservado (0) |
| 48 | 72 | ponteiro da raiz das raízes |
| 120 | 8 | tamanho do volume em blocos |
| 128 | 4 | épocas de chave usadas |
| 132 | 4 | reservado (0) |
| 136 | 8 | blocos livres |
| 144 | 3888 | reservado (0) |
| 4032 | 32 | SHA-256 dos bytes 0..4032 |
| 4064 | 32 | HMAC-SHA-256 dos bytes 0..4064 com a chave de cabeçalho (zero no modo hash) |

## Nó de árvore

Cabeçalho de 64 bytes: `OFNd` (0), nível u8 (4), 0 (5), itens u16 (6), árvore dona u64 (8), txg u64 (16), endereço do próprio bloco u64 (24), zeros até 64.

Chave de 24 bytes: objeto u64 (0), tipo u8 (8: 0 inode, 1 dirent, 2 extent, 3 xattr), 7 zeros, deslocamento u64 (16). A ordem é a lexicográfica de `(objeto, tipo, deslocamento)`.
