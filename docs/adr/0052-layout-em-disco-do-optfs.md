# ADR 0052: Layout em disco do OptFS

- Status: proposta (aguarda a revisão do Eduardo; nenhum código do OptFS antes do aceite; T-502)
- Data: 2026-11-14
- Origem: SDD v1.0, seções 9.1 a 9.4 e 13.2; backlog do M5, T-502
- Relaciona-se com: ADR 0014 (princípios do OptFS), 0015 (imagem Merkle), 0038 (`memd`), 0053 (criptografia), 0056 (`storaged`)

## Contexto

A ADR 0014 fixa os princípios do OptFS: copy-on-write com árvore B+ de extents, árvore autenticada até o superbloco, dois superblocos rotativos com contador de transação, snapshots, LZ4 e zstd, cotas por realm. Ela não fixa o formato. As tarefas T-523 a T-525 e T-528 precisam saber o tamanho do bloco, o que um ponteiro carrega, como um commit fica atômico, como se escolhe o superbloco depois de uma queda, como snapshots compartilham blocos e quando um bloco liberado pode ser reusado.

Erro de formato custa caro: depois que há dados em disco, toda mudança exige migração. Por isso o formato é decidido aqui, antes do código.

## Decisão

### 1. Unidades e regiões

- Bloco de 4 KiB, o mesmo da árvore de Merkle da imagem (ADR 0015). Endereço é o número do bloco (`u64`) a partir do início da partição `data` (SDD 9.1). Inteiros em little-endian.
- **Cabeçalho do volume** (ADR 0053: identificação, algoritmo e keyslots) no bloco 0 e uma cópia idêntica no último bloco da partição. As duas cópias são gravadas em momentos diferentes, com `flush` entre elas, para que um dano localizado não leve as duas.
- **Superblocos A e B** nos blocos 2 e 3. Blocos 1 e 4 a 15 ficam reservados. O resto é área alocável.

### 2. Ponteiro de bloco (72 bytes)

| Campo | Bytes | Conteúdo |
|---|---|---|
| `endereço` | 8 | primeiro bloco |
| `nascimento` | 8 | txg em que o bloco foi escrito |
| `tamanho_lógico` | 4 | bytes antes da compressão (até 128 KiB) |
| `tamanho_físico` | 4 | bytes gravados, múltiplo de 4 KiB |
| `tipo` | 4 | nível na árvore (0 = folha), tipo do bloco (nó, dados, mapa de bits), compressão (0 nenhuma, 1 LZ4, 2 zstd reservado), modo de integridade |
| `nonce` | 12 | modo AEAD: época `u32` e contador `u64` (ADR 0053); modo hash: zero |
| `autenticação` | 32 | modo AEAD: tag de 16 bytes e 16 zeros; modo hash: SHA-256 do bloco gravado |

- **Modo hash:** o filho é conferido pelo SHA-256, o mesmo da Merkle da imagem (ADR 0015 e SDD 13.3). É o modo da imagem de sistema somente leitura e o modo em que a T-523 nasce.
- **Modo AEAD:** o filho é decifrado e autenticado com a tag guardada no pai (ADR 0053). A T-528 liga esse modo.
- Um volume tem um modo só, gravado no superbloco.
- Todo ponteiro é conferido antes do uso. Falha vira erro de E/S `Integrity` e um registro no log, nunca dado (SDD 9.2 e 9.3).

### 3. Árvores

Árvores B+ copy-on-write com nós de 4 KiB. O nó tem um cabeçalho de 64 bytes: `magic`, nível, quantidade de itens, árvore dona, txg e o endereço do próprio bloco (no modo hash, isso detecta escrita no lugar errado; no modo AEAD o endereço já está no AAD). A chave é `(objeto: u64, tipo: u8, deslocamento: u64)`, em ordem lexicográfica. Um nó interno de 4 KiB guarda cerca de 45 filhos.

| Árvore | Chave | Valor |
|---|---|---|
| Raiz das raízes | id da árvore | ponteiro da raiz de cada árvore abaixo |
| Datasets | id do dataset | raiz da árvore de arquivos viva, txg do último snapshot, cota, lista de mortos (item 7), id da chave (ADR 0053) |
| Arquivos (uma por dataset) | `(objeto, INODE, 0)`, `(dir, DIRENT, hash do nome)`, `(objeto, EXTENT, deslocamento)`, `(objeto, XATTR, hash)` | inode; entradas de diretório (nome de até 255 bytes UTF-8); extent com ponteiro de bloco ou dados embutidos de até 1 KiB; atributo estendido |
| Snapshots | `(dataset, id)` | txg, raiz da árvore de arquivos naquele txg, nome (até 63 bytes), hora, lista de mortos |
| Alocação | grupo de 128 MiB | ponteiro do mapa de bits do grupo (32 768 bits num bloco) |
| Épocas | época | sal e txg de criação (ADR 0053) |

- O hash do nome é um BLAKE3 com chave derivada por volume (ADR 0053), truncado a 64 bits, para que ninguém force colisões num diretório. Nomes que colidem ficam no mesmo item, como uma lista.
- **Datasets** são a unidade de cota, de chave e de snapshot. Cada realm terá o seu (SDD 9.3, "cotas por realm"). O M5 cria um só (`dados`). Os de usuário e de app chegam depois, sem mudar o formato.
- Links simbólicos guardam o destino como dados embutidos e só valem dentro do namespace (SDD 9.3).

### 4. Transação e commit atômico (T-522 e T-523)

As mudanças se acumulam em memória num grupo de transação (txg). O commit acontece quando um cliente pede `sync`, quando passam 5 s desde a primeira mudança suja, ou quando os bytes sujos chegam a 1/4 do cache do `optfs`.

A ordem do commit é:

1. Alocar blocos novos para todo nó e dado mudado, nunca um bloco em uso pelo txg atual ou pelo anterior (item 5).
2. Gravar todos esses blocos.
3. `flush` do `BlockStore` (ADR 0056), depois de todas as escritas concluídas.
4. Gravar o superbloco novo no bloco `2 + (txg mod 2)`.
5. `flush`.

O txg só fica **confirmado** depois do passo 5, e só então o `sync` volta. Uma queda antes do passo 4 deixa o superbloco antigo valendo, e os blocos novos eram livres. Uma queda no meio do passo 4 deixa um superbloco rasgado, que falha na conferência, e o outro vale (item 6).

O superbloco ocupa um bloco: `magic` `OPTFSSB1`, versão do formato, UUID do volume, txg, modo de integridade, ponteiro da raiz das raízes, tamanho do volume, contador de épocas, blocos livres e flags. No fim vêm o SHA-256 dos bytes anteriores (detecta escrita rasgada antes do desbloqueio) e um HMAC-SHA-256 com a chave de cabeçalho (ADR 0053). No modo hash o HMAC é zero, e a autenticidade vem do manifesto assinado (ADR 0015).

### 5. Liberação adiada

Um bloco liberado no txg N ainda é referenciado pela árvore do txg N−1, que é o superbloco de reserva. Ele vai para a lista "liberados em N" e só volta a ser alocável depois que o txg N+1 é confirmado. O TRIM sai no mesmo momento.

O volume reserva 2% do espaço para metadados. Assim, apagar com o disco cheio continua possível, já que apagar também copia nós.

### 6. Escolha do superbloco na montagem (T-524)

O `optfs` lê A e B. Um superbloco é válido quando o `magic` e a versão conferem, o SHA-256 confere, o HMAC confere (no modo AEAD, depois do desbloqueio) e a raiz das raízes confere com o ponteiro dele.

- Monta o válido de maior txg.
- Se o de maior txg falha, monta o outro e registra `optfs: superbloco txg=N inválido, montado txg=M`.
- Se nenhum é válido, não monta. O `optfs-check` do modo de resgate fica disponível.

Um commit confirmado nunca se perde. O superbloco do txg N só é sobrescrito pelo txg N+2, depois que N+1 foi confirmado.

### 7. Snapshots e rollback (T-525)

O modelo é o do nascimento, sem contador de referências.

- **Snapshot:** um item na árvore de snapshots com o txg e a raiz da árvore de arquivos do dataset. Custa O(1), dentro de um txg, e o dataset guarda o `txg do último snapshot`.
- **Liberar:** quando um txg libera um bloco de um dataset, ele volta ao espaço livre (item 5) se `nascimento > txg do último snapshot`. Caso contrário, algum snapshot ainda o usa, e o bloco vai para a lista de mortos do dataset.
- **Apagar o snapshot S** (com o anterior P e o seguinte X, ou o dataset vivo se S é o último): cada bloco da lista de mortos de X com `nascimento > P.txg` só era usado por S e é liberado. Os outros ficam. A lista de mortos de S se junta à de X.
- **Rollback para S:** apaga primeiro os snapshots posteriores a S e depois, num txg, troca a raiz viva pela de S. Os blocos vivos com `nascimento > S.txg` são liberados percorrendo a árvore viva e podando subárvores com `nascimento ≤ S.txg`. A poda é correta porque, no copy-on-write, um pai é reescrito sempre que um filho muda, então o pai nunca é mais velho que os filhos.
- **Leitura de snapshot:** uma árvore de arquivos somente leitura.
- Quem cria snapshots antes de mudanças da IA e de atualizações (SDD 9.3) é o chamador (`ai-exec`, `updated`), pela interface do `optfs`. A política de quando criar fica fora desta ADR.

### 8. Compressão

- A compressão é por extent de até 128 KiB, com LZ4 (`lib/olz4`) quando economiza ao menos um bloco. Senão o extent é gravado cru.
- zstd tem o código reservado no ponteiro, e o decodificador próprio fica para depois do M5.
- A compressão vem antes da cifra (ADR 0053).
- Nós de metadados não são comprimidos.

### 9. Verificação e especificação

- Todo parser de estrutura em disco (superbloco, nó, itens, snapshot, mapa de bits) trata o disco como não confiável e ganha alvo de fuzz (T-529), como os parsers de dispositivo (SDD 8).
- O `optfs-check` (modo de resgate) percorre todas as árvores, confere cada ponteiro e confere que o mapa de bits é igual ao conjunto de blocos alcançáveis, mais as listas de mortos, mais os liberados pendentes. No M5 ele só lê.
- O layout em bytes fica em `docs/spec/optfs.md`, e as constantes numa crate `lib/optfs-format` (`no_std`, `forbid(unsafe_code)`), as duas criadas na T-523. Divergir desta ADR exige ADR nova.

## Alternativas consideradas

- **Journaling, com snapshots em outra camada (estilo ext4):** rejeitada pela ADR 0014.
- **Contador de referências por extent (estilo btrfs):** o snapshot também sai em O(1), mas copiar um nó compartilhado atualiza contadores dos filhos. São mais escritas e mais código crítico. O modelo de nascimento não atualiza nada ao escrever.
- **Log-structured (estilo F2FS ou NILFS):** bom para flash, mas exige um coletor em segundo plano, e os snapshots ficam mais complexos.
- **CRC ou xxHash no modo sem cifra:** não é autenticado e não serve para a imagem verificada. O SHA-256 alinha com a ADR 0015 e com o SDD 13.3.
- **Liberar logo no txg seguinte:** quebra a reserva. Uma queda no superbloco N+1 faria montar N com blocos já reusados.

## Consequências

- Um commit custa duas esperas de `flush`. A T-532 mede a latência de `sync`.
- O espaço liberado volta com dois commits de atraso, e 2% do volume ficam reservados.
- O ponteiro de 72 bytes dá cerca de 45 filhos por nó interno. Quatro níveis endereçam milhões de folhas.
- A imagem de sistema (ADR 0057, depois do Gate 2) reusa este formato no modo hash, somente leitura.
- Fuzz (T-529) e queda de energia (T-533) são obrigatórios antes do aceite do M5.
- A T-523 cria `lib/optfs-format` e `docs/spec/optfs.md`.
- Qualquer mudança no que está acima exige ADR nova.
