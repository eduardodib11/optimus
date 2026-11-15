# ADR 0063: Snapshots do OptFS com registros na árvore de arquivos e `reclaim` por varredura

- Status: aceita em modo autônomo (2026-11-15), **aguardando revisão do Eduardo**
- Data: 2026-11-15
- Origem: SDD v1.0, seção 9.3; backlog do M5, T-525
- Relaciona-se com: ADR 0052 (layout do OptFS, item 7 e item 3), 0014

## Contexto

A ADR 0052, item 7, descreve snapshots pelo modelo de nascimento do ZFS: uma árvore de snapshots separada, uma lista de mortos por dataset e por snapshot, e a liberação de blocos de um snapshot apagado percorrendo a lista de mortos do seguinte. Isso pressupõe datasets, ou seja, a raiz das raízes da ADR 0052, item 3 (árvores de datasets, de snapshots, de alocação e de épocas).

O M5 só tem um dataset, e a T-523 (PRs #198 a #203) gravou a árvore de arquivos direto na raiz do superbloco, sem raiz das raízes. A T-525 (PR #206) precisava de snapshot, leitura, rollback e apagar. Implementá-los como a ADR descreve obrigaria a introduzir a raiz das raízes e as listas de mortos de uma vez, em disco, antes de haver mais de um dataset.

## Decisão

O PR #206 já está na main com o seguinte desvio da ADR 0052, que esta ADR registra:

1. **Registros de snapshot na árvore de arquivos.** Cada snapshot é um item `(0, Xattr, id)` com txg, ponteiro da raiz naquele instante e nome (até 63 bytes). O item `(0, Xattr, 0)` guarda o próximo identificador. O objeto 0 é reservado (o contador de objetos já mora em `(0, Inode, 0)`). A ADR 0052 previa a árvore de snapshots separada.
2. **Regra de nascimento mantida.** O caminho de escrita segue o item 7: um bloco com `nascimento ≤ txg do último snapshot` nunca é liberado por uma escrita (`Tx::set_snap_floor`, refeito a partir dos registros em `Fs::open`). O resto da liberação continua adiado em dois commits (item 5).
3. **Sem lista de mortos em disco.** Os blocos que as escritas deixaram de usar mas que um snapshot pode reter ficam marcados em uso. Quem os devolve é `Tx::reclaim`: varre as árvores vivas (a atual e as dos snapshots restantes), e todo bloco em uso que nenhuma alcança volta pela liberação adiada. Roda ao apagar um snapshot e no rollback. Depois de uma montagem, `mark_reachable` marca o conjunto alcançável pelas mesmas árvores, então um bloco morto que ninguém alcança já nasce livre.
4. **Rollback devolve a lista de snapshots daquele momento.** Como os registros vivem na árvore, a raiz do snapshot `S` não tem o registro do próprio `S`; o rollback o reinsere. Os snapshots posteriores somem junto com a árvore descartada, sem apagá-los um a um.
5. **Formato em disco.** Não muda nada em `lib/optfs-format` nem em `docs/spec/optfs.md`: o item usa a chave e o valor já definidos (`Xattr`, valor de até 1 KiB).

## Consequências

- Custo de `reclaim`: proporcional ao volume (uma varredura das árvores vivas e do mapa de blocos), e não ao que mudou. Aceitável com um dataset e volumes do M5; passa a ser caro com muitos snapshots e datasets grandes.
- Um bloco nascido no mesmo txg de um snapshot e reescrito antes do commit fica retido até o próximo `reclaim`. Por isso convém confirmar o txg logo depois de criar o snapshot.
- Não há risco de integridade: `reclaim` nunca libera um bloco alcançado por uma árvore viva, e a liberação continua adiada em dois commits, então o superbloco de reserva segue válido (testes do `optfs`: snapshot lê o passado depois de vários txgs, de queda e de remontagem; rollback e apagar devolvem o espaço só depois de dois commits).
- **Quando reverter para o item 7 da ADR 0052:** ao introduzir datasets com a raiz das raízes (realms, SDD 9.3), ou se a varredura aparecer nas medições de `sync` e de apagar snapshot (T-532). Isso é uma ADR nova que substitui esta: árvore de snapshots separada, lista de mortos por dataset e liberação por lista, mais migração dos registros do objeto 0.
- Esta ADR não altera as demais decisões da 0052.

## Alternativas consideradas

- **Implementar já a raiz das raízes e as listas de mortos.** Mais fiel à 0052, mas grava em disco estruturas que o M5 não usa (um dataset só) e ainda exige um formato de lista de mortos que a ADR não fixa por extenso. Adiada.
- **Contador de referências por bloco.** Rejeitada pela 0052.
- **Snapshots só em memória.** Não sobrevivem à queda, então não cumprem o SDD 9.3.
