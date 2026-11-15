# ADR 0066: `storaged`, descoberta por partição e filas do `BlockStore`

- Status: aceita em modo autônomo (2026-11-15), **aguardando revisão do Eduardo**
- Data: 2026-11-15
- Origem: SDD v1.0, seções 9.1 e 9.4; backlog do M5, T-520
- Relaciona-se com: ADR 0033 (OIDL), 0034 (`svcmgr`), 0036 (anel SPSC), 0056 (itens 1, 3, 4, 6 e 8), 0061 (`BlockDevice`), 0062

## Contexto

A ADR 0056 define o `BlockStore` e diz que "o manifesto distribui as capabilities" de cada partição, com a prioridade máxima no badge que o `svcmgr` põe. O `svcmgr` não faz nenhuma das duas coisas: ele entrega um endpoint por serviço (`provides`) com o badge de identidade do cliente (ADR 0034), sem distinguir partição nem prioridade. O OIDL também não leva `handle` dentro de `struct`, então o `Queue` do item 3 da ADR 0056 não existe como está escrito. A T-520 implementa o `storaged` e precisa fixar esses pontos para o contrato rodar.

## Decisão

1. **Descoberta.** O `storaged` provê `optimus.storage.Storage@1.0`, com um só método, `open(nome)`. Ele acha a partição pelo nome na GPT (`sys-a`, `sys-b`, `data`) e devolve um endpoint `BlockStore` com `SEND` e `GRANT` (sem `GRANT` a chamada `open_queue` não leva capabilities; o badge não muda, porque a capability já tem badge). O badge dele (cunhado pelo `storaged` a partir do endpoint que o `svcmgr` lhe deu) diz a sessão e a partição, então a capability não serve para outra partição nem para criar outras. Os dois contratos convivem no mesmo endpoint, separados pelo identificador de interface no rótulo (ADR 0033).
2. **Direitos por manifesto ficam para depois.** No M5 qualquer cliente do `Storage` abre qualquer partição. O que já vale, qualquer que seja o cliente, é o que o item 1 da ADR 0056 exige do sistema: as `sys-*` são só de leitura (escrita volta `ReadOnly`). Limitar quem abre `data` e a prioridade máxima por cliente precisa de direitos por serviço no `svcmgr` e entra com o `updated` e o Gate 2.
3. **Filas.** O `Queue` do item 3 da ADR 0056 se divide, como no `BlockDevice`, em `open_queue(area, done, depth, priority, data_blocks)` (devolve o número da fila), `submit_ring(fila)` e `kick(fila)`. A `area` do cliente tem o anel de conclusões nos primeiros 8 KiB (`ostd::ring::object_bytes(4096)`) e, depois, a região de dados de `data_blocks` blocos de 4 KiB. O anel de conclusões é criado pelo cliente (o consumidor), e o `storaged` o abre como produtor.
4. **Sessões.** Cada `open` ocupa uma sessão (até 16, o limite do item 8 da ADR 0056, agora por `storaged` e não por partição) e cada sessão tem até 4 filas. `release()` devolve a sessão e fecha as filas dela. O `storaged` ainda não sabe quando um cliente morre (isso é a T-541); até lá, a sessão de quem morreu fica ocupada.
5. **Atendimento.** Uma fila atende um pedido por vez, na ordem; os blocos de um pedido andam em paralelo até a profundidade do driver. A ordem entre filas é a prioridade pedida, e um pedido esperando mais de 100 ms sobe ao topo (item 6). `FLUSH` só vai ao driver com a fila sem nada em voo, e um `FUA` vira escrita seguida de `FLUSH` quando o driver tem cache (item 5). O laço dorme no `recv` com prazo de 50 µs com pedidos em andamento e de 2 ms sem, como os drivers (ADR 0060); o `kick` já faz parte do contrato, mas o `storaged` só o usará quando houver espera por notificação.
6. **Disco de teste.** O `xtask` passa a gerar o disco de teste do `virtio-blk` com GPT (16 MiB; `sys-a` e `sys-b` de 4 MiB e `data` com o resto) e o autoteste do driver vai ao setor 64, entre a tabela e a primeira partição. O `drvcli` deixa de ser cliente do `BlockDevice` (o driver aceita uma sessão só) e passa a ser cliente do `Storage`, o que confere o aceite da T-520 pelo contrato.

## Alternativas consideradas

- **Um `provides` por partição.** O `svcmgr` não tem nome de instância no manifesto, e cada partição virar serviço obrigaria a mudar o `svcmgr`. Rejeitada para o M5.
- **Um só endpoint sem badge de sessão.** Qualquer cliente fecharia a fila de outro. Rejeitada.

## Consequências

- Fica fora desta ADR o tratamento de `Reset` (driver reiniciado) e de cliente morto, ambos da T-541 e da ADR 0051.
- Mudar o que está acima exige ADR nova.
