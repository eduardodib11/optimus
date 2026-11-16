# ADR 0063: `BlockDevice`, papéis dos anéis e sessão com `GRANT`

- Status: aceita; revisada e aprovada pelo Eduardo em 2026-11-16 (T-508)
- Data: 2026-11-14
- Origem: backlog do M5, T-514 (interface do `virtio-blk`)
- Relaciona-se com: ADR 0033 (OIDL), 0034 (`svcmgr`), 0036 (anel SPSC), 0056 (item 10), 0060

## Contexto

A ADR 0056 (item 10) diz que o `BlockDevice` é "o mesmo modelo de fila e o mesmo formato de registro" do `BlockStore`. No `BlockStore` o cliente cria o anel de conclusões e o dá ao serviço. Isso esbarra numa regra do `svcmgr` (ADR 0034): o cliente de um serviço só recebe `SEND` no endpoint, sem `GRANT`, e uma chamada só leva capabilities se o endpoint tiver `GRANT`. Sem uma saída, o `storaged` não consegue passar nada ao driver.

## Decisão

1. **Sessão com `GRANT`.** `BlockDevice.session()` devolve, na resposta (a resposta do provedor leva capabilities, porque o endpoint dele tem `GRANT`), uma cópia do endpoint do driver com `SEND|GRANT` e badge 1. Chamadas que levam capabilities (`attach_done`) só valem por ela. Nada muda no `svcmgr`, no manifesto (OMAN v1) nem no kernel.
2. **Papéis dos anéis** (ADR 0036: o consumidor cria o anel):
   - submissões: o driver é o consumidor e cria o anel; entrega o objeto e o `SIGNAL` da sua notificação por `submit_ring` e `submit_signal`;
   - conclusões: o `storaged` é o consumidor, cria o anel e o entrega por `attach_done(ring, signal)`.
3. **Região de dados.** É memória de DMA do driver (`data_region`), de `data_bytes` (4 páginas no `virtio-blk`). O `storaged` copia entre ela e a região do cliente, como na ADR 0056, item 4. Pedido de dados usa `offset` alinhado a 4 KiB e no máximo `max_sectors` (uma página, 8 setores de 512 bytes).
4. **Registros** (carga, tipo 1 nos dois anéis): submissão `id u64, op u8, flags u8, count u16, offset u32, sector u64` (24 bytes), com `op` 0 READ, 1 WRITE, 2 FLUSH e `flags` zero (o `storaged` emula FUA); conclusão `id u64, status u8`, com 0 ok ou um `BlockError`.
5. **Ordem e `FLUSH`.** O `FLUSH` é barreira: só vai ao dispositivo (ou conclui, em dispositivo write-through) quando nada está em voo. Pedido inválido conclui na hora com `BadRequest`, `OutOfRange` ou `ReadOnly`, sem ir ao dispositivo.
6. **Laço.** O mesmo da ADR 0060: um `recv` com prazo de 5 ms; a cada volta o driver colhe o `used ring`, confirma a IRQ e lê o anel de submissões. Por isso o anel de submissões não precisa de despertar (o driver nunca dorme nele).
7. **Limites.** `depth` = 4 pedidos em voo. O driver só tira do anel o que cabe; se o `storaged` passar de `depth` pedidos pendentes, uma conclusão pode não caber e o anel a descarta e a conta em `dropped` (o contrato é o mesmo do item 4 da ADR 0056).

## Alternativas consideradas

- **`GRANT` nos clientes de todo serviço:** amplia o que qualquer cliente pode fazer; rejeitada.
- **Conclusões por chamada (`reap()`):** troca o anel por uma chamada a cada poll; contraria a ADR 0056 ("fila assíncrona").
- **Região de dados do `storaged` mapeada no domínio de DMA:** sem cópia, mas depende da T-532; o contrato não impede.

## Consequências

- `oidlc` ganha cliente para `handle` como parâmetro e como sucesso da resposta (um só); `ostd::ipc::call_corpo_caps` leva as capabilities.
- A T-520 (`storaged`) usa `session()` + `attach_done` e lê o anel de submissões do driver como produtor.
- Qualquer mudança no que está acima exige ADR nova.
