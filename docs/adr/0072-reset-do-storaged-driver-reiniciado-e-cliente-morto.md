# ADR 0072: `Reset` do `storaged` com driver reiniciado e cliente morto

- Status: aceita sob a execução autônoma autorizada pelo Eduardo (2026-11-04), por ser fiel ao SDD 8.1 e às ADRs 0056, 0066 e 0067; fica sinalizada para revisão no PR da T-611
- Data: 2026-11-16
- Origem: SDD v1.0, seção 8.1 (falha contida e reiniciada); backlog do M6, T-611
- Relaciona-se com: ADR 0034 (item 8, badge e geração), 0035 (item 3, `obj_bind_notify`), 0051 (driver reiniciado), 0056 (item de falhas), 0063, 0066 (item 4), 0067

## Contexto

A ADR 0067 fechou a queda do `storaged` e deixou duas pendências do M5:

1. **Driver de bloco reiniciado.** A ADR 0056 promete que, se o driver morre, o `storaged` conclui os pedidos em voo com `Reset` e se reconecta ao `BlockDevice` novo. Não estava implementado: o `storaged` ficava esperando conclusões que não viriam, e o `virtio-blk` não conseguia reiniciar com os recursos que o `svcmgr` guarda (ADR 0067, item 4), por três razões: (a) o dispositivo continuava ligado, com a fila do morto; (b) o domínio de DMA ainda tinha as páginas do morto mapeadas nas mesmas IOVAs; (c) o `Interrupt` (`irq0`) só se ligava uma vez, e a ligação era a do morto.
2. **Cliente morto.** Quem abre uma sessão no `storaged` e morre sem `release` deixa a sessão e as filas ocupadas (16 sessões, 8 filas). A ADR 0066 (item 4) deixou isso para a T-541.

## Decisão

1. **Sondagem do driver.** A cada 250 ms (`PROBE_NS`) o `storaged` chama `BlockDevice.info` com prazo de 100 ms. `PeerClosed` ou `InvalidHandle` quer dizer que o `svcmgr` revogou o endpoint do driver: o driver morreu. Prazo vencido é driver lento, não morto, e nada muda. A sondagem roda no laço do `storaged`, com o buffer de IPC livre (depois do prazo do `recv`), então não atrasa a resposta de nenhum cliente.
2. **`Reset`.** Com o driver morto o `storaged` zera os pedidos em voo, conclui com `Reset` o pedido corrente de cada fila e tudo o que os clientes já submeteram, e passa a concluir com `Reset` cada pedido novo, sem tocar no driver. Escrita concluída com `Reset` não tem garantia (ADR 0056); o `OptFS` só confirma o txg depois do `flush` do superbloco, então o que o cliente refaz é seguro.
3. **Reconexão.** A cada 50 ms o `storaged` tenta `connect` do `BlockDevice` no `svcmgr` (uma tentativa por volta, prazo de 200 ms). Com o endpoint novo refaz a ligação (`info`, sessão, anéis, região de dados, `attach_done`) num segundo banco de endereços, confere que o disco é o mesmo (setores e tamanho do setor) e só então larga a ligação velha, com todas as capabilities dela. As filas e as sessões dos clientes continuam como estavam.
4. **Driver reiniciado.** O `virtio-blk` passa a `restart = "on-failure"`. Ao partir ele reseta o dispositivo (status 0; o dispositivo para de consultar a fila do morto) e só então solta, com `dma_unmap`, as páginas que o morto deixou mapeadas nas IOVAs fixas do driver. O erro do `dma_unmap` de IOVA que não existe é ignorado.
5. **`Interrupt` religável.** `obj_bind_notify` sobre um `Interrupt` passa a trocar a ligação (como já valia para `Thread`, `CapSpace` e `DmaDomain`) em vez de devolver `Busy`; a troca zera a máscara e o disparo guardado, que eram do morto. Sem isso o driver reiniciado com os recursos do `svcmgr` não consegue religar a linha. Não muda a ABI (34 syscalls): é o `obj_bind_notify` que já existe, com o `BIND` que o driver já tinha. Quem tem `BIND` na linha já podia ligá-la uma vez; agora pode religá-la.
6. **Cliente morto.** O badge com que o `svcmgr` entrega o `Storage` ao cliente leva o id do serviço e a geração dele (ADR 0034, item 8). O `storaged` guarda o dono (48 bits baixos do badge) em cada sessão. Quando um `Storage.open` chega com o mesmo id e geração diferente, o cliente anterior morreu e foi reiniciado (o `svcmgr` já revogou todas as capabilities dele): as sessões da geração velha são devolvidas e as filas delas fechadas. O log diz `storaged: cliente <id> morreu (geração a -> b): sessão s e n fila(s) liberadas`. Cliente morto que não volta mantém a sessão até o `storaged` reiniciar; o limite (16 sessões, 8 filas) continua valendo, e é o `svcmgr` que decide reiniciar o cliente.
7. **Cliente e `Reset`.** O cliente vê `IoError::Reset` na conclusão (o `drvcli` o trata como erro de E/S) e, com o `BlockStore` vivo (`info` responde), espera e refaz: remonta o volume e confere que o txg montado não é menor que o último confirmado.
8. **Testes.** `cargo xtask test caos-driver`: o `svcmgr` mata o `virtio-blk` no meio da escrita (`svcmgr.mata`); o `storaged` registra a queda e a volta do driver, o `drvcli` vê `Reset`, remonta e grava mais commits, e o `xtask` confere o disco. `cargo xtask test caos-cliente`: o `svcmgr` mata o `drvcli` (agora `restart = "on-failure"`) com uma fila aberta; a encarnação nova (geração maior que 1) só consegue abrir as 8 filas do `storaged` se a sessão da velha foi liberada, e o log mostra a liberação. Os dois entram no `test all` ao lado de `caos-storaged` (3 rodadas, `OPTIMUS_CAOS_ROUNDS`).

## Alternativas consideradas

- **O `devmgr` reinicia o driver, como na falta de DMA (ADR 0051):** o `devmgr` só sabe da falta de DMA, não da morte espontânea; saber exigiria um canal novo do `svcmgr` ao `devmgr` e recursos novos a cada queda, e a ADR 0067 já decidiu que o `svcmgr` devolve os recursos guardados. A contenção por falta de DMA continua sendo do `devmgr`.
- **Detectar a morte do driver por notificação (`CapSpace` ligado):** o `storaged` não tem o `CapSpace` do driver, e dá-lo vazaria autoridade; a sondagem custa uma IPC a cada 250 ms.
- **Detectar o cliente morto por heartbeat:** exigiria mudar o contrato do `BlockStore` e todo cliente; a geração do badge já diz, de graça, que o antigo morreu.
- **Manter o `Interrupt` de ligação única e fazer o driver reiniciado funcionar sem interrupção (polling):** deixaria a linha mascarada pelo morto (o GSI 22 é compartilhado com o `virtio-net`) e mudaria o desempenho do disco.

## Consequências

- O `OptFS` sobre o `BlockStore` sobrevive à queda e à volta do `virtio-blk`, e uma queda de cliente não esgota mais sessões e filas do `storaged` quando o `svcmgr` o reinicia.
- O kernel muda em `Interrupt::bind` (religar troca a ligação) e no ktest que esperava `Busy`; o resto do M6 não mexe no kernel.
- Em reconexão, o `storaged` conclui com `Reset` até o `svcmgr` ter o driver `Running` de novo (cerca de 100 ms no TCG); a espera de 8 s do boot não vale aqui, para não prender o laço.
- Fica fora desta ADR o driver que trava sem morrer (a sondagem só vê morte) e a queda do cliente cujo `svcmgr` não reinicia.
- Qualquer mudança no que está acima exige ADR nova.
