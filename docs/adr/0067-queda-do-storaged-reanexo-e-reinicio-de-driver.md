# ADR 0067: Queda do `storaged`, reanexo do `BlockDevice` e reinício de driver

- Status: aceita sob a execução autônoma autorizada pelo Eduardo (2026-11-04), por ser fiel à ADR 0056 (item "O `storaged` morre") e ao SDD 8.1; fica sinalizada para revisão no PR da T-541
- Data: 2026-11-15
- Origem: SDD v1.0, seção 8.1 (falha contida e reiniciada); backlog do M5, T-541
- Relaciona-se com: ADR 0034 (item 9, fim de instância), 0051 (driver reiniciado), 0056 (item de falhas), 0063 (sessão do `BlockDevice`), 0066

## Contexto

A ADR 0056 promete que, se o `storaged` morre, os clientes veem o `BlockStore` fechar, o `svcmgr` o reinicia e nenhum commit confirmado se perde. Três lacunas impediam isso:

1. O `storaged` parte pelo `devmgr`, como driver, casado com a ponte LPC do q35 (ADR 0066). O `svcmgr` só parte driver com recursos entregues pelo `devmgr`; o reinício sozinho falhava com `NotSupported` e a cota ficava presa.
2. O `virtio-blk` aceita um único `attach_done` (o anel de conclusões do `storaged`). O `storaged` novo era recusado com `BadRequest`, pois o driver ainda guardava o anel do morto.
3. Não havia como provocar a queda no meio de uma escrita.

## Decisão

1. **Reanexo do `BlockDevice`.** Um `attach_done` com a sessão (badge 1) de um driver que já tem anel de conclusões vale como o `storaged` novo: o driver larga o anel antigo, descarta o que o morto deixou no anel de submissões, espera até 500 ms o dispositivo terminar os pedidos em voo (para que nenhum DMA caia numa página que o cliente novo vai usar) e marca como órfão o que sobrar, que nunca vai ao anel do cliente novo. Só o `storaged` tem a sessão (ADR 0063), então não há disputa.
2. **Anel que já andou.** O `storaged` novo abre o anel de submissões que o driver criou e o antigo já usou: `Producer::open` passa a ler o `head` do anel (antes partia de 0 e, com o `tail` adiantado, o produtor entrava em pânico).
3. **Escritas do morto.** Escrita que o cliente não viu concluir com `FLUSH` não vale (ADR 0056): o `OptFS` só confirma o txg depois do `flush` do superbloco, e as escritas em voo vão para blocos livres. Descartar a fila é seguro.
4. **Reinício de driver que morreu sozinho.** O `svcmgr` guarda os recursos de um driver que morreu sem `driver_stop` e os entrega de novo na partida seguinte, quando a política do manifesto manda reiniciar. `driver_stop` (ADR 0051), o desligamento e uma falha de partida apagam os recursos, como antes; a contenção de falta de DMA continua sendo do `devmgr`, com recursos novos. O filho novo reaproveita a cota do morto (objetos do morto, como o anel que o `virtio-blk` ainda mapeia, a prendem até o reanexo, e reservar outra estourava a cota do `svcmgr`). Uma partida que falha apaga o filho e a cota dele, e a nova tentativa espera 250 ms. O `storaged` passa a `restart = "on-failure"`.
5. **O que o cliente vê.** Quem estava dentro de uma chamada ao `storaged` quando ele morreu recebe `PeerClosed`; uma chamada nova numa cópia que o `svcmgr` já revogou recebe `InvalidHandle`. O cliente trata os dois como "o `BlockStore` morreu", reconecta pelo `svcmgr` e reabre a sessão e as filas. O cliente de E/S por anéis percebe a queda pelo prazo da conclusão (2 s no `drvcli`) e confirma com `info`.
6. **Teste.** `svcmgr.mata` no bootfs (`<serviço> <atraso em ms>`): depois do atraso o `svcmgr` mata o processo e registra `svcmgr: mata: <serviço> voltou em N ms`. `cargo xtask test caos-storaged` roda 3 rodadas (`OPTIMUS_CAOS_ROUNDS`) com atraso aleatório de 3 a 6 s enquanto o `drvcli` grava commits sem parar na partição `caos`; o cliente reconecta, remonta, confere que o txg montado não é menor que o último confirmado e que o conteúdo bate, e grava mais commits. O `xtask` confere o disco no fim de cada rodada.

## Alternativas consideradas

- **O `devmgr` reinicia o `storaged` ao ver a morte:** exigiria um canal de morte do `svcmgr` ao `devmgr` e recursos novos a cada queda, sem ganho para um driver que só usa o `devmgr` para partir.
- **Tornar o `storaged` serviço de boot:** prende a cota no desligamento quando não há disco (ADR 0066).
- **Recusar o reanexo e reiniciar o driver de bloco junto:** derruba o disco por causa de um cliente.

## Consequências

- Fica fora desta ADR o cliente morto (sessão ocupada até `release`) e o `Reset` com o driver reiniciado: continuam como pendência do M5.
- Qualquer mudança no que está acima exige ADR nova.
