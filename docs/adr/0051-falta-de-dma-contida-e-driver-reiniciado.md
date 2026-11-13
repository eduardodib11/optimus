# ADR 0051: Falta de DMA contida e driver reiniciado

- Status: aceita sob a execução autônoma autorizada pelo Eduardo (2026-11-04), por ser fiel ao SDD 8.1 e ao item 4 da ADR 0044; fica sinalizada para revisão nos PRs da T-422
- Data: 2026-11-13
- Origem: SDD v1.0, seção 8.1 (driver isolado; falha contida e reiniciada); backlog do M4, T-422
- Relaciona-se com: ADR 0035 (item 6, `obj_bind_notify`), 0042 (itens 4 e 5), 0044 (item 4), 0050

## Contexto

A ADR 0044 (item 4) manda a falta de IOMMU virar registro no log e "um evento ao `devmgr`, que reinicia o driver (T-422)". Hoje o kernel só registra a falta (`okernel: falta de DMA: dev=… iova=… motivo=…`): o driver que a causou segue vivo e com o domínio. Falta dizer como o evento chega ao `devmgr`, o que significa conter, e como o driver volta, sem acrescentar syscall (a ABI v1 fica em 34).

## Decisão

1. **Evento por notificação.** `obj_bind_notify` passa a aceitar um `DmaDomain` (direito `BIND`, que o `devmgr` já tem nas originais, ADR 0044 item 3): o domínio sinaliza `bits` na `Notification` ligada a cada falta de DMA atribuída a um dos dispositivos dele. O kernel descobre o domínio pelo BDF da falta (a tabela `ATTACHED`) no tratador da interrupção de falta (VT-d) ou na leitura do log de eventos (AMD-Vi). O detalhe da falta continua só no log. Sem ligação, nada muda.
2. **Um bit por driver.** O `devmgr` liga todas as notificações dos domínios que criou a uma só, com um bit por driver ligado (até 64; o `devmgr` já limita os ligados). Acordado, ele lê os bits e trata cada driver que faltou.
3. **Contenção.** Para cada driver que faltou, o `devmgr`: (a) pede ao `svcmgr` que pare o driver (`driver_stop(id)`, método novo, só do `devmgr`, só para driver em `Running`: destrói a thread do driver como o desligamento ordenado faz, sem a política de reinício do serviço); (b) revoga e destrói as originais dos recursos, o que destrói o domínio e o desliga do BDF (ADR 0042, item 5): sem domínio, a IOMMU barra todo DMA do dispositivo até a nova partida.
4. **Reinício.** Depois da contenção o `devmgr` repete a partida do item 4 da ADR 0042 (recursos novos, `driver_give` e `driver_start`), com recuo e teto: no máximo 3 faltas do mesmo driver em 60 s; passado disso, o driver fica parado e o `devmgr` registra `devmgr: driver <nome> isolado após N faltas`. O sistema e os outros drivers seguem.
5. **Geração.** O `devmgr` carimba o `badge` da cópia do `dma` entregue ao driver com o número da partida (0, 1, …), para um driver de teste saber se é a primeira vez.
6. **Sem segunda thread.** O `devmgr` continua com uma linha de execução (`max_threads` = 1): o laço do `DeviceBus` espera o endpoint com prazo de 50 ms e, a cada volta (por prazo ou por pedido atendido), lê a notificação de faltas sem bloquear. A contenção começa em até 50 ms da falta.
7. **Sem IOMMU** (ADR 0044, item 5) não há falta nem evento: a marca "isolamento de DMA ausente" continua valendo.
8. **Aceite (T-422).** `cargo xtask test iommu`: o `drvteste` na primeira partida faz o DMA fora do domínio e fica em laço; o `devmgr` o contém e o reinicia; na segunda partida ele faz o DMA válido e termina bem, o `okernel` registra a falta e o boot segue até o desligamento ordenado. Os testes de unidade cobrem o encaminhamento da falta ao domínio.

## Alternativas consideradas

- **O kernel mata o driver:** rejeitado, política de reinício fica em usuário (ADR 0001 e 0013).
- **Syscall nova para consultar faltas:** rejeitado, a ABI v1 está congelada em 34; `obj_bind_notify` já é o canal de eventos de objetos (ADR 0035).
- **Deixar o `svcmgr` reiniciar o driver sozinho:** rejeitado, os recursos do dispositivo são do `devmgr`, e só um novo `driver_start` com recursos novos o parte de novo.

## Consequências

- A T-422 sai em PRs pequenos: kernel (ligação e despacho), `svcmgr` (`driver_stop`, versão menor 1.3 do `Supervisor`), `devmgr` (contenção e reinício) e o cenário de teste.
- Qualquer mudança no que está acima exige ADR nova.
