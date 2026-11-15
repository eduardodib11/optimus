# ADR 0062: `NetDevice` e `InputDevice` por anéis SPSC

- Status: aceita (modo autônomo de Eduardo, 2026-11-15), aguardando a revisão dele
- Data: 2026-11-15
- Origem: backlog do M5, T-514 (interfaces dos drivers virtio de rede e de entrada)
- Relaciona-se com: ADR 0036 (anel SPSC), 0046 (item 5), 0060 (laço do driver), 0061 (`BlockDevice`, sessão com `GRANT`)

## Decisão

1. **Mesmo modelo do `BlockDevice` (ADR 0061).** Cada contrato tem `info()`, `session()` (endpoint com `SEND|GRANT`, badge 1) e entrega de capabilities só pela sessão. O driver cria o anel que consome e o cliente cria o anel que consome; as capabilities do anel do driver vão em respostas, e a do cliente vai em `attach_*` pela sessão. Um segundo `attach_*` é recusado.
2. **`NetDevice` (`optimus.net`).** Dois anéis de 16 KiB de dados: transmissão (o driver consome; `tx_ring`, `tx_signal`) e recepção (o cliente consome; `attach_rx`). Cada registro (tipo 1) é um quadro Ethernet sem o cabeçalho do virtio, de 14 a 1514 bytes; o driver acrescenta o cabeçalho zerado. `info()` dá o MAC (48 bits baixos), o MTU (1500), o maior quadro e o tamanho dos anéis. Quadro inválido na transmissão é descartado; anel de recepção cheio descarta o quadro e o anel conta em `dropped`.
3. **`InputDevice` (`optimus.input`).** Um anel de eventos que o cliente consome (`attach_events`): cada registro (tipo 1) é um `Evdev` de 8 bytes (`oinput::Evdev`: tipo `u16`, código `u16`, valor `i32`). Sem `tx`. `info()` informa o tamanho do anel. Anel cheio descarta o evento mais novo (política única do anel, ADR 0036).
4. **Laço.** O dos dois drivers é o da ADR 0060: `recv` com prazo de 5 ms, e a cada volta o driver confere a IRQ (`irq_ack`), colhe as filas e lê o anel de transmissão. O `NetDevice` só tem um buffer de transmissão em voo (o do T-412).
5. **Código comum.** O laço de `recv` com prazo e o despacho de capabilities vão para `vdrv::serve`, usado pelo `virtio-blk`, `virtio-net` e `virtio-input`.

## Alternativas consideradas

- Quadro por chamada IPC: exigiria `vec` como parâmetro no cliente gerado e uma chamada por quadro; rejeitada.
- Um anel só de recepção sem `tx_ring` (transmissão por chamada): perde o lote e o mesmo modelo do bloco; rejeitada.

## Consequências

- O `netd` (M6) liga os anéis por `session()` e `attach_rx`; o `inputd`/`displayd` liga o de eventos.
- A cota do `drvcli` sobe para 704 KiB (a imagem dele cresceu e a cota de 576 KiB já não cobria os anéis).
- Qualquer mudança no que está acima exige ADR nova.
