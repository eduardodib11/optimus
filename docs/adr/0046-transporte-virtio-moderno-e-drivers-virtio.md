# ADR 0046: Transporte virtio moderno e drivers virtio

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 8.2 (M4: virtio blk, net, input, gpu 2D, rng, console), 19 ("Optimus VM Edition", só virtio) e 8.3; backlog do M4, T-410 a T-415
- Relaciona-se com: ADR 0012 (OIDL), ADR 0013, ADR 0042, ADR 0043, ADR 0044, ADR 0047

## Contexto

O alvo imediato do Optimus é rodar em VM, onde virtio é a interface de dispositivo (plano B "VM Edition"). Seis drivers compartilham o mesmo transporte. Cada descritor lido da fila vem de um dispositivo que, num cenário de ameaça, é hostil, e o SDD manda fuzzing dos parsers.

## Decisão

1. **Versão.** Só virtio "moderno" (1.0 ou superior): `VIRTIO_F_VERSION_1` obrigatório. Legacy/transitional não é suportado. Dispositivo que não negocia `VERSION_1` é recusado e registrado.
2. **Transporte.** Virtio sobre PCI (capabilities vendor-specific: comum, notificação, ISR, dispositivo). Virtio-MMIO fica para AArch64 (M12). Os BARs vêm como `MemoryObject` do `pcid` (ADR 0043).
3. **Biblioteca.** `lib/ovirtio`, `no_std`, `#![forbid(unsafe_code)]` fora de um módulo de acesso volátil (na `unsafe-allowlist.toml`, com `// SAFETY:`), comum a todos os drivers. Contém: negociação de features, configuração de filas, anéis divididos (split virtqueue) e anéis empacotados (`VIRTIO_F_RING_PACKED`) só se negociado, mas o M4 entrega apenas split.
4. **Features.** Negociação por lista branca por driver. Nunca se aceita feature que o driver não conhece. Obrigatório: `VERSION_1`; desejável: `RING_EVENT_IDX`; `IOMMU_PLATFORM` é exigido quando houver IOMMU (ADR 0044) para que o dispositivo respeite o `DmaDomain`.
5. **Filas e DMA.** Anéis e buffers vivem em `MemoryObject` mapeados no `DmaDomain` do driver (`dma_map`, ADR 0044). O driver só escreve endereços de E/S (IOVA), nunca endereços físicos.
6. **Notificações.** Uma capability `Interrupt` por vetor MSI-X (ADR 0043): um vetor de configuração e um por fila. Sem MSI-X, um vetor compartilhado com leitura de ISR. A notificação do dispositivo (doorbell) é escrita no BAR de notificação.
7. **Endurecimento contra dispositivo hostil.** O driver trata o que lê do anel como entrada não confiável: valida índice, comprimento e `next` de cada descritor contra o tamanho da fila e do buffer, limita cadeias a no máximo o tamanho da fila (sem ciclos), nunca confia em `used.len` além do buffer enviado, e copia dados de ou para buffers próprios antes de interpretar. Violação: o driver derruba o dispositivo (reset), registra e pede reinício ao `devmgr`.
8. **Drivers do M4.** Cada um um processo, com sua interface OIDL: `virtio-blk` → `BlockDevice` (T-411); `virtio-net` → `NetDevice` (T-412); `virtio-input` → `InputDevice`, alimentando o `inputd` (T-413); `virtio-rng` (T-414), que **alimenta** o gerador de semente do sistema sem substituir a fonte do kernel; `virtio-console` (T-415), texto na serial do QEMU; `gpu-virtio` 2D, ADR 0047 (T-416).
9. **Reinício.** Reset do dispositivo (escrita 0 em `device_status`) e renegociação completa a cada reinício; sem estado persistente no driver (8.3).
10. **Fuzzing.** Alvo `fuzz_virtqueue`: anéis e descritores sintéticos contra a biblioteca (T-421).

## Alternativas consideradas

- **Suportar virtio legacy:** rejeitado; aumenta superfície e o QEMU moderno fala virtio 1.0.
- **Emular IOMMU só quando houver:** é o que acontece (item 4), sem código especial.
- **Biblioteca por driver:** rejeitado; duplicaria o código mais sensível.

## Consequências

- T-410 (`lib/ovirtio`) abre caminho para T-411 a T-416, que podem rodar em paralelo depois dela.
- Novo módulo `unsafe` volátil entra na allowlist na T-410, com justificativa.
