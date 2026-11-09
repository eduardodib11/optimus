# ADR 0046: Transporte virtio moderno e drivers virtio

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 8.2; backlog do M4, T-406/T-410
- Relaciona-se com: ADR 0042, 0043, 0044

## Contexto

Os drivers do M4 em VM são virtio. O SDD pede só o que o hardware real mínimo exige, e o QEMU q35 expõe virtio moderno sobre PCI.

## Decisão

1. **Só virtio moderno** (1.0+, `VIRTIO_F_VERSION_1`) sobre PCI. Legacy e transitional não são suportados. Features exigidas: `VERSION_1`, `ACCESS_PLATFORM` quando houver IOMMU.
2. **Crate `virtio-core`** em `lib/`, `no_std`, `forbid(unsafe_code)`, sobre um trait `Mmio` e um trait `DmaBuf`. O `unsafe` fica só na camada do driver que mapeia o BAR e a memória de DMA.
3. **Filas split**: descritores, `avail` e `used` em memória do `DmaDomain`. Validação do índice e do tamanho de cada descritor lido do dispositivo (o dispositivo não é confiável).
4. **Notificações**: MSI-X, um vetor por fila, entregue por `Interrupt` ligado a `Notification` (T-404).
5. Cada driver (blk, net, input, rng, console, gpu) é um processo separado, com manifesto casando em `1af4:10xx`, e entrega seu trait OIDL (`BlockDevice`, `NetDevice`, `InputDevice`, `Entropy`, `Console`, `DisplayDevice`).

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-406/T-410 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
