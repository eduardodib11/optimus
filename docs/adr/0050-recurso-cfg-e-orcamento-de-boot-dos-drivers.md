# ADR 0050: Recurso `cfg` para drivers PCI e orçamento de boot

- Status: aceita sob a execução autônoma autorizada pelo Eduardo (2026-11-04), por ser fiel ao SDD 8.1; fica sinalizada para revisão no PR da T-411
- Data: 2026-11-13
- Origem: SDD v1.0, seção 8 (drivers); backlog do M4, T-411
- Relaciona-se com: ADR 0042 (item 4), 0043, 0046, 0034

## Contexto

O virtio moderno descobre as regiões de registradores (configuração comum, notificação, ISR e do dispositivo) pelas capabilities de fornecedor (`0x09`) do espaço de configuração PCI. O driver não tem a janela ECAM (ADR 0042, item 4: só recebe o que é do dispositivo), então não consegue lê-las. Além disso, o quarto driver do M4 estourou dois limites do boot.

## Decisão

1. **`cfg`.** Para todo nó PCI, o `devmgr` entrega ao driver o recurso `cfg`: uma cópia só de leitura (`MAP | READ`) dos primeiros 256 bytes do espaço de configuração da função, tirada na partida, num `MemoryObject` da cota do próprio `devmgr`. É um instantâneo: o driver não escreve na configuração (MSI, MSI-X e bus master continuam só com o `devmgr`).
2. **Orçamento de boot.** O limite padrão do heap do kernel passa de 32 para 40 MiB (`kheap=` continua valendo) e a cota de partida do `svcmgr`, de 14 para 15 MiB; a cota do `devmgr` sobe para 2816 KiB. O bootfs e as cotas dos serviços crescem a cada driver, e o plano do `svcmgr` já previa "32 MiB, a fixar".
3. **`ostd`.** `Mapping` ganha `read8/16` e `write8/16` voláteis, porque os campos de 8 e 16 bits da configuração comum do virtio exigem acesso da largura certa (o teto de `unsafe` de `lib/ostd/src/arch` sobe de 16 para 20).

## Alternativas consideradas

- **Dar a janela ECAM ao driver:** rejeitado, deixaria o driver ler e escrever a configuração de qualquer função.
- **Colocar as capabilities do virtio no `Node`:** rejeitado, o nó do `pcid` ficaria específico de um fornecedor.

## Consequências

- Os drivers virtio (T-411 a T-416) leem as capabilities de `cfg` com `virtio_core::cap::find`.
- Qualquer mudança no que está acima exige ADR nova.
