# ADR 0049: `IoPortRange` e IRQ legada como `Interrupt`

- Status: proposta (aplicada sob a regra de execução autônoma de Eduardo, 2026-11-04)
- Data: 2026-11-10
- Origem: backlog do M4, T-404 e T-406 (RTC e PS/2, pedido da Thread 2)
- Relaciona-se com: ADR 0013 (drivers em usuário), ADR 0042 (devmgr), ADR 0044 (IOMMU, item 6), ADR 0045 (acpid), SDD v1.0 seções 6.1, 6.8, 9 e 14.2

## Contexto

A tabela 6.1 do SDD tem o tipo `IoPortRange` (portas de E/S, só x86, direitos
`READ` e `WRITE`) e a seção 9 diz que o driver recebe "`IoPortRange` quando
necessário". Até o M3 só existe o tipo, sem criação nem uso (ADR 0037, item
16). O RTC (portas 0x70 e 0x71, IRQ 8) e o controlador PS/2 (portas 0x60 e
0x64, IRQ 1 e 12) da T-406 precisam das duas coisas que faltam: portas de E/S
no anel 3 e a IRQ legada, que chega pelo IOAPIC e não por MSI.

Hoje o kernel deixa o PIC 8259 mascarado, só lê o IOAPIC da MADT e não o
programa. Toda IRQ de dispositivo é MSI ou MSI-X (T-404).

## Decisão

1. **Criação.** `obj_create(cota de dispositivo, IoPortRange, base, count)`:
   `count` portas a partir de `base`, `1 <= count` e `base + count <=
   0x10000`. Só a cota de dispositivo cria (`AccessDenied` com cota comum),
   como a MMIO (ADR 0042, item 4). O kernel recusa com `InvalidArgument` as
   portas que ele mesmo usa: PIC (0x20 e 0x21, 0xa0 e 0xa1), PIT (0x40 a
   0x43), a COM1 do registro do kernel (0x3f8 a 0x3ff), o reset (0xcf9) e a
   saída do QEMU (0xf4). A capability nasce com `READ | WRITE`.
2. **Uso.** O x86 não separa leitura de escrita no mapa de E/S. Por isso a
   ligação exige os dois direitos: `thread_configure(thread, 0, 0, 0,
   faixa, CONFIGURE_IO_PORTS)` dá à thread acesso direto (`in`/`out`) às
   portas da faixa, sem syscall por acesso. A thread guarda até 4 faixas
   (`Busy` na quinta); `faixa = 0` tira todas. A flag usa `r8`, como
   `CONFIGURE_EXCEPTION`: as duas juntas são `InvalidArgument`. Vale
   `thread = SELF`. Nenhuma syscall nova: a contagem 34 não muda. É uma
   extensão compatível da ABI v1, como a ADR 0048.
3. **Mapa de E/S.** Cada CPU tem na TSS um mapa de 8 KiB (mais o byte final),
   todo negado. Na troca de contexto o kernel nega as faixas da thread que
   sai e libera as da que entra. Uma thread sem faixas não custa nada além
   de um teste. `IOPL` fica 0 sempre.
4. **Revogação.** A ligação segura o objeto. O acesso dura até a thread
   tirar as faixas ou morrer, como uma MMIO mapeada. O `devmgr` revoga os
   recursos de um driver quando o `svcmgr` o encerra (ADR 0042, item 5), e a
   morte das threads tira o acesso.
5. **IRQ legada.** `obj_create(cota de dispositivo, Interrupt, 0, 0,
   irq::ISA | n)` cria o `Interrupt` da IRQ ISA `n` (de 1 a 15, menos a 2,
   que é a cascata). O kernel acha a GSI pelos overrides da MADT (sem
   override, GSI = `n`, borda e nível alto), escolhe o IOAPIC dela, pega um
   vetor livre e programa a entrada para o BSP em modo fixo. Devolve
   `[handle, 0, 0]`: não há endereço nem dado de MSI. Uma IRQ só tem um
   `Interrupt` vivo (`Busy`). Quando o objeto morre, a entrada volta a ficar
   mascarada.
6. **Nível e máscara.** Uma linha por nível (um override com o SCI, por
   exemplo) fica mascarada no IOAPIC do disparo até o `irq_ack`. Uma linha
   por borda só usa a máscara de software do `Interrupt`, como a MSI.
7. **Com remapeamento de interrupções.** O VT-d bloqueia o formato de
   compatibilidade (ADR 0044, item 6). Com ele ligado, a entrada do IOAPIC
   vai no formato remapeável, com a entrada da IRT presa ao `source-id` do
   IOAPIC que vem do escopo da DMAR. Sem esse escopo, a IRQ legada dá
   `NotSupported` em vez de deixar a entrada sem verificação de origem.
8. **No devmgr.** O nó do `DeviceBus` ganha `ports: vec<Ports, 4>` (base e
   quantidade) e `irqs: vec<u8, 4>` (IRQs ISA). O `acpid` os preenche pelos
   recursos `_CRS` (ADR 0045). O `devmgr` cria uma `IoPortRange` por faixa
   (`ioN`) e um `Interrupt` por IRQ (`irqN`, depois dos de MSI) e os entrega
   ao driver como os demais recursos.

## Alternativas rejeitadas

- **Syscall por acesso (`io_read`/`io_write`):** custa uma transição de anel
  por byte, caro demais para o PS/2 e o RTC, e muda a contagem de syscalls.
- **`IOPL = 3` para o driver:** libera todas as 65536 portas, inclusive as
  do kernel. Fere o menor privilégio (ADR 0013).
- **Mapa de E/S por `AddressSpace`:** a TSS é por CPU e a troca acontece
  por thread. Guardar por thread evita procurar o espaço na troca, e um
  driver de várias threads liga cada uma no começo.
- **Deixar a IRQ legada sem verificação de origem com remapeamento:** um
  dispositivo poderia disparar o vetor do teclado escrevendo no índice da
  IRT. Fere o item 6 da ADR 0044.

## Consequências

- O `timed` pode ganhar o RTC depois (ADR 0037, item 16).
- A TSS de cada CPU cresce 8 KiB.
- O `pcid` pode usar a faixa 0xcf8 a 0xcff como alternativa ao ECAM (ADR
  0043, item 1), porque o kernel não a reserva.
- Testes: ktest de `in`/`out` permitidos e negados (`#GP` vira falta do
  processo), faixas recusadas, IRQ 1 do PS/2 do QEMU entregue pela
  notificação, com e sem remapeamento.
