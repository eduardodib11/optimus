# ADR 0055: Falta do AMD-Vi por interrupção e `devmgr` sem espera por prazo

- Status: aceita (aprovada por Eduardo em 2026-11-14)
- Data: 2026-11-14
- Origem: SDD v1.0, seção 8.1 (driver isolado; falha contida e reiniciada); pendência do M4 (`docs/aceite/m4.md`); backlog do M5, T-505 e T-507
- Relaciona-se com: ADR 0009 (kernel tickless), 0044 (IOMMU), 0051 (falta de DMA contida), 0035 (`obj_bind_notify`)

## Contexto

A contenção da T-422 (ADR 0051) só funciona no VT-d. O tratador `kiommu::on_fault_irq` só é ligado à interrupção de falta do VT-d. No AMD-Vi, o log de eventos só é lido quando alguém chama `kiommu::faults`, e em execução ninguém chama. A falta é bloqueada pela IOMMU, mas fica sem registro e sem evento ao `devmgr`.

O item 6 da ADR 0051 tem um segundo problema, que a T-507 pede para decidir. O `devmgr` espera o endpoint com prazo de 50 ms (`POLL_NS`) para olhar a notificação de faltas. Isso dá 20 despertares por segundo, para sempre, mesmo com a máquina parada, num sistema cujo kernel é tickless justamente para não acordar à toa (ADR 0009). E o driver que faltou ainda pode rodar até 50 ms antes da contenção.

## Decisão

1. **AMD-Vi com interrupção do log de eventos.** A IOMMU AMD é uma função PCI, cujo BDF vem do IVHD (`unit.bdf`, já lido pelo `acpi::ivrs`) e que tem capability MSI. O kernel, dono da IOMMU (ADR 0044, item 1):
   - programa a MSI dessa função pela ECAM (MCFG, que o kernel já lê), com destino na BSP e o vetor `IOMMU_FAULT_VECTOR`, o mesmo do VT-d;
   - liga `EventIntEn` (bit 3 do registrador de controle).

   O tratador é o mesmo `on_fault_irq`. Ele lê o log, avança a cabeça, limpa `EventLogInt` (bit 1 do status, que se limpa escrevendo 1) e sinaliza o domínio de cada BDF (ADR 0051, item 1).
2. **Transbordo.** Com `EventOverflow` no status, o tratador registra `okernel: log de eventos do AMD-Vi transbordou`, desliga o log, zera cabeça e cauda e o religa, como manda a especificação do AMD-Vi. A falta perdida no transbordo só aparece na contagem. O driver que a causou é contido na falta seguinte.
3. **A função da IOMMU é do kernel.** O kernel recusa MSI, BAR e `DmaDomain` para o BDF da IOMMU, e o `devmgr` nunca casa driver com ele.
4. **Sem MSI na função**, ou se a programação falhar, o kernel não lê o log periodicamente, porque continua tickless. Ele registra a marca `okernel: AMD-Vi sem interrupção de falta: contenção de DMA ausente`, no espírito do "isolamento de DMA ausente" da ADR 0044 (item 5). O DMA ruim continua bloqueado. Só a contenção e o reinício ficam faltando.
5. **Sem remapeamento.** O AMD-Vi ainda não remapeia interrupções, então a MSI da própria IOMMU vai direta, como o evento de falta do VT-d.
6. **Decisão da T-507: segunda thread no `devmgr`, sem prazo no laço.** O `devmgr` passa a `max_threads` = 2.
   - A thread nova só espera, sem prazo, a notificação de faltas (`ntfy_wait`).
   - Acordada, ela faz `ipc_call` ao endpoint do próprio `devmgr` com uma capability de badge reservado (`FAULT_BADGE`) e os bits lidos.
   - O laço principal volta a `ipc_recv` sem prazo e trata a mensagem de falta em série com os pedidos do `DeviceBus`, com a mesma contenção dos itens 3 a 5 da ADR 0051. Não há estado compartilhado nem trava entre as threads.
   - Enquanto o laço trata uma falta, as seguintes se acumulam como bits na notificação.
   - Este item substitui o item 6 da ADR 0051.
7. **Aceite** (T-510 e T-511): `cargo xtask test iommu` com `-device amd-iommu` mostra `okernel: falta de DMA` em até 1 ms do DMA, pelo carimbo do log, e o `devmgr` contém e reinicia o `drvteste`, com o mesmo roteiro do VT-d. Nos dois IOMMUs, o relatório registra o tempo entre a falta e a contenção, que deixa de ter o piso de 50 ms. O primeiro passo da T-510 é confirmar que o `amd-iommu` do QEMU entrega a MSI do log de eventos. Se não entregar, a T-510 para e volta com isso antes de seguir.

## Alternativas consideradas

- **Ler o log do AMD-Vi periodicamente no kernel:** exige um timer periódico no kernel, contra a ADR 0009. Rejeitada.
- **Manter o prazo de 50 ms no `devmgr`:** custa 20 despertares por segundo em toda máquina, inclusive em notebook e Lite, e deixa o driver ruim rodando até 50 ms. Rejeitada.
- **Notificação ligada ao endpoint (como no seL4):** `ipc_recv` passaria a voltar também por sinal. Muda a semântica da ABI v1, que está congelada. Rejeitada.
- **Segunda thread que faz a contenção ela mesma:** exigiria travar o estado dos drivers entre as duas threads. A mensagem ao próprio endpoint serializa sem trava. Rejeitada.

## Consequências

- O `devmgr` ganha uma thread, com pilha e a cota dela, e uma capability de envio ao próprio endpoint.
- Com a máquina parada, nada acorda por causa das faltas.
- A contenção vale nos dois IOMMUs, e a pendência do M4 fecha com a T-510 e a T-511.
- O kernel ganha a programação da MSI da IOMMU AMD (`dma/amdvi.rs` e `kiommu.rs`). É código crítico, feito com Opus/high (T-510).
- Qualquer mudança no que está acima exige ADR nova.
