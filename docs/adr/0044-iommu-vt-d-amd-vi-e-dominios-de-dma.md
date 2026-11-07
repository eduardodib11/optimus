# ADR 0044: IOMMU: Intel VT-d e AMD-Vi, domínios de DMA e modo sem IOMMU

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 6 (capability `DmaDomain`, syscall 31 `dma_map`/`dma_unmap`), 8, 8.1, 8.2 (M4: IOMMU Intel VT-d e AMD-Vi) e 13.2/13.5; backlog do M4, T-403 e T-422
- Relaciona-se com: ADR 0006 (cota), ADR 0013, ADR 0031 (travas e shootdown), ADR 0042, ADR 0043, modelo de ameaças (D2, D6, B8)

## Contexto

O SDD manda que todo driver tenha um `DmaDomain` da IOMMU e que DMA fora do domínio falhe. Sem IOMMU, o sistema roda em modo degradado e avisado. A tabela de syscalls tem `dma_map`/`dma_unmap` na vaga 31 "via flag", mas não define os argumentos nem quem programa o hardware. A IOMMU é TCB: erro aqui quebra o isolamento de todos os drivers.

## Decisão

1. **Quem programa.** O kernel (`okernel`) programa as tabelas da IOMMU e a invalidação, pois elas protegem contra DMA e precisam ser confiáveis; o código fica em `arch/x86_64/iommu/` (VT-d e AMD-Vi) atrás de um trait comum `Iommu` em `okernel`. O `devmgr` só pede domínios por syscall. Descoberta: tabelas ACPI `DMAR` (Intel) e `IVRS` (AMD), lidas pelo kernel a partir do que o `optboot` já passa na `BootInfo`.
2. **`DmaDomain`.** Objeto de kernel, um por driver (e por dispositivo atribuído), criado por `obj_create(quota, DmaDomain, ...)`, cobrando as tabelas da cota. Direito `MAP`. A capability é entregue ao driver pelo `devmgr`; a vinculação do dispositivo (RID/BDF) ao domínio é feita por uma segunda capability, `bind`, que fica com o `devmgr` e nunca com o driver.
3. **`dma_map` (syscall 31, flag `MAP`).** Argumentos: `DmaDomain`, `MemoryObject`, deslocamento, comprimento, endereço de E/S (IOVA) pedido ou 0 para o kernel escolher, e flags `READ`/`WRITE` (sem execução, que não existe em DMA). Exige que a capability do objeto tenha os direitos correspondentes. O kernel fixa as páginas do objeto (não podem ser liberadas ou descomprometidas, ver ADR 0038) enquanto mapeadas. `dma_unmap` desfaz, invalida o IOTLB e só então libera a fixação. Mapear exige `MAP` no domínio e `READ`/`WRITE` no objeto; cada mapa cobra metadados da cota do domínio.
4. **Faults.** Falha de tradução gera interrupção da IOMMU; o kernel registra no `klog` (BDF, IOVA, tipo) e entrega o evento ao `devmgr` por notificação. Três faults em 10 s no mesmo domínio: o `devmgr` mata e reinicia o driver (ADR 0042). O sistema não cai (8.1). O fault grava em `auditd`.
5. **Invalidação.** Invalidação síncrona do IOTLB a cada `dma_unmap` e na destruição do domínio; sem modo preguiçoso no M4. Em SMP, a ordem de travas segue a ADR 0031.
6. **Domínio padrão.** Dispositivos sem driver ficam no domínio de bloqueio (sem tradução permitida). Nenhum dispositivo opera com passagem direta ("identity") se a IOMMU está presente. DMA remapeado também cobre interrupções (VT-d Interrupt Remapping e AMD-Vi equivalente), ligado quando houver suporte.
7. **Sem IOMMU.** O `devmgr` sobe o driver mesmo assim, o `dma_map` vira registro de limites sem proteção, e a máquina é marcada "isolamento de DMA ausente" no Cockpit e no `auditd` (8.1, 13.5). Esse estado é testado explicitamente (T-420, T-422).
8. **Cedo no boot.** O `optboot`/kernel ativa a IOMMU antes de qualquer driver e antes de ligar `bus master` em qualquer dispositivo (ver B8 no modelo de ameaças). DMA antes disso continua um risco aceito de ataque físico.
9. **Teste.** QEMU q35 com `intel-iommu` emulado (T-420); AMD-Vi fica verificado por revisão e por testes de estrutura de tabela até haver máquina real. Fuzz do parser `DMAR`/`IVRS` na T-421.

## Alternativas consideradas

- **IOMMU em processo de usuário:** rejeitado; a TCB de isolamento de DMA não pode depender de processo que pode falhar.
- **Domínio único compartilhado:** rejeitado; um driver comprometido leria a memória de outro.
- **Exigir IOMMU:** rejeitado; o SDD admite modo degradado avisado.

## Consequências

- Muda a ABI v1 só no preenchimento de `dma_map`/`dma_unmap`, que já tem vaga reservada (syscall 31); nenhuma syscall nova. Os argumentos entram em `kabi` com testes.
- A fixação de páginas por DMA cria uma dependência com a paginação em usuário (ADR 0038): objetos `LAZY` mapeados em `DmaDomain` ficam sempre Present.
- AMD-Vi é entregue sem teste em hardware no M4; fica registrado em `docs/aceite/` do Gate 2.
