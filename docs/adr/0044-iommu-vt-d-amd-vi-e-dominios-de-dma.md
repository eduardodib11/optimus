# ADR 0044: IOMMU (VT-d e AMD-Vi), domínios de DMA e modo sem IOMMU

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 13.2; backlog do M4, T-403
- Relaciona-se com: ADR 0013, 0042, 0043

## Contexto

A ADR 0013 manda IOMMU obrigatória quando presente. Falta o desenho: quem programa a IOMMU, o que é o `DmaDomain` e o que acontece sem IOMMU.

## Decisão

1. **A IOMMU é programada pelo kernel**, em módulo pequeno (`iommu`), porque as tabelas decidem o isolamento. Detecção por DMAR (VT-d) e IVRS (AMD-Vi), lidas da `BootInfo`.
2. **DmaDomain** é um objeto do kernel (tipo 11) com tabela de páginas da IOMMU própria, cobrada da cota de quem o cria. Direitos: `MAP`. `dma_map(domínio, memobj, iova, tamanho, flags)` mapeia páginas de um `MemoryObject` em IOVA; `dma_unmap` desfaz e invalida o IOTLB. Flags: leitura, escrita. Sem execução.
3. **Vínculo dispositivo-domínio**: o `devmgr` chama `dma_attach(domínio, bdf)`, operação do `DmaDomain` com direito `BIND`. Só o `devmgr` tem esse direito; o driver só tem `MAP`.
4. **Faltas** de IOMMU viram registro estruturado no log (`dev`, `iova`, `motivo`) e um evento ao `devmgr`, que reinicia o driver (T-422).
5. **Sem IOMMU**: `DmaDomain` existe como objeto lógico (sem proteção de hardware), `dma_map` só valida e devolve o endereço físico como IOVA, e o sistema publica a marca "isolamento de DMA ausente" ao `auditd` e ao Cockpit. O driver roda.
6. **Remapeamento de interrupções** fica ligado quando existe; MSI-X passa por ele.
7. Código crítico: `unsafe` só no acesso aos registros e tabelas, com `// SAFETY:` e teste de QEMU com `-device intel-iommu`.

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-403 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
