# ADR 0013: Drivers em espaço de usuário, com IOMMU obrigatória quando presente

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 8 e 13.2
- Relaciona-se com: ADR 0001 (microkernel), ADR 0006 (cotas), ADR 0007 (IPC)

## Contexto

Drivers são a maior parte do código de um sistema e a parte com mais falhas, e
analisam descritores de hardware que pode ser malicioso (USB, Thunderbolt).
Num kernel monolítico, um driver com falha derruba ou entrega a máquina. E um
dispositivo com DMA livre escreve em qualquer página física, mesmo que o driver
esteja num processo isolado.

## Decisão

- Cada driver é um processo isolado, criado pelo `devmgr`, que recebe só as
  capabilities do seu dispositivo: MemoryObject dos BARs, Interrupt (MSI-X),
  IoPortRange quando preciso e um DmaDomain da IOMMU.
- Com IOMMU presente (VT-d, AMD-Vi, SMMUv3), ela é obrigatória: o dispositivo só
  faz DMA nas páginas mapeadas no seu DmaDomain.
- Sem IOMMU, o driver roda mesmo assim, e o sistema marca a máquina como
  "isolamento de DMA ausente" no HUD e no `auditd`.
- Drivers expõem traits assíncronas (`BlockDevice`, `NetDevice` etc.) via OIDL e
  DEVEM tolerar reinício; estado persistente fica no serviço de cima.
- No kernel fica só o mínimo: UART e framebuffer GOP para log de pânico.

## Alternativas

- **Drivers no kernel, como Linux e Windows:** sem custo de IPC e com muito
  código pronto, mas qualquer falha vira falha do kernel; contraria a ADR 0001.
- **Drivers no kernel em Rust com isolamento por linguagem:** reduz falhas de
  memória, mas não contém lógica errada, travamentos nem DMA malicioso.
- **Drivers em usuário sem exigir IOMMU:** um driver tomado programaria o DMA
  para dominar a máquina; recusar máquinas sem IOMMU excluiria parte do Lite.

## Consequências

- Driver comprometido ou travado não domina a máquina; o `svcmgr` o reinicia.
- Interrupções viram sinais de Notification e cada E/S passa por IPC e anéis em
  memória compartilhada; o desempenho depende do IPC rápido (RNF-03).
- O suporte a VT-d e AMD-Vi precisa existir cedo (M4). Máquinas sem IOMMU
  ficam em modo degradado e avisado, um risco aceito (seção 13.5).
- Todo parser de descritores (PCI, USB, ACPI) DEVE ter alvo de fuzzing.
