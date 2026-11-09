# ADR 0043: Enumeração de PCIe e publicação de nós de dispositivo

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 8; backlog do M4, T-402
- Relaciona-se com: ADR 0042, 0045

## Contexto

O `devmgr` precisa de uma lista de dispositivos. Em x86-64 ela vem do espaço de configuração PCIe (ECAM, tabela MCFG do ACPI) e, para o que não é PCI, do `acpid`.

## Decisão

1. **pcid** é um processo de usuário com um `MemoryObject` do ECAM (entregue pelo `root`, que lê o MCFG da `BootInfo`) e nada mais. Sem ECAM, cai no acesso por portas 0xCF8/0xCFC via `IoPortRange`.
2. A varredura percorre barramentos de 0 a 255 e segue pontes (tipo 1). Lê vendor, device, classe, BARs (dimensiona escrevendo 1s, com decodificação desligada durante o dimensionamento) e capabilities (MSI, MSI-X, PCIe).
3. Cada função vira um nó (ADR 0042). BARs viram `MemoryObject` de MMIO, criados pelo `root` por pedido do `pcid` com o intervalo físico, e só são entregues ao driver casado.
4. O `pcid` não habilita bus master. Quem habilita é o `devmgr`, depois de o driver ter um `DmaDomain` (ADR 0044).
5. **Parser de superfície externa**: sem `unsafe` fora do acesso ao ECAM, sem pânico e com alvo de fuzzing (T-421).
6. Aceite: a lista do QEMU q35 bate com `lspci`.

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-402 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
