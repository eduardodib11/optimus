# ADR 0042: Optimus Driver Framework: devmgr, manifesto de casamento e capabilities entregues

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 8 (drivers, ODF); backlog do M4, T-401
- Relaciona-se com: ADR 0013, 0034, 0035

## Contexto

O SDD manda drivers em processos isolados, criados por um gerenciador, que recebem só as capabilities do seu dispositivo (ADR 0013). Falta definir quem casa dispositivo com driver, em que formato e o que cada driver recebe.

## Decisão

1. **devmgr** é um serviço de usuário, filho do `svcmgr`. Ele é o único dono dos nós de dispositivo. Os provedores de enumeração (`pcid`, `acpid`) publicam nós para ele por IPC (OIDL `DeviceBus`).
2. **Nó de dispositivo.** Id estável, barramento, `vendor:device`, `class:subclass:progif`, lista de `compatible` e recursos (BARs, IRQs, portas).
3. **Manifesto de driver** no formato da ADR 0034, seção `[match]`: `pci = ["vvvv:dddd"]`, `class = ["cc:ss:pp"]`, `compatible = ["..."]`. Pontuação: id exato = 3, classe com subclasse e progif = 2, classe = 1, `compatible` = 1. O maior valor vence; empate é erro do manifesto e o `devmgr` registra e não carrega nenhum.
4. **Capabilities entregues**: `MemoryObject` por BAR (só os do nó), `Interrupt` por vetor MSI-X, `IoPortRange` quando o nó tem portas, `DmaDomain` próprio (ADR 0044) e `MemoryQuota` limitada pelo manifesto. Nunca recebe a cota nem o `CapSpace` do `devmgr`.
5. **Ciclo de vida.** O `devmgr` supervisiona pelo `svcmgr` (ADR 0035). Morte do driver revoga todas as capabilities do dispositivo e o `DmaDomain`; o reinício reentrega recursos novos. Estado persistente fica no serviço de cima (ADR 0013).
6. **Sem driver no kernel.** Nenhuma lógica de dispositivo entra no kernel além do que a ADR 0043 a 0044 descreve (acesso de configuração, IOMMU e vetores).

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-401 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
