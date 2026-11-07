# ADR 0042: Optimus Driver Framework: `devmgr`, manifesto de casamento e capabilities entregues

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 8 (Drivers), 8.1 (ODF), 8.3 (regras) e 14 (OIDL); backlog do M4, T-401
- Relaciona-se com: ADR 0001, ADR 0003, ADR 0012 (OIDL), ADR 0013 (drivers em usuário), ADR 0029 (criação de processos), ADR 0034 (manifesto e `svcmgr`), ADR 0043, ADR 0044

## Contexto

O SDD 8 diz que cada driver é um processo isolado, criado pelo `devmgr`, com acesso só ao seu dispositivo: regiões MMIO, IRQs e um `DmaDomain`. Um driver que trava é reiniciado sem derrubar o sistema. A 8.1 define enumeração, casamento por manifesto ("o mais específico vence") e as capabilities entregues. A 8.3 exige tolerância a reinício e que nenhum driver acesse memória fora dos `MemoryObject` recebidos. Falta fixar o formato do manifesto, a regra de especificidade e o protocolo entre `devmgr` e driver.

## Decisão

1. **`devmgr`.** Processo de usuário, filho do `svcmgr` (ADR 0034), dono do catálogo de nós de dispositivo. Recebe nós do `acpid` (ADR 0045) e da varredura PCIe (ADR 0043), casa cada nó com um manifesto e cria o processo do driver com `proc_create` (ADR 0029). O kernel não conhece o conceito de driver.
2. **Manifesto de driver.** Arquivo `driver.toml`-equivalente no formato de manifesto da ADR 0034, com: `name`, `binary`, `provides` (interfaces OIDL, por exemplo `BlockDevice`), `needs` (tipos de capability e limites: BARs, vetores MSI-X, `DmaDomain`, `IoPortRange`) e uma lista de regras `match`. Uma regra `match` combina `vendor`, `device`, `subvendor`, `subdevice`, `class`, `subclass`, `prog_if` (PCI) ou `compatible` (ACPI/Device Tree). Campos ausentes valem como curinga.
3. **Especificidade.** A pontuação de uma regra é o número de campos preenchidos, ponderado: `vendor+device+subsystem` > `vendor+device` > `class+subclass+prog_if` > `class+subclass` > `class`; `compatible` casa na ordem da lista, a primeira entrada vence. Vence a regra de maior pontuação. Empate entre manifestos diferentes é erro de catálogo: o `devmgr` recusa os dois, registra no `logd` e não sobe nenhum driver para o nó.
4. **Capabilities entregues.** Só as que o manifesto declara em `needs` e que o dispositivo realmente tem: `MemoryObject` de cada BAR (MMIO), `Interrupt` (MSI-X, ADR 0043/0046), `DmaDomain` (ADR 0044) e `IoPortRange` apenas quando um BAR de E/S ou o manifesto exigir. Cada capability é derivada com os direitos mínimos e entra no `CapSpace` do filho. O driver nunca recebe capability do `devmgr` nem de outro driver.
5. **Cota.** Cada driver recebe uma `MemoryQuota` própria, com teto no manifesto, derivada da cota do `devmgr` (ADR 0006). Esgotar a cota mata só o driver.
6. **Reinício.** O `devmgr` observa a morte do driver pelo evento de ciclo de vida (ADR 0035) e o reinicia com atraso exponencial (100 ms, dobrando, teto de 10 s) e no máximo 5 tentativas em 60 s; depois disso o nó fica `falho` e o fato vai ao `auditd`. Estado persistente fica no serviço de cima (8.3). O `DmaDomain` é destruído e recriado a cada reinício.
7. **Interfaces.** Cada driver expõe ao resto do sistema só a interface OIDL declarada em `provides` (`BlockDevice`, `NetDevice`, `InputDevice`, `AudioDevice`, `DisplayDevice`), publicada no `svcmgr`. O protocolo `devmgr`↔driver (`probe`, `start`, `stop`, `health`) também é OIDL.
8. **Sem IOMMU.** O driver sobe mesmo assim, e o `devmgr` marca a máquina como "isolamento de DMA ausente" (8.1), o que o Cockpit e o `auditd` exibem (ADR 0044).
9. **Firmware binário.** Blobs de fabricante só carregam se constarem do catálogo assinado, com hash fixo (8.1). Fora do escopo do M4; o manifesto reserva o campo `firmware`.
10. **Fuzzing.** O parser de manifesto e o casamento entram no alvo de fuzz do `devmgr` (8.3).

## Alternativas consideradas

- **Drivers no kernel:** rejeitado (ADR 0013).
- **Casamento por ordem de arquivo:** rejeitado; viola "o mais específico vence".
- **Entregar o espaço de configuração PCI inteiro ao driver:** rejeitado; o `devmgr` guarda o config space e expõe só leituras e o que o manifesto permite.

## Consequências

- T-401 pode começar: sem mudança de ABI do kernel, só serviço de usuário e esquema de manifesto.
- O formato de manifesto de driver estende o da ADR 0034 sem alterá-lo.
- Empates de catálogo viram erro explícito, testável.
