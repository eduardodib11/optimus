# ADR 0043: Enumeração de PCIe e publicação de nós de dispositivo

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 8, 8.1, 8.2 (M4: PCIe) e 8.3; backlog do M4, T-402 e T-404
- Relaciona-se com: ADR 0013, ADR 0030 (estado por CPU), ADR 0031, ADR 0042, ADR 0044, ADR 0045

## Contexto

A 8.1 manda o `devmgr` varrer PCIe e publicar nós de dispositivo, entregando `MemoryObject` dos BARs e `Interrupt` (MSI-X). A varredura lê um espaço de configuração controlado por hardware não confiável, e a 8.3 exige alvo de fuzzing para todo parser de descritores. Falta decidir onde a varredura roda, como o espaço de configuração é acessado e como BARs e interrupções chegam ao driver.

## Decisão

1. **Onde roda.** A varredura é um serviço de usuário, `pcid`, filho do `devmgr`. O kernel não varre PCI.
2. **Acesso ao config space.** Via ECAM, com a região descrita pela tabela ACPI `MCFG` (lida pelo `acpid`, ADR 0045). O `pcid` recebe um `MemoryObject` MMIO só dessa região ECAM, sem direito `EXEC`. Sem `MCFG`, o `pcid` cai no acesso por portas `0xCF8/0xCFC` com um `IoPortRange` restrito a essas portas, apenas em x86-64. Acesso por portas é serializado e marcado como degradado no log.
3. **Varredura.** Busca em profundidade por barramento, dispositivo e função, seguindo as pontes (tipo de cabeçalho 1), com limite de profundidade 8 e de 256 barramentos. IDs `0xFFFF` encerram a função. Leituras fora de limite ou ciclos de ponte são descartados e registrados no `logd`; nenhuma leitura gera pânico.
4. **Nó de dispositivo.** Para cada função, o `pcid` publica ao `devmgr` um nó com: localização (`seg:bus:dev.fn`), `vendor`, `device`, `subvendor`, `subdevice`, `class`, `subclass`, `prog_if`, `revision`, lista de BARs (tipo, base, tamanho, prefetch) e as capabilities PCI (MSI, MSI-X, PCIe) já analisadas. O `devmgr` usa esse nó no casamento (ADR 0042).
5. **BARs.** O tamanho vem do protocolo escrever-todos-uns/ler, com decodificação desligada durante a sondagem. BARs de MMIO viram `MemoryObject` MMIO (contíguos, sem `EXEC`) entregues ao driver; BARs de E/S viram `IoPortRange`, só quando o manifesto pedir. Se o firmware não alocou um BAR, o `pcid` não o realoca no M4: o nó fica marcado `bar_nao_alocado` e nenhum driver o recebe. BARs de 64 bits ocupam dois slots.
6. **Interrupções.** O `pcid` programa a tabela MSI-X e entrega ao driver capabilities `Interrupt` por vetor (T-404). O vetor e o endereço de mensagem vêm do kernel (alocação por CPU, ADR 0030); o driver não escreve a tabela MSI-X diretamente. Sem MSI-X, usa MSI; INTx só se o manifesto permitir e é compartilhado (ADR 0031).
7. **Comando PCI.** O driver só recebe `bus master` e decodificação de memória ligados depois que o `DmaDomain` existir (ADR 0044). O `pcid` mantém o registro de comando; o driver pede mudanças por IPC e o `pcid` valida.
8. **Hot-plug.** Fora do M4. O `pcid` varre na partida e sob pedido explícito do `devmgr`.
9. **Fuzzing.** Alvo `fuzz_pcie_scan` com config space sintético (T-421).

## Alternativas consideradas

- **Varredura no kernel:** rejeitado; aumenta a TCB sem necessidade.
- **Dar ao driver o config space completo:** rejeitado; permitiria reprogramar BARs e vizinhos.
- **Realocar BARs no M4:** adiado; o QEMU q35 com OVMF já aloca.

## Consequências

- O critério de aceite da T-402 (lista igual à do `lspci` do host no q35) é verificável sem hardware real.
- O kernel precisa só expor a alocação de vetores MSI-X por CPU e a capability `Interrupt` por vetor, na T-404.
