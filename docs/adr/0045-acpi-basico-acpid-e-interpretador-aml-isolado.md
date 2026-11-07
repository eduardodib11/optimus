# ADR 0045: ACPI básico: `acpid` com interpretador AML próprio e isolado

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 8.1 ("`acpid`, que contém o interpretador AML próprio, isolado"), 8.2 (M4: ACPI básico), 8.3 e matriz de riscos (interpretador AML); backlog do M4, T-405
- Relaciona-se com: ADR 0003 (sem crates), ADR 0013, ADR 0042, ADR 0043, ADR 0044

## Contexto

O kernel já lê as tabelas mínimas para partir os APs e o APIC (`okernel/src/acpi`, ADR 0030). O ACPI completo exige interpretar AML, bytecode fornecido pelo firmware, que é superfície de ataque externa e historicamente fonte de falhas. O SDD manda que o interpretador seja próprio e isolado em `acpid`, e nenhuma crate externa entra na imagem.

## Decisão

1. **Divisão.** O kernel continua lendo só `RSDP`, `XSDT`, `MADT`, `HPET` e o que a partida SMP e o temporizador precisam, sem AML. Tudo o mais é do `acpid`, processo de usuário, filho do `devmgr`, em espaço de endereçamento próprio.
2. **Entrada.** O `acpid` recebe do `optboot` (via `BootInfo`, ADR 0034) um `MemoryObject` somente leitura com as tabelas ACPI copiadas (RSDT/XSDT, `FADT`, `DSDT`, `SSDT`, `MCFG`, `DMAR`, `IVRS`, `MADT`). Ele não acessa a memória física do firmware.
3. **Escopo do M4 ("ACPI básico").** (a) Listar tabelas e validar cabeçalhos e somas de verificação; (b) publicar `MCFG` ao `pcid` (ADR 0043) e `DMAR`/`IVRS` ao kernel/`devmgr` (ADR 0044); (c) interpretar o suficiente de AML do `DSDT`/`SSDT` para montar o espaço de nomes e avaliar `_HID`, `_CID`, `_UID`, `_ADR`, `_CRS`, `_PRT` e `_STA`; (d) publicar os nós de dispositivo ACPI ao `devmgr` com `compatible` derivado de `_HID`/`_CID`. Fora do M4: gerenciamento de energia (S3/S4, `_PS0/_PS3`), bateria, térmica, hot-plug, métodos com efeitos colaterais além de leitura.
4. **Interpretador.** Escrito do zero em Rust, `no_std`, `#![forbid(unsafe_code)]`, em `lib/oaml`. Fases: analisador de AML para uma árvore (`TermList`) e interpretador de leitura com limites duros: profundidade de chamada 64, 1 000 000 de passos por avaliação, 4 MiB de heap, tempo máximo por avaliação 50 ms. Estouro de limite aborta só aquela avaliação, nunca o `acpid`.
5. **Acesso a hardware.** `OperationRegion` de `SystemMemory` só dentro de regiões MMIO listadas em `_CRS` e entregues como `MemoryObject` ao `acpid`; `SystemIO` só em `IoPortRange` concedido; `PCI_Config` só via IPC ao `pcid`; `EmbeddedControl`, `SMBus` e `CMOS` ficam não suportados no M4 e retornam erro. Escrita em qualquer região é recusada no M4 (somente leitura).
6. **Isolamento.** O `acpid` não recebe `DmaDomain`, nem capability de threads ou processos de outros, nem rede. Ao morrer, o `devmgr` o reinicia (ADR 0042) e republica os nós; a falha repetida deixa o sistema sem nós ACPI e vira aviso no `auditd`, sem impedir o boot (varredura PCIe independe de AML).
7. **Fuzzing.** O analisador AML e o interpretador entram no alvo de fuzz (`fuzz_aml`) com corpus das tabelas do QEMU (8.3, T-405, T-421).
8. **Testes.** Tabelas do QEMU q35 são lidas sem pânico; tabelas corrompidas geram erro, não travamento.

## Alternativas consideradas

- **ACPICA ou `acpi` do crates.io:** rejeitado (ADR 0003).
- **Interpretar AML no kernel:** rejeitado; superfície de ataque externa na TCB.
- **Sem AML, só tabelas estáticas:** rejeitado; `_PRT` e `_CRS` são necessários em hardware real e o SDD prevê o interpretador.

## Consequências

- Novo componente `lib/oaml` (parser e interpretador), com alvo de fuzz obrigatório.
- A leitura mínima de tabelas no kernel não muda.
- Gerenciamento de energia fica para marco posterior, por nova ADR.
