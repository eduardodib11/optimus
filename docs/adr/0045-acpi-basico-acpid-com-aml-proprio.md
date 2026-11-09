# ADR 0045: ACPI básico: acpid com interpretador AML próprio e isolado

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 8; backlog do M4, T-405
- Relaciona-se com: ADR 0003, 0042, 0043

## Contexto

O kernel já lê MADT. O resto do ACPI (DSDT/SSDT, namespace, métodos) é um interpretador de linguagem, grande e alimentado por firmware, ou seja, superfície de ataque.

## Decisão

1. O interpretador AML roda em um processo de usuário `acpid`, nunca no kernel. Recebe as tabelas como `MemoryObject` somente leitura.
2. Implementação própria, `no_std`, sem crates externas (ADR 0003), com limites duros: profundidade de pilha, número de operações por método e memória por cota. Estourar o limite aborta o método.
3. Subconjunto v1: espaço de nomes, `Device`, `_HID`, `_CID`, `_ADR`, `_CRS`, `_PRT`, `_STA`, `Method` com controle de fluxo e aritmética, `OperationRegion` apenas de `SystemMemory` e `SystemIO` dentro dos intervalos entregues. Eventos e energia ficam para depois.
4. Saída: nós de dispositivo ao `devmgr` com `compatible` derivado de `_HID`/`_CID` e recursos de `_CRS`.
5. Fuzzing do parser no alvo de fuzz (T-421). Aceite: tabelas do QEMU lidas sem pânico.

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-405 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
