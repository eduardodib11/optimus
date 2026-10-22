# Spec Driven Development no Optimus OS

Este diretório organiza o desenvolvimento em três níveis. Cada nível só começa depois que o anterior foi aprovado.

```
docs/spec-driven/
├── README.md              este arquivo
├── constituicao.md        princípios e regras não negociáveis (muda raramente, por ADR)
└── specs/
    └── 001-svcmgr/
        ├── spec.md        o quê e por quê: histórias, critérios de aceite, fora de escopo
        ├── plan.md        como: decisões, arquitetura, interfaces, riscos, ADRs necessárias
        └── tasks.md       quebra em tarefas pequenas, ordenadas, com critério de pronto
```

## Fluxo

1. **Constituição.** Regras do projeto que valem para todas as especificações (segurança, `unsafe`, DCO, ADR antes do código).
2. **Spec.** Descreve o comportamento esperado, sem falar de implementação. Fonte: PRD e SDD.
3. **Plano.** Traduz a spec em decisões técnicas e aponta as ADRs que precisam ser aceitas antes do código.
4. **Tarefas.** Cada tarefa cabe num PR de até 400 linhas, com aceite verificável. Os números T-3xx do backlog do M3 continuam valendo.
5. **Implementação com testes primeiro.** Nenhum código entra sem teste que falhe antes.
6. **Revisão.** Mudança de TCB, `kabi`, cripto ou política exige revisão do responsável de segurança.

## Hierarquia de fontes

Em caso de conflito, vale nesta ordem:

1. ADR aceita posterior ao SDD (`docs/adr/`).
2. SDD v1.0 (`docs/sdd/optimus-os-sdd-v1.0.pdf`).
3. PRD (`docs/prd/PRD.md`).
4. Especificações e planos deste diretório.

Uma especificação que contradiz o SDD não é aprovada. Ou ela muda, ou o SDD muda por ADR.

## Estado

| Especificação | Marco | Status |
|---|---|---|
| 001-svcmgr | M3 (T-350 a T-354) | rascunho para revisão |

Os demais marcos entram aqui conforme os backlogs forem detalhados.
