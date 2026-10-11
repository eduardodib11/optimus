# ADR 0006: Alocação de objetos do kernel cobrada de MemoryQuota

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 6.1, 6.3, 7.2 e 14.4
- Relaciona-se com: ADR 0001

## Contexto

Num microkernel, processos criam objetos do kernel (threads, endpoints, tabelas
de página, slots de capability). Se o kernel alocar de um heap global, um
processo pode esgotar a memória do kernel e derrubar os demais (negação de
serviço), e o tempo de alocação deixa de ser previsível. O kernel também não
pagina a si mesmo, então memória dada ao kernel precisa ter dono.

## Decisão

Toda criação de objeto usa `obj_create(quota, tipo, args)` e debita bytes de uma
capability `MemoryQuota`, com direitos `CREATE` e `SPLIT`. Quando a última
capability de um objeto é apagada, ele é destruído e os bytes voltam à cota. O
crescimento do `CapSpace` também é cobrado. Criação além da cota retorna
`QuotaExceeded`.

O `root` recebe toda a memória, divide-a em cotas e as entrega ao `svcmgr`, que
dá a cada serviço a cota declarada no manifesto (ex.: `mem:quota:32MiB`).
Internamente o kernel usa buddy e slab; a cota limita, não escolhe o endereço.

## Alternativas

- **Untyped memory do seL4:** o usuário recebe memória física bruta e a
  "retipa" em objetos. É verificada e muito flexível, mas expõe layout físico,
  exige gerência de capabilities de memória no usuário e torna root e serviços
  bem mais complexos.
- **Heap global do kernel com limites por processo** (estilo Linux, cgroups):
  simples de usar, mas a contabilidade é feita depois e pressão de memória no
  kernel ainda afeta todos.
- **Pools fixos por tipo de objeto:** previsíveis, mas desperdiçam memória e
  impõem limites globais arbitrários.

## Consequências

- Determinismo e resistência a DoS: um serviço só esgota a própria cota.
- Mais simples que untyped e fácil de explicar em manifestos.
- Todo serviço declara orçamento de memória no manifesto.
- O kernel precisa contabilizar bytes exatos por objeto, incluindo metadados.
