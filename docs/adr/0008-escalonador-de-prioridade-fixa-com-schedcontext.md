# ADR 0008: Escalonador de prioridade fixa (256 níveis) com SchedContext

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 6.1, 6.6, 6.9 e 13.2
- Relaciona-se com: ADR 0007, ADR 0009, ADR 0010

## Contexto

O Optimus tem cargas de tempo real (áudio, entrada, compositor, voz com meta de
800 ms ponta a ponta) junto com trabalho longo de fundo (indexação, raciocínio
da IA, `evolved`). Prioridade sozinha não basta: uma thread de alta prioridade
com defeito monopolizaria a CPU. Também é preciso evitar inversão de prioridade
quando um cliente chama um servidor por IPC.

## Decisão

- Escalonamento preemptivo de prioridade fixa, 256 níveis, round-robin dentro
  do nível com fatia padrão de 5 ms.
- Cada thread executa sobre um `SchedContext` com orçamento e período. Sem
  orçamento, ela espera o próximo período.
- Em `ipc_call`, o cliente doa o `SchedContext` ao servidor, que roda com o
  tempo e a prioridade do cliente.
- Filas por CPU, com migração periódica e em wake-up, respeitando afinidade e
  NUMA.
- As faixas são centralizadas: 240–255 tempo real (áudio, entrada, compositor),
  200–239 drivers, 128–199 serviços e `ai-exec`, 64–127 apps e IA em primeiro
  plano, 1–63 fundo, 0 ocioso.

## Alternativas

- **Escalonador justo (CFS/EEVDF do Linux):** bom para vazão geral, mas sem
  garantia temporal para áudio e com latência difícil de prever.
- **EDF puro:** ótimo em teoria, mas sobrecarga e comportamento sob sobrecarga
  são piores, e é menos familiar para quem configura serviços.
- **Prioridade fixa sem orçamento (L4 clássico):** simples, mas não isola
  thread com defeito nem limita DoS de CPU.

## Consequências

- Tempo real para áudio e UI e isolamento temporal entre serviços.
- A doação em IPC evita inversão de prioridade sem protocolo extra.
- A política de prioridades é centralizada na seção 6.6; manifestos declaram a
  prioridade dentro dessas faixas.
