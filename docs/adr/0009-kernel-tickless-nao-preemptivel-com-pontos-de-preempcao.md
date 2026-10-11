# ADR 0009: Kernel tickless, não preemptível, com pontos de preempção

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 6.2, 6.6 e 6.8
- Relaciona-se com: ADR 0001 (microkernel), ADR 0008 (escalonador), ADR 0010 (SMP)

## Contexto

O okernel deve caber em 1 MiB e quase todas as syscalls são curtas. Algumas não
são: `cap_revoke` pode apagar milhares de descendentes. O escalonador (ADR 0008)
atende áudio, entrada e compositor em tempo real, então a latência até a thread
mais prioritária rodar precisa ser limitada. No perfil Lite, um tick periódico
também gasta energia ao acordar a CPU ociosa à toa.

## Decisão

- O kernel não é preemptível: uma syscall roda até terminar ou até um ponto de
  preempção explícito. Interrupções só marcam trabalho pendente.
- Toda operação de duração não limitada DEVE ser fatiada. Ao fim de cada fatia
  ela verifica se há preempção pendente; se houver, salva o progresso no próprio
  objeto e retorna, e a syscall é retomada depois. A meta do M2 é no máximo
  50 µs por fatia (T-204, revogação de 10⁵ capabilities).
- Não há tick periódico. Cada CPU programa o timer em modo deadline para o
  próximo evento: fim de fatia (5 ms padrão), recarga de orçamento de um
  SchedContext ou prazo de IPC. CPU sem trabalho dorme em `mwait`/WFI.
- Threads de usuário continuam preemptíveis a qualquer instante (seção 6.6).

## Alternativas

- **Kernel preemptível, como o Linux com `PREEMPT` ou `PREEMPT_RT`:** reduz
  latência sem fatiar à mão, mas exige proteger todo estado contra preempção a
  qualquer ponto, com contadores de preempção e locks dormentes. Isso aumenta o
  código, dificulta a prova das invariantes (TLA+, Kani) e não combina com um
  kernel pequeno cujas operações já são curtas.
- **Tick periódico (HZ fixo):** acorda a CPU centenas de vezes por segundo.
- **Não preemptível sem pontos de preempção:** a revogação de uma árvore grande
  bloquearia a CPU por milissegundos e quebraria o tempo real do áudio.

## Consequências

- A latência do kernel é limitada pela maior fatia, medida e testada no CI.
- Toda operação nova no kernel DEVE ser provadamente curta ou fatiada.
- Operações fatiadas precisam de estado de retomada e de testes de interrupção.
- Orçamentos usam o relógio monotônico (TSC ou timer ARM), não contagem de ticks.
