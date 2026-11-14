# Linha de base do IPC em KVM (T-519, passo 1)

Data: 2026-11-14. Commit medido: `26353a0` (main).
Ambiente: runner `ubuntu-24.04` do GitHub Actions, com `/dev/kvm` (KVM aninhado), workflow "Bench em KVM" (`.github/workflows/bench-kvm.yml`), execução 43606593765 (concluída com sucesso). Os testes de kernel e de SMP em KVM também passaram nesse run.

Esta rodada é a linha de base da T-519. Ela só mede; o caminho do IPC no kernel não mudou.

## Resultado

Mediana e p99 são as medidas de referência. Amostras: 10 000 por medida.

### 1 CPU

| Benchmark | Mediana | p99 | Mín. | Máx. | Média | Meta (KVM) |
|---|---|---|---|---|---|---|
| IPC `ipc_call` → `ipc_reply_recv`, ida e volta | 1,04 µs (1041 ns) | 1,08 µs | 1,02 µs | 42,12 µs | 1,06 µs | ≤ 1 µs |
| Troca de contexto entre processos (por troca) | 450 ns | 455 ns | 430 ns | 16,16 µs | 457 ns | ≤ 2 µs |
| Troca de contexto no mesmo processo (por troca) | 295 ns | 295 ns | 290 ns | 16,93 µs | 299 ns | — |

Com 1 CPU o servidor e o cliente dividem a mesma CPU, então o IPC entre CPUs não se aplica (a linha foi pulada pelo xtask).

### 4 CPUs

| Benchmark | Mediana | p99 | Mín. | Máx. | Média | Meta (KVM) |
|---|---|---|---|---|---|---|
| IPC `ipc_call` → `ipc_reply_recv`, ida e volta | 1,00 µs (1001 ns) | 1,24 µs | 981 ns | 35,02 µs | 1,03 µs | ≤ 1 µs |
| IPC entre CPUs (servidor noutra CPU), ida e volta | 1,01 µs (1011 ns) | 1,12 µs | 1,00 µs | 30,97 µs | 1,03 µs | — |
| Troca de contexto entre processos (por troca) | 425 ns | 430 ns | 420 ns | 15,45 µs | 434 ns | ≤ 2 µs |
| Troca de contexto no mesmo processo (por troca) | 290 ns | 290 ns | 285 ns | 15,20 µs | 293 ns | — |

## Leitura

- A meta de ≤ 1 µs em KVM não foi atingida na mediana, em nenhuma das duas configurações: 1041 ns com 1 CPU e 1001 ns (IPC) e 1011 ns (entre CPUs) com 4 CPUs.
- A diferença para a meta é pequena (4 % com 1 CPU, 0,1 % a 1,1 % com 4 CPUs). A troca de contexto está dentro das metas (≤ 2 µs).
- Nesta rodada a mediana com 4 CPUs ficou abaixo da de 1 CPU, o que é consistente com o observado em T-430 (1,02 a 1,04 µs). A variação entre rodadas é da ordem de algumas dezenas de nanossegundos.
- Pior caso (máx.) de 30 a 42 µs: são amostras isoladas do host/hipervisor, não a faixa de trabalho. Por isso a meta é sobre a mediana e o p99.

## Comparação com a rodada de T-430 (2026-11-09, mesmo workflow)

| Medida | T-430 (1 CPU) | 2026-11-14 (1 CPU) |
|---|---|---|
| IPC mediana | 1,02 a 1,04 µs (ressalva da T-430) | 1,04 µs |

Os valores da T-430 vêm do relatório de aceite; a comparação vale como ordem de grandeza, não como medida pareada.

## Limites desta medida

- Ambiente: runner hospedado do GitHub Actions com KVM aninhado (AMD EPYC), não hardware real. As metas do SDD valem em KVM, conforme a nota de medição do projeto.
- Esta é a linha de base antes de qualquer otimização. A ADR 0058 e a mudança do caminho rápido vêm nos passos 2 a 4 da T-519.
- Os relatórios completos do workflow saem no log do job; o artefato `bench-kvm` fica num host que o proxy da sessão bloqueia. Os números deste arquivo foram copiados das linhas `bench:` e das tabelas do log do job 132482453620.

Referências: run https://github.com/eduardodib11/optimus/actions/runs/43606593765
