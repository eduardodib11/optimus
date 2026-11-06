# Gate 1 (fim do M3)

Fonte: SDD v1.0, seção 19 (Gate 1: processos isolados em SMP e IPC ≤ 1 µs) e `docs/backlog/m3.md`, T-368. Data: 2026-11-06.

## Checklist

| # | Item | Situação | Evidência |
|---|---|---|---|
| 1 | Processos isolados em `-smp 4` e caos verdes | Cumprido | `cargo xtask test integration` (smp 1 e 4, #125) e `cargo xtask test chaos` (100/100 rodadas, pior volta 146 ms em TCG, #126) |
| 2 | `okfuzz` por 4 h em `-smp 4` sem pânico | Em execução | Rodada de 4 h com uma CPU já passou (T-214, `docs/aceite/m3-t213-t214.md`). A de `-smp 4` roda no workflow `fuzz-noturno.yml` (input `smp`, padrão 4 desde #127); o resultado entra aqui |
| 3 | IPC ≤ 1 µs em KVM, par na mesma CPU, ou decisão sobre o plano B | Decisão registrada | Ver abaixo |
| 4 | Integração verde no CI | Cumprido | Job `integration` do CI, obrigatório desde #125 |
| 5 | Backlog do M4 publicado | Cumprido | `docs/backlog/m4.md` |

## Item 3: decisão sobre o IPC

Não há runner com `/dev/kvm` (nem o GitHub Actions hospedado nem o contêiner de desenvolvimento). Em TCG, `docs/bench/2026-11-06-m3-smp4.md` mede 29,6 µs por ida e volta na mesma CPU e 29,6 µs entre CPUs. Esse número mede a emulação: o caminho rápido do §6.7 não tem trabalho proporcional a 30 µs.

Decisão: o plano B (mudar o caminho do IPC) **não** é acionado sem medida em KVM. O Gate 1 fecha com esta pendência declarada. A primeira rodada de `cargo xtask bench` em KVM vira a linha de base; se passar de 1 µs com o par fixado, abre-se uma tarefa de otimização no M4 antes do T-420. O gate de regressão de 5% (T-367) só compara rodadas em KVM.

## Recalibração do plano (§19)

- O M3 coube no bloco planejado (T-301 a T-368), com os desvios registrados nas ADRs 0029 a 0039.
- Cotas: o heap do usuário pede segmentos de 2 MiB, então cada serviço precisa de pelo menos ~1 MiB de folga além do código. O M4 deve dimensionar as cotas dos drivers pela mesma regra.
- A pendência de `Mutex::lock_timeout` (prazo no `futex_wait`, muda a ABI v1) passa para o M4.
- O HUD/Cockpit continua só no M4, via `displayd` (decisão de 2026-11-04).

## Resultado

Gate 1 aprovado com uma ressalva: item 3 depende de medida em KVM, e o item 2 em `-smp 4` está em execução no CI.
