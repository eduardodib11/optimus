# Medição em KVM pendente (T-302, 2026-10-17)

## Estado

- **Não medido.** Nenhuma linha de base em KVM existe ainda. Os números em `docs/bench/2026-10-11-*.md` vêm do TCG e não valem para as metas do SDD (≤ 1 µs no IPC e ≤ 2 µs na troca entre processos).
- Host de desenvolvimento deste trabalho: `/dev/kvm` ausente e `/proc/cpuinfo` sem `vmx` nem `svm`, então a virtualização por hardware não está disponível aqui.
- Resultado: a parte do T-302 que depende de KVM fica pendente. Esta página registra o bloqueio e o procedimento.

## O que falta para fechar T-302

Um host ou runner com:

1. `/dev/kvm` acessível pelo usuário que roda o `cargo xtask`. Em Linux, o usuário precisa estar no grupo `kvm`.
2. QEMU capaz de KVM. Com `/dev/kvm` acessível, o `xtask` escolhe KVM sozinho e grava `Acelerador: KVM` no relatório. Não há flag para isso.
3. Um comando de medição, que gera o relatório neste diretório:

```
cargo xtask bench
```

Sem `/dev/kvm`, o mesmo comando roda com TCG e o relatório avisa que os números não valem para as metas.

## Campos que o relatório deve trazer

Os mesmos do relatório TCG de 2026-10-11, com o acelerador trocado:

- Acelerador: KVM (com versão do kernel do host e do QEMU)
- Commit medido e linha de base TCG para comparação
- IPC de ida e volta (`ipc_call` → `ipc_reply_recv`): mediana, p99 e máximo
- Troca de contexto entre processos e no mesmo processo
- Nota sobre a distância até as metas: ≤ 1 µs no IPC, ≤ 2 µs na troca entre processos

## Por que importa

O Gate 1 do M3 exige IPC ≤ 1 µs em KVM com o par fixado na mesma CPU (T-368, item 3). Sem essa medição, não dá para dizer se o caminho rápido já cumpre a meta ou se falta o plano B. Os números de TCG da linha de base mostram IPC de cerca de 42 µs na mediana, mas isso mede a emulação, não o kernel.
