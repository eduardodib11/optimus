# Ordem de travas do kernel

Tabela final do T-315, a partir da ADR 0031 (item 3). Toda `SpinLock` do
kernel tem uma `LockClass` (`kernel/okernel/src/sync.rs`); em debug, `lock`
confere a ordem contra todas as travas que a CPU já tem na mão e acusa
pânico na violação. Mudar um nível daqui em diante exige emenda à ADR 0031.

Só se toma uma trava de classe **posterior** às que estão na mão. Duas da
mesma classe, só na `Fila`, em ordem crescente de id de CPU (chave da
trava).

| Nível | Classe (`LockClass`) | Travas no código | Regra |
|---|---|---|---|
| 1 | `Cdt` | `cap::xcdt::CDT` | global (ADR 0028) |
| 2 | `CapSpace` | `SharedCapSpace` (`cap::object`, `obj_create`) | uma por vez |
| 3 | `Object` | `ipc::Endpoint.queues`, `ipc::Reply.caller`, `ipc::Reply.donation`, `notify::Notification.state`, `notify::Interrupt.line`, `futex::FutexTable.inner`, `thread::Thread.binding`, `kirq::LINES`, `kcap::ROOT` | uma por vez |
| 4 | `IpcSlot` | `thread::Thread.ipc` | depois do objeto |
| 5 | `AddressSpace` | `SharedAddressSpace` (`cap::object`, `obj_create`) | uma por vez |
| 6 | `RunQueue` | `kthread::SCHED` (chave 0 até o T-323, que a divide por CPU) | duas só em ordem crescente de id |
| 7 | `SchedLeaf` | `thread::Thread.sched`, `thread::Thread.donated` | folha do escalonador |
| 8 | `KernelStacks`, depois `KernelPageTables` | `kvm::STACK_SLOTS`, depois `kmem::KERNEL_PT` | nessa ordem |
| 9 | `Heap`, depois `Frames` | `kheap::HEAP`, depois `kmem::FRAMES` | nessa ordem |
| 10 | `Diagnostic` | `kthread::DEBUG_LOG`, `kfault::LAST`, `platform::PLATFORM`, `ksmp::tsc::LAST` (teste de salto do TSC na partida), `ksmp::start::AP_JOB` (trabalho de teste dos APs ociosos) | folha |

Notas:

- O registro de eventos do escalonador (`trace`) mora dentro de `SCHED` e
  não tem trava própria.
- `platform::PLATFORM` não está na tabela da ADR: é o ponteiro para a
  plataforma, gravado uma vez no boot e só copiado depois, sem tomar outra
  trava com ele na mão. Fica como folha do nível 10.
- O logger da serial (`klog`) usa uma trava própria de teste-e-troca, fora
  de `SpinLock`: é a última folha (qualquer código pode registrar com
  travas na mão) e nada se toma com ela.
- O cache de frames por CPU (T-328) não terá trava (ADR 0031, item 3).
- Liberar memória (soltar um `Arc`) toma `Heap` e talvez `Frames`; por
  isso o alocador vem depois de tudo que pode soltar objetos com trava na
  mão. Soltar a última referência de um objeto com trava de nível 3 ou
  maior na mão pode violar a ordem: o `Drop` de `Endpoint` e de `Reply`
  toma a trava do objeto e acorda threads (fila), e o de `Thread` solta a
  pilha (`KernelStacks`) e, em cascata, o `CapSpace` e os objetos dele.
  Por isso o escalonador solta a thread morta (`dead`) só depois de largar
  a fila.

## Pontos sem nenhuma trava

Em debug, `ksync::assert_none_held` acusa pânico se a CPU tem qualquer
trava na mão em:

- `switch_context` (`kthread::schedule_to`);
- volta ao usuário (`syscall_handler`, faltas de usuário em `idt.rs`);
- fim do tratamento de uma interrupção;
- entrada no ocioso (`cpu::wait_for_interrupt`).

## Verificação

- Host: `cargo test -p okernel --lib sync`.
- Kernel: os testes `sync.*` provocam violações e conferem que são
  acusadas; a suíte inteira (`cargo xtask test all`) roda com a
  verificação ligada, já que o kernel de teste é de debug.
- Custo: em debug, a verificação deixa o caminho de IPC cerca de três
  vezes mais lento no TCG (o ping-pong do `ktest` passou de ~0,36 ms para
  ~1,2 ms por ida e volta); em release ela não existe.
