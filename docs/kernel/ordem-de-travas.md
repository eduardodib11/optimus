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
| 6 | `RunQueue` | escalonador de cada CPU (`kthread::BSP_SCHED` e `kthread::SCHEDS`, chave = id da CPU, T-323) | duas só em ordem crescente de id; o despertar entre CPUs (T-324) toma a da CPU antiga e depois a do destino, nunca as duas juntas |
| 7 | `SchedLeaf` | `thread::Thread.sched` (o `SchedContext` dela e o doado) | folha do escalonador |
| 8 | `KernelStacks`, depois `KernelPageTables` | `kvm::STACK_SLOTS`, depois `kmem::KERNEL_PT` | nessa ordem |
| 9 | `Heap`, depois `Frames` | `kheap::HEAP`, depois `kmem::FRAMES` | nessa ordem |
| 10 | `Diagnostic` | `kthread::DEBUG_LOG`, `kfault::LAST`, `platform::PLATFORM`, `ksmp::tsc::LAST` (teste de salto do TSC na partida), `ksmp::start::AP_JOB` (trabalho de teste dos APs ociosos) | folha |

Notas:

- O registro de eventos do escalonador (`trace`) mora dentro da `Sched` de cada CPU e
  não tem trava própria.
- `platform::PLATFORM` não está na tabela da ADR: é o ponteiro para a
  plataforma, gravado uma vez no boot e só copiado depois, sem tomar outra
  trava com ele na mão. Fica como folha do nível 10.
- O logger da serial (`klog`) usa uma trava própria de teste-e-troca, fora
  de `SpinLock`: é a última folha (qualquer código pode registrar com
  travas na mão) e nada se toma com ela.
- Os caches por CPU de frames e de objetos do heap (T-328,
  `docs/kernel/caches-por-cpu.md`) não têm trava (ADR 0031, item 3): só a
  própria CPU os usa, com IF=0, por `percpu::with_frame_cache` e
  `percpu::with_object_cache`, que acusam pânico na reentrada. Com o cache
  de objetos emprestado, a CPU pode tomar `Heap` (para trazer ou devolver
  um lote) e, por ele, `Frames` e o cache de frames; com o de frames, só
  `Frames`.
- Liberar memória (soltar um `Arc`) toma `Heap` e talvez `Frames`; por
  isso o alocador vem depois de tudo que pode soltar objetos com trava na
  mão. Soltar a última referência de um objeto com trava de nível 3 ou
  maior na mão pode violar a ordem: o `Drop` de `Endpoint` e de `Reply`
  toma a trava do objeto e acorda threads (fila), e o de `Thread` solta a
  pilha (`KernelStacks`) e, em cascata, o `CapSpace` e os objetos dele.
  Por isso o escalonador solta a thread que saiu da CPU (`switch_prev`,
  talvez a última referência de uma que terminou) só depois de largar a
  fila, em `finish_switch`.
- O caminho rápido de IPC (T-331, `ipc::fast`) lê as capabilities
  emprestadas, com a trava do `CapSpace` (2) na mão, e por baixo dela toma
  uma trava de objeto (3) de cada vez e o `IpcSlot` (4) da outra thread.
  Nenhuma referência é solta com a trava do `CapSpace` na mão: quando é
  preciso entregar de um remetente que chegou de outra CPU, ele clona o
  `Reply` e larga o `CapSpace` antes, como o caminho comum.
- O TLB shootdown (T-326, `ksmp::tlb::flush`) não toma trava, mas espera
  as outras CPUs confirmarem com a trava de quem chamou na mão: a do
  `AddressSpace` em `unmap`/`protect`/`map` (o frame só volta ao buddy
  depois). Não trava porque o alvo atende o pedido no IPI (anel 3 ou
  ocioso) ou em `ipi::poll`, que toda espera do kernel chama, inclusive o
  giro de `SpinLock::lock`: uma CPU parada esperando aquela mesma trava
  atende o shootdown enquanto gira. O atendimento só invalida a TLB e
  confirma; não toma trava, não espera e não manda IPI. `kmem::unmap` e
  `kmem::unmap_pages` largam `KernelPageTables` antes do shootdown e só
  depois liberam os frames.

- Eventos de ciclo de vida (T-348, ADR 0035, item 3.4 e lacuna 6): o
  estado do processo mora no `CapSpace` (nível 2) e o evento de morte da
  thread, com o pedido de encerramento, em `Thread.binding` (nível 3). Na
  morte, a thread toma `Thread.binding` (copia a ligação e a solta), depois
  o `CapSpace` (desconta e copia a ligação do processo, e solta), e só
  então sinaliza: notificação (3) e, por último, a fila do escalonador (6)
  do despertar. As esperas de notificação e de futex se publicam no
  `IpcSlot` (4) da thread com a trava do objeto (3) na mão; quem encerra
  lê o slot, solta-o e só então toma a trava do objeto para tirar a thread
  da fila.

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
