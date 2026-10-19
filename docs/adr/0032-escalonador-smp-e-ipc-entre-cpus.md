# ADR 0032: Escalonador SMP e IPC entre CPUs

- Status: proposta (aguarda aprovação de Eduardo)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.6, 6.7, 6.9, 14.2 e 15; backlog do M3, T-305
  (lacunas 9, 10 e 11)
- Relaciona-se com: ADR 0007 (IPC), ADR 0008 (escalonador com
  `SchedContext`), ADR 0009 (kernel não preemptível), ADR 0010 (SMP),
  ADR 0027 (registradores de IPC), ADR 0030 (estado por CPU), ADR 0031
  (travas e IPIs), T-313, T-323 a T-327, T-331

## Contexto

O escalonador do M2 (`kthread.rs`) é uma estrutura global `SCHED` sob uma
trava: `current`, a fila de prontas de 256 níveis, as listas de threads sem
orçamento (`throttled`) e de prazos de IPC (`timeouts`), a thread morta
pendente e o registro dos testes. `wake` põe a thread nessa fila;
`handoff` é o caminho rápido do IPC (troca direta, sem passar pela fila);
o `SchedContext` doado em `ipc_call` fica em `Thread.donated` e o orçamento
é lido e gravado em atômicas soltas, "só pelo escalonador, com a trava da
fila".

As seções 6.6 e 6.9 pedem filas por CPU, migração periódica e no
wake-up, afinidade e NUMA, e futex indexado por (AddressSpace, endereço).
A 6.7 limita o caminho rápido a "call e reply entre threads na mesma CPU",
com meta de 1 µs. Nada disso diz:

- como uma thread que acabou de se pôr numa fila de `Endpoint` (ainda na
  CPU, antes de trocar de contexto) é acordada por outra CPU sem que duas
  CPUs usem a mesma pilha de kernel;
- onde a afinidade entra na ABI (nenhuma syscall da 14.2 a recebe) e como
  ela convive com a doação de `SchedContext`;
- em que CPU roda o servidor que recebe o `SchedContext` de um cliente de
  outra CPU;
- quando acontece a "migração periódica" num kernel sem tick.

## Decisão

### 1. Estado por CPU

A `Sched` global vira uma por CPU, dentro da `PerCpu` (ADR 0030):

- **Parte compartilhada**, sob a trava `Fila` daquela CPU (ADR 0031,
  nível 6): fila de prontas (`RunQueue` de 256 níveis), `throttled`,
  `timeouts` e `outbox` (threads a recolocar em outra CPU).
- **Parte local**, só a própria CPU mexe, com IF=0 e sem trava: `current`,
  `charging`, `charged_at`, `started_at`, `slice_end`, `dead`,
  `switch_prev` e o registro dos testes (eventos ganham o id da CPU).
- **Resumo atômico**, lido por outras CPUs sem trava para decidir onde
  acordar e de quem roubar: `cur_prio` (prioridade da atual; um valor
  especial para ocioso), `nr_ready`, `need_resched` e `idle_polling` (a CPU
  está em `mwait` vigiando `need_resched`). Valores velhos só pioram a
  escolha, nunca a correção.

A `Thread` ganha `cpu: AtomicU32` (CPU dona da thread: a da fila em que
está ou da última em que rodou) e `on_cpu: AtomicBool` (a pilha de kernel
dela está em uso por uma CPU). As transições de `RunState` de `Blocked`
para `Ready` passam a ser `compare_exchange`: só quem vence enfileira.

O `SchedContext` ganha a máscara de afinidade (item 4) e o orçamento
(`remaining`, `replenish_at`, `active`) passa para uma trava folha
(`FolhaSched`, nível 7): `refill`, `consume` e `activate` viram uma seção
crítica cada, porque duas CPUs podem cobrar o mesmo `SchedContext` na
janela da doação (item 6).

### 2. Invariantes

- **I1, execução única:** uma thread é `current` de no máximo uma CPU, e
  `on_cpu` vale exatamente enquanto ela é `current` ou `switch_prev` da
  CPU `cpu` dela.
- **I2, fila única:** uma thread está em no máximo uma fila de prontas, e
  estar na fila da CPU `c` implica `cpu == c`.
- **I3, troca segura:** a CPU `c` só troca para `t` se `t.on_cpu` é falso
  ou `t` é a própria `switch_prev` de `c`. Nenhuma CPU rouba ou recoloca
  uma thread com `on_cpu`.
- **I4, afinidade:** a CPU `c` só **começa** a rodar `t` se `c` está em
  `permitidas(t)` = máscara do `SchedContext` efetivo de `t` (o doado, se
  houver) ∩ CPUs ligadas.
- **I5, `SchedContext` exclusivo:** um `SchedContext` é o efetivo de no
  máximo uma thread em `Running`.
- **I6, nenhum despertar perdido:** toda thread que passa de `Blocked` a
  `Ready` termina numa fila de prontas ou como `current`.
- **I7, prazos locais:** o prazo de IPC de `t` está na lista `timeouts` da
  CPU `t.cpu`, e só essa CPU o vence.
- **I8, `cpu` estável:** `t.cpu` só muda com `t.on_cpu` falso.

### 3. Troca de contexto (`schedule`)

Na CPU `c`, com IF=0:

1. `ipi::poll()` (ADR 0031) e vencimento dos prazos da **própria** lista
   (`expire_timeouts`, que acorda pelo item 5 sem nunca esperar).
2. Toma a fila de `c`; cobra a atual; devolve à fila as `throttled` de `c`
   cujo período virou.
3. `Preempt`: a atual segue se tem orçamento, ninguém mais prioritário
   está pronto, a fatia não acabou **e** `c ∈ permitidas(atual)`.
4. A anterior, em `Yield` ou `Preempt`, volta à fila de `c` se `c` ainda é
   permitida; senão vai para `outbox`.
5. Escolhe a próxima: `direct` (caminho rápido) ou a primeira da fila.
   Thread da fila que `c` não pode rodar (I4: a máscara mudou enquanto
   esperava) vai para `outbox` e a busca continua. Fila vazia: roubo do
   ocioso (item 7) antes de cair no ocioso.
6. Marca `next.on_cpu`, atualiza `cur_prio` e `nr_ready`, põe a anterior em
   `switch_prev`, solta a fila.
7. Troca de espaço com a ordem da máscara `active` (ADR 0031, item 7),
   `FS_BASE` (ADR 0030), FPU, e `switch_context`.
8. Já na próxima (`finish_switch`): `switch_prev.on_cpu = false`
   (`Release`), solta a morta e recoloca cada thread de `outbox` pelo item
   5 (escolha de CPU, trava da fila de destino, IPI), sem trava de `c` na
   mão.

A saída de toda syscall e de todo tratador de interrupção que volta ao
anel 3 consulta `need_resched` da CPU e chama `preempt()` se estiver
ligado; é por aí que o IPI de reescalonar e a perda de afinidade (item 6)
fazem efeito.

### 4. Afinidade na ABI

- **A máscara é do `SchedContext`**, não da thread: o `SchedContext` já é
  "orçamento de CPU" (seção 6.1), e com a doação a máscara anda junto com o
  tempo e a prioridade. Uma thread roda nas CPUs permitidas pelo
  `SchedContext` em que roda agora (I4).
- `kabi::sched::CpuMask`: 256 bits (`[u64; 4]`, bit `i` = CPU de id
  lógico `i`, ADR 0030), `kabi::MAX_CPUS = 256`.
- **`sched_configure(sc, orçamento, período, prioridade, máscara, 0)`:**
  `r8` passa a ser o endereço de usuário de uma `CpuMask` (alinhada a 8,
  lida por `copy_from_user`) ou 0 para manter a atual; `r9` é reservado e
  deve ser 0 (senão `InvalidArgument`). Um `SchedContext` novo permite
  todas as CPUs. Máscara sem nenhuma CPU ligada dá `InvalidArgument`;
  endereço ilegível também. O `ostd` atual já passa zero em `r8` e `r9`,
  então nada quebra.
- Mudar a máscara de um `SchedContext` em uso numa CPU que saiu dela liga
  `need_resched` lá (IPI `RESCHED`); a thread sai na próxima decisão. A
  syscall volta sem esperar.
- **`sys_info(seletor)`** ganha o formato: seletor em `rdi`, valores em
  `rdx`, `r10` e `r8`; seletor desconhecido dá `NotSupported`. Primeiro
  seletor, `SYS_INFO_CPUS = 1`: CPUs ligadas, total de ids lógicos e zero.
  A ADR 0038 acrescenta os seletores de memória no mesmo formato.

### 5. Acordar uma thread (`wake`)

`wake(t, valor)` pode ser chamado com trava de objeto ou de `IpcSlot` na
mão (futex, notificação, `PeerClosed`, prazo) e **nunca espera**:

1. `compare_exchange(Blocked, Ready)` no estado; quem perde volta.
2. Destino: se `t.on_cpu`, `t.cpu` (a thread ainda está saindo da CPU
   dela; I3 impede outra de pegá-la). Senão, a escolha de CPU abaixo.
3. Se o destino muda, tira o prazo da lista de `t.cpu` (trava dela) e só
   depois toma a fila do destino; nunca as duas juntas. Grava `t.cpu`,
   enfileira (ou põe em `throttled` sem orçamento).
4. Aviso: destino = esta CPU e `t` mais prioritária que a atual, liga
   `need_resched` local (quem chama decide o ponto de preempção, como hoje).
   Destino remoto ocioso: se `idle_polling`, só grava `need_resched` (o
   `mwait` acorda sem IPI); senão manda `RESCHED`. Destino remoto rodando
   algo menos prioritário que `t`: `RESCHED`. Senão, nada.

**Escolha de CPU** (lê só os resumos atômicos), com `p` = prioridade de
`t` e `P` = `permitidas(t)`:

1. `t.cpu`, se está em `P` e está ociosa ou roda algo abaixo de `p`
   (cache quente);
2. senão, uma CPU ociosa de `P`, procurada a partir de `t.cpu`;
3. senão, a CPU de `P` com a menor `cur_prio`, se for menor que `p`
   (empurrão de tempo real: a pronta mais prioritária não espera atrás de
   uma menos prioritária noutra CPU);
4. senão, `t.cpu` se está em `P`, ou a primeira de `P`.

A busca é linear nas CPUs (até 256 leituras atômicas); uma máscara de
ociosas evita a varredura no caso comum.

### 6. IPC entre CPUs e doação

- **O servidor segue quem chama.** Em `ipc_call` que acha um receptor
  esperando, a mensagem é entregue e o `SchedContext` doado (como hoje);
  depois, **sem nenhuma trava na mão** (ADR 0031, regra 4), quem chama
  espera `receptor.on_cpu` ficar falso (o receptor pode estar saindo da
  CPU dele, logo depois de entrar na fila do `Endpoint`), atendendo IPIs
  a cada volta, e então faz `receptor.cpu = esta CPU` e `handoff`. Como a
  máscara efetiva do receptor passou a ser a de quem chama, e quem chama
  roda aqui, I4 vale. A ida e volta inteira acontece na CPU de quem chama:
  é o caminho rápido da 6.7, para qualquer par cliente e servidor, desde
  que o servidor estivesse esperando.
- A espera por `on_cpu` termina: a janela do receptor (entre entrar na
  fila do `Endpoint` e `switch_context`) só toma travas, que quem espera
  não segura, e acorda prazos locais, o que nunca espera (item 5). Nenhuma
  janela de `recv` espera outra CPU, então não há ciclo.
- **Resposta:** em `ipc_reply_recv` (ou `ipc_send` no `Reply`), se quem
  chamou tem `cpu` = esta CPU (o caso normal, pelo item acima) e está fora
  da CPU, `handoff` direto, como hoje. Senão, devolve a doação e acorda
  quem chamou pelo item 5 (IPI se preciso); o servidor segue com o
  próprio `SchedContext` ou com a próxima doação.
- **Servidor que pega um remetente da fila** (estava ocupado quando o
  cliente chamou): recebe o `SchedContext` do cliente na CPU onde está. Se
  essa CPU não está na máscara do cliente, liga `need_resched` local; ao
  sair da syscall, `preempt()` o manda para `outbox` (item 3, passo 4) e
  ele é recolocado numa CPU permitida antes de rodar código de usuário.
- **Cobrança na janela:** quem chama ainda está sendo cobrado na CPU dele
  quando o receptor pode começar a rodar com o mesmo `SchedContext` em
  outra (só no caso do servidor que pega remetente da fila). A trava folha
  do orçamento (item 1) torna as duas cobranças corretas; I5 continua
  valendo porque quem chama não está em `Running` depois de bloquear.
- `ipc_send` sem `Reply` não doa: o receptor acorda pelo item 5, nas CPUs
  do próprio `SchedContext`.
- **Notificações e futex** acordam pelo item 5 de qualquer CPU, inclusive
  do tratador de IRQ (que roda na CPU 0, ADR 0031).
- **Futex:** a tabela global vira 64 baldes (`SpinLock` da classe objeto)
  escolhidos por hash da chave. A chave continua sendo o **endereço
  físico** da palavra (como no T-209), o que faz processos que
  compartilham um `MemoryObject` usarem a mesma fila. A leitura da palavra
  segue sob a trava do balde, então a regra "nenhum despertar se perde"
  vale entre CPUs pelas mesmas razões de hoje.
- **Destruição concorrente:** `Endpoint`, `Reply` ou `Notification` que
  morre noutra CPU acorda os que esperam com `PeerClosed` pelo item 5;
  uma thread ainda na janela é acordada na própria CPU e a encontra já
  `Ready` ao trocar de contexto.
- **`thread_suspend`, destruição e leitura de estado de uma thread que
  roda noutra CPU:** marcam o pedido na thread, mandam `RESCHED` e esperam
  `on_cpu` falso sem travas (ADR 0031, regra 4), para que
  `thread_read_state` veja os registradores já salvos.

### 7. Balanceamento sem tick

- **No ocioso:** antes de dormir, a CPU procura a de maior `nr_ready` que
  tenha alguma pronta além da atual; toma as duas filas em ordem de id e
  rouba a pronta mais prioritária que possa rodar aqui e não tenha
  `on_cpu` (I3, I4). Uma tentativa por vez; sem sucesso, dorme.
- **Periódico, de carona no timer:** CPU ocupada já arma o timer no fim da
  fatia (5 ms). Na decisão vinda do timer, se passaram 10 ms desde o
  último balanço, compara o próprio `nr_ready` com o das CPUs permitidas e
  puxa uma thread se alguma tem pelo menos duas prontas a mais; a escolhida
  é a mais prioritária roubável cuja prioridade não seja menor que a da
  melhor pronta local.
- **Na hora de acordar:** a escolha de CPU (item 5) já espalha threads
  novas e faz o empurrão de tempo real.
- Sem custo de migração calculado no M3: a preferência por `t.cpu` é a
  única afinidade de cache.

### 8. Ocioso por CPU

O ocioso é o contexto de boot de cada CPU (ADR 0030). Com `MONITOR` e
`MWAIT`, vigia a linha de `need_resched` e marca `idle_polling`; sem eles
(TCG), `sti; hlt` e IPI para acordar. Antes de dormir: `ipi::poll()`, roubo
(item 7) e IF=0 para olhar a fila de novo.

### 9. NUMA

Adiado. O kernel não lê a SRAT no M3; o buddy tem uma zona e a escolha de
CPU ignora distância. A `CpuMask` e a escolha do item 5 deixam lugar para
preferir CPUs do mesmo nó depois, sem mudar a ABI.

## Alternativas

- **Afinidade na thread (como `sched_setaffinity`):** mais familiar e
  serve a threads presas a hardware, mas a ABI v1 não tem registrador livre
  em `thread_configure`, e com a doação a thread passaria a ter duas
  regras (a dela e a do tempo que recebeu). Se aparecer thread presa a uma
  CPU por hardware (escrita de MSR do `powerd`), o caminho é a função
  remota do kernel (ADR 0031), não afinidade.
- **Servidor fica na CPU dele e o IPC cruza por IPI:** cache do servidor
  sempre quente, mas toda chamada entre CPUs custa dois IPIs e duas trocas,
  o caminho rápido só vale para pares já fixados na mesma CPU, e a cobrança
  do mesmo `SchedContext` em duas CPUs vira o caso comum. É a alternativa
  se a medição do T-331 mostrar que servidores muito chamados de várias
  CPUs sofrem com a migração.
- **Fila global com trava única:** escolha ótima de prioridade, mas a
  trava vira o gargalo com mais de 4 CPUs e contraria a ADR 0010.
- **Acordar com espera por `on_cpu` em todo `wake`:** dispensaria a regra
  de enfileirar na CPU da thread, mas `wake` é chamado com travas de objeto
  na mão (futex, notificação) e esperar nelas fere a regra 4 da ADR 0031.
- **Lista de despertares por CPU, entregue por IPI (como o
  `ttwu_queue` do Linux):** evita tocar a fila remota, mas cada despertar
  remoto custa um IPI mesmo quando a CPU não precisa ser interrompida.
- **Balanceamento por tick dedicado:** contraria o kernel tickless da ADR
  0009; o timer de fim de fatia já acorda as CPUs ocupadas.
- **Futex por (AddressSpace, endereço virtual), como diz a 6.9:** não
  junta as filas de processos que compartilham memória, que é o caso dos
  anéis SPSC (6.7).

## Consequências

- ABI: `sched_configure` ganha a máscara em `r8` (`r9` reservado),
  `sys_info` ganha formato e o seletor de CPUs, `kabi` ganha `CpuMask` e
  `MAX_CPUS`. É mudança antes da primeira versão publicada da ABI v1, como
  a da ADR 0026; a tabela 14.2 e a 6.6 do SDD são atualizadas na próxima
  revisão.
- O caminho rápido continua só na mesma CPU, mas quase toda chamada a um
  servidor que espera passa a ser na mesma CPU. O Gate 1 mede o par
  cliente e servidor numa CPU (backlog, lacuna 9) e também mede a ida e
  volta com o cliente em outra CPU, para ver o custo da migração do
  servidor.
- Servidores muito usados migram entre CPUs com os clientes; o cache deles
  esfria. O T-331 e o T-367 medem.
- Uma thread em `Running` pode ficar alguns microssegundos numa CPU fora da
  máscara depois de receber uma doação ou de a máscara mudar, até o
  próximo ponto de decisão (item 3); nunca roda código de usuário assim.
- A prioridade é global só aproximadamente: a pronta mais prioritária pode
  esperar até a CPU de destino atender o IPI, limitado pela maior seção
  não preemptível (ADR 0009).

### Verificação

- TLA+ (T-313): o `Ipc.tla` ganha N CPUs, `cpu`, `on_cpu`, filas de prontas
  por CPU, `current` por CPU, a janela entre entrar na fila do `Endpoint`
  e trocar de contexto, o servidor que segue quem chama com a espera por
  `on_cpu`, o roubo do balanceador, o prazo local e a destruição do
  `Endpoint` com `PeerClosed`. Invariantes I1 a I8 junto com as atuais
  (`NoMissedRendezvous`, `CallerBlocked`, `ReplyOnce`); vivacidade
  `CallAnswered` com justiça fraca; `CHECK_DEADLOCK TRUE`. TLC com 2 e 3
  CPUs. Mutações que devem ser acusadas: roubar thread com `on_cpu` (I1),
  `wake` sem `compare_exchange` (I2), migrar o servidor sem esperar
  `on_cpu` (I3), prazo vencido por outra CPU (I7), e esperar `on_cpu` com a
  trava do objeto na mão (deadlock). O `CapRevoke.tla` ganha a revogação
  numa CPU com a cópia em uso por IPC noutra.
- Kernel (T-323): suíte de escalonador e IPC verde em `-smp 1` com o
  estado por CPU; sem regressão acima de 5% no benchmark.
- Kernel (T-324, T-325): dois processos em CPUs distintas alternando
  10⁶ vezes; thread bloqueada acorda na CPU certa; threads presas à
  máscara; carga desigual em 4 CPUs converge com desvio ≤ 20%;
  `sched_configure` com máscara vazia ou endereço ruim recusado.
- Kernel (T-327): ping-pong de 10⁶ idas e voltas com cliente e servidor
  começando em CPUs diferentes; mutex de usuário com 4 threads em 4 CPUs
  sem perda de despertar; `PeerClosed` correto na destruição concorrente.
- `okfuzz` com `--smp` (T-330) e o estresse do T-329 com a verificação de
  ordem de travas ligada.

### Lacunas do SDD

- A 6.6 fala em afinidade e NUMA, mas nenhuma syscall da 14.2 os recebe e
  `sys_info` não tem formato. **Decidido por Eduardo em 2026-10-19:** a
  afinidade fica no `SchedContext` (item 4), não na thread; a máscara anda
  com a doação e uma thread roda nas CPUs que o `SchedContext` efetivo
  permite (I4). Uma thread presa a hardware usa a função remota do kernel
  (ADR 0031), não máscara de thread.
- A 6.7 diz "mesma CPU" sem dizer o que acontece entre CPUs nem em que CPU
  roda o servidor que recebe a doação. **Eduardo precisa decidir** se o
  servidor segue quem chama (esta ADR) ou fica na CPU dele.
- A 6.9 indexa o futex por (AddressSpace, endereço); o código e esta ADR
  usam o endereço físico. Um frame liberado e reaproveitado pode dar
  despertar espúrio a quem ainda esperava na chave antiga, o que a
  semântica de futex já permite.
- A 6.6 não diz quando acontece a "migração periódica" sem tick; aqui é
  de carona no timer de fim de fatia, a cada 10 ms.
- A 6.6 pede NUMA; esta ADR o adia (backlog, lacuna 11). **Eduardo
  precisa confirmar** o adiamento.
- O Gate 1 (seção 19) não diz se o 1 µs vale com o par na mesma CPU; o
  backlog propõe que sim, e esta ADR faz disso o caso comum.
