# ADR 0031: Travas, interrupções e TLB shootdown em SMP

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.4, 6.5, 6.8 e 6.9; backlog do M3, T-304
  (lacuna 10)
- Relaciona-se com: ADR 0009 (kernel não preemptível), ADR 0010 (SMP),
  ADR 0028 (trava `CDT`), ADR 0030 (estado por CPU), ADR 0032 (escalonador
  SMP), ADR 0035 (fila de timers), T-313, T-314, T-315, T-322, T-326

## Contexto

A seção 6.9 pede "locks por objeto (ticket spinlock) com ordem fixa" e
"TLB shootdown por IPI, agrupado e limitado às CPUs que usaram o
AddressSpace". A ADR 0028 pôs a trava global `CDT` na frente da ordem:
`CDT → CapSpace → objeto → AddressSpace → fila`. Com um núcleo só, nada
disso foi posto à prova:

- `sync.rs` é um spinlock de teste-e-troca, sem justiça, sem classe e sem
  verificação de ordem;
- o kernel roda sempre com IF=0 (ADR 0009, `FMASK` do `syscall.rs`);
  interrupções só chegam no anel 3 ou no ocioso, então nenhum tratador
  encontra trava tomada na própria CPU;
- `kvm.rs` só invalida a TLB se o espaço alterado for o do `CR3` atual
  (sem PCID, trocar `CR3` limpa a TLB), e `kmem::unmap` faz `invlpg` só
  local;
- o pânico manda NMI "a todas as outras" e a outra CPU para ao ver
  `FROZEN`, mas um segundo pânico simultâneo encerra a máquina como
  "pânico durante o pânico".

Com várias CPUs, IF=0 no kernel cria o risco que a lacuna 10 do backlog
aponta: a CPU A espera o ack de um shootdown da CPU B, e B, também com
IF=0, gira numa trava que A segura; o IPI nunca é atendido e as duas param
para sempre.

## Decisão

### 1. Ticket spinlock

- `SpinLock<T>` passa a ser um ticket lock com dois contadores `AtomicU32`,
  `next` e `serving`, e uma classe fixa (`SpinLock::with_class(classe,
  valor)`; `with_key(classe, chave, valor)` acrescenta a chave de desempate
  das filas por CPU). `SpinLock::new(valor)` só existe nos testes de host,
  com a classe `Unchecked`, fora da verificação.
  - `lock`: `t = next.fetch_add(1, Relaxed)`; gira até
    `serving.load(Acquire) == t`, com `spin_loop()` e **atendendo a caixa
    de IPIs a cada volta** (item 5).
  - `unlock` (no `Drop` da guarda): `serving.store(t + 1, Release)`, sem
    RMW, porque só a dona escreve `serving`. Contadores com aritmética
    circular de 32 bits.
  - `try_lock`: lê `s = serving`; `next.compare_exchange(s, s + 1)`. Se der
    certo, `serving` ainda vale `s` (só a dona o muda, e não há dona),
    então a trava é dela. O pânico só usa `try_lock`.
- Justiça FIFO: quem pega senha primeiro entra primeiro, o que limita a
  espera a (CPUs − 1) seções críticas.
- Não há trava dormente nem trava de leitura e escrita no M3. `RwLock` e
  RCU só entram onde a medição (T-328, T-329) mostrar disputa.

### 2. Travas e interrupções

- **Toda trava é tomada com IF=0.** Como o kernel inteiro roda assim, não
  existe variante "irqsave" (nenhuma trava é "IRQ-safe" por outro meio): em debug, `lock` confere IF=0 e entra em
  pânico se não for. O código que roda com IF=1 (o laço ocioso entre `sti;
  hlt`, o retorno ao usuário) não toma travas; o ocioso desliga as
  interrupções antes de olhar a fila.
- Tratadores de IRQ e de IPI só rodam quando a CPU estava no anel 3 ou no
  ocioso, portanto **sem nenhuma trava na mão**; podem tomar travas das
  classes objeto (notificação, `Interrupt`) e fila (acordar thread).
- NMI e `#MC` nunca tomam travas: usam a pilha IST, acham a `PerCpu` pelo
  topo dela (ADR 0030) e só leem e escrevem atômicas.
- IRQs de dispositivo vão todas para a CPU 0 no M3 (destino do MSI e do
  IOAPIC); `irq_ack` funciona de qualquer CPU. Ainda não há código de
  IOAPIC ou MSI no kernel, então esta regra é uma intenção que a primeira
  IRQ de dispositivo vai cumprir. Distribuir IRQs fica para quando houver
  driver que precise.

### 3. Ordem global de travas

Cada trava pertence a uma classe com nível. Só se toma uma trava de nível
**maior** que a última tomada; duas da mesma classe só onde a tabela diz.

| Nível | Classe | Travas | Regra |
|---|---|---|---|
| 1 | `Cdt` | `xcdt::CDT` | global (ADR 0028) |
| 2 | `CapSpace` | `SharedCapSpace` | uma por vez (ADR 0028) |
| 3 | `Objeto` | filas de `Endpoint`, `Reply.caller` e `Reply.donation`, `Notification`, `Interrupt.line`, baldes de futex (ADR 0032), `Thread.binding`, `kirq::LINES`, `kcap::ROOT` | uma por vez |
| 4 | `IpcSlot` | `Thread.ipc` | depois do objeto |
| 5 | `AddressSpace` | `SharedAddressSpace` | uma por vez |
| 6 | `Fila`, depois `FilaTimers` | fila de prontas de cada CPU (ADR 0032), depois a fila de `Timer`s de cada CPU (ADR 0035, T-349) | duas `Fila` só em ordem crescente de id lógico de CPU; `FilaTimers` é folha |
| 7 | `FolhaSched` | `Thread.sched` (o `SchedContext` dela e o doado, `Thread.donated`) | folha |
| 8 | `TabelasKernel` | `kvm::STACK_SLOTS`, depois `kmem::KERNEL_PT` | nessa ordem |
| 9 | `Alocador` | `kheap::HEAP`, depois `kmem::FRAMES` | nessa ordem |
| 10 | `Diagnóstico` | `kthread::DEBUG_LOG`, `kfault::LAST`, `platform::PLATFORM`, `ksmp::tsc::LAST`, `ksmp::start::AP_JOB` | folha |

A tabela completa e atual está em `docs/kernel/ordem-de-travas.md`. O
registro de eventos do escalonador mora dentro da `Sched` de cada CPU e não
tem trava própria. O orçamento do `SchedContext` (`remaining`, `replenish_at`
e `active`) também não tem: são atômicas soltas (ver a limitação na ADR 0032,
item 1).

**Fila de timers por CPU (emenda de 2026-10-20, ADR 0035).** A classe
`FilaTimers` entra logo depois de `Fila`, como folha: nada se toma com ela
na mão. O tratador do timer remove os `Timer`s vencidos sob essa trava,
**solta a trava** e só então sinaliza a `Notification` de cada um (classe
objeto, nível menor, que não poderia ser tomada com a fila de timers na
mão). Rearmar de outra CPU toma a trava da CPU dona, sempre com IF=0.

- É a ordem da seção 6.9 com a `CDT` da ADR 0028 na frente, a fila de cada
  CPU no lugar da "fila do escalonador" e os níveis que o código já tem
  depois dela (o escalonador reserva memória com a fila na mão, então o
  alocador vem depois; tabelas do kernel alocam frames).
- Os caches de frames e de objetos por CPU (T-328) não têm trava: só a própria CPU o
  usa, com IF=0 e sem trocar de contexto no meio.
- O `MemoryObject` não tem trava hoje. Quando ganhar uma (commit sob
  demanda, ADR 0038), ela é da classe objeto e vem **antes** do
  `AddressSpace`: a falta de página resolve o objeto e só depois mapeia.
- O T-315 classifica toda trava que existir quando ele rodar e publica a
  tabela final em `docs/`; mudança de nível depois disso exige emenda a
  esta ADR.

### 4. Verificação da ordem em debug

- A `PerCpu` (ADR 0030) tem uma pilha de até 16 classes tomadas. `lock`
  confere a regra do item 3 contra o topo; para a classe `Fila`, confere
  também que o id de CPU da nova fila é maior que o da anterior. Violação é
  pânico com as duas classes e os locais (`#[track_caller]`).
- Em debug também: nenhuma trava na mão ao trocar de contexto
  (`switch_context`), ao voltar ao usuário, ao entrar no ocioso e ao
  esperar por outra CPU (itens 6 e 7); e um contador de voltas que acusa
  pânico ("provável deadlock na classe X") depois de 10⁸ voltas numa
  mesma trava.
- Em release a pilha não existe e a trava custa só os dois contadores.

### 5. IPIs

- Vetores reservados ao kernel: `0xF0` reescalonar, `0xF1` função remota,
  `0xF2` TLB; `0x20` continua sendo o timer e `0xFF` o espúrio.
  `kirq::create` passa a recusar `0xF0..=0xFE`.
- Envio por `apic::send_ipi(apic_id, vetor)` (x2APIC: um `wrmsr` no ICR;
  xAPIC: espera o bit de entrega pendente, escreve `ICR_HIGH` e
  `ICR_LOW`), sempre com IF=0.
- Cada `PerCpu` tem uma caixa de pedidos:
  - `pending: AtomicU32` com os bits `RESCHED`, `CALL` e `TLB` (resumo
    lido numa só carga);
  - `tlb_inbox: [AtomicU64; 4]`: bit `i` ligado quer dizer "a CPU `i` tem
    um pedido de shootdown para mim";
  - `tlb_req`: o pedido de shootdown que **esta** CPU fez (item 7); como
    quem pede espera o fim, há no máximo um por CPU;
  - `call_req`: função remota pedida a esta CPU (`fn(u64)`, argumento e
    flag de feito).
- **Atendimento** (`ksmp::ipi::poll()`): se `pending` for zero, volta (uma
  carga). Senão `Mailbox::poll` zera `pending`, roda a função remota e
  liga `need_resched` (ADR 0032) para `RESCHED`, e `poll` trata TLB
  (`ksmp::tlb::serve`, item 7). O atendimento não toma
  trava, não espera e não manda IPI.
- `ipi::poll()` roda no tratador dos vetores `0xF0`–`0xF2`, **em toda volta
  de espera ativa** (trava, ack, `on_cpu` da ADR 0032), em todo ponto de
  preempção das operações fatiadas (ADR 0009) e antes de entrar no ocioso.
  O IPI que chega depois de a caixa ter sido atendida por sondagem acha a
  caixa vazia e só faz o EOI.
- A função remota (`ksmp::ipi::call_on(cpu, f, arg)`) é síncrona e
  restrita: `f` não toma trava, não espera e não manda IPI (MSRs, testes de
  IPI do T-322 e, no futuro, o `powerd`). O destino tem 100 ms para
  atender, senão pânico.

### 6. Regras contra deadlock

1. Travas só com IF=0; NMI e `#MC` sem travas (item 2).
2. Ordem do item 3, conferida em debug.
3. Toda espera ativa atende a caixa de IPIs a cada volta (item 5). Com
   isso, quem espera ack de shootdown **pode** segurar travas: a CPU que
   gira na trava atende o pedido e manda o ack.
4. Esperar pelo estado de outra CPU que não seja ack de shootdown (o
   `on_cpu` da ADR 0032) só sem nenhuma trava na mão, porque a outra CPU
   pode precisar de qualquer trava para terminar a troca de contexto.
5. Nenhuma trava atravessa `switch_context`, o retorno ao usuário ou o
   ocioso.
6. Funções remotas e o atendimento da caixa não tomam travas.

### 7. TLB shootdown

Estado:

- `LOADED[c]`: a raiz (`CR3`) que a CPU `c` carregou por último, uma palavra
  atômica por CPU (a "máscara `active`" é espalhada: a CPU `c` pertence a
  `X` quando `LOADED[c]` é a raiz de `X`). Sem PCID, trocar de `CR3`
  descarta as traduções do espaço anterior, então só as CPUs com a raiz de
  `X` carregada **agora** podem ter traduções velhas.
- Troca de espaço na CPU `c` (`kvm::load_root`): `note_root(nova)` grava
  `LOADED[c]` com `swap(SeqCst)`, que no x86 é barreira completa,
  **depois** `mov cr3`. Não há `clear`: uma CPU que ficou ociosa com a raiz
  velha continua alvo, o que é conservador e correto.

Protocolo (CPU `I` muda o espaço `X`, que ela tranca):

1. Com a trava de `X`: muda as PTEs e junta as páginas num lote de até 32;
   além disso o lote vira "esvaziar tudo". Frames que saem do mapeamento
   vão para uma lista local e **não** são liberados ainda.
2. Invalida localmente se `X` está no `CR3` de `I` (`invlpg` por página ou
   recarga do `CR3`).
3. `fence(SeqCst)`; alvos = as CPUs ligadas, menos `I`, com `LOADED[c]`
   igual à raiz de `X` (para o kernel, todas). Sem alvos, vai ao passo 6.
4. Preenche `I.tlb_req` (raiz de `X`, páginas ou "tudo", `acks` = número de
   alvos); para cada alvo `t`, liga o bit `I` em `t.tlb_inbox`, liga `TLB`
   em `t.pending` e manda o vetor `0xF2`.
5. Gira até `acks == 0`, atendendo a própria caixa a cada volta. Passados
   100 ms sem todos os acks (1 s sob TCG, onde uma vCPU pode ficar sem
   rodar no host por mais tempo), pânico, com o diagnóstico de cada alvo
   que não respondeu.
6. Solta a trava de `X`, libera os frames do lote e só então volta ao
   usuário.

Atendimento na CPU `t`: para cada bit `i` de `tlb_inbox` (trocado por zero
de uma vez), lê o pedido de `i`; se a raiz é a do seu `CR3` atual, ou o
pedido é do kernel, invalida as páginas (ou tudo); depois decrementa
`acks` de `i` com `Release`. Se `t` já trocou de espaço, não há o que
invalidar e só confirma.

- Por que basta: se `t` carregou `X` antes da mudança, a raiz dela está
  em `LOADED` quando o passo 3 a lê e ela recebe o pedido; se carregou depois, o
  passeio de páginas já vê as PTEs novas. O par barreira-RMW da troca e
  `fence` do passo 3 impede que as duas coisas falhem juntas.
- **Agrupado:** um `vm_unmap` ou `vm_protect` faz **uma rodada por
  chamada**, não uma por página, com `Flush::All` acima de 32 páginas;
  rodadas de CPUs diferentes andam em paralelo, cada uma no seu
  `tlb_req`. As operações não são fatiadas (ver a lacuna sobre o teto de
  50 µs, abaixo).
- **Quando faz:** `vm_unmap` e `vm_protect` fazem sempre a rodada, mesmo
  quando `vm_protect` só amplia, porque uma tradução velha mais restrita
  daria falta espúria. Só `vm_map` em página vazia não faz. O tratador de
  faltas não precisa conferir a PTE atual por causa disso.
- **Metade do kernel:** `kmem::unmap` e `kmem::protect` usam o mesmo
  protocolo com alvos = todas as CPUs ligadas menos a atual. É raro (pilhas
  de threads mortas, MMIO no boot). Cada pilha de kernel devolvida faz um
  shootdown, para a pilha toda (até 32 páginas), e só depois seus frames
  voltam ao buddy.
- **PCID fica desligado no M3.** Com PCID, a máscara deixaria de ser "quem
  tem o `CR3` agora" e passaria a ser "quem pode ter traduções com esta
  etiqueta", com geração por espaço (`tlb_gen`) e cache de etiquetas por
  CPU. Esse desenho fica descrito aqui e só entra se o T-331 mostrar que a
  troca entre processos não chega a 2 µs sem ele, com emenda a esta ADR.
- **Páginas globais no kernel (emenda de 2026-10-19, T-331).**
  - **O que muda:** toda folha da metade alta leva o bit G e o BSP liga o CR4.PGE no `kmem::init`; os APs herdam o CR4 do BSP.
    - `PageTables::globalize_kernel_half` marca as folhas deixadas pelo optboot.
    - `kmem::map` e `kmem::protect` marcam as novas.
    - A metade baixa nunca é global.
  - **Por quê:** a metade alta é a mesma em todo espaço, então as traduções do kernel podem sobreviver à troca de `CR3`. Sem isso, cada troca de processo jogava fora também as traduções do kernel.
  - **O que o protocolo já cobria:** uma tradução global só sai com `invlpg` ou desligando o PGE.
    - O shootdown do kernel já usa `invlpg` por página e `flush_tlb_all` (PGE desligado e religado) para "tudo".
    - Os alvos do kernel já são todas as CPUs ligadas, e não as raízes em `LOADED`, então a premissa "trocar `CR3` limpa a TLB" nunca valeu para ele.
    - Nenhum modelo TLA+ muda (não há `Shootdown.tla`).
  - **Testes:**
    - `mm.folhas_do_kernel_globais`;
    - `smp.shootdown_do_kernel_sem_traducao_velha`, que agora exercita traduções que atravessam a troca de `CR3`.
  - **PCID continua desligado.**

### 8. Pânico em SMP

- `PANIC_CPU: AtomicU32` (sem dono = `u32::MAX`) substitui `PANICKING`.
  A primeira CPU que o troca é a dona do pânico. A mesma CPU entrando de
  novo é "pânico durante o pânico" (saída de emergência, como hoje); outra
  CPU desliga as interrupções e estaciona em `hlt` para sempre, sem
  imprimir.
- A dona chama `freeze_others` (NMI a todas as outras, como hoje). Cada
  CPU congelada, no tratador de NMI, grava em `PerCpu::panic_dump` o `rip`,
  o `rsp`, o `RFLAGS`, o `CR3` e a thread atual do quadro interrompido,
  incrementa `FROZEN_COUNT` e fica em `hlt` sem `iret` (o NMI seguinte fica
  bloqueado).
- A dona espera até 10 ms por `FROZEN_COUNT == CPUs ligadas − 1`, imprime
  pela serial o quadro de cada CPU (e quais não responderam), desenha a
  tela e reinicia, como hoje. Nada no caminho do pânico toma trava, então
  uma CPU congelada com trava na mão não o impede.
- `#MC` que chega a várias CPUs ao mesmo tempo cai na mesma regra: uma é
  dona, as outras estacionam.

### 9. A trava `CDT` no M3

A `CDT` continua global no M3. `cap_mint`, `cap_delete`, `cap_revoke` e a
transferência são raras perto de IPC e uso de capabilities (que só tomam o
`CapSpace`), e a revogação já é fatiada, então a `CDT` fica na mão no
máximo uma fatia (≤ 50 µs). O T-329 mede a disputa; travas por subárvore,
que a ADR 0028 deixou abertas, só com medição e ADR própria.

## Alternativas

- **Manter o teste-e-troca:** mais simples, mas sem justiça; com muitas
  CPUs uma pode esperar sem limite, o que fura a latência da ADR 0009.
- **MCS ou qspinlock:** escalam melhor com muitas CPUs disputando a mesma
  trava (cada uma gira na própria linha de cache), mas precisam de nó por
  CPU e por nível de aninhamento. O ticket lock basta para 2 a 8 CPUs do
  M3; a interface (`SpinLock<T>` com classe) permite trocar depois.
- **Kernel com IF=1 e travas "irqsave":** IPIs seriam atendidos durante a
  espera sem sondagem, mas todo tratador teria de levar em conta código do
  kernel interrompido no meio, contra a ADR 0009.
- **Shootdown sem esperar acks (épocas, liberação adiada):** quem pede não
  espera; os frames só voltam ao buddy depois que toda CPU passou por um
  ponto quiescente. Menos espera, mas `vm_unmap` deixa de garantir que a
  página sumiu ao voltar, o que o `memd` (T-363) precisa.
- **Shootdown por NMI:** chega mesmo com IF=0, mas o tratador de NMI
  passaria a mexer na TLB e em estruturas compartilhadas, e NMIs não se
  aninham.
- **PCID já no M3:** economiza o refazer da TLB a cada troca de processo,
  mas torna a máscara preguiçosa e o protocolo mais difícil de provar;
  entra só com medição (item 7).
- **Travas por subárvore da `CDT` agora:** mais paralelismo em revogações
  independentes, mas exige ordem entre subárvores e muda o modelo
  `CapRevoke.tla` sem número que justifique.

## Consequências

- Nenhuma mudança de ABI de usuário. `vm_unmap` e `vm_protect` passam a
  custar uma rodada de IPI quando o espaço roda em outra CPU.
- A latência de um shootdown é limitada pela maior seção não preemptível
  do kernel (≤ 50 µs, ADR 0009) mais o tempo de entrega do IPI: uma CPU no
  kernel só atende quando gira, chega a um ponto de preempção ou volta ao
  usuário.
- Toda trava nova precisa de classe; o revisor confere a classe e a
  tabela do item 3.
- O caminho de pânico fica testável com várias CPUs.

### Verificação

- Host (T-314): exclusão mútua e justiça FIFO com threads em 10⁶
  operações; `try_lock` sob disputa; teste de que a guarda devolve a senha
  certa com contadores perto do limite de 32 bits.
- Kernel (T-314, T-315): teste que provoca violação de ordem (`Fila` antes
  de `Objeto`, duas filas fora de ordem) e espera o pânico de debug; a
  suíte inteira com a verificação ligada.
- Kernel (T-322, T-326): IPI de ida e volta entre todos os pares de CPUs;
  pânico provocado numa CPU qualquer congela as outras e deixa o dump de
  todas; uma thread em outra CPU lê uma página, a primeira faz `vm_unmap` e
  a segunda recebe falta, 10⁵ vezes sem leitura velha; shootdown com a
  outra CPU girando numa trava que quem pede segura (o caso da lacuna 10).
- TLA+ (T-313): o protocolo de invalidação por CPU com acks (fila `pend`,
  `Ack`, liberar só depois dos acks) está modelado em `CapRevoke.tla` para
  os caches de handles, e as filas e o IPI de reescalonar em `Ipc.tla`
  (`docs/spec/tla/README.md`). Não existe um módulo `Shootdown.tla` para a
  TLB: a propriedade "nenhuma CPU traduz para um frame já liberado" é
  coberta pelos testes de kernel (T-326, abaixo) e fica como tarefa de
  acompanhamento modelar a TLB (`LOADED`, `note_root` antes do `CR3`,
  liberação depois dos acks).
- Estresse (T-329): 30 min em `-smp 4` com a verificação de ordem ligada.

### Lacunas do SDD

- A 6.9 fixa uma ordem que não tem a `CDT` (ADR 0028) nem diz o que
  fazer com duas filas, com o alocador e com as tabelas do kernel; a
  tabela do item 3 substitui a da 6.9 na próxima revisão.
- O SDD não diz como o kernel com IF=0 (ADR 0009) atende IPIs; a regra de
  sondagem nas esperas é desta ADR.
- A 6.9 fala em shootdown "agrupado" sem dizer agrupado como, nem quando
  os frames voltam ao alocador; aqui é uma rodada por
  chamada, com frames liberados depois dos acks.
- **Decidido (2026-10-20):** a 6.4 manda usar PCID "para evitar flush de
  TLB"; o PCID fica adiado. As páginas globais do kernel (T-331) já
  poupam as traduções do kernel na troca de `CR3`, e a troca de contexto
  foi medida em 385 ns em KVM com 4 CPUs, abaixo da meta de 2 µs que
  serviria de gatilho. Eduardo confirma no PR.
- **Decidido (2026-10-20):** `vm_unmap` e `vm_protect` fazem uma rodada por
  chamada, sem fatiar, e cada pilha de kernel devolvida faz o seu
  shootdown. **Lacuna conhecida:** o teto de 50 µs da ADR 0009 para um
  `vm_unmap` de faixa muito grande depende de fatiar a operação com uma
  rodada por fatia; fica como tarefa de acompanhamento, sem mudança de
  código nesta ADR. Eduardo confirma no PR.
- A 6.5 diz que o pânico "congela as CPUs", sem dizer o que fazer com dois
  pânicos simultâneos nem o que se registra de cada CPU.
- A 6.8 não diz para qual CPU vão as IRQs de dispositivo; no M3, todas
  para a CPU 0.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- O construtor do `SpinLock` é `with_class`/`with_key`; `new` só nos testes.
- Fica explícito que não existe variante "irqsave".
- A tabela de travas ganha `FilaTimers` (emenda da ADR 0035), perde o
  orçamento do `SchedContext` e o registro do escalonador, e lista as
  travas folha reais do nível 10.
- O estado do shootdown é `LOADED[c]` com `note_root`, não uma máscara
  `active` por espaço; o prazo é 1 s sob TCG, com diagnóstico por alvo.
- `vm_unmap` e `vm_protect` fazem sempre uma rodada por chamada, sem fatiar;
  o tratador de faltas não confere a PTE; cada pilha de kernel faz o seu
  shootdown.
- `call_on` e o atendimento da caixa têm os nomes e o prazo do código.
- A regra de IRQs na CPU 0 é marcada como intenção, sem código de IOAPIC.
- `Shootdown.tla` não existe: o texto cita `CapRevoke.tla` e `Ipc.tla` e
  deixa a modelagem da TLB como tarefa de acompanhamento.
- Decididos: PCID adiado, rodada por chamada e shootdown por pilha.
