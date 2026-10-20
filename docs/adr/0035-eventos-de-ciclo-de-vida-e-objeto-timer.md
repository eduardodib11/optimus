# ADR 0035: Eventos de ciclo de vida (morte de thread e processo) e objeto Timer

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.1, 6.4, 6.7, 6.8, 7.2, 14.2 e 14.4; backlog do
  M3, T-308
- Relaciona-se com: ADR 0007 (IPC e notificações), ADR 0028 (derivação entre
  `CapSpace`s), ADR 0029 (criação de processos), ADR 0034 (svcmgr), T-348,
  T-349, T-354, T-358

## Contexto

A 7.2 manda o `svcmgr` reiniciar serviços que morrem, revogar as
capabilities do processo antigo e fazer os clientes receberem `PeerClosed`.
Para isso, alguém precisa saber que o processo morreu. Hoje:

- "Processo" não é objeto do kernel (a 6.1 não o lista). Um processo é, na
  prática, um `CapSpace` mais um `AddressSpace` mais as threads ligadas a eles
  por `thread_configure` (ADR 0029).
- `obj_bind_notify` (syscall 25) só aceita `Interrupt`
  (`sys.rs`: `obj.object.as_interrupt()?`).
- Uma thread que sai (`thread_exit`, 33), falta sem endpoint de exceções
  (6.4) ou é encerrada some sem aviso.
- Nada impõe `max_threads` nem `ipc_rate` do manifesto (14.4).
- A 6.7 e a 6.8 dizem que "timer" é fonte de evento ligável a uma
  `Notification`, mas o objeto não está na 6.1 nem em `kabi::ObjectType` e
  `obj_create` não sabe criá-lo. O `svcmgr` precisa dele para o recuo
  exponencial (100 ms a 30 s) e o `orun` para os prazos das tarefas.

A ABI v1 tem 34 syscalls fechadas (14.2, 14.6): a solução precisa caber nas
existentes, como a ADR 0029 fez.

## Decisão

### 1. Definição de processo

Para o kernel, **processo = `CapSpace`**: o grupo de threads cujo
`thread_configure` ligou o mesmo `CapSpace`. O kernel mantém, no
`CapSpace`, `live_threads: u32` (atômico): incrementa em `thread_start`
e decrementa quando a thread morre (por `thread_exit`, falta fatal ou
encerramento forçado). O processo "morre" quando `live_threads` volta a
zero depois de ter sido maior que zero. Não há objeto `Process` novo.

### 2. Registro da causa da morte

Cada `Thread` guarda ao morrer: `cause` (`Exited` = 1, `Faulted` = 2,
`Killed` = 3), `code` (u64) e `aux` (u64). `Exited`: `code` é o argumento
de `thread_exit`; `Faulted`: `code` é o vetor da exceção e `aux` o
endereço que faltou (a mesma informação da mensagem de falta, `kabi::
fault`); `Killed`: `code` zero. O `CapSpace` guarda o mesmo registro do
processo: a **primeira** morte anormal (`Faulted` ou `Killed`), ou, se
todas foram normais, a da última thread. Exceção: `EXIT_GROUP` e
`cap_delete(DESTROY)` gravam a causa do processo na própria chamada
(`Exited` com o código dado, e `Killed`, respectivamente) e nenhuma morte
posterior, como a `Killed` das outras threads, a sobrescreve.

Leitura: `sys_info(classe = 2 /*EXIT*/, handle)` (em `sys_info`, `rsi`
é o argumento da classe: o handle na classe 2 e zero nas demais, ADR 0032,
item 4) devolve `[cause, code,
aux]`; `cause = 0` significa "ainda vivo". Exige `READ_STATE` na `Thread`
ou `MANAGE` no `CapSpace`. As classes de `sys_info` ficam reservadas
assim: 0 = versão da ABI (reservada), 1 = CPUs (já existe, ADR 0032,
`kabi::sched::SYS_INFO_CPUS = 1`), 2 = morte (esta ADR), 3 = memória e
pressão (ADR 0038), 4 = hora de parede do boot (ADR 0037), 5 =
aleatoriedade (ADR 0039).

### 3. `obj_bind_notify` estendido

`obj_bind_notify(obj, ntfy, bits, a3, a4, a5)` (registradores `rdi`, `rsi`,
`rdx`, `r10`, `r8`, `r9`): `bits` é a máscara de bits sinalizada (como
hoje); `a3`–`a5` ganham significado por tipo de `obj` e **devem ser zero**
onde não são usados (senão `InvalidArgument`).

| Tipo de `obj` | `a3` | `a4` | `a5` | Evento |
|---|---|---|---|---|
| `Interrupt` | 0 | 0 | 0 | disparo da linha (como hoje) |
| `Thread` | 0 | 0 | 0 | a thread morreu |
| `CapSpace` | 0 | 0 | 0 | `live_threads` chegou a zero |
| `Timer` | prazo | período | flags | vencimento (item 6) |
| `DebugLog` | 0 | 0 | 0 | registro novo no log do kernel (ADR 0036) |

Regras:
1. Exige `BIND` em `obj` e `SIGNAL` em `ntfy`. `BIND` passa a valer
   também para `Thread`, `CapSpace` e `Timer` (o bit já existe; só a
   documentação de `kabi::Rights::BIND` muda).
2. **Uma** ligação por objeto; ligar de novo a substitui. `bits = 0`
   desliga.
3. O evento de `Thread`/`CapSpace` é **nível**: o objeto guarda o estado
   "morto". Ligar depois da morte sinaliza `bits` imediatamente, antes de
   a syscall voltar. Assim nenhum evento se perde entre `thread_start` e
   `obj_bind_notify`. O evento sinaliza uma vez por ligação.
4. O kernel sinaliza a partir do caminho de morte (com IF=0, como o
   `Interrupt`). Como o objeto (por exemplo `Thread.binding`) e a
   `Notification` são da mesma classe `Objeto`, "uma por vez" (ADR 0031),
   o kernel lê e clona sob a trava do objeto o `Arc` da `Notification` e
   os bits, solta a trava e só então sinaliza (como `Interrupt::ack`); a
   fila do escalonador vem depois (ordem da 6.9). Sem alocação: a ligação
   guarda o `Arc` e os bits dentro do objeto.
5. Para `Thread` a leitura do registro (item 2) devolve valor definitivo
   assim que o bit é sinalizado: o registro é escrito antes do sinal.

### 4. Encerramento forçado: `cap_delete` com flag

`cap_delete(handle, flags)`: `flags` (`rsi`) ganha `DESTROY = 1`; zero
é o comportamento atual (apagar só a capability). Requer o direito novo
`DESTROY` (bit 21) **na própria capability**; `Rights::ALL` passa a
`(1 << 22) - 1`. Como `cap_mint` só reduz direitos, `obj_create` concede
`DESTROY` ao criador em `CapSpace`, `Thread` e `Endpoint` (direitos
padrão desses tipos). `ostd::process` deriva, com `cap_mint`, cópias sem
`DESTROY` para tudo que entrega ao filho; o `root` mantém o direito só na
cópia que entrega ao `svcmgr`.

Efeito por tipo:
- `CapSpace`: o processo é encerrado. Todas as threads ligadas passam a
  `Killed`; as bloqueadas saem das filas de espera (IPC, notificação,
  futex); as em execução em outra CPU são encerradas no próximo ponto de
  entrada no kernel (reschedule-IPI, ADR 0031/0032). Depois o kernel
  esvazia a tabela, o que apaga as capabilities (e por consequência
  destrói os `Endpoint`s, cujos pares veem `PeerClosed`) e solta os
  `Reply` pendentes (o chamador que esperava resposta recebe
  `PeerClosed`). A capability do próprio `CapSpace` guardada dentro dele
  não impede nada: a destruição é explícita, não por contagem.
  Uma thread `Killed` que esperava em `ipc_call` não está em fila: o
  `Reply` dela passa a marcar "chamador morto". Quando o servidor responde,
  a resposta é descartada e o servidor segue com o próprio `SchedContext`
  (a doação da ADR 0032 se desfaz sem acordar ninguém), o que mantém o
  invariante I5 da ADR 0032. A T-348 testa o caso.
- `Thread`: encerra aquela thread (`Killed`).
- `Endpoint`: destrói o objeto; quem espera recebe `PeerClosed`.
- Outros tipos: `NotSupported`.

Invariante: depois que `cap_delete(..., DESTROY)` retorna, nenhuma thread
do processo está pronta para rodar; o evento do `CapSpace` só dispara
quando a última deixou de executar de fato. O `svcmgr` só reinicia depois
do evento (sem janela em que a instância velha ainda execute).

`thread_exit(código, flags)` (`rdi`, `rsi`): `flags & EXIT_GROUP` (1,
ADR 0039) encerra o processo inteiro, como um `DESTROY` sobre o próprio
`CapSpace` que dispensa o direito (auto-encerramento); as demais threads
terminam como `Killed` e a causa do processo é `Exited` com o código dado.

### 5. Limite de threads: `max_threads`

`obj_create(quota, CapSpace, arg0)`: `arg0` é o limite de threads vivas
(0 = sem limite; é o comportamento de hoje, que ignora `arg0`).
`thread_start` falha com `QuotaExceeded` se `live_threads` já é igual ao
limite. O `root` aplica o `max_threads` do manifesto ao criar o
`CapSpace` (ADR 0034, `Root.spawn`). O limite é do `CapSpace`, então vale
para threads criadas pelo próprio processo (`ostd::thread::spawn`).

### 6. Objeto `Timer`

- `kabi::ObjectType::Timer = 14` (Vcpu e Vm ficam 12 e 13). `obj_create(
  quota, Timer, 0)`; custo: um objeto pequeno cobrado da cota; direitos
  padrão: `BIND` (arma, rearma e cancela) e nenhum outro.
- **Armar:** `obj_bind_notify(timer, ntfy, bits, prazo, período, flags)`:
  - `prazo`: ns monotônicos absolutos (os de `clock_get`); `0` desarma.
    Com `flags & RELATIVE` (bit 0), `prazo` é um deslocamento a partir
    de agora. Prazo no passado dispara imediatamente (o bit é sinalizado
    antes de a syscall voltar).
  - `período`: 0 = disparo único. Senão repete, com mínimo de 100 µs
    (`InvalidArgument` abaixo disso). Atrasos de mais de um período
    **coalescem**: um único sinal e o próximo prazo é o primeiro múltiplo
    maior que "agora". Não há contagem de estouros (o bit é idempotente).
  - `flags`: bit 0 `RELATIVE`; os demais `InvalidArgument`.
  - `bits = 0` também desarma. Armar de novo troca ligação, prazo e período.
- **Disparo:** o tratador do timer da CPU dona do `Timer` sinaliza `bits`
  na `Notification`. Um disparo único deixa o `Timer` desarmado.
- **Onde vive:** cada CPU tem uma fila de timers ordenada por prazo, com
  nós intrusivos dentro do próprio `Timer` (sem alocar no disparo). O
  prazo programado no timer da CPU (modo deadline, 6.8, sem tick) passa a
  ser o mínimo entre fim de fatia, recarga de `SchedContext`, prazos de
  IPC e o primeiro `Timer`. A CPU dona é a que armou; rearmar de outra CPU
  toma o lock da fila da CPU dona (IRQ-safe, ADR 0031). O estado do
  `Timer` (prazo, período, ligação) é protegido **só** pelo lock da fila;
  o lock do objeto não é usado nele, para não inverter a ordem
  objeto → fila (6.9) no tratador. A fila de timers tem classe própria na
  tabela de travas da ADR 0031 (folha logo depois de `Fila`). O tratador
  remove os vencidos sob a trava, solta e só então sinaliza as
  `Notification`s.
- **Cancelamento e destruição:** apagar a última capability desarma e
  tira o nó da fila antes de liberar a memória. Teste: nenhuma
  referência pendurada depois de `cap_delete` concorrente com o disparo.
- **Precisão** (aceite do T-349): erro ≤ 100 µs em KVM, ≤ 1 ms em TCG,
  1000 timers.
- **Uso:** `ostd::time::sleep` e prazos do `orun` armam um `Timer` e
  esperam na `Notification`; o `svcmgr` usa um por serviço em recuo.

### 7. `ipc_rate`: sem imposição no M3

Contar IPC no caminho rápido custa o que a 6.7 quer evitar (meta de 1 µs).
No M3 o `ipc_rate` fica **no formato do manifesto e é informativo**: o
`svcmgr` o registra no log. Proposta para depois do M3: cobrança no
`SchedContext` do cliente (um serviço que satura a CPU de outros já gasta o
orçamento dele) e, se não bastar, contador por `Endpoint` verificado só no
caminho lento. Isso exige decisão de Eduardo (ver abaixo).

### 8. Mudanças em `kabi` (resumo)

`ObjectType::Timer = 14`; `Rights::DESTROY` (bit 21); `cap_delete::DESTROY`;
`event`/`exit` com `cause` e a classe 2 de `sys_info`; `kabi::timer::{
RELATIVE, MIN_PERIOD_NS}`; descrição de `obj_bind_notify` por tipo. O
teste `numeros_estaveis` passa a contar 15 tipos de objeto. Os bits de
direito (`DESTROY` = 21 aqui, `EVICT` = 22 na ADR 0038) e os tipos de
objeto (`Timer` = 14 aqui, `DebugLog` = 15 na ADR 0036) não colidem. A
ordem de implementação segue a numeração; o PR que trouxer o `EVICT`
antes do `DESTROY` reserva o bit 21 mesmo assim, e o teste de `kabi` que
trava `Rights::ALL` e o número de tipos é atualizado em cada PR. A tabela
6.1 e
a 14.2 do SDD recebem a linha de `Timer` e o texto dos registradores.

## Alternativas

- **Objeto `Process` novo:** daria um lugar óbvio para eventos e
  `max_threads`, mas é um tipo a mais com sua própria árvore de direitos e
  duplica o que o `CapSpace` já representa (ADR 0029).
- **Processo avisa o `svcmgr` ao sair (`goodbye()`):** não cobre falta,
  `abort` nem encerramento; o `svcmgr` não pode confiar no morto.
- **Heartbeat/sondagem:** gasta CPU, e a detecção demora.
- **Mensagem de saída por IPC enviada pelo kernel:** exigiria `Endpoint`
  de saída em cada thread (como o de exceções) e alocação no kernel.
- **Timer como serviço (`timed`):** mais um salto de IPC em cada prazo;
  dependência circular (o `timed` depende do `svcmgr`, que precisa de
  timers); latência de IPC no lugar do timer de hardware.
- **Só prazo no `ntfy_wait`/`ipc_recv`:** não serve ao `orun`, que espera
  várias fontes numa única `Notification`.
- **Syscalls novas (`timer_arm`, `proc_kill`):** quebram a ABI v1 fechada em
  34 syscalls (14.6).
- **Encerrar o processo por contagem de referências do `CapSpace`:** a
  thread guarda capability do próprio `CapSpace` (ciclo, ADR 0029) e
  outras threads podem guardar a do vizinho; a contagem não chega a zero.

## Consequências

- O `svcmgr` fica com um laço simples: `ntfy_wait`, ler a causa com
  `sys_info`, decidir (política de reinício), `cap_delete(DESTROY)` se
  ainda for preciso, revogar, `Root.reap`, `Root.spawn`.
- O caminho de morte do kernel ganha trabalho (sinalizar, registrar
  causa) e uma nova região crítica; precisa de teste de estresse com 100
  processos criados e mortos sem perder evento (T-348) e de modelo TLA+
  (T-313) para a corrida morte × bind × destruição concorrente.
- `DESTROY` é um direito poderoso (equivale a "kill -9"): só o criador
  do processo o tem, e a revisão de segurança (17.2) é obrigatória.
- O Timer acrescenta uma fila por CPU e entra no cálculo do próximo
  prazo do timer em modo deadline; o `Timer` só muda de CPU se for
  desarmado e armado de novo.
- `ipc_rate` não é imposto no M3: um serviço malcomportado ainda pode
  inundar IPC; mitigação parcial por prioridade e orçamento do
  `SchedContext`.

## Fora do escopo

Eventos de `Endpoint` com mensagem pendente (6.7); `Timer` de relógio de
parede; coalescência de timers por tolerância; contagem de estouros;
`ipc_rate`; processos zumbis com código de saída para o pai (o `svcmgr`
lê direto do objeto); alertas (viram log, ADR 0036).

## Lacunas do SDD e decisões para Eduardo

1. **Resolvidas aqui:** morte de processo, evento ligável, Timer no
   kernel, `max_threads`.
2. **Decidido (2026-10-20):** direito e flag `DESTROY` em `cap_delete`.
   A flag não abre a ABI v1, e só quem cria o processo recebe o direito;
   uma syscall dedicada ficaria para uma versão maior da kabi.
3. **Decidido (2026-10-20):** Timer como objeto do kernel e `ObjectType`
   14 (altera a tabela 6.1). Como serviço, cada prazo custaria um IPC e
   criaria um ciclo `timed` e `svcmgr`.
4. **Decidido (2026-10-20):** `ipc_rate` informativo no M3 e a proposta
   de cobrança futura. Contar no caminho rápido custaria parte do ganho
   já medido.
5. **Decidido (2026-10-20):** período mínimo do Timer de 100 µs, o mesmo
   `MIN_PERIOD_NS` dos `SchedContext`s.
6. **Decidido (2026-10-20), SMP:** sinalizar com IF=0, na ordem objeto,
   notificação, fila (item 3.4). Com as ADRs 0031 e 0032 já
   implementadas, a regra entra em `docs/kernel/ordem-de-travas.md`
   quando a T-348 e a T-349 chegarem.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- Classes de `sys_info` renumeradas: 0 versão, 1 CPUs (ADR 0032), 2 morte
  de processo, 3 memória e pressão, 4 hora de parede, 5 aleatoriedade.
- A leitura da causa da morte usa a classe 2 (antes "classe 1 /*EXIT*/"),
  e o resumo do `kabi` também.
- Registrado que os bits de direito e os tipos de objeto das ADRs 0035,
  0036 e 0038 não colidem, com a ordem de implementação e o teste de
  `kabi` atualizado em cada PR.
- As decisões da seção final foram registradas como decididas.

### Revisão geral

- `obj_create` concede `DESTROY` ao criador de `CapSpace`, `Thread` e
  `Endpoint`, e o `root` deriva as cópias sem ele (antes o direito era
  impossível de derivar).
- O item 3.4 manda clonar a ligação sob a trava do objeto e sinalizar
  depois de soltá-la, pela ordem de travas da ADR 0031.
- A fila de timers remete à classe própria da ADR 0031, com a regra
  "remover, soltar, sinalizar".
- A causa do processo gravada por `EXIT_GROUP` e `DESTROY` na chamada não
  é sobrescrita pelas mortes `Killed` posteriores.
- O encerramento forçado trata o chamador morto em `ipc_call` (doação de
  `SchedContext`).
- O argumento de `sys_info` (`rsi`) fica documentado para a classe 2.
