# ADR 0048: Prazo no `futex_wait` e `Mutex::lock_timeout`

- Status: aceita (aprovada por Eduardo em 2026-11-09)
- Data: 2026-11-09
- Origem: backlog do M4, T-431; pendência da ADR 0039 (item 6) e do Gate 1
- Relaciona-se com: ADR 0035 (Timer), ADR 0039 (runtime do `ostd`), ADR 0032 (futex em SMP), SDD v1.0 seções 6.8 e 14.2

## Contexto

O `futex_wait(endereço, esperado)` do kernel não tem prazo. Por isso o
`ostd` entrega `Condvar::wait_timeout` e `join_timeout` por outro caminho
(uma `Notification` por thread mais um `Timer`), mas não consegue entregar
`Mutex::lock_timeout`: o `unlock` teria de conhecer os esperadores com prazo,
o que custaria o `swap` do caminho rápido do `Mutex`. Drivers e serviços do
M4 precisam de trava com prazo (um driver não pode travar para sempre atrás
de um dispositivo que não responde, ADR 0013).

Hoje o `ostd` chama `futex_wait` com `a[2] = 0`, `a[3] = 0` (argumentos 2 a 5
ignorados). A ABI v1 tem 34 syscalls estáveis (SDD 6.8).

## Decisão

1. **Mesma syscall, argumento novo e opcional.** `futex_wait(endereço,
   esperado, prazo_ns, flags)`: `a[2]` é um prazo absoluto em ns na base de
   `clock_get`; **0 = sem prazo**, o comportamento de hoje. `a[3]` são flags
   reservadas e devem ser 0 (`InvalidArgument` caso contrário). Nenhuma
   syscall nova, a contagem 34 não muda, e todo binário existente continua
   válido porque já passa 0. Isso é uma extensão compatível da ABI v1, não
   uma ABI v2.
2. **Semântica.** Prazo no passado ou igual a agora: devolve `TimedOut` sem
   bloquear (depois de conferir a palavra: se ela já mudou, `WouldBlock`
   como hoje, que vem primeiro). Se o prazo vence com a thread na fila, o
   kernel a tira da fila do futex e devolve `TimedOut`. Um `futex_wake` que
   chega junto com o vencimento vence a corrida: a thread sai acordada
   (`Ok`) e o prazo é cancelado. Nenhum despertar se perde (a retirada da
   fila e o despertar tomam a mesma trava do balde, ADR 0032, item 6).
3. **Implementação no kernel.** Cada thread tem um temporizador de espera
   embutido (o mesmo tipo de fila de prazos por CPU da ADR 0035, sem objeto
   `Timer` nem capability, e cobrado da estrutura da thread, sem cota
   nova). Armar acontece depois de entrar na fila e com a trava do balde
   tomada; o vencimento, em contexto de interrupção do timer, toma a trava
   do balde, retira a thread (se ainda estiver) e a acorda com `TimedOut`.
4. **`ostd`.** `Mutex::lock_timeout(Duration) -> Option<Guard>` e
   `try_lock_until(Instant)`. O caminho rápido (`swap`/CAS no estado) não
   muda: o prazo só entra no laço lento, que passa o prazo ao `futex_wait`.
   `Condvar::wait_timeout` e `join_timeout` continuam como estão (migrar para
   o prazo do futex é opcional e fica fora desta tarefa).
5. **Testes.** Kernel: prazo vence, `futex_wake` antes do prazo, corrida
   entre os dois, prazo no passado, flags inválidas. `utest`:
   `sync.mutex_lock_timeout` (estoura e obtém), em `--smp 1`, `2` e `4`.
   Fuzzing (`okfuzz`): inclui `futex_wait` com prazo e flags aleatórias.
6. **Documentação.** Atualizar a tabela de syscalls (`kabi`) e a ADR 0039 (item
   6), que deixa de listar `lock_timeout` como "fica de fora".

## Alternativas consideradas

- **Syscall nova (`futex_wait_until`):** rejeitado. Passaria de 34 para 35
  syscalls "estáveis" e exigiria reabrir o conjunto da ABI v1.
- **Prazo por `Notification` + `Timer` em usuário (como o `Condvar`):**
  rejeitado para o `Mutex`. O `unlock` teria de acordar a `Notification` de
  cada esperador, e isso custa um passo no caminho rápido.
- **Não fazer:** possível (nada do M4 depende disso), mas deixa drivers sem
  trava com prazo; o Gate 1 já adiou a pendência para o M4.

## Consequências

- Muda o kernel (`futex`, `sys`, escalonador/timer): código crítico, com
  revisão dupla e modelo mais forte.
- A ABI v1 ganha um significado para `a[2]` e `a[3]` do `futex_wait`; fica
  registrado na tabela. Programas que passavam lixo nesses registradores
  deixam de ser válidos (o `ostd` passa 0).
- **Auditoria dos chamadores (2026-11-09).** Todos zeram `a[2]` e `a[3]`:
  `ostd` (`futex_wait` e `futex_wait_until`, argumentos explícitos), `okfuzz`
  (passa zeros), os dois laços de `kernel/okernel/src/arch/x86_64/user.S` e o
  stub de `services/utest/src/vida.rs`. Os dois laços de `user.S` deixavam
  lixo em `rdx` e `r10` e quebraram os testes de SMP na CI; foram corrigidos
  no mesmo PR. Ressalva: binário fora do repositório que chame `futex_wait`
  sem zerar `rdx` e `r10` passa a receber um prazo (ou `InvalidArgument`);
  não há tal binário na imagem (o `ostd` é o único runtime, ADR 0039), e a
  ABI v1 ainda não foi congelada para terceiros.
- Custo no caminho lento: uma entrada a mais na fila de prazos por espera
  com prazo; sem prazo, nenhum custo.
