# ADR 0039: Runtime do `ostd`: alocador, TLS, aleatoriedade e política de `unsafe`

- Status: proposta (aguarda aprovação de Eduardo)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.5, 7.1, 17.1 e 17.3; backlog do M3, T-312
- Relaciona-se com: ADR 0002 (Rust estável, assembly só em `arch`), ADR 0003
  (sem crates externas), ADR 0029, ADR 0035, ADR 0036, ADR 0038, T-333 a
  T-338

## Contexto

O `ostd` de hoje cobre só o mínimo (entrada, syscalls, IPC, threads cruas,
carregador de ELF). A 7.1 promete alocador estilo mimalloc, threads,
`Mutex`/`Condvar` sobre futex, coleções, tempo e logs. Quatro decisões
bloqueiam isso:

1. **Alocador.** Precisa de `unsafe` (ponteiros brutos, `GlobalAlloc`), e
   a regra atual só deixa `unsafe` em `lib/ostd/src/arch/` (`lib.rs` tem
   `#![deny(unsafe_code)]` e o `arch` o reabilita). O `xtask check` só
   confere se cada crate fora de `unsafe-allowlist.toml` tem
   `#![forbid(unsafe_code)]`; não policia módulos dentro de `lib/ostd`.
2. **TLS.** O kernel não salva nem restaura `FS_BASE` por thread, e
   `#[thread_local]` é instável no Rust estável (ADR 0002).
3. **Aleatoriedade.** Não há syscall de entropia. O `optboot` já põe 64
   bytes em `BootInfo.rng_seed` (EFI_RNG + RDSEED/RDRAND), mas o kernel não
   os usa nem os repassa. `HashMap` e o próprio alocador (endurecimento) a
   pedem; o ASLR de usuário continua pendente desde o M2 (6.5 pede 30+
   bits).
4. **Panic e saída.** Um `panic!` numa thread de serviço hoje só imprime e
   encerra a thread; o processo continua com as demais.

## Decisão

### 1. Política de `unsafe` e a lista de permissão

- `unsafe-allowlist.toml` ganha uma tabela por **módulo/crate** com um
  teto de blocos `unsafe` (a contagem que a 16.4 já cita no CI):

```toml
crates = ["boot/optboot", "kernel/okernel", "lib/ostd", "lib/oalloc"]

[unsafe_budget]            # blocos/impls/fns unsafe por caminho
"lib/ostd/src/arch"  = 40  # syscall, _start, acesso a memória mapeada, FS
"lib/ostd/src/sync"  = 12  # Mutex/Condvar/RwLock/Once (UnsafeCell)
"lib/ostd/src/tls"   = 10  # bloco da thread, destrutores
"lib/ostd/src/ring"  = 14  # anéis compartilhados (ADR 0036)
"lib/ostd/src/alloc" = 6   # cola de GlobalAlloc sobre lib/oalloc
"lib/oalloc"         = 80  # alocador (núcleo)
```
  Os números acima são **pontos de partida**: o primeiro PR de cada
  módulo os ajusta; depois só sobem com alteração visível do arquivo.
- `xtask check` passa a: (a) varrer `lib/ostd/src/**/*.rs`; (b) recusar
  `unsafe` ou `allow(unsafe_code)` fora dos caminhos do orçamento; (c)
  contar `unsafe` por caminho e falhar acima do teto; (d) exigir, nos
  módulos listados, `#![allow(unsafe_code)]` no arquivo raiz do módulo e
  uma seção `# Unsafe` na documentação dele com as invariantes.
  `lib/ostd/src/lib.rs` continua `#![deny(unsafe_code)]`. O restante da
  `ostd` (e todos os serviços) continua `#![forbid(unsafe_code)]`.
- Todo bloco `unsafe` leva `// SAFETY:` e revisão por duas pessoas (17.1).
  Módulos de `unsafe` têm teste sob **Miri** (job noturno de nightly,
  16.4) no host. Por isso o núcleo do alocador é uma **crate separada**,
  `lib/oalloc` (`no_std`, sem syscalls, genérica sobre um `PageSource`),
  testável no host; a cola com o kernel (`ostd::alloc`) é pequena.
- Os serviços não ganham `unsafe`. `#[global_allocator]` fica em
  `ostd::alloc` (um `unsafe impl GlobalAlloc` pequeno).

### 2. Alocador (`lib/oalloc` + `ostd::alloc`)

Estilo mimalloc, escrito do zero:
- **Fonte de memória:** cada *segmento* tem 2 MiB, alinhado a 2 MiB, é um
  `MemoryObject` criado da cota do processo (preguiçoso, ADR 0038, quando
  existir) e mapeado com `vm_map` numa janela de 16 TiB da metade baixa. O
  endereço do segmento é sorteado (item 4), o que dá 23 bits de entropia
  ao endereço do heap enquanto o ASLR geral de usuário não chega.
  Segmentos vazios sobrando além de um são devolvidos (`vm_unmap` e
  `cap_delete` do objeto, e a cota volta).
- **Páginas:** cada segmento tem 32 páginas de 64 KiB; a primeira guarda o
  cabeçalho do segmento (dono, contadores, mapa de páginas). Dado o
  ponteiro, `ptr & !(2 MiB − 1)` acha o segmento.
- **Classes de tamanho:** 8 a 8 KiB com 4 classes por duplicação (perda
  ≤ 12,5%). Acima disso e até 512 KiB: blocos de múltiplas páginas de 64
  KiB dentro de um segmento; acima: segmento próprio (múltiplos de 2 MiB).
- **Heap por thread:** páginas por classe com lista livre local (`free`),
  `local_free` (liberado pelo dono) e `thread_free` (pilha atômica que
  outras threads empurram); o dono recolhe `thread_free` quando `free`
  esvazia. Sem lock no caminho comum. Estado global mínimo: lista de
  segmentos abandonados (pilha atômica) e o gerador de endereços.
- **Thread que sai:** o heap dela vira abandonado; outra thread adota
  segmentos abandonados ao precisar de memória.
- **Endurecimento:** ponteiros da lista livre codificados por XOR com chave
  por heap (da entropia, item 4) e *canary*; liberação dupla e liberação
  de ponteiro alheio detectadas e abortam o processo.
- **Falha:** memória esgotada devolve null, o runtime chama
  `handle_alloc_error` e o processo termina (item 5).
- **Sem alocação** no caminho rápido de IPC nem em código de interrupção
  (17.1); o buffer de IPC vive no bloco da thread.
- **Aceite (T-334):** 10⁶ alocações/liberações aleatórias com 4
  threads sem vazamento nem corrupção; fragmentação medida em carga
  sintética e registrada.

O `PageSource` real precisa de três handles do processo: cota, o próprio
`AddressSpace` e (para criar objetos) o direito `CREATE`. Eles vêm do
descritor de partida (ADR 0034, `CapDesc.kind` quota/aspace) e são
guardados em `ostd::rt::Env` antes da primeira alocação; `entry!` chama
`rt::init` (o `root` e o `hello` recebem os handles direto em `Start`).
Alocar antes de `rt::init` é um erro de programação e aborta.

### 3. TLS por `FS_BASE`

- **Kernel (T-333):** `Thread` guarda `fs_base: u64`. A troca de contexto o
  salva e restaura (`WRFSBASE`/`RDFSBASE` se `CPUID.7.0:EBX[0]` e o kernel
  ligar `CR4.FSGSBASE`; senão `WRMSR` em `IA32_FS_BASE`). `GS_BASE` de
  usuário continua zero e fora da ABI (o kernel usa GS para o estado por
  CPU).
- **ABI, sem syscall nova:** `kabi::thread::CONFIGURE_TLS = 1 << 2` em
  `thread_configure`. O valor vai em `r10` (o mesmo registrador do buffer
  de IPC; por isso `CONFIGURE_TLS` não pode vir junto de
  `CONFIGURE_IPC_BUFFER`: `InvalidArgument`). Aceita só endereço canônico
  de usuário (`< USER_END`). `thread_configure` sobre a **própria** thread
  aceita `thread = 0` para estas três mudanças (buffer, exceção e TLS),
  sem capability da thread; isso elimina o ciclo "a thread guarda a
  capability dela mesma" (ADR 0029). Ligar `CapSpace`/`AddressSpace`
  continua exigindo a capability.
- **Bloco da thread** (`ostd::tls::ThreadBlock`, uma página gravável,
  apontada por `FS_BASE`, com o ponteiro para si mesmo no início como o
  ABI x86-64 espera): `self_ptr`, `tid`, ponteiro para o heap da thread,
  endereço do buffer de IPC (4 KiB na página seguinte), handle do
  endpoint de exceções, e a tabela de slots do `thread_local!`.
- **`thread_local!`** (`ostd::tls`): a macro cria um `static` descritor
  (tamanho, alinhamento, inicializador e destrutor) numa seção
  `.ostd_tls_desc`, reunida pelo script de ligação `user.ld` (o mesmo truque
  do `.ostd_entry`); o índice do slot é a posição do descritor na
  seção. O valor é alocado e inicializado no primeiro acesso, na
  tabela do bloco, e destruído na saída da thread. Sem `#[thread_local]`.
- A thread principal usa um bloco estático em `.bss`; `spawn` aloca o
  bloco, a pilha (com página de guarda) e passa o `FS_BASE` ao filho.

### 4. Aleatoriedade

- **Kernel:** `sys_info(classe 4)` devolve três palavras (24 bytes)
  aleatórias criptográficas, sem capability, a qualquer processo.
  Implementação: DRBG baseado em BLAKE3 em modo chaveado (`optcrypt`), com
  chave inicial `BLAKE3(rng_seed ‖ "okernel-drbg")`, reaplicada a cada
  saída (apagamento rápido de chave) e misturada com `RDSEED`/`RDRAND` e o
  TSC quando existirem; um DRBG por CPU, derivado do principal. Se a
  `rng_seed` é toda zero (o `optboot` avisa "sem RNG"), devolve
  `NotSupported`.
- **`ostd::rand`:** `secure_fill(buf)` chama o kernel em pedaços de 24
  bytes (para chaves e nonces); `fast()` é um xoshiro256++ por thread
  semeado uma vez por `secure_fill`, **não** criptográfico (índice de
  tabela hash, sorteio de endereço). `HashMap` usa SipHash-1-3 com chave
  de 128 bits tirada de `fast()` por mapa.
- **Falha da entropia:** `NotSupported` não derruba o programa. O `ostd`
  usa uma mistura de `clock_get`, endereços de pilha e `tid` com
  `log` de nível `warn` na primeira vez, e marca `rand::is_degraded()`;
  serviços que fazem criptografia checam essa marca e se recusam a
  iniciar.
- **O que não é:** `sys_info(4)` não é um gerador de volume; o consumo
  grande usa o DRBG do usuário semeado por ele.

### 5. Panic, abort e fim do processo

- `panic = "abort"` (workspace). O `panic_handler` do `ostd` escreve a
  mensagem (`ostd::log` se houver, senão `debug_write`, ADR 0036) e encerra
  o **processo**, não só a thread: `thread_exit(código, flags)` ganha
  `flags` em `rsi` com `EXIT_GROUP = 1`, que equivale a o processo se
  destruir (`cap_delete` com `DESTROY` no próprio `CapSpace`, ADR 0035,
  sem exigir o direito porque é auto-encerramento). `cause = Exited`,
  `código = 0x7061_6E69` (`"pani"`) no pânico; o `svcmgr` lê isso e
  registra `error`.
- `handle_alloc_error`, liberação dupla e canary violado chamam o mesmo
  caminho (`ostd::process::abort(motivo)`).

### 6. Outros pontos do runtime (resumo, sem decisão nova)

`Mutex`/`Condvar`/`RwLock`/`Once` sobre `futex_wait`/`futex_wake`
(módulo `sync`, `unsafe` limitado a `UnsafeCell` e `Sync` manual);
`Instant`/`sleep` sobre `clock_get` e `Timer` (ADR 0035); coleções
(`HashMap`, anel, fila) e UTF-8 próprios, reexportando `alloc` onde cabe;
`thread::spawn`/`join` com cota por thread e pilha padrão de 64 KiB.

## Alternativas

- **Alocador como módulo do `ostd` e sem crate separada:** menos um
  crate, mas o `unsafe` pesado ficaria no `ostd`, difícil de testar sob
  Miri porque o `ostd` depende de syscalls reais.
- **Liberar `unsafe` em todo o `ostd`:** simples, mas desfaz a regra de
  auditoria da 17.1; a contagem por módulo mantém o controle.
- **TLS ELF padrão (`PT_TLS`, `#[thread_local]`):** exigiria nightly (ADR
  0002) e suporte do carregador ao segmento; ficaria para quando o Rust
  estável permitir.
- **TLS por `WRFSBASE` direto no usuário, sem syscall:** mais rápido, mas
  exige `CR4.FSGSBASE`, que nem todo hardware/emulador oferece; fica como
  otimização futura, sobre o mesmo bloco de thread.
- **Entropia distribuída pelo `root` (semente por processo):** evita uma
  syscall mas coloca o `root` (TCB) no caminho de toda semente, não serve
  ao `root` e ao `hello`, que nascem antes, e a semente não se renova.
- **`RDRAND` direto no usuário:** não existe em todo hardware (nem no
  AArch64 base) e não cobre máquinas virtuais antigas; serve só como
  mistura.
- **Criptografia de verdade no PRNG rápido (`ChaCha`):** adiciona
  dependência de `optcrypt` ao caminho de `HashMap` sem ganho de
  segurança para um índice de tabela.

## Consequências

- `kabi`: `thread::CONFIGURE_TLS`, `thread = 0` como "eu mesmo",
  `exit::GROUP`, classe 4 de `sys_info`. O kernel muda em `kthread.rs`,
  `thread.rs` e `sys.rs` (T-333, mais o DRBG).
- `unsafe-allowlist.toml` e `xtask check_unsafe` mudam em conjunto com a
  aprovação desta ADR (T-312 diz: "ADR aceita e allowlist atualizado
  conforme a decisão"). Esta ADR **não** os altera.
- Nova crate `lib/oalloc`; o workspace e o CI de unsafe/Miri a incluem.
- A janela de 16 TiB e o sorteio de endereços dão ao heap 23 bits de
  entropia; o ASLR da pilha, do código (PIE) e do `mmap` continua
  pendente.
- `thread = 0` muda a ADR 0029 (que o `hello` apaga a capability da
  própria thread para quebrar o ciclo: passa a não ser necessário para
  buffer, exceção e TLS).
- A saída em `panic` com `EXIT_GROUP` faz um serviço morrer inteiro, o que
  é o que o `svcmgr` espera (reinício por política).

## Fora do escopo

ASLR completo de usuário; `PT_TLS` e `#[thread_local]`; alocador com
páginas grandes (2 MiB) para `MemoryObject` contíguo; `WRFSBASE` no
usuário; `GS` de usuário; SIMD no `ostd`; mapeamento de arquivos;
`orun` (executor assíncrono).

## Lacunas do SDD e decisões para Eduardo

1. **Resolvidas aqui:** desenho do alocador, TLS sem `#[thread_local]`,
   fonte de entropia, mecanismo e contagem de `unsafe` fora de `arch/`.
2. **Decisão de Eduardo:** orçamento de `unsafe` por módulo na
   `unsafe-allowlist.toml` e a crate `lib/oalloc` (altera a regra do
   `xtask check`).
3. **Decisão de Eduardo:** `sys_info(classe 4)` público para entropia, em
   vez de distribuição pelo `root`, e o uso de BLAKE3 chaveado como DRBG
   no kernel (alternativa: ChaCha20 quando a `optcrypt` o tiver).
4. **Decisão de Eduardo:** `thread = 0` como "eu mesmo" em
   `thread_configure` e `EXIT_GROUP` em `thread_exit` (dois acréscimos de
   ABI).
5. **Decisão de Eduardo:** serviços que dependem de criptografia recusam
   iniciar com entropia degradada.
6. **Pendente:** ASLR de usuário (pilha, código, `mmap`) segue aberto;
   esta ADR dá a fonte de entropia e o heap aleatório, nada mais.
