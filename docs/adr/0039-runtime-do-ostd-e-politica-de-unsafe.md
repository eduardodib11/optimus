# ADR 0039: Runtime do `ostd`: alocador, TLS, aleatoriedade e política de `unsafe`

- Status: aceita (aprovada por Eduardo em 2026-10-20)
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
  Os testes da `lib/oalloc` rodam sob **Miri** (nightly) no host, só nos
  PRs que mudam essa crate. O job noturno de Miri da 16.4 não existe no
  CI de hoje e fica para depois: criá-lo gasta minutos de Actions, e
  Eduardo decidiu não criar esse job agora. Por isso o núcleo do alocador é
  uma **crate separada**,
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
- **Classes de tamanho:** de 8 a 8 KiB. Até 64 bytes as classes são
  lineares, de 8 em 8 (8, 16, 24, ..., 64); acima de 64 há 4 classes por
  duplicação (degraus de 25%). A perda por arredondamento é de no máximo
  0,25/1,25 = 20% (perda ≤ 20%); 12,5% exigiria 8 classes por duplicação.
  Abaixo de 64 bytes não cabem 4 classes por duplicação com alinhamento
  de 8, daí as classes lineares. Acima disso e até 512 KiB: blocos de
  múltiplas páginas de 64
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

O `PageSource` real precisa da cota do processo, com o direito `CREATE`
para criar objetos, e do espaço de endereços. A cota vem do descritor de
partida (ADR 0034): o `PageSource` a acha pelo `CapDesc` com `kind = 2` e
`index = 0xFFFF`, e a guarda em `ostd::rt::Env` antes da primeira
alocação. Essa cota é o `mem:quota` obrigatório e único do manifesto. O
espaço de endereços não precisa de handle: `vm_map` e
`vm_unmap` aceitam `aspace = 0` como "o espaço de endereços da thread que
chama", no mesmo espírito do `thread = 0` do item 3, e nenhum serviço
guarda capability do próprio `AddressSpace` (o mesmo ciclo que o
`thread = 0` evita); `entry!` chama
`rt::init` (o `root` e o `hello` recebem os handles direto em `Start`).
Alocar antes de `rt::init` é um erro de programação e aborta.

### 3. TLS por `FS_BASE`

- **Kernel (T-333):** `Thread` guarda `fs_base: u64`. A troca de contexto o
  salva e restaura com `WRMSR` em `IA32_FS_BASE`, gravando **apenas
  quando o valor muda** entre a thread que sai e a que entra. No M3 o
  kernel **não liga `CR4.FSGSBASE`**: com o bit ligado, o usuário ganharia
  na hora `WRFSBASE`, `WRGSBASE` e as duas leituras, e um processo poderia
  gravar o `GS_BASE`, que o kernel não salva por thread; o valor vazaria
  para a próxima thread (de outro processo) depois do `swapgs`. `GS_BASE`
  de usuário continua zero e fora da ABI (o kernel usa GS para o estado
  por CPU). O custo do `WRMSR` entra no bench de troca de contexto em KVM
  (hoje 385 ns). Se um dia o bit for ligado, o kernel passa a salvar e
  restaurar também o `GS_BASE` de usuário.
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

- **Kernel:** `sys_info(classe 5)` devolve três palavras (24 bytes)
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
  de 128 bits tirada de `fast()` por mapa. Premissa registrada: como
  `fast()` não é criptográfico, isso resiste a HashDoS enquanto ninguém
  observa saídas do xoshiro; é suficiente para o M3.
- **Falha da entropia:** `NotSupported` não derruba o programa. O `ostd`
  usa uma mistura de `clock_get`, endereços de pilha e `tid` com
  `log` de nível `warn` na primeira vez, e marca `rand::is_degraded()`;
  serviços que fazem criptografia checam essa marca e se recusam a
  iniciar.
- **O que não é:** `sys_info(5)` não é um gerador de volume; o consumo
  grande usa o DRBG do usuário semeado por ele.

### 5. Panic, abort e fim do processo

- `panic = "abort"` (workspace). O `panic_handler` do `ostd` escreve a
  mensagem (`ostd::log` se houver, senão `debug_write`, ADR 0036) e encerra
  o **processo**, não só a thread: `thread_exit(código, flags)` ganha
  `flags` em `rsi` com `EXIT_GROUP = 1`, que equivale a o processo se
  destruir (`cap_delete` com `DESTROY` no próprio `CapSpace`, ADR 0035,
  sem exigir o direito porque é auto-encerramento). O `EXIT_GROUP` usa o
  `CapSpace` ao qual a thread está ligada, **sem handle**: o processo não
  guarda capability do próprio `CapSpace`. `cause = Exited`,
  `código = 0x7061_6E69` (`"pani"`) no pânico; o `svcmgr` lê isso e
  registra `error`. O `EXIT_GROUP` grava a causa do processo na própria
  chamada, e as mortes `Killed` das outras threads não a sobrescrevem
  (ADR 0035, item 2).
- **`thread_exit` passa a ler o código.** Hoje o argumento é ignorado: o
  `ostd` manda zeros (`lib/ostd/src/thread.rs`) e `exit_current()` não lê
  código nenhum (`kthread.rs`). A T-333 (dono sugerido do `EXIT_GROUP`, de `thread = 0` e de
  `aspace = 0`) faz
  o kernel ler o código em `rdi` e levá-lo ao registro de morte da ADR
  0035 (`code` de `Exited`); sem isso o `svcmgr` nunca vê o `"pani"`.
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
- **TLS por `WRFSBASE` direto no usuário, sem syscall, e troca de
  contexto com `RDFSBASE`/`WRFSBASE`:** mais rápido, mas exige
  `CR4.FSGSBASE`, que nem todo hardware/emulador oferece, e abre ao
  usuário o `WRGSBASE`, que vazaria `GS_BASE` entre threads (item 3).
  Fica como otimização futura, sobre o mesmo bloco de thread, e só com o
  kernel salvando também o `GS_BASE` de usuário.
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
  `exit::GROUP`, classe 5 de `sys_info`, e `aspace = 0` em
  `vm_map`/`vm_unmap` como "o espaço da thread que chama". O kernel muda em
  `kthread.rs`,
  `thread.rs` e `sys.rs` (T-333; o DRBG e a classe 5 de `sys_info` são da
  T-337, dono sugerido).
- `unsafe-allowlist.toml` e `xtask check_unsafe` mudam em conjunto com a
  aprovação desta ADR (T-312 diz: "ADR aceita e allowlist atualizado
  conforme a decisão"). Esta ADR **não** os altera.
- Nova crate `lib/oalloc`; o workspace e a checagem de `unsafe` a
  incluem. Os testes dela sob Miri rodam só nos PRs que a alteram; o job
  noturno fica para depois.
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
2. **Decidido (2026-10-20):** orçamento de `unsafe` por módulo na
   `unsafe-allowlist.toml` e a crate `lib/oalloc` (altera a regra do
   `xtask check`; a mudança é da T-334).
3. **Decidido (2026-10-20):** `sys_info(classe 5)` público para
   entropia, em vez de distribuição pelo `root`, e o uso de BLAKE3
   chaveado como DRBG no kernel. ChaCha20 só se a `optcrypt` o ganhar por
   outro motivo.
4. **Decidido (2026-10-20):** `thread = 0` como "eu mesmo" em
   `thread_configure` e `EXIT_GROUP` em `thread_exit` (dois acréscimos de
   ABI), com o código de saída chegando ao registro de morte da ADR 0035.
5. **Decidido (2026-10-20):** serviços que dependem de criptografia
   recusam iniciar com entropia degradada.
6. **Decidido (2026-10-20):** `CR4.FSGSBASE` não é ligado no M3; a troca
   usa `WRMSR` só quando o valor muda (item 3).
7. **Decidido (2026-10-20):** Miri roda os testes da `lib/oalloc` só nos
   PRs que mudam essa crate. O job noturno fica para depois, e não se
   cria agora.
8. **Pendente:** ASLR de usuário (pilha, código, `mmap`) segue aberto;
   esta ADR dá a fonte de entropia e o heap aleatório, nada mais.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- A entropia passa a ser a classe 5 de `sys_info` (antes classe 4),
  incluindo a seção Consequências.
- `CR4.FSGSBASE` não é ligado no M3: a troca de contexto usa
  `WRMSR IA32_FS_BASE`, só quando o valor muda; se o bit for ligado um
  dia, o kernel também salva e restaura o `GS_BASE` de usuário. A seção
  Alternativas foi ajustada.
- Classes de tamanho lineares de 8 em 8 até 64 bytes e 4 por duplicação
  acima, com perda de no máximo 20% (antes "12,5%").
- `thread_exit` passa a ler o código em `rdi` e levá-lo ao registro de
  morte da ADR 0035.
- O `EXIT_GROUP` usa o `CapSpace` ao qual a thread está ligada, sem
  handle.
- `vm_map` e `vm_unmap` aceitam `aspace = 0` como o espaço da thread que
  chama.
- O `PageSource` acha a cota pelo `CapDesc` com `kind = 2` e
  `index = 0xFFFF` (ADR 0034).
- Miri: testes da `lib/oalloc` só nos PRs que mudam a crate; o job
  noturno fica para depois.
- Registrada a premissa do SipHash com chave de `fast()`.
- As decisões da seção final foram registradas como decididas.

### Revisão geral

- A lacuna "Pendente: ASLR de usuário" passa a ser a 8 (havia dois 6).
- O `EXIT_GROUP` grava a causa do processo na chamada, sem ser
  sobrescrito pelas mortes `Killed` das outras threads.
- O dono sugerido de `EXIT_GROUP`, `thread = 0` e `aspace = 0` é a T-333;
  o do DRBG e da classe 5 de `sys_info` é a T-337.
- A cota do processo é o `mem:quota` obrigatório do manifesto.

## Notas da implementação (T-334, 2026-10-20)

O que a T-334 fez diferente do texto acima ou acrescentou, sem mudar o
desenho:

- **Orçamento de `unsafe`.** Os tetos de partida foram ajustados ao uso real:
  `lib/ostd/src/arch` 7 (era 40), `lib/ostd/src/alloc` 8 (era 6) e
  `lib/oalloc` 64 (era 80; 44 no núcleo e 20 nos testes). Os caminhos `sync`,
  `tls` e `ring` entram no primeiro PR de cada módulo. O `xtask check` conta
  `unsafe` (bloco, `impl`, `fn`, `trait`, `extern`), recusa `unsafe` e
  `allow(unsafe_code)` fora dos caminhos do orçamento em `lib/ostd/src/**`,
  exige `// SAFETY:` em todo bloco e `impl`, `#![allow(unsafe_code)]` e a
  seção `# Unsafe` na raiz de cada módulo, e `#![deny(unsafe_code)]` na raiz
  da crate que só tem `unsafe` em módulos (`lib/ostd`).
- **`rt::init`.** O texto diz que `entry!` chama `rt::init`. Como o kernel
  entrega a cota e o espaço de endereços em posições diferentes por processo
  (`rdi`/`rsi` no `root` e no `utest`; juntos em `rsi` no `hello`), quem
  chama `ostd::rt::init(Env { quota, aspace })` é a função principal, antes
  da primeira alocação. Alocar antes aborta (encerra a thread, com uma linha
  no registro, até o `EXIT_GROUP` da T-333). O `aspace` em `Env` some com o
  `aspace = 0` da T-333.
- **Endurecimento.** Além do elo `endereço ^ chave` por página, um bitmap por
  página marca os blocos livres: a liberação dupla é detectada com
  exatidão, sem ler o conteúdo do bloco do usuário (que pode estar por
  inicializar), e um elo adulterado que aponte para bloco entregue também
  falha. O *canary* fica no cabeçalho do segmento (valor fixo mais um valor
  que depende do endereço e do segredo do `Global`). Um ponteiro fora da
  janela é recusado por `PageSource::owns` sem ser tocado. Liberação dupla
  entre threads é detectada quando o dono recolhe a `thread_free`.
- **Alinhamento.** Até 64 KiB (o início das páginas e dos blocos grandes);
  acima disso o pedido falha com nulo.
- **Heap global provisório.** Sem TLS (T-333) e sem threads do `ostd`
  (T-335), `ostd::alloc` usa um heap só atrás de um spinlock. O `oalloc` já
  é por thread; a T-335 liga um `Heap` por thread ao bloco da thread.
- **Endereço do segmento.** Contador a partir de 16 TiB na janela, sem
  sorteio e sem reaproveitar endereços (a entropia é da T-337).
- **Miri.** O CI não filtra `paths` por job; o job `miri` roda em todo PR e
  só instala o nightly e roda os testes se `git diff` contra a base tocar
  `lib/oalloc/`.

**Observação para decisão (não implementada).** A fragmentação medida
(`docs/bench/`) mostra que pedidos de 8 KiB a 64 KiB ocupam uma página
inteira de 64 KiB (perda de até 87%), porque as classes param em 8 KiB e os
blocos de várias páginas começam em 64 KiB. Numa carga de 8 B a 64 KiB a
perda de arredondamento chega a 120%. Opções: manter (alocações dessa faixa
são raras nos serviços do M3); estender as classes até 32 KiB (uma página
guarda 2 a 4 blocos; a sobra no fim da página chega a 25%); ou páginas
"médias" de 512 KiB como o mimalloc. Muda `MAX_SMALL` e a tabela de classes,
sem mudar a API.

## Notas da implementação (T-333, 2026-10-20)

O que a T-333 fez diferente do texto acima ou acrescentou, sem mudar o
desenho:

- **"Só quando o valor muda".** A troca compara o TLS da thread que entra
  com o valor que está na CPU (lido com `RDMSR`), não com o campo da thread
  que sai. O usuário muda o `FS_BASE` sem syscall ao carregar um seletor em
  FS (`mov fs, ax` zera a base), e a comparação com a thread que saiu
  deixaria a próxima com o mesmo TLS, até de outro processo, com base zero.
  O `WRMSR` continua só quando o valor difere.
- **TLS de outra thread.** Com a capability, `CONFIGURE_TLS` vale também
  para uma thread que roda noutra CPU; ela recebe o valor na próxima vez que
  entrar numa CPU. Na própria thread (por `thread = 0` ou pela capability
  dela) o kernel grava o `MSR` antes de voltar da syscall.
- **`thread = 0` com ligação.** `cspace` ou `aspace` diferentes de zero com
  `thread = 0` dão `InvalidArgument`.
- **`aspace = 0`** vale como capability com `MAP | UNMAP` (os direitos de
  um `AddressSpace` recém-criado). `vm_protect` não o aceita, como no item 2.
- **`EXIT_GROUP` ainda não.** O item 5 o define como o `DESTROY` do próprio
  `CapSpace` (ADR 0035, item 4), que é da T-348. Até lá `thread_exit` com
  `EXIT_GROUP` volta `NotSupported` (flags desconhecidas, `InvalidArgument`)
  e a thread segue; o `panic_handler` tenta o `EXIT_GROUP` e, recusado,
  encerra a thread com o código `"pani"`. O código de `thread_exit` já vai
  ao registro de morte da thread (`Exited`), e a falta fatal grava
  `Faulted`; a leitura por `sys_info` (classe 2) e o registro do processo
  são da T-348.
- **`ostd`.** `rt::Env` ficou só com a cota. Há `thread::set_tls`,
  `thread::exit_with`, `thread::exit_group`, `thread::SELF` e `vm::SELF`;
  ler o TLS e o bloco da thread ficam para a T-335, com o módulo `tls`.

## Notas da implementação (T-335, 2026-10-20)

- **`CONFIGURE_BIND_SELF`.** O item 3 diz que ligar `CapSpace`/`AddressSpace`
  continua exigindo a capability, mas nenhum serviço guarda capability do
  próprio `CapSpace` ou `AddressSpace` (ciclo de referências), então
  `thread::spawn` não teria como ligar a thread nova. `thread_configure` ganhou
  a flag `kabi::thread::CONFIGURE_BIND_SELF` (`1 << 3`): com a capability da
  thread alvo (`WRITE_STATE`) e `cspace = aspace = 0`, o alvo inativo passa a
  rodar no `CapSpace` e no `AddressSpace` de quem chama. Quem chama já tem
  poder sobre os dois, então nada novo é concedido.
  Aceita por Eduardo em 2026-10-20 como exceção ao item 3 (PR #68).
- **`thread_local!`.** O índice do slot vem de um contador global, atribuído no
  primeiro acesso, e não da posição de um descritor em `.ostd_tls_desc`; o
  `user.ld` não mudou. Contrato igual (tabela de slots no bloco, valor criado
  no primeiro acesso e destruído na saída da thread), com limite de 32 chaves.
- **Bloco e pilha.** O bloco ocupa páginas inteiras e tem o buffer de IPC como
  última página; o de `spawn` fica no mesmo `MemoryObject` da pilha, acima
  dela, e a página de guarda abaixo da pilha nunca é mapeada.
- **Heap por thread.** Sem o spinlock global; a `KernelSource` mantém uma
  trava só para os endereços da janela. A thread que sai roda os destrutores do
  `thread_local!` e devolve o heap; cada thread que aloca toma pelo menos um
  segmento de 2 MiB da cota.
- **`unsafe`.** `lib/ostd/src/tls` = 23 (a ADR previa 10) e `arch` = 9.
- **Fim de thread.** Sem notificação de morte (T-348), `join` espera uma flag
  do bloco que a thread grava num bloco de assembly sem pilha; thread que morre
  por falta ou pânico não é juntável até a T-348.
