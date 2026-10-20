# ADR 0038: `memd`, paginação em espaço de usuário e memória comprimida

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.1, 6.3, 6.4, 7.3 e 14.2; backlog do M3, T-311
- Relaciona-se com: ADR 0006 (alocação cobrada de cota), ADR 0007, ADR 0029,
  ADR 0031 (shootdown, futura), ADR 0033, ADR 0034, ADR 0035, T-360 a T-364

## Contexto

A 6.3 diz que "o kernel não pagina a si mesmo" e a 6.4 que "o kernel não
resolve faltas de usuário: envia mensagem ao endpoint de exceções da
thread; o `memd` ou o supervisor resolve, mapeia ou encerra o processo". A
7.3 dá ao `memd` três funções: resolver faltas, memória comprimida (LZ4) sob
pressão e mapeamento de arquivos. Falta o que o `memd` precisa do kernel:

- Hoje um `MemoryObject` nasce com **todos** os frames, zerados e
  cobrados (`vm.rs`). Não existe página "ainda não comprometida".
- `mem_op` (syscall 9) tem só o nome na tabela ("commit, zero, cache"),
  sem registradores nem semântica, e nada descomprometer ou retirar páginas.
- Não há sinal de pressão de memória.
- O `memd` não pode retirar mapeamentos de terceiros: não tem a
  `AddressSpace` dos clientes e o objeto não conhece suas regiões
  (as regiões referenciam o objeto, não o contrário).
- Mapeamento de arquivos exige `storaged` e OptFS, posteriores ao M3.

A solução precisa caber nas 34 syscalls da ABI v1.

## Decisão

### 1. Memória gerenciada: `MemoryObject` preguiçoso

- `obj_create(quota, MemoryObject, tamanho, flags)` (flags em `r10`, zero
  = comportamento de hoje): bit 0 `LAZY`. Um objeto `LAZY` nasce com todas
  as páginas **Absent** (sem frame). A cota é debitada na criação só pelos
  metadados (estado por página e vetor de frames, ≈ 9 bytes por página).
- Estado de cada página de um objeto: **Absent** (sem frame),
  **Hidden** (com frame zerado ou preenchido, mapeado só em visões `RAW`)
  e **Present** (com frame, visível em todos os mapeamentos).
  Objetos sem `LAZY` são sempre Present.
- Novo direito `Rights::EVICT` (bit 22): comprometer/ocultar/liberar
  páginas e ler o bit de acesso. `Rights::ALL` passa a `(1 << 23) - 1`
  (o bit 21 é o `DESTROY` da ADR 0035; se este PR vier antes, ele reserva
  o bit 21 mesmo assim).
  Um objeto `LAZY` nasce com `EVICT` entre os direitos do criador, que
  pode derivar cópias sem ele (`cap_mint`).
- `vm_map` ganha o bit de flag `RAW` (`kabi::vm::RAW = 1 << 2`): a região
  enxerga páginas Hidden e Present. Exige `EVICT` na capability do
  objeto e é recusada com `EXEC`. `ALL_FLAGS` passa a incluir `RAW`.
- O objeto passa a conhecer suas regiões (lista de pares
  `AddressSpace` fraca, endereço, comprimento, `RAW`). Isso custa uma
  entrada por mapeamento, cobrada da cota do espaço.

### 2. `mem_op` (syscall 9)

`mem_op(obj, op, offset, len, flags)` nos registradores `rdi`, `rsi`,
`rdx`, `r10`, `r8`. `offset` e `len` em bytes, múltiplos de 4096. Retorno:
`[valor, 0, 0]`.

| `op` | Nome | Efeito | Direito |
|---|---|---|---|
| 0 | `COMMIT` | Absent → Hidden (zerada). Com `flags & PUBLISH` (1), vai a Present e instala as entradas de página nos mapeamentos normais e `RAW`. Já comprometida: nada. Debita a cota dona do objeto. | `WRITE` |
| 1 | `ZERO` | zera o intervalo (qualquer estado comprometido). | `WRITE` |
| 2 | `CACHE` | atributo de cache (`flags`); `NotSupported` no M3. | `WRITE` |
| 3 | `PUBLISH` | Hidden → Present (instala nos mapeamentos normais). | `EVICT` |
| 4 | `HIDE` | Present → Hidden: remove das visões normais, **só retorna depois do shootdown completo**; o frame fica. | `EVICT` |
| 5 | `DECOMMIT` | Hidden → Absent (Present é primeiro ocultado): remove também das visões `RAW`, shootdown, libera o frame e credita a cota dona. | `EVICT` |
| 6 | `AGE` | até 64 páginas de `offset`: devolve em `valor` o mapa de bits das páginas Present com bit de acesso (A) ligado e **limpa** esses bits (com invalidação de TLB). | `EVICT` |

Erros: `InvalidArgument` (alinhamento, fora do objeto, `len` > 64
páginas em `AGE`, op desconhecida), `QuotaExceeded` (cota dona sem bytes),
`AccessDenied`, `WrongType`. Todas as operações sobre intervalo são
fatiadas e preemptíveis (ADR 0009): o progresso fica no objeto e a syscall
é retomada; `COMMIT` e `DECOMMIT` são idempotentes por página.

**Invariantes:**
1. Um frame só volta ao buddy depois que toda CPU que possa ter a tradução
   no TLB confirmou a invalidação (ADR 0031). Sem janela de acesso obsoleto.
2. Após `HIDE` retornar, nenhuma CPU acessa a página por visão normal.
3. Página Hidden nunca aparece numa visão normal; Present aparece em todas.
4. Bytes debitados = frames comprometidos × 4096 + metadados; destruir o
   objeto credita o que restar.
5. A cota debitada é a do **dono** do objeto (guardada na criação), não a
   de quem chama `mem_op`. Quem tem `WRITE`/`EVICT` não gasta a própria
   cota, e quem cria um objeto `LAZY` fixa o teto de memória física que ele
   pode ter Present+Hidden.

### 3. Falta de página e resolução

- O kernel continua a mandar a mensagem de falta (`kabi::fault`) ao
  endpoint de exceções da thread, sem alterá-la. A falta de página em
  região de objeto `LAZY` em página não Present usa o mesmo caminho.
- O `memd` é o tratador padrão: `svcmgr` configura o endpoint de exceções
  do processo com uma capability do `memd` de **badge = id do processo**
  (método `Root.set_exception` da ADR 0034, chamado antes de `start`;
  `Root.spawn` não ganha parâmetro novo). O badge diz de qual processo é
  a falta; a mensagem tem o endereço.
- Fluxo demand-zero: `memd` acha a região pelo endereço, calcula o
  deslocamento no objeto e faz `COMMIT(obj, off, 4096, PUBLISH)`,
  depois responde com `REPLY_RESUME`. Uma resposta com outro rótulo
  encerra a thread (comportamento atual).
- Fluxo de restauração: página Absent que o `memd` guardou comprimida:
  (1) `COMMIT` sem `PUBLISH` (Hidden, zerada); (2) descomprime na visão
  `RAW` que o `memd` tem do objeto; (3) confere o hash; (4) `PUBLISH`; (5)
  `REPLY_RESUME`. Outra thread do mesmo processo não vê a página
  meio preenchida: enquanto Hidden, ela falta e fica na fila do `memd`.
- Acesso fora de qualquer região registrada, endereço < 64 KiB ou acesso
  proibido (escrita em região RO, execução fora de EXEC): resposta sem
  `RESUME`, o `memd` conta e avisa o `svcmgr` (item 6), que encerra o
  processo (`cap_delete` com `DESTROY`, ADR 0035).
- **Crescimento de pilha:** uma região `Stack` aceita faltas até o limite
  de reserva registrado; a página de guarda abaixo dela **não** pertence
  a nenhuma região.

### 4. Interface `optimus.mem.Mem@1` (OIDL, ADR 0033)

```
package optimus.mem @1.0;
enum RegionKind : u8 { Heap, Stack, Anon }
struct Region { object: handle<MemoryObject>, base: u64, len: u64,
                kind: RegionKind, max_compressed: u64 }
enum MemError : u8 { AccessDenied, InvalidArgument, TooMany, Busy }
interface Mem {
    manage(r: Region) -> result<u32, MemError>;     // id da região
    unmanage(id: u32) -> result<(), MemError>;
}
```
- O cliente é o próprio processo, identificado pelo badge (id do processo
  atribuído pelo `svcmgr`). `manage` confere por `cap_info` que `object` é
  `MemoryObject` com `READ|WRITE|MAP|EVICT`; o cliente garante que mapeou
  o objeto em `base`. Mentir só prejudica o próprio cliente (faltas fora
  da tabela viram encerramento).
- Limites: 64 regiões por processo, 1024 no `memd`.
- `unmanage` volta o controle ao cliente (o `memd` descomprime tudo que
  tiver antes de devolver `Ok`, ou devolve `Busy`).

### 5. Pressão de memória

- O kernel cria dois objetos `Interrupt` sintéticos no boot e os dá ao
  `root` (que os passa a quem tem `kernel:mem-pressure` no manifesto):
  **baixa** (quadros livres < 1/8 do total) e **crítica** (< 1/32). Como
  qualquer `Interrupt`, ligam-se a uma `Notification` com
  `obj_bind_notify` e ficam mascarados até `irq_ack`; um novo `ack` com a
  condição ainda verdadeira dispara de novo. Histerese: a baixa rearma ao
  passar de livres > total/8 + total/16, e a crítica ao passar de
  livres > total/32 + total/64.
- Contagem de "livres": desde a T-328 os frames também ficam nos caches
  por CPU. Os limiares e o `sys_info` contam como livres os frames do
  buddy **e** os dos caches por CPU, porque ambos atendem uma alocação
  sem trabalho do `memd`. A leitura dos caches é aproximada (sem travar
  as outras CPUs), o que basta para limiares de 1/8 e 1/32.
- `sys_info(classe 3)` devolve `[quadros_totais, quadros_livres,
  quadros_comprometidos_de_objetos_lazy]`, sem capability (dados sem
  segredo). A classe 1 é a de CPUs (ADR 0032) e a 2 é a morte (ADR 0035).
- Os limiares (1/8, 1/32) são constantes do kernel no M3; ajustáveis
  depois por uma classe de `sys_info` ou `sched_configure`.

### 6. `memd` (T-361, T-364) e política

- **Estado:** tabela de regiões por processo; por página de objeto
  gerenciado, o estado do `memd` (`resident`, `compressed {classe, slot,
  tamanho, hash}`). Hash: 8 primeiros bytes de BLAKE3 do conteúdo
  original (`optcrypt`).
- **LRU aproximado (relógio):** sob pressão **baixa**, varre objetos
  gerenciados em ordem crescente de prioridade do processo (fundo
  primeiro), usa `AGE` em lotes de 64 páginas, e escolhe as páginas
  sem acesso desde a última volta. Limpar o bit de acesso com
  invalidação de TLB a cada lote de 64 páginas é caro em SMP. Uma variante
  sem invalidação, que aceita alguma imprecisão como o Linux faz, pode
  entrar depois se a T-367 mostrar o custo do `AGE`.
- **Despejo de uma página:** `HIDE` → copia da visão `RAW` e comprime
  (`olz4`, formato de blocos do LZ4 de referência, T-362) → se o resultado
  ≤ 3072 bytes, guarda no repositório e faz `DECOMMIT`; senão
  desiste (página "incompressível" volta a `PUBLISH` e sai da lista por
  um período). O repositório do `memd` são páginas próprias (cota do
  `memd`) divididas em classes de 512, 1024, 2048 e 3072 bytes.
- **Auto-paginação:** se `COMMIT` dá `QuotaExceeded`, o `memd` despeja
  uma página do **mesmo processo** (a mais fria) e repete. O total
  comprimido por processo respeita `max_compressed` de `manage`; passou
  disso, o `memd` recusa e a falta resulta em encerramento do processo.
- **Pressão crítica:** o `memd` para de despejar para quem já tem muito
  comprimido, registra `error` no `logd` e pede ao `svcmgr`
  (`Control.kill(process, reason)`, restrito pelo manifesto ao `memd`) o
  encerramento do serviço **reiniciável** de menor prioridade que mais
  consome. Não há OOM-killer no kernel.
- **Segurança:** o `memd` vê o conteúdo de toda memória gerenciada. O
  registro é **opcional**: `keyd`, `authd` e processos com segredos não
  o usam. O repositório guarda páginas sem criptografia no M3 (decisão de
  Eduardo abaixo). Após restaurar, o `memd` zera o espaço.
- Prioridade do `memd`: 190 (serviço de sistema alto), para atender faltas
  antes das aplicações; seu orçamento de CPU limita o despejo. **Premissa
  não conferida no código:** a falta vira um `ipc_call` em nome da thread
  (`fault.rs`), e a prioridade só vale para as faltas se esse `ipc_call`
  doar o `SchedContext` ao tratador, como o `ipc_call` comum. Com a
  doação, o `memd` atende cada falta na prioridade de quem faltou e os
  190 valem só para o despejo. Sem a doação, um serviço entre 191 e 199
  que gire pode atrasar as faltas de todos. Conferir isso é o primeiro
  teste da T-360.

### 7. Fora do escopo do M3

Mapeamento de arquivos e arquivos como páginas (`storaged`/OptFS), swap em
disco, compartilhamento de páginas (KSM), páginas grandes (2 MiB) em
objetos gerenciados, NUMA no despejo, criptografia do repositório,
resolução de falta sem `memd` dentro do kernel (otimização possível se o
T-367 mostrar custo alto de falta), `CACHE` real, `dma_map` com objetos
`LAZY`, ASLR de usuário.

## Alternativas

- **Kernel resolve demand-zero sozinho (como Linux):** evita um IPC por
  falta, mas põe política de memória no kernel e contraria a 6.4. Pode
  voltar como otimização medida.
- **`memd` com a `AddressSpace` de cada cliente (`vm_unmap` direto):** o
  `memd` precisaria de `UNMAP` em todos os espaços, ampliando muito seu
  poder; o direito `EVICT` por objeto o limita ao que os clientes
  registraram.
- **Syscalls novas (`vm_evict`, `vm_commit`):** quebram as 34 da ABI v1.
  `mem_op` já existe na tabela e foi pensada para isso.
- **Estado Hidden ausente (COMMIT + cópia + mapeamento direto):** deixa
  outra thread do cliente ver página meio restaurada.
- **Sinal de pressão por nova `Notification` do kernel:** exigiria
  syscall ou tipo novo; um `Interrupt` sintético usa a ligação existente
  e o `ack` de rearme.
- **Pressão por `sys_info` com sondagem:** o `memd` consumiria CPU e
  responderia tarde.

## Consequências

- `kabi`: `Rights::EVICT`, `vm::RAW`, `mem::{COMMIT, ZERO, CACHE,
  PUBLISH, HIDE, DECOMMIT, AGE, PUBLISH_FLAG}`, flag `LAZY` e classe 3 de
  `sys_info`. A 14.2 e a 6.1 do SDD recebem os registradores.
- O objeto `MemoryObject` fica mais complexo (estado por página, lista de
  regiões) e o `vm_unmap`/destruição de espaço precisam tirar a região da
  lista do objeto: nova fonte de corrida, a incluir no `CapRevoke.tla` e
  no estresse (T-329). `HIDE`/`DECOMMIT` dependem do shootdown do T-326
  e entram depois dele (T-363).
- Falta de página custa 2 trocas de contexto e 3 syscalls; aceitável no
  M3 (meta de latência medida em T-367).
- O `memd` entra na TCB funcional de confidencialidade da memória
  gerenciada; ver item 6.
- O teste de aceite "carga 1,5× a cota física sem OOM" só é possível se
  o `memd` tiver cota própria suficiente para o repositório; a ADR
  dimensiona-a pelo `max_compressed`.

## Lacunas do SDD e decisões para Eduardo

1. **Resolvidas aqui:** semântica de `mem_op`, comprometimento sob
   demanda, retirada de mapeamento por objeto, sinal de pressão, protocolo
   de falta e de restauração.
2. **Decidido (2026-10-20):** `EVICT` (bit 22), `vm_map` com `RAW` e
   objeto `LAZY` (três acréscimos de ABI), e a semântica "o dono do
   objeto paga". Sem ela, o `memd` gastaria a própria cota com a memória
   dos outros.
3. **Decidido (2026-10-20):** pressão por dois `Interrupt` sintéticos e
   os limiares 1/8 e 1/32, com a histerese do nível crítico definida.
4. **Decidido (2026-10-20):** repositório comprimido **sem** criptografia
   no M3. O `memd` guardaria a chave e veria o conteúdo de qualquer jeito,
   então cifrar custaria CPU por página sem proteger de quem lê.
5. **Decidido (2026-10-20):** política de OOM (`Control.kill` de serviço
   reiniciável de menor prioridade) e a prioridade 190 do `memd`, esta
   sujeita à premissa de doação de fatia registrada no item 6.
6. **Pendente:** mapeamento de arquivos permanece sem desenho até o
   `storaged`/OptFS.
7. **Dependência:** ADR 0031 precisa garantir "ack antes de liberar frame"
   (invariante 1; pronto desde a T-326); a ADR 0034 já define
   `Root.set_exception` e `Control.kill`; ADR 0035 define `DESTROY`.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- O texto cita `Root.set_exception` da ADR 0034 em vez de um parâmetro
  `exception` em `Root.spawn`.
- A histerese do nível crítico é definida (livres > total/32 + total/64).
- A contagem de quadros livres passa a dizer que inclui os caches por CPU
  (T-328).
- O custo do `AGE` em SMP é registrado, com uma variante sem invalidação
  para depois da T-367.
- A pressão e a memória passam para a classe 3 de `sys_info`.
- Registrado que a prioridade 190 do `memd` supõe doação de fatia na falta
  de página, a conferir como primeiro teste da T-360.
- As decisões da seção final foram registradas como decididas.
