# ADR 0033: Gramática e formato de fio do OIDL

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 4.3, 6.7, 14.3 e 17.3; backlog do M3, T-306
- Relaciona-se com: ADR 0007 (IPC), ADR 0012 (OIDL e `oidlc`), ADR 0027
  (registradores de IPC), ADR 0034 (manifesto e descoberta), T-340 a T-347

## Contexto

A ADR 0012 manda que toda chamada entre processos passe por uma interface
`.oidl` e promete "layout fixo, little-endian", mas o SDD (14.3) não dá
gramática nem formato de fio. Faltam: alinhamento, representação de `string`,
`vec`, enums e `result<>`; como o método é identificado; como o erro volta;
onde ficam os `handle<T>`; o que acontece com dados maiores que o buffer de
IPC. Isso bloqueia `lib/oidl-rt`, o `oidlc` e todo serviço (T-340 em diante).

O que o kernel já fixa (ADR 0027 e `kabi::ipc`): rótulo de 64 bits; até 6
palavras em registradores (`r8`, `r9`, `r12`–`r15`); até 504 palavras no
buffer de IPC (4 KiB menos 64 bytes de cabeçalho); até 4 capabilities; badge
do remetente em `rdi` na saída de `ipc_recv`. O kernel não interpreta nada
disso.

Um problema do próprio exemplo do SDD: `list(path: string<4096>) ->
result<vec<DirEntry, 4096>, FsError>` não cabe numa mensagem. O pedido já tem
4096 bytes de caminho (o limite de uma mensagem é 4032 bytes), e a resposta
teria mais de um megabyte.

## Decisão

### 1. Gramática (resumo; a EBNF completa vai em `docs/spec/oidl.md` no T-341)

```
arquivo     = "package" nome "@" versao ";" { decl } ;
versao      = inteiro "." inteiro ;                  (* maior.menor *)
decl        = "type" id "=" tipo ";"                 (* apelido *)
            | "enum" id ":" ("u8"|"u16"|"u32") "{" id ["=" n] {"," id ["=" n]} "}"
            | "flags" id ":" ("u8"|"u16"|"u32") "{" id "=" n {"," ...} "}"
            | "struct" id "{" campo {"," campo} "}"
            | "interface" id "{" { metodo } "}" ;
metodo      = { anotacao } ["oneway"] id "(" [campo {"," campo}] ")"
              ["->" "result" "<" (tipo|"()") "," tipo ">"] ";" ;
anotacao    = "@tool" "(" "risk" "=" ("R0".."R4") "," "desc" "=" texto ")" ;
tipo        = "u8".."u64" | "i8".."i64" | "bool" | id
            | "string" "<" N ">" | "vec" "<" tipo "," N ">"
            | "handle" "<" id ">" ;
```

- Tipos primitivos: `u8`, `u16`, `u32`, `u64`, `i8`, `i16`, `i32`, `i64`,
  `bool`. Não há `f32`/`f64` na v1 (nenhum serviço do M3 precisa; entram
  numa versão menor do `oidlc` se aparecerem).
- Todo `string<N>` e `vec<T, N>` exige N literal (limite obrigatório, como
  na 14.3). `string` é UTF-8 validado; `N` conta bytes.
- `enum` e `flags` declaram o tipo-base. Valor de enum fora do conjunto
  declarado e bit de `flags` não declarado são `BadMessage` na decodificação.
- `Timestamp` é um apelido predefinido no pacote `optimus.core`:
  `i64`, nanossegundos desde 1970-01-01 UTC (hora de parede do `timed`).
  O SDD usa o nome sem defini-lo. O pacote `optimus.core` é o arquivo
  `idl/optimus.core.oidl`, versionado e visível, e não um texto embutido
  no `oidlc`.
- `oneway` marca um método sem resposta (vira `ipc_send`) e não tem `->`.
  Todo outro método DEVE declarar `-> result<T, E>`.
- `@tool` é obrigatório em todo método exposto à IA e não afeta o fio.
- `handle<T>` só aparece como parâmetro ou como campo da estrutura que é
  diretamente o tipo de topo do resultado; nunca em `struct` aninhada nem
  em `vec`. `T` é uma interface do mesmo pacote ou de outro
  (`optimus.fs.File`) ou um tipo de objeto do kernel pré-declarado em
  `optimus.kernel`: `MemoryObject`, `Notification`, `Endpoint`, `Reply`,
  `MemoryQuota`, `CapSpace`, `AddressSpace`, `Thread`, `SchedContext`.

### 2. Identificação do método: o rótulo de 64 bits

```
 63            32 31          16 15           0
+----------------+--------------+--------------+
| interface_id   | minor_min    | método       |
+----------------+--------------+--------------+
```

- `interface_id`: 32 bits baixos (little-endian, primeiros quatro bytes) de
  `BLAKE3("<pacote>.<Interface>@<maior>")`, em UTF-8 sem terminador. Exemplo:
  `BLAKE3("optimus.fs.Directory@1")` começa por `bb d8 7c a1 ...`, então
  `interface_id = 0xA17C_D8BB`. O `oidlc` calcula e grava a constante no
  código gerado; dois ids iguais no conjunto de interfaces compiladas são
  erro de compilação. A versão **maior** entra no hash, então `@1` e `@2`
  convivem no mesmo endpoint. A checagem do `oidlc` só enxerga as
  interfaces compiladas juntas, e um serviço de terceiros pode colidir
  com outro. Por isso o `svcmgr` recusa, no registro (ADR 0034), dois
  serviços com o mesmo `interface_id` e nomes de interface diferentes.
- `método`: ordinal da declaração dentro da interface, a partir de 0.
  Método novo só entra no fim da interface (a regra "métodos novos só em
  versão menor" da 14.3 fica verificável). Remover ou reordenar é mudança
  de versão maior.
- `minor_min`: a versão menor em que o método nasceu. O servidor devolve
  `VersionTooOld` se sua versão menor for menor que `minor_min`.

Rótulo da **resposta**:

```
 63 62 61            16 15           0
+-----+----------------+--------------+
| tipo|     zero       |   código     |
+-----+----------------+--------------+
```

`tipo` 0 = `Ok` (corpo é o tipo T), 1 = `Err` (corpo é o tipo E; `código`
zero), 2 = erro de protocolo (corpo vazio; `código` abaixo), 3 = reservado.
Códigos: 1 `UnknownInterface`, 2 `UnknownMethod`, 3 `VersionTooOld`, 4
`BadMessage`, 5 `TooLarge`, 6 `Overloaded`, 7 `Internal`. Os erros do kernel
(`PeerClosed`, `TimedOut`, `Revoked` etc.) não viajam no rótulo; saem da
própria syscall.

### 3. Corpo: layout

O corpo de um pedido é a estrutura dos parâmetros, na ordem da declaração;
o de uma resposta é T ou E. Regras:

1. Little-endian. Cada campo fica no menor deslocamento múltiplo do seu
   alinhamento; alinhamento = tamanho para inteiros, 1 para `bool` (0 ou 1;
   outro valor é `BadMessage`), o do tipo-base para `enum`/`flags`, o maior
   alinhamento dos campos para `struct` (tamanho arredondado a ele). A ordem
   é a da declaração, sem reordenar.
2. **Cabeça e cauda.** A cabeça é a estrutura de topo com tamanho estático.
   `string<N>` ocupa na cabeça um **ponteiro** de 8 bytes (alinhamento 4):
   `desloc: u32` (a partir do início do corpo) e `len: u32` (bytes).
   `vec<T, N>` idem, com `len` = número de elementos. Os bytes apontados
   ficam na **cauda**, depois da cabeça.
3. **Cauda canônica.** O decodificador percorre os ponteiros em pré-ordem
   (cabeça em ordem de campo; ao achar um `vec`, lê a região dele e depois
   os ponteiros dos elementos, em ordem) mantendo um cursor que começa no
   fim da cabeça. Cada região começa em `desloc == cursor` (alinhado a 8
   bytes, com zeros de enchimento) e o cursor avança `len × tamanho`
   arredondado a 8. Região fora desse lugar, sobreposta, voltando atrás ou
   além do fim do corpo é `BadMessage`. Assim a decodificação é uma passada
   só, sem ciclos nem sobreposição, e o corpo codificado de um valor é
   único (útil para fuzz diferencial e testes de ida e volta).
4. O enchimento (entre campos, no fim de região e no fim do corpo, que é
   arredondado a 8 bytes) é zero ao escrever e **ignorado** ao ler.
5. `result<T, E>` só existe no retorno de método; vive no rótulo da
   resposta (seção 2), não no corpo. `result<(), E>` tem `Ok` com corpo
   vazio.
6. `vec<T, N>` aceita qualquer `T` de tamanho fixo e também `T` com
   ponteiros (um `DirEntry` com `string`); a profundidade é limitada pelo
   tipo, que é finito.

### 4. Corpo no transporte

Seja L o tamanho do corpo em bytes (múltiplo de 8).

- L ≤ 48: as L/8 palavras vão em registradores (`info.words = L/8`,
  `info.buffer_words = 0`).
- 48 < L ≤ 4032: todas as palavras vão no buffer de IPC
  (`info.words = 0`, `info.buffer_words = L/8`).
- L > 4032: o `oidlc` recusa, em tempo de compilação, qualquer método cujo
  tamanho **máximo** calculado pelos limites declarados passe de 4032 bytes,
  somando cabeça, cauda e enchimento. Não há fragmentação nem desvio
  automático para `MemoryObject` na v1. O servidor que receber mais do que
  declarou responde `TooLarge`.

`handle<T>` não ocupa bytes no corpo. As capabilities vão no cabeçalho do
buffer de IPC (`info.caps`, no máximo 4) na ordem em que os `handle`
aparecem na declaração. O `oidlc` recusa, em tempo de compilação, o
método que declare mais de 4 `handle` (somando os do pedido ou os do
resultado), que é o limite de `info.caps`. Quem recebe confere por
`cap_info` que o objeto é
um `Endpoint` (ou o tipo do kernel declarado); senão `BadMessage`. O kernel
exige `GRANT` no endpoint por onde passam.

### 5. Dados grandes

Há três caminhos, escolhidos por quem escreve a interface:

1. **Paginação explícita**: a resposta devolve `vec<T, N>` pequeno e um
   cursor `u64`; o cliente chama de novo.
2. **Região compartilhada**: o método recebe ou devolve
   `handle<MemoryObject>` mais um `len: u64`; o protocolo diz quem escreve
   e quem lê.
3. **Anel SPSC** (ADR 0036) para fluxos contínuos.

O exemplo do SDD vira, em `idl/optimus.fs.oidl`:

```
package optimus.fs @1.0;

struct DirEntry { name: string<255>, kind: EntryKind, size: u64, modified: Timestamp }
struct DirPage  { entries: vec<DirEntry, 8>, next: u64 }
enum EntryKind : u8 { File, Dir, Link }
enum FsError : u8 { NotFound, NotDirectory, Io }

interface Directory {
    @tool(risk = R0, desc = "Lista o conteúdo de uma pasta")
    list(path: string<1024>, cursor: u64) -> result<DirPage, FsError>;

    @tool(risk = R2, desc = "Move um item para a lixeira")
    trash(path: string<1024>) -> result<(), FsError>;

    open(path: string<1024>, flags: OpenFlags) -> result<handle<File>, FsError>;
}
```

Tamanho máximo de `list`: pedido 16 + 1024; resposta 16 + 8×32 +
8×256 = 2320 bytes. Ambos cabem. `string<4096>` não cabe (4104 bytes), e a
própria ADR 0011 diz que não há caminho global; capabilities de diretório
tornam o caminho relativo, e 1024 sobra.

### 6. Vetores dourados

`interface_id` de `optimus.fs.Directory@1` = `0xA17C_D8BB` (calculado com a
BLAKE3 de referência; o teste do `oidlc` DEVE refazer a conta). Todas as
palavras abaixo são `u64` little-endian.

`trash("/a/b")`: método 1.
- rótulo `0xA17C_D8BB_0000_0001`, `info.words = 2`.
- corpo (16 bytes): cabeça `desloc = 8` (u32), `len = 4` (u32); cauda
  `2f 61 2f 62 00 00 00 00`.
- palavras: `0x0000_0004_0000_0008`, `0x0000_0000_622f_612f`.

Resposta `Err(NotDirectory)` (valor 1 do enum de `u8`):
- rótulo `0x4000_0000_0000_0000`, `info.words = 1`, palavra
  `0x0000_0000_0000_0001`.

Resposta `Ok(())` de `trash`: rótulo `0`, `info.words = 0`.

`list("/d", 0)`: método 0.
- rótulo `0xA17C_D8BB_0000_0000`, `info.words = 3`.
- cabeça (16 bytes): `path = {desloc 16, len 2}`, `cursor = 0`; cauda
  `2f 64` + 6 zeros.
- palavras: `0x0000_0002_0000_0010`, `0x0`, `0x0000_0000_0000_642f`.

Resposta `Ok(DirPage{ entries: [ {name:"ab", kind:File, size:300,
modified:1_700_000_000_000_000_000} ], next: 0 })`, 56 bytes, vai no buffer
(`info.words = 0`, `info.buffer_words = 7`), rótulo 0:
```
w0 0x0000_0001_0000_0010   entries = {desloc 16, count 1}
w1 0x0000_0000_0000_0000   next = 0
w2 0x0000_0002_0000_0030   entrada 0: name = {desloc 48, len 2}
w3 0x0000_0000_0000_0001   kind = File (u8), enchimento
w4 0x0000_0000_0000_012c   size = 300
w5 0x1797_9cfe_362a_0000   modified
w6 0x0000_0000_0000_6261   cauda: "ab" + zeros
```

### 7. Código gerado e erros no cliente

O servidor gerado recebe `ipc_recv`, confere `interface_id` e `minor_min`,
decodifica com validação total (limites, UTF-8, enums, cauda canônica) e só
então chama o método do trait; o badge chega ao método como `Context`.
O cliente gerado devolve `Result<T, CallError<E>>` com `CallError` =
`Remote(E)` | `Protocol(ProtoError)` | `Kernel(kabi::Error)`. Nenhum
`panic!` na decodificação: tudo é `Result` (17.1). Sem alocação no
caminho de códigos gerados cujos limites são estáticos (os tipos usam
`heapless`-style próprios do `oidl-rt`).

### 8. Evolução (semver)

- Versão menor: pode acrescentar método ao fim da interface, tipo novo, e
  variante nova de `enum` **somente** em `enum` marcado `open` (leitor que
  não conhece o valor o recebe como `Unknown(n)`). Nada mais muda.
- Versão maior: qualquer outra mudança. Interface nova com id novo;
  `svcmgr` aceita servir as duas (ADR 0034).
- `oidlc check-compat velha.oidl nova.oidl` implementa isso (T-342).

## Alternativas

- **Rótulo = hash do nome do método:** não precisa de ordem de
  declaração, mas colide e não carrega a versão. O ordinal com
  `minor_min` dá erro de versão preciso.
- **Tudo inline, tamanho fixo no máximo (sem cauda):** o mais simples,
  mas `string<255>` num `DirEntry` custaria 256 bytes por entrada mesmo
  para nomes curtos, estourando o buffer.
- **Ponteiros relativos estilo Cap'n Proto, com listas aninhadas e
  ponteiros livres:** mais expressivo, mas o validador precisa tratar
  ciclos e sobreposição. A cauda canônica de passada única é bem mais
  simples de provar e de fuzzar.
- **Desvio automático para `MemoryObject` quando passa do buffer:**
  esconde um custo de syscalls e de cota no código gerado. Fica explícito
  no protocolo.
- **Codificação variável (varint/protobuf):** ADR 0012 já recusou.

## Consequências

- `lib/oidl-rt` é pequeno: cursor de leitura e escrita, validação de
  cauda canônica, UTF-8, enums.
- O decodificador é um alvo de fuzzing natural (17.3), com a propriedade
  `encode(decode(x)) == x` para todo `x` aceito.
- Dois testes entram além dos vetores dourados: um do `svcmgr`, que recusa
  o registro de dois serviços com o mesmo `interface_id` e nomes
  diferentes, e um do `oidlc`, que recusa o método com mais de 4
  `handle`.
- O tamanho máximo de toda mensagem é conhecido em compilação; nenhum
  método pode estourar o buffer.
- O exemplo do SDD (14.3) não compila como está: `string<4096>` e
  `vec<DirEntry, 4096>` passam de 4032 bytes. O SDD ganha o exemplo do
  item 5 na próxima revisão.
- `handle<T>` fora de topo (por exemplo, `vec<handle<File>, 4>`) não é
  possível na v1; para listar vários, o método devolve um por vez.
- Cada interface gasta 32 bits do rótulo de `interface_id`: um mesmo
  endpoint pode servir várias interfaces e versões maiores.

## Fora do escopo

Ponto flutuante; `option<T>`; mapas; unions; streaming do `oidlc`;
fragmentação automática; AArch64 (mesmo formato, ADR 0027 já iguala as seis
palavras); o texto completo da EBNF (T-341).

## Lacunas do SDD e decisões para Eduardo

1. **Resolvida aqui:** gramática, rótulo, corpo, erros, `handle<T>`.
2. **Decidido (2026-10-20):** alterar o exemplo da 14.3 (`string<1024>`,
   `DirPage`) em vez de aumentar o buffer de IPC. O buffer de duas páginas
   mudaria a ABI (ADR 0027) e encareceria todo thread.
3. **Decidido (2026-10-20):** `Timestamp` como `i64` em ns UTC, e o
   `optimus.core` como arquivo `idl/optimus.core.oidl`.
4. **Decidido (2026-10-20):** `interface_id` de 32 bits por BLAKE3
   truncada, com colisão detectada na compilação e, para serviços de
   terceiros, conferida também no registro do `svcmgr`.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- O `svcmgr` recusa, no registro, dois serviços com o mesmo `interface_id`
  e nomes diferentes (novo teste).
- O `oidlc` recusa método com mais de 4 `handle` (novo teste).
- `optimus.core` fica decidido como arquivo `idl/optimus.core.oidl`.
- As decisões da seção final foram registradas como decididas.
