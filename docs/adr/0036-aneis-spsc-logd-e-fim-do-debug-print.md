# ADR 0036: Anéis SPSC, log estruturado, `logd` e fim do `DEBUG_PRINT`

- Status: proposta (aguarda aprovação de Eduardo)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.7, 7.1, 7.3, 14.2 e 17.3; backlog do M3, T-309
- Relaciona-se com: ADR 0007 (anéis SPSC), ADR 0033 (OIDL), ADR 0034
  (svcmgr), ADR 0035 (Timer, `obj_bind_notify`), T-339, T-355 a T-357

## Contexto

A 6.7 diz que dados em volume usam "anéis SPSC em MemoryObject
compartilhado com Notification para despertar", mas não define layout,
protocolo de despertar, nem o que acontece quando o anel enche. O `logd`
(7.3) é o primeiro consumidor: "logs estruturados em anéis por serviço".
Hoje os processos escrevem com `kabi::DEBUG_PRINT` (0x8000_0000), uma
syscall fora da ABI v1 que qualquer thread pode chamar sem capability, até
64 bytes por vez, direto na serial (`kthread.rs::debug_print`). A 14.2 já
prevê `debug_write` (nº 0) "só com cap de debug". A `ntfy_signal` faz OR de
`bits | badge` (não mascara), e o log do kernel (`klog.rs`) escreve na
serial COM1 sob um spinlock.

## Decisão

### 1. Anel SPSC genérico (`ostd::ring`)

Um anel é um `MemoryObject` mapeado `READ|WRITE` pelos dois lados, um
produtor e um consumidor. Layout (little-endian; cada grupo em sua linha
de cache de 64 bytes):

```
Página 0 (cabeçalho)
  0   magic       u32   "ORNG"
  4   version     u16   1
  6   kind        u16   1 = log; outros reservados à ADR do protocolo
  8   data_len    u32   potência de 2, múltiplo de 4096, ≤ 16 MiB
  12  flags       u32   bit 0: política "descartar novos" (única na v1)
  64  tail        u64   produtor: bytes escritos desde o início (monótono)
  72  dropped     u64   produtor: registros descartados (monótono)
  80  shed        u64   produtor: registros omitidos por marca-d'água
  128 head        u64   consumidor: bytes consumidos (monótono)
  136 waiting     u32   consumidor: 1 = vai dormir
Páginas 1..: dados (data_len bytes)
```

- Posição no anel = `contador & (data_len − 1)`. Livre = `data_len − (tail −
  head)`.
- **Registro:** `len: u32` (bytes de carga útil), `kind: u16` (0 =
  enchimento, 1 = log, demais por protocolo), `flags: u16`, seguido da
  carga útil, tudo arredondado a 8 bytes. Um registro **nunca atravessa**
  o fim do vetor: se não couber até o fim, o produtor grava um registro de
  enchimento (`kind` 0) que ocupa o resto e recomeça em 0. Carga útil
  ≤ 4096 − 8 bytes na v1.
- **Produtor:** (1) lê `head` com `Acquire`; se `tail − head > data_len`
  ou `head` regrediu, o anel é inválido: para de escrever e conta; (2)
  se faltar espaço, incrementa `dropped` (política "descartar novos") e
  retorna; (3) escreve o registro; (4) `tail.store(novo, Release)`; (5)
  fence `SeqCst`; (6) se `waiting == 1`, chama `ntfy_signal`.
- **Consumidor:** (1) `tail.load(Acquire)`; valida `tail − head ≤
  data_len`; (2) para cada registro: confere `len` (alinhado, dentro de
  `tail`, sem atravessar o fim), `kind` conhecido; registro inválido
  marca o anel como corrompido, descarta tudo até `tail` e conta; (3)
  `head.store(novo, Release)`. Para dormir: `waiting = 1`, fence
  `SeqCst`, reler `tail`; se mudou, `waiting = 0` e continua; senão
  `ntfy_wait`; ao acordar `waiting = 0`. O par de fences `SeqCst` do
  produtor e do consumidor impede o despertar perdido (é o padrão Dekker
  clássico; o modelo `Ring.tla`, abaixo, o confere).
- Cada lado trata os campos do outro como **não confiáveis** (o par pode
  ser um serviço comprometido). Nada neste protocolo faz o kernel
  depender do conteúdo do anel.
- `Notification`: um por consumidor, com um bit por anel. O consumidor
  entrega ao produtor uma capability `SIGNAL` com o **badge** do bit
  daquele anel (`cap_mint`). Como `ntfy_signal` faz `bits | badge`, o
  produtor pode acordar o consumidor, mas não impedir o bit correto de
  subir; bits extras são tratados como despertar espúrio (o consumidor
  varre todos os anéis). Mudar `ntfy_signal` para mascarar pelo badge
  seria mais forte (decisão de Eduardo, abaixo).
- Marcas-d'água do produtor (`kind` log): acima de 7/8 cheio, omite
  `Debug` e `Trace` (conta em `shed`); acima de 15/16, só `Error` passa.
  Assim `Error` quase sempre cabe.
- Operação segura: o acesso à memória compartilhada fica atrás de
  `Producer`/`Consumer` do `ostd::ring` (módulo com `unsafe` pequeno,
  ADR 0039); nenhuma API exporta ponteiros.

### 2. Registro de log (`kind` 1)

Carga útil, little-endian, ≤ 1024 bytes:

```
 0  ts_ns   u64   clock_get (monotônico) no produtor
 8  level   u8    1 error, 2 warn, 3 info, 4 debug, 5 trace  (= okernel::log::Level)
 9  nfields u8    ≤ 8
 10 tid     u16   id lógico da thread no serviço
 12 msg_len u16   ≤ 512 (UTF-8)
 14 _       u16   0
 16 mensagem (msg_len bytes)
    campos: nfields × { key_len u8, key (≤ 32), tipo u8, valor }
      tipo 0: string (len u16 + bytes)  1: u64  2: i64  3: bool (u8)
```

O produtor não envia nome do serviço: o anel já identifica o serviço (o
`logd` o registrou, item 3). Número de sequência por serviço é a posição no
anel; o `logd` acrescenta um `seq` global crescente.

### 3. Interface `optimus.log.Log@1` (OIDL, ADR 0033)

```
package optimus.log @1.0;
struct Ring { ring: handle<MemoryObject>, notify: handle<Notification> }
struct Line { seq: u64, ts_ns: u64, level: u8, tid: u16,
              service: string<31>, text: string<512> }
struct LinePage { lines: vec<Line, 6>, next_seq: u64, lost: u64 }
enum LogError : u8 { AccessDenied, TooMany, NotFound, Busy }
interface Log {
    register(ring_pages: u16) -> result<Ring, LogError>;
    query(service: string<31>, max_level: u8, since_seq: u64)
        -> result<LinePage, LogError>;
    set_level(service: string<31>, max_level: u8) -> result<(), LogError>;
}
```

- `register`: cria o anel (`MemoryObject` da cota do `logd`, `ring_pages`
  entre 4 e 256, padrão 16 + 1 de cabeçalho), `READ|WRITE|MAP` para os
  dois lados, sem `EXEC`; o `logd` guarda a primeira cópia, entrega a
  segunda e a capability `SIGNAL` com badge. O `logd` identifica o
  cliente pelo badge do `Endpoint` (ADR 0034) e chama
  `Supervisor.name_of(id)` no `svcmgr` (item adicional ao ADR 0034) para
  obter o nome. **Um anel por serviço** (segundo `register` do mesmo
  serviço devolve o mesmo anel ou `Busy`); no máximo 64 anéis.
- `query`: devolve as últimas linhas desde `since_seq`, filtradas por
  serviço (vazio = todos) e nível; `lost` conta as linhas descartadas no
  intervalo (dos anéis e da rotação em memória). Só serviços com
  capability `SEND` de `Log` chegam; **`query` exige** que o badge do
  cliente esteja numa lista de leitores do manifesto do `logd` (M3:
  `rescue` e `svcmgr`); senão `AccessDenied`.
- `set_level`: nível máximo aceito de um serviço (o produtor lê o limite
  num campo `flags` do cabeçalho, em versão posterior); no M3 o `logd`
  apenas filtra na ingestão.

### 4. `logd` (M3)

- Um `Notification`, um laço: `ntfy_wait`, varre os anéis, converte
  registros em linhas, dá `seq`, guarda em **rotação em memória** por
  serviço (padrão 256 KiB de linhas por serviço, 4 MiB no total; a mais
  antiga cai) e escreve a linha na serial (via `debug_write`, item 5) com
  prefixo `<nível> [<serviço>] mensagem k=v`.
- **Sem persistência** no M3: `/data/log` depende do OptFS (7.3). O
  consumidor persistente virá depois sem mudar o protocolo.
- Descartes viram linhas sintéticas de nível `warn` do próprio `logd`
  (`"<serviço>: N registros perdidos"`), no máximo uma por segundo por
  serviço.
- O alerta de reinícios (7.2) vira linha de nível `error` do `svcmgr`
  (cliente normal do `logd`); o consumidor de alertas do `auditd` é
  posterior.
- Log do kernel (T-357): ver item 6.

### 5. Fim do `DEBUG_PRINT`: capability de depuração

- Novo tipo de objeto do kernel `DebugLog` (`ObjectType = 15`; `Timer`
  é 14, ADR 0035). Só o kernel o cria, no boot (como `Interrupt`; `obj_create`
  o recusa) e o entrega ao `root` entre as capabilities iniciais (na
  extensão do pacote de `rdx`/`rdi` da ADR 0029, ou por uma segunda
  mensagem de partida; a definir no T-355). Direitos: `WRITE`
  (`debug_write`), `READ` (mapear o anel do kernel, item 6) e `BIND`.
- **`debug_write(log, ptr, len, nível)`** (syscall 0, já na tabela):
  `rdi` handle, `rsi` ponteiro, `rdx` bytes (≤ 256), `r10` nível (1 a 5).
  Exige `WRITE`. O kernel escreve `nível [badge hex] texto` no log do
  kernel; o **badge da capability** identifica quem escreveu (o `svcmgr`
  deriva cada cópia com `cap_mint` e badge = id do serviço; não se
  falsifica a origem). Texto não-UTF-8 é recusado (`InvalidArgument`).
- **Quem recebe a capability:** `root` → `svcmgr` (`kernel:debug` no pool,
  ADR 0034) → só serviços que a pedem no manifesto: no M3 `logd` (para a
  serial) e, até o `logd` subir, o `hello` e o próprio `root` (saída
  de boot). Os demais usam `ostd::log` + `Log`.
- **`DEBUG_PRINT` (0x8000_0000)** sai da imagem de produção: o kernel só
  o compila com a feature `ktest-debug` (ligada em `xtask test kernel`
  e `fuzz`, onde os programas de usuário em assembly dependem dele). Nas
  imagens normais o número devolve `NotSupported`. `kabi::DEBUG_PRINT`
  fica documentado como "só testes".
- **Passos (T-355):** (1) `DebugLog` + `debug_write` + testes de
  `AccessDenied`; (2) `ostd::debug` troca o destino; (3) `root`/`hello`
  migram; (4) feature `ktest-debug`; (5) `okfuzz` sem regressão.

### 6. Log do kernel para o `logd`

- O kernel mantém um anel próprio (`MemoryObject` de 64 KiB, alocado no
  boot e cobrado de uma cota do kernel) com os mesmos registros do item 2
  e `tid = 0xFFFF`. O produtor é "o kernel" sob o lock do `klog`; a
  política é **sobrescrever o mais antigo** (o kernel nunca espera nem
  confia no consumidor). Por isso o anel do kernel é de **leitura**
  para o `logd` (`READ|MAP`), que guarda sua posição fora do anel e
  detecta perda comparando `seq` do registro e `tail`
  (seqlock: reler `tail` depois de ler o registro; se o registro foi
  coberto, descarta e conta).
- Despertar: `obj_bind_notify(debuglog, ntfy, bits)` (ADR 0035
  estendido ao `DebugLog`) sinaliza quando o anel passa de vazio a não
  vazio (no máximo uma vez por milissegundo).
- O kernel **continua** escrevendo na serial (necessário para pânico e
  boot). O `logd` **não** reimprime linhas do kernel na serial; só as
  guarda para consulta.

### 7. Verificação

- `Ring.tla`: modelo do protocolo de despertar (produtor, consumidor,
  `waiting`) mostrando que nenhum despertar se perde, e mutação que remove
  a fence e quebra a invariante.
- Alvos de fuzzing: decodificador de registro e consumidor de anel (o
  produtor é adversário).
- Testes: 10⁷ registros entre dois processos em CPUs distintas sem
  perda nem reordenação, descarte contado quando cheio (T-339); 5
  serviços × 10⁵ linhas (T-356).

## Alternativas

- **Anel com sobrescrita do mais antigo também nos serviços:** o produtor
  nunca perde o último, mas o consumidor teria de ler com seqlock de um
  par possivelmente hostil e o `head` deixaria de existir. Mantido só
  para o kernel, onde o produtor é confiável.
- **Um anel único MPSC no `logd`:** exige sincronização entre produtores
  não confiáveis; um serviço ruidoso afeta os outros. Um anel por serviço
  isola descartes.
- **Log por IPC (`ipc_send` por linha):** uma troca de contexto por
  linha; o caminho rápido não é para isso, e o `logd` ocuparia a CPU.
- **Dois `MemoryObject`s (dados do produtor RO para o consumidor, `head`
  do consumidor RO para o produtor):** impede um lado de escrever nos
  campos do outro, ao custo de duas capabilities e mapeamentos por anel.
  Não adotado no M3 porque cada lado já valida; reavaliar para o `auditd`.
- **Manter `DEBUG_PRINT` e só limitar a taxa:** continua uma syscall sem
  capability, contra 4.3 e 17.1.
- **`DebugLog` como `IoPortRange` da COM1:** funcionaria no x86, mas
  exige máscara de E/S no TSS e não existe no ARM.

## Consequências

- A ABI ganha o tipo `DebugLog` (15) e o uso de `debug_write` (syscall 0,
  sem número novo); `kabi` ganha `debug::{MAX_BYTES, ...}` e `ring::{
  Header, Record}` (layout compartilhado por `ostd` e `logd`).
- O texto de log nunca passa por alocação no `ostd::log`: formata numa
  pilha de até 512 bytes e copia para o anel.
- O sistema tem dois destinos de serial: o kernel (direto) e o `logd`
  (por `debug_write`); ambos passam pelo lock do `klog`, então as linhas
  não se misturam por caractere.
- Atacar o `logd` por um produtor comprometido se limita ao seu anel; o
  pior caso é perder as linhas dele.
- Sem persistência, o log é perdido em reinício do `logd` (o kernel
  guarda o anel dele; o `logd` relê o que sobrou).

## Fora do escopo

Persistência e rotação em disco; `auditd`; assinatura de linhas; formato
de transporte para rede; filtros por campo; níveis por serviço aplicados
no produtor; anel MPSC; qualquer outro `kind` além de log.

## Lacunas do SDD e decisões para Eduardo

1. **Resolvidas aqui:** layout do anel, protocolo de despertar, política
   de overflow, formato do registro, substituição do `DEBUG_PRINT`.
2. **Decisão de Eduardo:** novo `ObjectType::DebugLog` para a capability
   de `debug_write` (a 14.2 só diz "cap de debug"; a 6.1 não tem o tipo).
3. **Decisão de Eduardo:** `ntfy_signal` passar a **mascarar** os bits
   pelo badge quando o badge é diferente de zero, no lugar do OR atual
   (mudança de semântica já testada em T-209).
4. **Decisão de Eduardo:** `query` restrito a uma lista de leitores
   (`rescue`, `svcmgr`) no M3.
5. **Decisão de Eduardo:** política "descartar novos" com marcas-d'água
   para os serviços e "sobrescrever" só para o kernel.
6. **Dependência:** a ADR 0034 ganha `Supervisor.name_of(id: u32)
   -> result<string<31>, SvcError>`, restrito a quem tem `kernel:`-pool
   ou o papel de `logd` no manifesto.
