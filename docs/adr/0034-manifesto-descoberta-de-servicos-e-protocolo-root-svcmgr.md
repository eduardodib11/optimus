# ADR 0034: Manifesto binário, descoberta de serviços e protocolo root/svcmgr

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 4.3, 5.3, 7.2, 13, 14.4 e 18; backlog do M3, T-307
- Relaciona-se com: ADR 0011 (sem namespace global), ADR 0018 (assinaturas
  híbridas), ADR 0029 (criação de processos pelo usuário), ADR 0033 (OIDL),
  ADR 0035 (ciclo de vida), T-350 a T-354

## Contexto

O SDD diz que o `root` reparte as capabilities iniciais, que o `svcmgr`
lê manifestos assinados, resolve dependências e entrega a cada serviço só o
que o manifesto lista (4.3, 7.2). O exemplo da 14.4 usa nomes como
`dev:net/*`, `log:write`, `time:read` e `mem:quota:32MiB` sem dizer que
capability cada um vira nem quem a emite. (Esta ADR troca `log:write` e
`time:read` por `svc:`, ver item 5.) Não há namespace global (ADR
0011), então "descoberta" tem de ser um corretor de capabilities. O SDD
também não define o formato do "TOML compilado para binário" nem quem o
compila, e exige assinatura quando a `optcrypt` só tem BLAKE3 (Ed25519 e
ML-DSA-65 estão nas ADRs 0004 e 0018, sem marco no M3).

Estado do código: o `root` carrega o `hello` do bootfs pelo `ostd::process`
(ADR 0029) e cria processos com `cap_mint` entre `CapSpace`s. O bootfs
(OBFS v1) tem cabeçalho e entradas de 128 bytes, nomes de até 64 bytes, até
1024 entradas, hash BLAKE3 por entrada.

## Decisão

### 1. Quem faz o quê

- **`root`** (TCB): único processo que recebe do kernel as capabilities
  iniciais (cota raiz, bootfs, e as que vierem: capability de debug, ADR
  0036; interrupções). Cria processos e divide cotas **somente** a pedido do
  `svcmgr`. Fala OIDL, interface `optimus.root.Root@1`, num `Endpoint` que
  ele mesmo cria.
- **`svcmgr`** (TCB): lê os manifestos, monta o grafo, pede ao `root` os
  processos, entrega capabilities, supervisiona (ADR 0035) e é o corretor
  de descoberta. Nenhum outro serviço fala com o `root`.
- **Identidade pelo badge.** O `root` entrega ao `svcmgr` uma capability
  `SEND` do endpoint do `root` com badge `1`; ele recusa (`AccessDenied`
  no protocolo, ver abaixo) qualquer mensagem com outro badge. Como o
  `svcmgr` é o único que tem capability para esse endpoint, o badge é só
  defesa em profundidade.
- **Prioridade.** O `root` e o `svcmgr` rodam numa prioridade fixa acima
  da faixa dos serviços (1 a 199): 200, constante em `services/root`.
  Assim a supervisão não espera um serviço que fique girando.

### 2. Partida do svcmgr

O `root` lê `svc/svcmgr` do bootfs, cria o processo e, no `CapSpace` dele,
coloca: o endpoint do `root` (badge 1), um `MemoryObject` do bootfs só com
`READ|MAP`, uma cota de partida (fixa, 8 MiB no M3; constante em
`services/root`), e as capabilities de origem do kernel (**kernel pool**)
na ordem em que o `root` as recebeu. O `svcmgr` descobre os handles por um
descritor (item 5). A partir daí o `root` só fica em `ipc_recv` no seu
endpoint.

### 3. Interface `optimus.root.Root@1`

```
package optimus.root @1.0;
interface Root {
    split_quota(bytes: u64) -> result<handle<MemoryQuota>, RootError>;
    spawn(binary: string<63>, quota: handle<MemoryQuota>,
          priority: u8, max_threads: u16) -> result<Spawned, RootError>;
    set_exception(child: u32, ep: handle<Endpoint>) -> result<(), RootError>;
    start(child: u32, a0: u64, a1: u64) -> result<(), RootError>;
    reap(child: u32) -> result<(), RootError>;
}
struct Spawned { child: u32, cspace: handle<CapSpace>, thread: handle<Thread> }
enum RootError : u8 { AccessDenied, NoSuchBinary, QuotaExceeded, Busy, Io }
```

- `split_quota` debita da cota-pool do `root` (tudo menos a reserva do
  `svcmgr`); o `root` nunca devolve mais do que o pool tem.
- `spawn` carrega o ELF `binary` (nome OBFS), cria `CapSpace`
  (com `max_threads`, ADR 0035), `AddressSpace`, pilha, thread e
  `SchedContext` com `priority`, **sem iniciar**. Devolve o `CapSpace`
  (`MANAGE|BIND|DESTROY`) e a `Thread` (`READ_STATE|SUSPEND|BIND`, sem
  `START`; direitos de ciclo de vida da ADR 0035) como
  capabilities da resposta (2 de no máximo 4) e o `child` que o `root`
  guarda.
- `set_exception` entrega ao filho, antes de `start`, o endpoint de
  exceções (em geral uma capability do `memd` com badge = id do processo,
  ADR 0038); o `root` a coloca no `CapSpace` do filho e a registra em
  `thread_configure`.
- `start` é o único jeito de iniciar: o `root` chama `thread_start` com
  `a0` e `a1` (`a0` = handle, no `CapSpace` do filho, do canal de controle
  do item 5). O `svcmgr` só chama `start` depois de entregar as caps.
- `reap` libera as estruturas do `root` de um filho morto.
- O `root` valida que `binary` existe no bootfs e que o `hash BLAKE3` da
  entrada confere (`obfs::verify`) antes de mapear.

### 4. Manifesto binário (`OMAN` v1)

Fonte: `services/<nome>/manifest.toml` no formato da 14.4, com este
subconjunto de TOML (sem tabelas inline nem datas): `[service]`
(`name`, `binary`, `priority`, `restart`), `[capabilities]` (`needs`,
`provides`), `[limits]` (`max_threads`, `ipc_rate`). O compilador é a
ferramenta de host `tools/mkmanifest` (T-350), que usa um parser TOML
externo permitido pelo SDD 16.2 (ferramenta de host, `cargo-vet`); a
saída é binária, determinística (mesma entrada, mesmos bytes) e vai no
bootfs como `manifest/<nome>.oman`. O mesmo compilador recebe **todos** os
manifestos, verifica o grafo acíclico, os nomes, os limites e recusa o
build se algo falhar (4.3: "grafo acíclico verificado no build").

Layout (tudo little-endian; referências a texto são `{off: u32, len: u32}`
a partir do início do arquivo; textos UTF-8 na região de cadeias, alinhada
a 4):

```
Cabeçalho (96 bytes)
  0  magic        [u8;4]  "OMAN"
  4  version      u32     1
  8  total_len    u32     bytes do arquivo, inclusive assinatura
  12 flags        u32     0 (reservado)
  16 name         ref     [a-z0-9-]{1,31}
  24 binary       ref     nome OBFS, ex.: "svc/netd" (≤ 63 bytes)
  32 binary_hash  [u8;32] BLAKE3 do ELF
  64 priority     u16     1..=199 no M3
  66 restart      u8      0 always, 1 on-failure, 2 never
  67 _reservado   u8      0
  68 max_threads  u16     1..=1024
  70 _reservado   u16     0
  72 ipc_rate     u32     mensagens por segundo (0 = sem limite)
  76 needs_n      u16     ≤ 64
  78 provides_n   u16     ≤ 32 (needs_n + provides_n ≤ 94)
  80 needs_off    u32     alinhado a 8
  84 provides_off u32     alinhado a 8
  88 sig_off      u32     0 se sem assinatura
  92 sig_len      u16     bytes da assinatura
  94 sig_alg      u16     0 nenhuma; 1 Ed25519+ML-DSA-65 (ADR 0018)
Registro de need (24 bytes)
  0  kind   u8   1 svc, 2 mem, 3 dev, 4 fs, 5 kernel
  1  flags  u8   bit 0: opcional (aresta "fraca", não ordena a partida)
  2  minor  u16  versão menor mínima (kind 1)
  4  major  u16  versão maior (kind 1)
  6  _      u16  0
  8  name   ref  interface (kind 1), classe/padrão (3), id (4), nome (5)
  16 value  u64  bytes (kind 2), máscara de direitos (3, 4, 5)
Registro de provide (16 bytes)
  0  major  u16
  2  minor  u16
  4  _      u32  0
  8  name   ref  "pacote.Interface", ex.: "optimus.log.Log"
```

Limites: arquivo ≤ 4096 bytes; `needs_n + provides_n ≤ 94`, para que o
descritor de partida (item 6) caiba com o canal de controle e a cota; campos
reservados DEVEM ser zero (o leitor
recusa, para a v2 poder usá-los); toda `ref` dentro do arquivo; `total_len`
igual ao tamanho da entrada OBFS. `svcmgr` revalida tudo ao carregar (o
leitor é um alvo de fuzzing, 17.3), inclusive a ausência de ciclo.

### 5. Nomes de capability: o que cada `needs` vira

| Entrada TOML | `kind` | Capability entregue | Emitida por |
|---|---|---|---|
| `svc:optimus.log.Log@1` (ou `.2` = menor mínima) | 1 | `Endpoint` com `SEND`, badge = id do cliente | `svcmgr` (derivado do endpoint do provedor) |
| `mem:quota:32MiB` | 2 | `MemoryQuota` com `CREATE|SPLIT` e esse orçamento | `root`, pedido pelo `svcmgr` |
| `dev:net/*` | 3 | MMIO, `Interrupt` e `DmaDomain` do padrão | `devmgr` (**não existe no M3**) |
| `fs:<dir>[:ro|:rw]` | 4 | `Endpoint` de diretório (ADR 0011) | `storaged`/`optfs` (**fora do M3**) |
| `kernel:debug`, `kernel:mem-pressure` | 5 | capability de origem do kernel (`DebugLog`, `Interrupt` de pressão; ADRs 0036 e 0038) | `root` (do kernel pool) |

Não há apelidos: cada coisa tem um nome só. Os nomes `log:write` e
`time:read` do exemplo do SDD (14.4) viram `svc:optimus.log.Log@1` e
`svc:optimus.time.Clock@1`, e o `mkmanifest` recusa os nomes antigos
como desconhecidos. O exemplo da 14.4 ganha essa troca na próxima
revisão do SDD. No M3, `dev:` e `fs:` compilam, mas o `svcmgr` recusa
iniciar o serviço
que os pede (`NotSupported` no log): evita rodar com menos privilégio do
que o manifesto diz e mascarar erro.

`provides` lista `pacote.Interface@maior.menor`. Para cada uma, o
`svcmgr` cria um `Endpoint` com `obj_create` debitando a cota do
**serviço** (ele a tem em mãos, vinda de `split_quota`, antes de
entregá-la) e entrega ao provedor a capability completa
(`RECV|SEND|GRANT`); a raiz de derivação para os clientes fica com o
`svcmgr`.

### 6. Descritor de partida e canal de controle

Para cada serviço, antes de `start`, o `svcmgr` faz `cap_mint` (ADR 0029)
dentro do `CapSpace` do filho, na ordem: canal de controle (`Endpoint` do
`svcmgr`, badge = id do serviço), cota, `needs` e `provides`. A cota do
processo ganha um `CapDesc` próprio, com `kind = 2` e `index = 0xFFFF`,
para o `ostd` achá-la sem adivinhar (ADR 0039). Os handles
resultantes são conhecidos do `svcmgr` (retorno de `cap_mint`). O filho
recebe em `rdi` o handle do canal de controle e chama:

```
package optimus.svc @1.0;
interface Supervisor {
    bootstrap() -> result<Boot, SvcError>;                  // descritor
    ready() -> result<(), SvcError>;                        // fim da partida
    connect(interface: u32, minor: u16)
        -> result<handle<Endpoint>, SvcError>;              // lazy / reconexão
    name_of(id: u32) -> result<string<31>, SvcError>;       // id do badge -> nome
}
interface Control {      // só para quem o manifesto autoriza (memd no M3)
    kill(process: u32, reason: u8) -> result<(), SvcError>;
}
struct CapDesc { kind: u8, index: u16, handle: u32, name_hash: u32 }
struct Boot { caps: vec<CapDesc, 96>, generation: u16 }
enum SvcError : u8 { NotInManifest, NotRunning, VersionTooOld, Busy }
```

`CapDesc.handle` é o handle já presente no `CapSpace` do filho
(`index` = posição em `needs`/`provides`, ou `0xFFFF` para a cota do
processo); `name_hash` = `interface_id` da ADR 0033. Um `CapDesc` tem
12 bytes pelo layout da ADR 0033 (`kind` em 0, `index` em 2, `handle`
em 4, `name_hash` em 8). O manifesto aceita até 64 `needs` e 32
`provides`, com `needs + provides ≤ 94`; somados o canal de controle e a
cota, são até 96 capabilities, e o descritor cabe numa mensagem
(96 × 12 + 16 = 1168 < 4032).
`name_of` só atende serviços que o manifesto do `svcmgr` marca como
consumidores de nomes (`logd`); `Control.kill` só atende o `memd`. `connect` serve a reconexão depois de `PeerClosed` e as dependências
`opcional`; só atende o que está em `needs` (`NotInManifest` senão, que no
kabi corresponde a `AccessDenied` para o chamador do kernel quando for
syscall).

### 7. Ordem e estados de partida

Estados: `Pending` → `Spawned` → `Starting` → `Running` →
(`Failed` | `Stopped`). Aresta de dependência: A `needs svc:X` e B
`provides X` ⇒ B antes de A, salvo `opcional`. A partida é por camadas do
grafo; serviços independentes sobem em paralelo. Um serviço está
`Running` quando chama `ready()`. Se um provedor não fica `Running` em 5 s
(constante do `svcmgr`), o cliente espera mais 5 s e é marcado `Failed`
(registra erro; reinício segundo a política, ADR 0035).

### 8. Badge

`badge` do cliente = `(generation << 32) | id`, `id` = índice do serviço no
conjunto de manifestos compilado, `generation` = 16 bits que contam
reinícios do cliente. O provedor lê o badge de `ipc_recv` e o repassa ao
método gerado como `Context`; o provedor decide autorização por `id`.

### 9. Reinício e revogação

Quando um provedor morre (ADR 0035), o `svcmgr` faz `cap_revoke` na
capability-raiz do endpoint dele (os clientes recebem `PeerClosed`/
`Revoked`), apaga a raiz (destruindo o `Endpoint`), pede ao `root` um novo
processo (`reap`, `spawn`) e repete o item 6; os clientes chamam
`connect` e recebem o novo endpoint. A mesma regra vale quando um
**cliente** morre: nenhuma capability dele sobrevive, porque seu `CapSpace`
é destruído (ADR 0035).

### 10. Assinatura no M3 (caminho provisório)

- A seção 4.3 e a 14.4 pedem manifesto assinado. A `optcrypt` só tem BLAKE3
  no M3; Ed25519 e ML-DSA-65 chegam em marco posterior (ADRs 0004, 0018).
- **Regra do M3:** a autenticidade do manifesto vem do bootfs, cuja imagem
  o `optboot` confere (hash, depois assinatura quando houver). Cada
  manifesto tem `binary_hash` (BLAKE3 do ELF), o `root` confere a entrada
  OBFS no `spawn`, e o `svcmgr` confere que `binary_hash` é o hash da
  entrada (ligando manifesto a binário). `sig_alg = 0`. O `svcmgr` aceita
  manifesto sem assinatura **somente** se leu da cópia do bootfs que o
  `root` lhe deu e **somente** se o build do sistema tiver
  `--features trusted-bootfs`, ligada no M3.
- **Promoção:** quando o `optboot` e a `optcrypt` verificarem as duas
  assinaturas, a feature `trusted-bootfs` sai, o `mkmanifest sign` passa
  a preencher `sig_off/sig_len/sig_alg = 1` (assinatura sobre o BLAKE3 do
  arquivo sem a cauda de assinatura), e o `svcmgr` recusa `sig_alg = 0`.
  O formato já reserva o espaço, então não muda de versão.
- **Limite honesto:** no M3 "assinado" significa "íntegro dentro de um
  bootfs verificado"; não há identificação do autor por manifesto e não
  há revogação de chave. Um bootfs adulterado antes do `optboot` conferir
  não é detectado pelo manifesto.

## Alternativas

- **Namespace global de nomes (`/svc/log`):** contraria a ADR 0011.
- **Cada serviço pede ao `root` o que precisa:** o `root` teria de saber
  as políticas de todos; contraria o desenho (`root` só responde ao
  `svcmgr`).
- **Endpoint criado pelo próprio provedor e registrado depois:** o
  provedor seria quem escolhe seu nome; o `svcmgr` não conseguiria
  garantir que o cliente fala com o provedor autorizado.
- **Manifesto em TOML dentro da imagem, interpretado no `svcmgr`:** parser
  de texto na TCB; o binário compilado em host reduz a superfície.
- **Esperar o ML-DSA e o Ed25519 para o M3:** bloquearia o `svcmgr` por um
  marco que o SDD ainda não agenda.

## Consequências

- `svcmgr` e `root` ficam pequenos e com contratos OIDL; ambos são TCB
  (revisão dupla, seção 17.2).
- Os endpoints de um serviço saem da cota dele; a ABI de `cap_mint` com
  destino (ADR 0029) basta para entregar cota e capabilities.
- `kabi` não muda; `ostd` ganha o cliente `Supervisor` e `idl/` ganha
  `optimus.root.oidl` e `optimus.svc.oidl`.
- O formato `OMAN` fica pronto para a assinatura sem nova versão.

## Fora do escopo

`devmgr`, `dev:` e `fs:` funcionais; manifestos vindos da imagem `.osi`;
vários processos do mesmo serviço; realms; medição de perfil no primeiro
boot (15.4); atualização de manifesto em execução; `ipc_rate` aplicado
(ADR 0035).

## Lacunas do SDD e decisões para Eduardo

1. **Resolvidas aqui:** formato do manifesto, quem compila, mapa de nomes
   para capabilities, protocolo root/svcmgr, badge, descoberta.
2. **Decidido (2026-10-20):** o caminho provisório de assinatura (item 10)
   e o nome `trusted-bootfs` para a feature. A promoção torna-se
   obrigatória antes da primeira imagem distribuída, junto com a ADR 0018.
3. **Decidido (2026-10-20):** sem apelidos. O exemplo da 14.4 troca
   `log:write` e `time:read` por `svc:`.
4. **Decidido (2026-10-20):** o serviço paga o `Endpoint` do provedor. A
   cota fixa de 8 MiB do `svcmgr` não cresce com o número de serviços.
5. **Decidido (2026-10-20):** faixa de prioridade aceita pelo compilador
   de 1 a 199 no M3 (200+ para drivers e 240+ para tempo real só com
   flag). O `root` e o `svcmgr` rodam em 200.
6. **Decidido (2026-10-20):** `ipc_rate` fica no formato, sem imposição no
   M3 (ADR 0035).

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- O vetor de `Boot.caps` passa de 64 para 96 `CapDesc`, e o manifesto
  exige `needs + provides ≤ 94`.
- O texto corrige o tamanho do `CapDesc` para 12 bytes (a conta passa a ser
  96 × 12 + 16).
- A cota do processo ganha um `CapDesc` próprio (`kind = 2`,
  `index = 0xFFFF`).
- O `root` e o `svcmgr` rodam em prioridade 200, acima da faixa dos
  serviços.
- Os apelidos `log:write` e `time:read` saem; o exemplo da 14.4 usa
  `svc:`, e a tabela `aliases.toml` deixa de existir.
- As decisões da seção final foram registradas como decididas.
- `name_of` continua como está; a ADR 0036 deixa de pedi-lo como item
  adicional.
