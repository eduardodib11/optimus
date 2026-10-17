# Especificações TLA+ do okernel (T-008)

Modelos iniciais de capabilities e IPC do Optimus OS, conforme o SDD v1.0
(§6.2, §6.7, §14.2) e as ADRs 0001 e 0007.

## CapRevoke.tla

Modela dois CapSpaces (slots 1..N/2 e N/2+1..N numa só numeração, `space[s]`
diz o dono) e a árvore de derivação entre eles (ADR 0028): `obj_create` (cap
raiz com todos os direitos), `cap_mint` (filho local com direitos ⊆ do pai),
`Transfer` (cópia por IPC, exige GRANT, vira **filha remota** da original),
`cap_delete` e `cap_revoke` fatiado e preemptível (`RevokeStart`, `RevokeStep`
apaga uma folha descendente, local ou remota, por vez, `RevokeEnd`).

`cap_delete` normal sobe os filhos para o avô. Se o slot tem filho remoto (ou
é cópia remota com filhos), vira **marcador**: `marker[s]`, sem direitos nem
handle utilizável, mas preso na árvore até os descendentes sumirem
(`ReapMarker` o libera então; `cap_revoke` também apaga marcadores folha).
Há várias revogações simultâneas (`revoking` é conjunto): apagar a cópia que
está em revogação encerra aquela revogação. Mint, transferência e nova
revogação dentro de qualquer subárvore em revogação (através dos CapSpaces)
são recusados (`Busy`), assim como delete do alvo. A trava global `CDT` faz
cada operação atômica, então o modelo as executa como passos únicos.

Invariantes: `TypeOK`, `MintMonotonic` (filho ⊆ pai, salvo pai marcador),
`ParentValid` (sem pai pendurado), `Acyclic`, `MarkerValid`, `RevokingLive`,
`RevokeComplete` (após revoke de c não sobra descendente, remoto incluído) e
`NoStaleHandle` (handle antigo ou de marcador não resolve). Vivacidade:
`RevokeTerminates` (toda revogação iniciada termina). `CHECK_DEADLOCK FALSE`:
slots com geração esgotada são aposentados e o modelo finito acaba; isso é
fim legítimo. Configuração: N = 4, Rights = {R, G}, MaxGen = 1.

## Ipc.tla

Um Endpoint com fila de remetentes e de receptores. Clientes fazem
`ipc_send`/`ipc_call`; servidores fazem `ipc_recv`/`ipc_reply_recv`. Um call
recebido entrega ao servidor um Reply de uso único, consumido na resposta.
A mensagem pode levar uma capability, transferida só se a cap do remetente
tiver `GRANT` (constante `Granted`).

Invariantes: `TypeOK`, `NoDoubleQueue` (thread em no máximo uma fila, e fila
coerente com o estado), `NoMissedRendezvous`, `CallerBlocked` (chamador
bloqueado até a resposta), `ReplyOnce` e `GrantRequired`. Vivacidade:
`CallAnswered`. `CHECK_DEADLOCK TRUE`: o sistema nunca trava por inteiro.

## SMP (T-313, ADR 0031 e 0032)

Com `CPUs` (`CapRevoke*.cfg`, `Ipc*.cfg`) os modelos ganham várias CPUs.
Os arquivos sem sufixo rodam com uma CPU e reproduzem o modelo anterior.
O `Ipc3.cfg` usa dois clientes: com três clientes e três CPUs passou de 40 milhões
de estados sem terminar.

**Ipc.tla.** Cada thread tem `cpu[t]`. Um wake na mesma CPU deixa a thread
em `Run`; um wake em outra CPU a deixa em `Ready` (IPI pendente) até `Pick`
(a CPU a escolhe). `Migrate` move uma thread que não está executando.
Vivacidade: `ReadyRuns` (nenhum IPI se perde) e `CallAnswered`, com justiça
fraca em `Pick`. Fora do escopo desta rodada: destruição de Endpoint com
threads em outra CPU (fica coberta pela destruição concorrente do CapRevoke).

**CapRevoke.tla.** Cada CPU tem um cache de handles resolvidos (`cache`). Uso
do cache não revalida. Liberar um slot (`Free`) põe as cópias em cache na
fila de invalidação (`pend`, o shootdown); a CPU confirma com `Ack`.
`RevokeEnd` só termina com `pend` vazio. Fantasmas: `rf` (liberados desde o
último cap_revoke concluído), `rdone` (liberados antes de um concluído) e
`stale` (uso de cópia de handle de `rdone` que não resolve). Invariante
`NoStaleUse`: depois de um cap_revoke concluído, nenhuma CPU usa cópia
do handle revogado. Uso entre `Free` e `Ack`, com a revogação em curso, é legal.

**Resultados (TLC, TLA+ tools 1.8.0):**

| Config | Estados distintos | Resultado |
|---|---|---|
| Ipc.cfg (1 CPU) | 5.024 | sem erro |
| Ipc2.cfg (2 CPUs) | 903.680 | sem erro (≈ 6 min) |
| Ipc3.cfg (3 CPUs, 2 clientes) | 135.432 | sem erro (≈ 38 s) |
| CapRevoke.cfg (1 CPU, N = 3) | 24.959 | sem erro |
| CapRevoke2.cfg (2 CPUs, N = 3) | 189.245 | sem erro (≈ 1 min) |
| CapRevoke3.cfg (3 CPUs, N = 3) | 1.473.785 | sem erro (≈ 14 min) |

**Mutações (TLC acusa a invariante ou propriedade):**

- Fim da revogação sem esperar `pend` (`RevokeEnd` sem `pend = {}`): `NoStaleUse` violada.
- Liberar sem enviar shootdown (`Free` sem `pend'`): `NoStaleUse` violada.
- `Ack` sem remover a cópia do cache: `NoStaleUse` violada.
- Sem justiça fraca em `Pick` (IPI que nunca é atendido): `CallAnswered` e `ReadyRuns` violadas.

N = 4 foi descartado nas configs de CPUs: com cache por CPU, `CapRevoke` com
1 CPU passou de 6,7 milhões de estados sem terminar. N = 3 cobre os mesmos
casos de revogação concorrente.

## Fora do escopo

Badges, tipos de objeto, contagem de referências e cota (ADR 0006), vários
endpoints e processos, prazos/`TimedOut`, cancelamento, `PeerClosed`,
revogação concorrente com IPC em andamento, conteúdo das mensagens, doação
de SchedContext, caminho rápido, notificações e anéis SPSC. Afinidade e
NUMA (T-325) não entram: dependem da decisão de Eduardo.

## Como rodar

    curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
    cd docs/spec/tla
    java -XX:+UseParallelGC -cp /caminho/tla2tools.jar tlc2.TLC -workers auto -config CapRevoke.cfg CapRevoke.tla
    java -XX:+UseParallelGC -cp /caminho/tla2tools.jar tlc2.TLC -workers auto -config Ipc.cfg Ipc.tla

Resultado esperado: "No error has been found" (≈1 min, 147510 estados distintos para CapRevoke; ≈2 s para Ipc). Testes de
mutação (mint que amplia direitos, delete sem avançar geração, revoke que
termina cedo, revoke que ignora elos remotos (`RevokeComplete`), Reply não consumido, transferência sem GRANT, remoção da
justiça) fazem o TLC acusar a invariante ou propriedade correspondente.
Apague `states/` e `*_TTrace_*` gerados antes de versionar.
Para as configs de CPUs, use `-config CapRevoke2.cfg` (ou `Ipc2.cfg`, etc.).
