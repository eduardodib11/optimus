# Especificações TLA+ do okernel (T-008)

Modelos iniciais de capabilities e IPC do Optimus OS, conforme o SDD v1.0
(§6.2, §6.7, §14.2) e as ADRs 0001 e 0007.

## CapRevoke.tla

Modela um CapSpace com `N` slots, handles `<<slot, geração>>` e a árvore de
derivação: `obj_create` (cap raiz com todos os direitos), `cap_mint` (filho
com direitos ⊆ do pai), `cap_delete` (filhos sobem para o avô) e
`cap_revoke` fatiado e preemptível (`RevokeStart`, `RevokeStep` apaga uma
folha por vez intercalado com outras ações, `RevokeEnd`). Durante a
revogação, mint dentro da subárvore e delete do alvo são recusados (`Busy`).

Invariantes: `TypeOK`, `MintMonotonic` (filho ⊆ pai), `ParentValid` (sem
pai pendurado), `Acyclic`, `RevokeComplete` (após revoke de c não sobra
descendente) e `NoStaleHandle` (handle antigo não resolve após reuso do slot).
Vivacidade: `RevokeTerminates`. `CHECK_DEADLOCK FALSE`: slots com geração
esgotada são aposentados e o CapSpace finito acaba; isso é fim legítimo.

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

## Fora do escopo

Badges, tipos de objeto, contagem de referências e cota (ADR 0006), vários
endpoints e processos, prazos/`TimedOut`, cancelamento, `PeerClosed`,
revogação concorrente com IPC em andamento, conteúdo das mensagens, doação
de SchedContext, caminho rápido, notificações e anéis SPSC, SMP.

## Como rodar

    curl -L -o tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
    cd docs/spec/tla
    java -XX:+UseParallelGC -cp /caminho/tla2tools.jar tlc2.TLC -workers auto -config CapRevoke.cfg CapRevoke.tla
    java -XX:+UseParallelGC -cp /caminho/tla2tools.jar tlc2.TLC -workers auto -config Ipc.cfg Ipc.tla

Resultado esperado: "No error has been found" (≈10 s e ≈2 s). Testes de
mutação (mint que amplia direitos, delete sem avançar geração, revoke que
termina cedo, Reply não consumido, transferência sem GRANT, remoção da
justiça) fazem o TLC acusar a invariante ou propriedade correspondente.
Apague `states/` e `*_TTrace_*` gerados antes de versionar.
