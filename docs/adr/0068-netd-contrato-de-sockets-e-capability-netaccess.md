# ADR 0068: `netd`, contrato de sockets e capability `NetAccess`

- Status: aceita (modo autônomo de Eduardo, 2026-11-16), aguardando a revisão dele
- Data: 2026-11-16
- Origem: backlog do M6, T-602 (SDD v1.0, seções 10, 10.2 e 14.4)
- Relaciona-se com: ADR 0011 (sem root), 0017 (pilha de rede própria), 0034 (manifesto e corretor do `svcmgr`), 0036 (anéis SPSC), 0060 (laço dos drivers), 0064 (`NetDevice`)

## Contexto

A ADR 0017 manda a pilha inteira para o `netd` em espaço de usuário e a ADR 0064 já define o `NetDevice` (quadros por anéis). Falta dizer como um cliente pede um socket, onde mora a política de saída (`NetAccess`) e como os dados passam sem cópia. O SDD (14.4) fixa o manifesto do `netd`: `provides = ["optimus.net.Socket@1", "optimus.net.Config@1"]`, prioridade 150, `restart = "always"`.

## Decisão

1. **Um processo, uma capability de entrada.** O `netd` é o único cliente do `NetDevice` (ADR 0064). Os clientes falam com ele por `optimus.net.Socket@1`; ninguém mais vê quadros. A configuração (`Config@1`: endereços, rotas, DNS, estado do enlace) é um contrato separado, só leitura para clientes comuns e escrita para o `svcmgr` e a UI de rede.
2. **`NetAccess` é um endpoint com badge, sem objeto novo no kernel.** O corretor do `svcmgr` (ADR 0034) entrega ao cliente um endpoint do `netd` cujo badge identifica uma política registrada no `netd` pelo manifesto do cliente: lista de destinos (nome, faixa de IP, porta, protocolo), limite de conexões e taxa. A política mora no `netd`; o kernel não muda e a ABI v1 também não. Derivar só reduz: o cliente pode repassar uma versão mais estreita, nunca mais larga.
3. **Negado por padrão.** Sem `NetAccess` não há socket. Entrada é bloqueada: um `listen` só é aceito para serviços listados no manifesto e aprovados pelo usuário (SDD 10.2). Todo destino é checado na criação da conexão e a cada resolução de nome (o nome resolvido tem de cair na lista, o que impede *DNS rebinding* para destinos não listados).
4. **Dados por anéis, controle por IPC.** `connect`, `listen`, `accept`, `close` e `shutdown` são chamadas IPC. Cada socket tem dois anéis SPSC (ADR 0036) de bytes, `tx` e `rx`, criados pelo cliente e ligados com a `Notification` dele. Datagramas UDP usam registros delimitados no mesmo anel. Janela do TCP e anel não são acoplados: o `netd` só anuncia janela do tamanho do espaço livre do `rx`.
5. **Cotas.** Memória de socket sai da `MemoryQuota` do `netd` (32 MiB no manifesto do SDD), com teto por cliente definido na política. Estouro recusa novos sockets; não derruba o `netd`.
6. **Morte e reinício.** Se o `netd` morre, os clientes recebem `PeerClosed` e as conexões TCP se perdem (sem estado persistente, ADR 0067 como modelo). O `svcmgr` reinicia o `netd`; o `NetDevice` aceita novo `attach_rx`. Se o cliente morre, o `netd` fecha os sockets dele (RST) e libera os anéis.
7. **IA sem rede direta.** Nenhum processo `ai-*` recebe `NetAccess`. O `ai-exec` o tem, com política e auditoria (SDD 10.2 e 12).
8. **Auditoria.** Cada decisão de política (aceita ou negada) vai para o `logd` com cliente, destino e motivo, sem conteúdo dos dados.

## Alternativas consideradas

- `NetAccess` como objeto do kernel: daria revogação nativa, mas põe política de rede na base de confiança e muda a ABI v1. Rejeitada; a revogação é feita pelo `netd`, que fecha os sockets do badge.
- Sockets por mensagem IPC (um `send` por pacote): mais simples, mas a ≥ 1 µs por chamada limita a vazão. Rejeitada a favor dos anéis.
- Política dentro do `svcmgr`: o `svcmgr` não deve ver tráfego nem destinos em tempo de execução. Rejeitada.

## Consequências

- O `oidlc` ganha `socket.oidl` e `netconfig.oidl` em `idl/optimus/`.
- O manifesto precisa de uma necessidade `net:access` com a política; o compilador de manifestos e o corretor aprendem o formato (T-637).
- O `tlsd` (ADR 0070) é cliente do `netd` e serve TLS aos demais; o cliente de TLS também precisa de `NetAccess`.
- Qualquer mudança no que está acima exige ADR nova.
