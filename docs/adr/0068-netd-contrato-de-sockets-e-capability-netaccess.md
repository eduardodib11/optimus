# ADR 0068: `netd`, contrato de sockets e capability `NetAccess`

- Status: aceita; revisada e aprovada pelo Eduardo em 2026-11-16 (T-606)
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

## Notas de implementação (T-637, 2026-11-16)

Detalhes que a decisão deixava abertos; nenhum muda o que está acima.

- **Como a política chega ao `netd`.** A necessidade `net:access:<texto>` do manifesto (`NeedKind::Net`, kind 6 no OMAN v1; o campo `name` leva o texto) não vira capability. O `netd` pergunta ao `svcmgr` com `Supervisor.net_policy(id)` (1.4) na primeira chamada de cada badge e guarda a resposta; só quem provê `optimus.net.Socket@1` recebe, e um serviço sem a necessidade recebe o texto vazio, que é "sem política": nada é permitido. Assim o `svcmgr` continua sem ver tráfego nem destinos em tempo de execução, e a política sobrevive ao reinício do `netd`, que a pede de novo.
- **Formato do texto** (`onet::policy`, validado no build pelo `mkmanifest`): itens separados por `;`: `connect=<tcp|udp>:<destino>:<portas>` (destino: IPv4, faixa `a.b.c.d/n`, `*`, nome ou `*.sufixo`; portas: `80`, `1-1024` ou `*`), `listen=tcp:<portas>`, `conns=N` (sockets abertos, padrão 8) e `rate=N` (novas conexões por segundo, padrão 10). Até 8 regras `connect` e 4 `listen`.
- **Um endpoint só.** O `netd` atende um endpoint com recepção de prazo curto (como o `storaged`, ADR 0060) e despacha pela interface do rótulo, então `Config@1` (só leitura) é servida no mesmo endpoint de `Socket@1` e o manifesto provê só `Socket@1`. A separação em dois endpoints espera uma espera combinada em mais de um endpoint, que o kernel ainda não tem; a escrita de `Config@1` (DHCP) chega com a T-633.
- **Quem cria cada anel.** O anel de recepção é do cliente (ele o consome e o cria, na cota dele) e o `netd` o abre como produtor; o de transmissão é do `netd` (ele o consome e o cria, da `MemoryQuota` dele, 12 KiB por socket) e o cliente o abre como produtor. É a regra da ADR 0036: quem consome cria o anel. A memória do `rx` sai da cota do cliente, não da do `netd`; o teto de memória por cliente fica então em `conns` (item 5).
- **Sem acordar o `netd` por anel.** O `netd` dorme em `recv` com prazo de 100 µs (com socket aberto) ou 1 ms (sem), como o `storaged` (ADR 0060), e olha todos os anéis a cada volta. `tx_signal` existe por simetria com o `NetDevice`; o sinal não é necessário.
- **`close` e o dono.** Um cliente que reinicia (geração nova do mesmo serviço) faz o `netd` fechar o que a geração anterior deixou aberto (item 6); o morto sem reinício só é notado no próximo `open` de qualquer cliente do mesmo serviço. O `netd` ainda não vê a morte de um cliente (não tem o `CapSpace` dele para ligar a uma `Notification`): fica como limite conhecido, que a T-638 revisita.
- **UDP conectado.** O `connect` fixa o par e só os datagramas dele chegam; datagrama para o `netd` de outra origem recebe "porta inalcançável". `sendto` e `listen` UDP ficam para quando houver uso (o DNS do `netd` fala UDP por dentro, sem socket de cliente).
