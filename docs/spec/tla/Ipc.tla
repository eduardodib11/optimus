------------------------------- MODULE Ipc -------------------------------
(* Optimus OS / okernel -- um Endpoint síncrono com ipc_call,             *)
(* ipc_reply_recv, ipc_send, ipc_recv e Reply de uso único               *)
(* (SDD v1.0 §6.2, §6.7, §14.2; ADR 0007). Clientes chamam/enviam;      *)
(* servidores recebem/respondem. Sem prazos nem cancelamento.            *)
(* SMP (T-313, ADRs 0031 e 0032): cada thread está numa CPU (cpu[t]). Um  *)
(* wake entre CPUs deixa a thread em "Ready" (fila da CPU, IPI pendente) *)
(* até a CPU escolhê-la (Pick); um wake na mesma CPU a torna "Run" direto. *)
(* Migração move uma thread que não está executando para outra CPU.      *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Clients,  \* threads clientes
          Servers,  \* threads servidoras
          Granted,  \* clientes cuja cap do Endpoint tem GRANT (⊆ Clients)
          CPUs      \* CPUs do sistema (com uma CPU, nunca há wake remoto)

Threads == Clients \cup Servers
None    == "none"
States  == {"Run", "Ready", "SendBlk", "CallBlk", "RecvBlk", "WaitReply"}
Msg     == [t : Clients, call : BOOLEAN, cap : BOOLEAN]

VARIABLES st,        \* estado de cada thread
          sendQ,     \* fila de remetentes bloqueados no Endpoint
          recvQ,     \* fila de receptores bloqueados no Endpoint
          reply,     \* Reply que cada servidor guarda: cliente ou None
          delivered, \* fantasma: respostas entregues ao cliente na chamada atual
          capsFrom,  \* fantasma: clientes de quem o servidor recebeu capability
          cpu        \* CPU de cada thread (fila em que está ou onde executa)

vars == <<st, sendQ, recvQ, reply, delivered, capsFrom, cpu>>

Range(q) == {q[i] : i \in DOMAIN q}
Senders  == {m.t : m \in Range(sendQ)}
\* A cap só é transferida se a cap do Endpoint do remetente tiver GRANT;
\* sem GRANT o kernel recusa a transferência (AccessDenied) e não anexa nada.
Xfer(m)  == m.cap /\ m.t \in Granted
Gain(m)  == IF Xfer(m) THEN capsFrom \cup {m.t} ELSE capsFrom
\* Wake feito por a: na mesma CPU, t vai direto a Run; em outra CPU, Ready
\* até a CPU de t escolhê-la (IPI). Lido com o cpu antes do passo.
WakeSt(t, a) == IF cpu[t] = cpu[a] THEN "Run" ELSE "Ready"

Init == /\ st = [t \in Threads |-> "Run"]
        /\ sendQ = <<>> /\ recvQ = <<>>
        /\ reply = [s \in Servers |-> None]
        /\ delivered = [c \in Clients |-> 0]
        /\ capsFrom = {}
        /\ cpu \in [Threads -> CPUs]

\* Remetente c (envio ou chamada) encontra o Endpoint: entrega ao primeiro
\* receptor, ou entra na fila de envio.
Deliver(c, call, cap, del) ==
  LET m == [t |-> c, call |-> call, cap |-> cap] IN
  IF recvQ # <<>>
  THEN LET s == Head(recvQ) IN
       /\ recvQ' = Tail(recvQ) /\ sendQ' = sendQ
       /\ st' = [st EXCEPT ![s] = WakeSt(s, c),
                           ![c] = IF call THEN "WaitReply" ELSE "Run"]
       /\ reply' = IF call THEN [reply EXCEPT ![s] = c] ELSE reply
       /\ capsFrom' = Gain(m) /\ delivered' = del
       /\ UNCHANGED cpu
  ELSE /\ sendQ' = Append(sendQ, m) /\ recvQ' = recvQ
       /\ st' = [st EXCEPT ![c] = IF call THEN "CallBlk" ELSE "SendBlk"]
       /\ UNCHANGED <<reply, capsFrom, cpu>> /\ delivered' = del

Send(c, cap) == st[c] = "Run" /\ Deliver(c, FALSE, cap, delivered)

Call(c, cap) == st[c] = "Run" /\ Deliver(c, TRUE, cap, [delivered EXCEPT ![c] = 0])

\* Parte de recepção, sobre o estado st1/rep1/del1 já atualizado.
RecvPart(s, st1, rep1, del1) ==
  IF sendQ # <<>>
  THEN LET m == Head(sendQ) IN
       /\ sendQ' = Tail(sendQ) /\ recvQ' = recvQ
       /\ st' = [st1 EXCEPT ![m.t] = IF m.call THEN "WaitReply" ELSE WakeSt(m.t, s)]
       /\ reply' = [rep1 EXCEPT ![s] = IF m.call THEN m.t ELSE None]
       /\ capsFrom' = Gain(m) /\ delivered' = del1
       /\ UNCHANGED cpu
  ELSE /\ recvQ' = Append(recvQ, s) /\ sendQ' = sendQ
       /\ st' = [st1 EXCEPT ![s] = "RecvBlk"]
       /\ reply' = rep1 /\ delivered' = del1 /\ capsFrom' = capsFrom
       /\ UNCHANGED cpu

\* ipc_recv: só sem Reply pendente (senão o chamador ficaria órfão).
Recv(s) == st[s] = "Run" /\ reply[s] = None
           /\ RecvPart(s, st, reply, delivered)

\* ipc_reply_recv: usa e consome o Reply, depois recebe.
ReplyRecv(s) ==
  /\ st[s] = "Run" /\ reply[s] # None
  /\ LET c == reply[s] IN
     RecvPart(s, [st EXCEPT ![c] = WakeSt(c, s)],
                 [reply EXCEPT ![s] = None],
                 [delivered EXCEPT ![c] = @ + 1])

\* A CPU escolhe uma thread da sua fila (wake remoto chegou pelo IPI).
Pick(t) == /\ st[t] = "Ready"
           /\ st' = [st EXCEPT ![t] = "Run"]
           /\ UNCHANGED <<sendQ, recvQ, reply, delivered, capsFrom, cpu>>

\* Migração: thread que não está executando vai para outra CPU (ADR 0032).
Migrate(t, k) == /\ st[t] \in {"Ready", "SendBlk", "CallBlk", "RecvBlk", "WaitReply"}
                 /\ cpu' = [cpu EXCEPT ![t] = k]
                 /\ UNCHANGED <<st, sendQ, recvQ, reply, delivered, capsFrom>>

Next == \/ \E c \in Clients, cap \in BOOLEAN : Send(c, cap) \/ Call(c, cap)
        \/ \E s \in Servers : Recv(s) \/ ReplyRecv(s)
        \/ \E t \in Threads : Pick(t)
        \/ \E t \in Threads, k \in CPUs : Migrate(t, k)

Spec == Init /\ [][Next]_vars /\ \A s \in Servers : WF_vars(ReplyRecv(s))
        /\ \A t \in Threads : WF_vars(Pick(t))

----------------------------------------------------------------------------
TypeOK == /\ st \in [Threads -> States]
          /\ sendQ \in Seq(Msg) /\ recvQ \in Seq(Servers)
          /\ reply \in [Servers -> Clients \cup {None}]
          /\ delivered \in [Clients -> 0..2] /\ capsFrom \subseteq Clients
          /\ cpu \in [Threads -> CPUs]

\* Uma thread nunca está em duas filas nem duas vezes na mesma; está numa
\* fila exatamente quando seu estado diz que está bloqueada nela.
NoDoubleQueue ==
  /\ Len(sendQ) = Cardinality(Senders) /\ Len(recvQ) = Cardinality(Range(recvQ))
  /\ Senders \cap Range(recvQ) = {}
  /\ \A t \in Threads : (t \in Senders <=> st[t] \in {"SendBlk", "CallBlk"})
                        /\ (t \in Range(recvQ) <=> st[t] = "RecvBlk")
\* Rendezvous: nunca há remetente e receptor esperando ao mesmo tempo.
NoMissedRendezvous == sendQ = <<>> \/ recvQ = <<>>
\* Quem chamou fica bloqueado até a resposta: em espera <=> exatamente um
\* servidor guarda o seu Reply.
CallerBlocked == \A c \in Clients :
  st[c] = "WaitReply" <=> Cardinality({s \in Servers : reply[s] = c}) = 1
\* Reply de uso único: no máximo uma resposta por chamada.
ReplyOnce == \A c \in Clients : delivered[c] <= 1
\* Transferência de capability exige GRANT.
GrantRequired == capsFrom \subseteq Granted

\* Vivacidade: toda chamada recebida é respondida.
CallAnswered == \A c \in Clients : st[c] = "WaitReply" ~> st[c] = "Run"
\* Vivacidade do wake entre CPUs: nenhum IPI se perde; thread em Ready roda.
ReadyRuns == \A t \in Threads : st[t] = "Ready" ~> st[t] = "Run"
=============================================================================
