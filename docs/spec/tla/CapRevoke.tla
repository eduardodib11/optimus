---------------------------- MODULE CapRevoke ----------------------------
(* Optimus OS / okernel -- CapSpaces, árvore de derivação entre CapSpaces,  *)
(* cap_mint, cap_delete, transferência por IPC e cap_revoke fatiado        *)
(* (SDD v1.0 §6.2, §6.9, §14.2; ADR 0001, ADR 0028).                       *)
(* Os slots de todos os CapSpaces ficam numa só numeração 1..N; space[s] diz *)
(* de qual CapSpace é o slot. Pai em outro CapSpace = elo remoto (ADR 0028).*)
(* A trava global CDT torna cada operação atômica: o modelo as executa como *)
(* passos únicos. Slot 0 é "sem pai". Handle = <<slot, geração>>.           *)
EXTENDS Naturals, FiniteSets

CONSTANTS N,       \* número total de slots (soma de todos os CapSpaces)
          Rights,  \* universo de direitos (ex.: {"R","W","G"})
          MaxGen   \* geração máxima; slot com gen = MaxGen é aposentado

Slots  == 1..N
space  == [s \in Slots |-> IF s <= N \div 2 THEN 1 ELSE 2]
None   == 0

VARIABLES used,     \* slot ocupado?
          rights,   \* máscara de direitos do slot
          parent,   \* pai na árvore (None = raiz); pode ser de outro CapSpace
          gen,      \* geração do slot (parte alta do handle)
          marker,   \* capability apagada que prende o slot (tem descendente remoto)
          revoking, \* conjunto de alvos com revogação em andamento
          done,     \* slot cuja revogação acabou de terminar (fantasma)
          inc,      \* fantasma: nº de encarnações do slot
          held      \* fantasma: handles já entregues, <<slot, gen, encarnação>>

vars == <<used, rights, parent, gen, marker, revoking, done, inc, held>>

RECURSIVE Anc(_, _)
Anc(s, k) == IF k = 0 \/ parent[s] = None THEN {}
             ELSE {parent[s]} \cup Anc(parent[s], k - 1)
Ancestors(s)      == Anc(s, N + 1)
Used              == {s \in Slots : used[s]}
Descendants(c)    == {s \in Used : c \in Ancestors(s)}
Children(c)       == {s \in Used : parent[s] = c}
RemoteChildren(c) == {s \in Children(c) : space[s] # space[c]}
InRevoke(s)       == \E r \in revoking : s = r \/ r \in Ancestors(s)
Resolves(h)       == used[h[1]] /\ ~marker[h[1]] /\ gen[h[1]] = h[2]

Init == /\ used = [s \in Slots |-> FALSE]
        /\ rights = [s \in Slots |-> {}]
        /\ parent = [s \in Slots |-> None]
        /\ gen = [s \in Slots |-> 0]
        /\ marker = [s \in Slots |-> FALSE]
        /\ revoking = {} /\ done = None
        /\ inc = [s \in Slots |-> 0]
        /\ held = {}

\* Ocupa o slot livre s com direitos r e pai p, entregando um handle novo.
Alloc(s, r, p) ==
  /\ ~used[s] /\ gen[s] < MaxGen
  /\ used' = [used EXCEPT ![s] = TRUE]
  /\ rights' = [rights EXCEPT ![s] = r]
  /\ parent' = [parent EXCEPT ![s] = p]
  /\ inc' = [inc EXCEPT ![s] = @ + 1]
  /\ held' = held \cup {<<s, gen[s], inc[s] + 1>>}
  /\ UNCHANGED <<gen, revoking, marker>> /\ done' = None

\* Libera s: filhos sobem para o avô (só chamado quando todos os elos
\* envolvidos são locais ou s é folha); a geração avança. Encerra a revogação
\* de s, se houver (devolve Revoked).
Free(s) ==
  /\ used' = [used EXCEPT ![s] = FALSE]
  /\ rights' = [rights EXCEPT ![s] = {}]
  /\ marker' = [marker EXCEPT ![s] = FALSE]
  /\ parent' = [x \in Slots |-> IF x = s THEN None
                                ELSE IF parent[x] = s THEN parent[s]
                                ELSE parent[x]]
  /\ gen' = [gen EXCEPT ![s] = @ + 1]
  /\ revoking' = revoking \ {s}
  /\ UNCHANGED <<inc, held>>

\* obj_create: capability raiz com todos os direitos.
Create(s) == Alloc(s, Rights, None)

\* cap_mint: cópia local com direitos iguais ou menores. Recusado (Busy)
\* dentro de uma subárvore em revogação, através dos CapSpaces.
Mint(p, s, r) ==
  /\ used[p] /\ ~marker[p] /\ ~InRevoke(p)
  /\ space[s] = space[p]
  /\ r \subseteq rights[p]
  /\ Alloc(s, r, p)

\* Transferência por IPC (exige GRANT): a cópia no slot d de outro CapSpace
\* vira filha remota da original.
Transfer(p, d, r) ==
  /\ used[p] /\ ~marker[p] /\ ~InRevoke(p) /\ "G" \in rights[p]
  /\ space[d] # space[p]
  /\ r \subseteq rights[p]
  /\ Alloc(d, r, p)

\* cap_delete: não apaga o alvo de uma revogação em curso (Busy). Com
\* descendente remoto (ou cópia remota com filhos) vira marcador: o slot
\* continua na árvore, sem direitos nem handle utilizável.
NeedsMarker(s) ==
  \/ RemoteChildren(s) # {}
  \/ parent[s] # None /\ space[parent[s]] # space[s] /\ Children(s) # {}

Delete(s) ==
  /\ used[s] /\ ~marker[s] /\ s \notin revoking
  /\ done' = None
  /\ IF NeedsMarker(s)
     THEN /\ marker' = [marker EXCEPT ![s] = TRUE]
          /\ rights' = [rights EXCEPT ![s] = {}]
          /\ UNCHANGED <<used, parent, gen, revoking, inc, held>>
     ELSE Free(s)

\* Marcador sem descendentes sobra: o slot é liberado.
ReapMarker(s) ==
  /\ used[s] /\ marker[s] /\ Children(s) = {}
  /\ Free(s) /\ done' = None

RevokeStart(c) ==
  /\ used[c] /\ ~marker[c] /\ ~InRevoke(c)
  /\ revoking' = revoking \cup {c} /\ done' = None
  /\ UNCHANGED <<used, rights, parent, gen, marker, inc, held>>

\* Uma fatia preemptível: apaga uma folha descendente do alvo c, local ou
\* remota (marcador incluído). Se a folha for alvo de outra revogação, essa
\* termina (Free a retira de revoking).
RevokeStep(c) ==
  /\ c \in revoking
  /\ \E s \in Descendants(c) :
        /\ Children(s) = {}
        /\ Free(s) /\ done' = None

RevokeEnd(c) ==
  /\ c \in revoking /\ Descendants(c) = {}
  /\ done' = c /\ revoking' = revoking \ {c}
  /\ UNCHANGED <<used, rights, parent, gen, marker, inc, held>>

Next == \/ \E s \in Slots : Create(s) \/ Delete(s) \/ RevokeStart(s)
                            \/ ReapMarker(s) \/ RevokeStep(s) \/ RevokeEnd(s)
        \/ \E p, s \in Slots, r \in SUBSET Rights :
              Mint(p, s, r) \/ Transfer(p, s, r)

Spec == Init /\ [][Next]_vars
        /\ \A c \in Slots : WF_vars(RevokeStep(c)) /\ WF_vars(RevokeEnd(c))

----------------------------------------------------------------------------
TypeOK == /\ used \in [Slots -> BOOLEAN]
          /\ rights \in [Slots -> SUBSET Rights]
          /\ parent \in [Slots -> Slots \cup {None}]
          /\ gen \in [Slots -> 0..MaxGen]
          /\ marker \in [Slots -> BOOLEAN]
          /\ revoking \subseteq Slots /\ done \in Slots \cup {None}

\* Direitos de um filho ⊆ direitos do pai (um marcador não guarda direitos).
MintMonotonic == \A s \in Used : parent[s] # None /\ ~marker[parent[s]] =>
                   rights[s] \subseteq rights[parent[s]]
\* Pai sempre existe (sem ponteiro pendurado) e livre não tem pai.
ParentValid == \A s \in Slots : parent[s] # None =>
                 used[s] /\ used[parent[s]]
\* A árvore não tem ciclos.
Acyclic == \A s \in Used : s \notin Ancestors(s)
\* Marcador está ocupado e sem direitos.
MarkerValid == \A s \in Slots : marker[s] => used[s] /\ rights[s] = {}
\* Após revoke completo de c, nenhum descendente de c existe, nem remoto.
RevokeComplete == done # None => Descendants(done) = {}
\* Handle antigo não resolve após reuso do slot (nem marcador resolve).
NoStaleHandle == \A h \in held : Resolves(<<h[1], h[2]>>) => h[3] = inc[h[1]]
\* Revogação só em curso sobre capability viva.
RevokingLive == \A c \in revoking : used[c]

\* Vivacidade: toda revogação iniciada termina.
RevokeTerminates == \A c \in Slots : (c \in revoking) ~> (c \notin revoking)
=============================================================================
