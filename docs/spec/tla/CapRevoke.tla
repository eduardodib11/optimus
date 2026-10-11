---------------------------- MODULE CapRevoke ----------------------------
(* Optimus OS / okernel -- CapSpace, árvore de derivação, cap_mint,        *)
(* cap_delete e cap_revoke fatiado (SDD v1.0 §6.2, §14.2; ADR 0001).     *)
(* Slot 0 é "sem pai". Handle = <<slot, geração>>.                       *)
EXTENDS Naturals, FiniteSets

CONSTANTS N,       \* número de slots do CapSpace
          Rights,  \* universo de direitos (ex.: {"R","W","G"})
          MaxGen   \* geração máxima; slot com gen = MaxGen é aposentado

Slots == 1..N
None  == 0

VARIABLES used,     \* slot ocupado?
          rights,   \* máscara de direitos do slot
          parent,   \* pai na árvore de derivação (None = raiz, obj_create)
          gen,      \* geração do slot (parte alta do handle)
          revoking, \* slot cuja revogação está em andamento (None = nenhuma)
          done,     \* slot cuja revogação acabou de terminar (fantasma)
          inc,      \* fantasma: nº de encarnações do slot
          held      \* fantasma: handles já entregues, <<slot, gen, encarnação>>

vars == <<used, rights, parent, gen, revoking, done, inc, held>>

RECURSIVE Anc(_, _)
Anc(s, k) == IF k = 0 \/ parent[s] = None THEN {}
             ELSE {parent[s]} \cup Anc(parent[s], k - 1)
Ancestors(s)   == Anc(s, N + 1)
Used           == {s \in Slots : used[s]}
Descendants(c) == {s \in Used : c \in Ancestors(s)}
Children(c)    == {s \in Used : parent[s] = c}
InRevoke(s)    == revoking # None /\ (s = revoking \/ revoking \in Ancestors(s))
Resolves(h)    == used[h[1]] /\ gen[h[1]] = h[2]   \* cap_* valida o handle

Init == /\ used = [s \in Slots |-> FALSE]
        /\ rights = [s \in Slots |-> {}]
        /\ parent = [s \in Slots |-> None]
        /\ gen = [s \in Slots |-> 0]
        /\ revoking = None /\ done = None
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
  /\ UNCHANGED <<gen, revoking>> /\ done' = None

\* Libera s: filhos sobem para o avô (direitos continuam ⊆ por transitividade);
\* a geração avança, invalidando handles antigos.
Free(s) ==
  /\ used' = [used EXCEPT ![s] = FALSE]
  /\ rights' = [rights EXCEPT ![s] = {}]
  /\ parent' = [x \in Slots |-> IF x = s THEN None
                                ELSE IF parent[x] = s THEN parent[s]
                                ELSE parent[x]]
  /\ gen' = [gen EXCEPT ![s] = @ + 1]
  /\ UNCHANGED <<inc, held>>

\* obj_create: capability raiz com todos os direitos.
Create(s) == Alloc(s, Rights, None)

\* cap_mint: cópia com direitos iguais ou menores. Recusado (Busy) dentro
\* de uma subárvore em revogação.
Mint(p, s, r) ==
  /\ used[p] /\ ~InRevoke(p)
  /\ r \subseteq rights[p]
  /\ Alloc(s, r, p)

\* cap_delete: não apaga o alvo de uma revogação em curso (Busy).
Delete(s) ==
  /\ used[s] /\ s # revoking
  /\ Free(s) /\ revoking' = revoking /\ done' = None

RevokeStart(c) ==
  /\ used[c] /\ revoking = None
  /\ revoking' = c /\ done' = None
  /\ UNCHANGED <<used, rights, parent, gen, inc, held>>

\* Uma fatia preemptível: apaga uma folha descendente do alvo.
RevokeStep ==
  /\ revoking # None
  /\ \E s \in Descendants(revoking) :
        /\ Children(s) = {}
        /\ Free(s) /\ revoking' = revoking /\ done' = None

RevokeEnd ==
  /\ revoking # None /\ Descendants(revoking) = {}
  /\ done' = revoking /\ revoking' = None
  /\ UNCHANGED <<used, rights, parent, gen, inc, held>>

Next == \/ \E s \in Slots : Create(s) \/ Delete(s) \/ RevokeStart(s)
        \/ \E p, s \in Slots, r \in SUBSET Rights : Mint(p, s, r)
        \/ RevokeStep \/ RevokeEnd

Spec == Init /\ [][Next]_vars /\ WF_vars(RevokeStep) /\ WF_vars(RevokeEnd)

----------------------------------------------------------------------------
TypeOK == /\ used \in [Slots -> BOOLEAN]
          /\ rights \in [Slots -> SUBSET Rights]
          /\ parent \in [Slots -> Slots \cup {None}]
          /\ gen \in [Slots -> 0..MaxGen]
          /\ revoking \in Slots \cup {None} /\ done \in Slots \cup {None}

\* Direitos de um filho ⊆ direitos do pai.
MintMonotonic == \A s \in Used : parent[s] # None =>
                   rights[s] \subseteq rights[parent[s]]
\* Pai sempre existe (sem ponteiro pendurado) e livre não tem pai.
ParentValid == \A s \in Slots : parent[s] # None =>
                 used[s] /\ used[parent[s]]
\* A árvore não tem ciclos.
Acyclic == \A s \in Used : s \notin Ancestors(s)
\* Após revoke completo de c, nenhum descendente de c existe.
RevokeComplete == done # None => Descendants(done) = {}
\* Handle antigo não resolve após reuso do slot.
NoStaleHandle == \A h \in held : Resolves(<<h[1], h[2]>>) => h[3] = inc[h[1]]

\* Vivacidade: toda revogação iniciada termina.
RevokeTerminates == revoking # None ~> revoking = None
=============================================================================
