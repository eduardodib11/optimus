# Nota para a próxima revisão do SDD: seção 6.9 (trava CDT)

O PDF do SDD v1.0 não se edita; esta nota pede a correção na próxima
revisão do documento.

**Seção 6.9 (ordem de travas).** A ordem passa de
`CapSpace → objeto → AddressSpace → fila` para

    CDT → CapSpace → objeto → AddressSpace → fila

onde `CDT` é a trava global da árvore de derivação entre `CapSpace`s
([ADR 0028](../adr/0028-arvore-de-derivacao-entre-capspaces.md)). `cap_mint`,
`cap_delete`, `cap_revoke` e a transferência por IPC tomam a `CDT` primeiro e,
com ela, tocam um `CapSpace` por vez; nunca seguram duas travas de `CapSpace`.

**Seção 6.2 (consequência).** A árvore de derivação atravessa `CapSpace`s: a
cópia transferida por IPC é filha da original, `cap_revoke` a alcança com os
descendentes, e `cap_delete` com descendente remoto deixa um marcador no slot.
O modelo está em [`docs/spec/tla/CapRevoke.tla`](../spec/tla/CapRevoke.tla).
