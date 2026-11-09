# ADR 0047: Contrato de DisplayDevice (OIDL) e gpu-virtio 2D

- Status: aceita (Eduardo, ao retomar o M4 em 2026-11-09)
- Data: 2026-11-09
- Origem: SDD v1.0, seção 11.1; backlog do M4, T-411/T-416
- Relaciona-se com: ADR 0041, 0046

## Contexto

A ADR 0041 põe o `gpu-virtio` 2D no M4 e o `displayd` depois. Falta fixar o contrato que o `displayd` consumirá.

## Decisão

1. **Trait `DisplayDevice`** (OIDL): `modes() -> [Mode]`, `set_mode(id)`, `create_buffer(w, h, formato) -> BufferId` (devolve `MemoryObject` compartilhado), `present(BufferId, [Rect])`, `events() -> Notification` (hotplug, troca de modo).
2. Formato único na v1: `XRGB8888`, 32 bits.
3. **gpu-virtio 2D** usa `RESOURCE_CREATE_2D`, `ATTACH_BACKING`, `SET_SCANOUT`, `TRANSFER_TO_HOST_2D` e `RESOURCE_FLUSH`. Sem 3D (virgl) na v1.
4. Só o `displayd` recebe a capability do `DisplayDevice` (ADR 0041, Faixa de Confiança).
5. Aceite: um quadro de cor sólida no QEMU.

## Alternativas consideradas

- **Fazer no kernel:** rejeitado, contraria a ADR 0001 e a ADR 0013.
- **Crate externa pronta:** rejeitado, contraria a ADR 0003.

## Consequências

- A tarefa T-411/T-416 pode começar.
- Qualquer mudança no que está acima exige ADR nova.
