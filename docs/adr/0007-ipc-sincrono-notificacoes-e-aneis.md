# ADR 0007: IPC síncrono, notificações assíncronas e anéis compartilhados

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 6.6, 6.7 e 14.2
- Relaciona-se com: ADR 0001, ADR 0008, ADR 0012

## Contexto

No microkernel (ADR 0001), quase toda operação de serviço é IPC. Há três padrões
de uso: chamadas curtas de pedido e resposta (abrir arquivo, consultar política),
eventos sem resposta (IRQ, timer, dado disponível) e grandes volumes (blocos de
disco, pacotes, áudio, quadros). A meta é ida e volta ≤ 1 µs (RNF-03).

## Decisão

O kernel oferece três mecanismos:

1. **IPC síncrono** por `Endpoint` e `Reply` de uso único: `ipc_call`,
   `ipc_reply_recv`, `ipc_send` e `ipc_recv`, com prazo opcional. Mensagem com
   rótulo de 64 bits, até 6 palavras em registradores ou 504 no buffer de IPC
   de 4 KiB (4 KiB menos 64 bytes de cabeçalho; ADR 0027), e até 4 capabilities (exige `GRANT`). O caminho rápido troca
   contexto direto na mesma CPU, sem passar pelo escalonador nem alocar.
2. **Notificações**: palavra de 64 bits de sinais (`ntfy_signal`, `ntfy_wait`,
   `ntfy_poll`). IRQ, timer ou endpoint ligam-se a um bit via
   `obj_bind_notify`, e o executor `orun` espera numa única notificação.
3. **Anéis SPSC** em `MemoryObject` compartilhado, com notificação para
   despertar, para dados grandes.

## Alternativas

- **Só IPC síncrono (L4 clássico):** rápido, mas força threads extras para
  eventos e copia dados grandes.
- **Só mensagens assíncronas com fila no kernel (Mach ports, canais do
  Zircon):** flexível, mas exige buffer e alocação no kernel e é mais lento em
  chamadas curtas.
- **Memória compartilhada para tudo:** máximo de vazão, mas sem transferência de
  capabilities nem sincronização garantida pelo kernel.

## Consequências

- Cada padrão usa o mecanismo mais barato; o caminho rápido sustenta a meta.
- Três mecanismos a documentar, especificar em TLA+ e testar.
- A OIDL gera stubs sobre esses mecanismos e esconde a escolha dos serviços.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- O buffer de IPC passa de 512 para 504 palavras, como fixa a ADR 0027.
