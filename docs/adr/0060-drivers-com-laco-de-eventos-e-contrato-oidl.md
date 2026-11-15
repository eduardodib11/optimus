# ADR 0060: drivers com laço de eventos servem o contrato OIDL no mesmo laço

- Status: aceita (modo autônomo de Eduardo, 2026-11-14), aguardando a revisão dele
- Data: 2026-11-14
- Origem: backlog do M5, T-514 (interfaces OIDL dos drivers virtio)
- Relaciona-se com: ADR 0033 (OIDL), 0034 (svcmgr), 0046 (virtio), 0047 (DisplayDevice), 0042 (devmgr)

## Contexto

O `virtio-console` (parte 1 da T-514) serve o contrato `Console` num laço de
`recv`, porque só reage a pedidos. O `virtio-net` e o `virtio-input` já têm um
laço próprio, que espera a IRQ do dispositivo (`Irq::wait`), e rodam com uma
thread só (`max_threads = 1`). Uma thread parada na IRQ não atende o endpoint,
e uma parada no endpoint perde a IRQ.

## Decisão

1. **Um laço, um bloqueio.** O driver com laço de eventos serve o contrato
   OIDL no mesmo laço, bloqueando só em `recv` com prazo. Ao vencer o prazo
   (ou depois de cada pedido), o driver esvazia as filas do dispositivo, como
   faz hoje depois do `irq.wait`. A IRQ deixa de ser a espera e vira só dica:
   ela continua ligada e acordada, e o driver a confere com `irq_ack` no
   mesmo passo.
2. **Prazo curto e fixo.** 5 ms no `virtio-input` (latência de tecla abaixo do
   que o olho percebe) e 5 ms no `virtio-net`. Ao ler o `used ring` o driver
   sempre confere tudo, então IRQ perdida não trava (já é a regra do
   `virtio-input`).
3. **Sem segunda thread na v1.** Evita estado compartilhado entre threads
   (`Mutex` dentro de driver) e a regra de `max_threads`. Uma segunda thread
   só entra por ADR nova, se o custo de CPU do laço medido em KVM justificar.
4. **Sem mudar o kernel.** Nada de ligar endpoint a notificação (ABI v1 fica
   como está).
5. **Cliente de teste.** O `drvcli` (partido pelo `devmgr`, ADR 0060 reusa o
   padrão da parte 1) conversa com cada driver pelo cliente gerado do `.oidl`.

## Alternativas consideradas

- **Segunda thread por driver:** rejeitada na v1, pelo estado compartilhado e
  pelo `max_threads`.
- **Ligar o endpoint a uma notificação (espera dupla):** exige syscall nova;
  contraria "sem mudar a ABI v1".
- **Manter os drivers sem contrato:** contraria o item 5 da ADR 0046.

## Consequências

- O driver acorda a cada prazo mesmo ocioso (200 acordadas por segundo com
  5 ms). Medir em KVM antes de aceitar de vez; se pesar, a ADR seguinte
  propõe a espera dupla.
- Libera a T-514 para `NetDevice` e `InputDevice`.
- Qualquer mudança no que está acima exige ADR nova.
