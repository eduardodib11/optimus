# ADR 0059: mouse PS/2 em processo próprio, no controlador 8042 compartilhado

- Status: aceita (modo autônomo de Eduardo, 2026-11-14)
- Data: 2026-11-14
- Origem: backlog do M5, T-516 (pendência da T-406)
- Relaciona-se com: ADR 0042 (devmgr, item 4), ADR 0045 (acpid), ADR 0049 (`IoPortRange` e IRQ legada), SDD v1.0 seção 9 (drivers isolados)

## Contexto

O `i8042d` (T-406) trata o teclado e descarta os bytes do mouse. O `acpid`
publica o mouse como nó `PNP0F13`, cujo `_CRS` traz só a IRQ 12: o 8042 é um
controlador só, e as portas 0x60 e 0x64 vêm no nó do teclado (`PNP0303`). O
`devmgr` liga um driver a um nó só, e o SDD pede um processo isolado por
driver.

## Decisão

1. **Processo próprio.** `ps2mouse` casa com `PNP0F13` e manda cada pacote de
   3 bytes ao `inputd` como `Event::Pointer`, por `optimus.input.Sink@1`.
2. **Portas herdadas.** O PS/2 `PNP0F13` fala pelas portas do 8042 por
   definição (ACPI). Quando o `_CRS` dele não traz portas, o `acpid` publica o
   nó com 0x60 e 0x64 (uma porta cada), para o `devmgr` entregá-las como
   `io0` e `io1`. O kernel não impede duas capabilities para a mesma porta.
3. **Dono do controlador.** O `i8042d` configura o byte de comando (IRQ 1 e
   12 ligadas, relógio do mouse ligado, tradução) e liga a porta do mouse
   (`0xA8`). O `ps2mouse` só manda `0xD4 0xF4` (Enable Streaming) e espera o
   `ACK`.
4. **Sem disputa pela porta de dados.** O status marca de quem é o byte do
   buffer de saída (bit 5). O `i8042d` só lê byte de teclado e o `ps2mouse` só
   byte de mouse; o byte do outro fica no controlador para o dono. Um mouse
   só manda pacote depois do `0xF4`, então sem `ps2mouse` não há byte de mouse
   para travar o teclado. O `i8042d` espera a resposta de comando só em byte
   que não seja do mouse e o `ps2mouse` tenta o `0xF4` três vezes, para o caso
   raro de os dois mexerem no controlador ao mesmo tempo.

## Consequências

- Um driver a mais no conjunto do `devmgr` (10).
- A regra das portas herdadas é só do `PNP0F13`; outro nó sem portas continua
  sem elas.
