# ADR 0047: Contrato `DisplayDevice` (OIDL) e `gpu-virtio` 2D

- Status: aceita ao mesclar este PR (pedido de Eduardo em 2026-11-07)
- Data: 2026-11-07
- Origem: SDD v1.0, seções 8.1 (`DisplayDevice` via OIDL), 8.2 (M4: virtio gpu 2D) e 11.1 (pilha gráfica: driver, `gpu-hal`, `forge`, `displayd`); backlog do M4, T-416 e T-432
- Relaciona-se com: ADR 0012, ADR 0041 (Cockpit via `displayd`), ADR 0042, ADR 0044, ADR 0046

## Contexto

O SDD 11.1 coloca o virtio-gpu 2D no M4 e o Cockpit sobre ele. A ADR 0041 já fixou que só o `displayd` desenha a Faixa de Confiança e que o `cockpit` não escreve no framebuffer. Falta o contrato entre o driver de vídeo e o `displayd`, e o recorte do `gpu-virtio` no M4. A T-416 é só o driver e um quadro de cor sólida; compositor e Cockpit vêm depois (T-432 e M8).

## Decisão

1. **Interface.** `DisplayDevice`, em OIDL (ADR 0012, esquema em `interfaces/`), implementada por todo driver de vídeo (virtio-gpu agora, Xe no M12, framebuffer GOP como reserva). Métodos:
   - `info() -> DisplayInfo`: lista de saídas (`scanout`), cada uma com modos `{largura, altura, taxa, formato}`, preferido e estado de conexão;
   - `set_mode(scanout, modo)`;
   - `create_buffer(largura, altura, formato) -> Buffer`: devolve um `MemoryObject` compartilhável, cobrado da cota do cliente;
   - `attach(scanout, Buffer)`: define o buffer exibido;
   - `flush(scanout, Retângulo[])` e `present(scanout, Buffer, Retângulo[]) -> Fence`: atualiza regiões sujas, devolvendo um `Notification` que sinaliza a conclusão;
   - `events() -> Notification` para hot-plug e mudança de modo.
2. **Formatos.** `B8G8R8X8` e `B8G8R8A8` (pré-multiplicado) no M4. Outros entram por ADR.
3. **Quem pode chamar.** A capability do `DisplayDevice` vai apenas ao `displayd`. Nenhum outro processo desenha no scanout. O `displayd` é, assim, o único com acesso para desenhar a Faixa de Confiança (SDD 11.2, ADR 0041).
4. **`gpu-virtio` 2D.** Driver sobre `lib/ovirtio` (ADR 0046), device id 16 (GPU). Usa as filas `controlq` e `cursorq`. Comandos do M4: `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`, `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`, `TRANSFER_TO_HOST_2D`, `RESOURCE_FLUSH`, `RESOURCE_UNREF`. 3D (virgl/Venus) fica de fora; features de 3D não são negociadas. O backing de cada recurso é o `MemoryObject` do cliente, mapeado no `DmaDomain` do driver (ADR 0044).
5. **Validação.** Retângulos, dimensões e formatos do cliente são validados e limitados (4096×4096 por buffer, 64 MiB por buffer, 256 MiB por cliente, ajustável por manifesto) antes de ir ao dispositivo. Respostas do dispositivo são tratadas como entrada não confiável (ADR 0046, item 7).
6. **Reserva sem GPU.** Se não há dispositivo virtio-gpu, o `displayd` usa o framebuffer GOP entregue pelo `optboot`, via um driver `fb-gop` com a mesma interface `DisplayDevice`. Isso não faz parte da T-416.
7. **Escopo do M4.** T-416: driver, interface OIDL, quadro de cor sólida no QEMU. T-432: `displayd` mínimo e o primeiro passo do Cockpit. `gpu-hal` e `forge` só entram quando o `displayd` pedir (ADR 0041 e SDD 11.1); não são trabalho desta ADR.
8. **Orçamento.** Latência de `present` a 60 fps com quadro até 16,6 ms; o orçamento de 8 ms para Default/Premium da ADR 0041 vale para o compositor com GPU real, não para o virtio 2D.
9. **Fuzzing.** Alvo `fuzz_gpu_resp`: respostas sintéticas do dispositivo ao driver (T-421).

## Alternativas consideradas

- **Expor o framebuffer cru ao Cockpit:** rejeitado (ADR 0041).
- **Incluir virgl 3D no M4:** adiado; exige `gpu-hal` e shaders SPIR-V.
- **Uma interface por GPU:** rejeitado; `DisplayDevice` é a abstração do SDD 8.1.

## Consequências

- O OIDL `DisplayDevice` entra como arquivo de esquema e é gerado pelo `oidlc` (T-416).
- Mudança futura de formato, saídas múltiplas por taxa mista ou 3D exigem ADR nova.
