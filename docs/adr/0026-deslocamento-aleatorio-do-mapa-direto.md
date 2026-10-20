# ADR 0026: Deslocamento aleatório do mapa direto na BootInfo

- Status: aceita (aprovada por Eduardo em 2026-10-11)
- Data: 2026-10-10
- Origem: SDD v1.0, seções 5.2, 6.4 e 6.5
- Relaciona-se com: ADR 0005 (optboot), T-103, T-107

## Contexto

A seção 6.4 põe o mapa direto da memória física em `0xFFFF_8000_0000_0000`
mais um deslocamento aleatório, e a 6.5 pede KASLR com entropia alta. Quem
monta as tabelas de página iniciais é o `optboot` (seção 5.1, passo 6), então
é ele que sorteia esse deslocamento. Mas a `BootInfo` v1 da tabela 5.2 só tem
`kaslr_slide`, o deslocamento da imagem do kernel: não há campo para o kernel
saber onde ficou o mapa direto. A implementação do T-103 usa hoje a base fixa,
sem deslocamento.

## Decisão

Acrescentar à `BootInfo` v1, antes da primeira versão publicada, o campo
`direct_map_base: u64`, com o endereço virtual onde o `optboot` mapeou o
endereço físico 0. O `optboot` sorteia a base em passos de 1 GiB dentro da
faixa `0xFFFF_8000_0000_0000..0xFFFF_C000_0000_0000`, descontado o tamanho da
RAM, usando bytes da semente que não vão para o kernel. Todos os ponteiros da
`BootInfo` continuam expressos no mapa direto.

## Alternativas

- **Base fixa (situação atual):** simples, mas um vazamento de qualquer ponteiro
  do mapa direto revela onde está toda a memória física. Contraria a 6.5.
- **Kernel remapeia sozinho depois do boot:** dispensa o campo, mas duplica a
  montagem de tabelas e deixa uma janela com o mapa em endereço conhecido.
- **BootInfo v2:** desnecessário enquanto nenhuma versão foi publicada.

## Consequências

- O kernel lê `direct_map_base` em vez de uma constante; `kabi` e `optboot`
  mudam juntos.
- Entropia do mapa direto: cerca de 16 bits com passos de 1 GiB em 64 TiB
  (65536 posições menos as ocupadas pela RAM).
- A tabela 5.2 do SDD ganha uma linha na próxima revisão do documento.
- A ADR 0037 acrescenta os campos da hora de parede na v1, pelo mesmo critério.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- Corrigida a entropia do mapa direto de 14 para cerca de 16 bits.
- Acrescentada a remissão à ADR 0037, que segue o mesmo critério na v1.
