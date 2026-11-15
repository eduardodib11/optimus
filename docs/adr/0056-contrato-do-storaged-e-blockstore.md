# ADR 0056: Contrato do `storaged`, `BlockStore` e `BlockDevice`

- Status: aceita (aprovada por Eduardo em 2026-11-14)
- Data: 2026-11-14
- Origem: SDD v1.0, seções 8, 9.1, 9.4 e 15; backlog do M5, T-506
- Relaciona-se com: ADR 0007 (anéis), 0033 (OIDL), 0036 (anel SPSC), 0038 (`memd`), 0046 (virtio), 0051 (reinício de driver), 0052 (OptFS)

## Contexto

O SDD 9.4 descreve a pilha: driver NVMe/AHCI/virtio-blk → `storaged` (filas, GPT, agendamento de E/S com prioridade herdada do cliente) → `optfs` (um processo por volume) → clientes por capability de diretório.

Hoje o `virtio-blk` (T-411) só faz o autoteste de um setor e não tem interface. A T-514 passa os drivers para OIDL. Falta fixar quatro coisas:

- o contrato entre driver e `storaged` (`BlockDevice`);
- o contrato entre `storaged` e seus clientes (`BlockStore`);
- onde fica o cache;
- como se cobram a cota e o erro de E/S.

Mudar esse contrato depois exige ADR nova, por isso ele nasce com fila assíncrona, e não com uma chamada síncrona por bloco.

## Decisão

### 1. Camadas e capabilities

- Cada disco tem um driver, que entrega `BlockDevice` só ao `storaged`.
- O `storaged` lê a GPT e expõe cada partição como um `BlockStore`. A partição é reconhecida pelo GUID de tipo e pelo nome (`sys-a`, `sys-b`, `data`, conforme o SDD 9.1).
- O manifesto distribui as capabilities:
  - o `optfs` do volume de dados recebe `data` com escrita;
  - o `updated`, depois do Gate 2, recebe o slot inativo com escrita e o ativo só para leitura;
  - o `rescue` recebe todas só para leitura no M5.
- Escrita no slot de sistema ativo é recusada pelo `storaged`, qualquer que seja a capability (SDD 9: o sistema nunca escreve na imagem em uso).

### 2. Unidade

O `BlockStore` sempre expõe blocos de 4 KiB, e o `storaged` converte para setores do dispositivo (512 ou 4096 bytes). Partição que não começa alinhada a 4 KiB é recusada. A GPT padrão já alinha em 1 MiB.

### 3. Controle por OIDL (`optimus.storage @1.0`)

```
enum IoError : u8 { Io, OutOfRange, ReadOnly, Reset, Full, BadRequest }
struct Info { blocks: u64, read_only: bool, flush: bool, max_depth: u16, max_blocks: u16 }

interface BlockStore {
    info() -> Info;
    open_queue(area: handle<MemoryObject>, done: handle<Notification>,
               depth: u16, priority: u8) -> result<Queue, IoError>;
    close_queue(id: u32) -> result<(), IoError>;
}
struct Queue { id: u32, submit: handle<MemoryObject>, kick: handle<Notification> }
```

- `area` é do cliente e contém o anel de conclusões e a região de dados.
- O `storaged` cria o anel de submissões (`submit`), porque é o consumidor dele (ADR 0036).
- O cliente sinaliza `kick`, e o `storaged` sinaliza `done`.
- `depth` vai até 64, e `max_blocks` é 32 (128 KiB por pedido).

### 4. Caminho de dados por anéis SPSC (`ostd::ring`, ADR 0036)

- **Submissão** (32 bytes): `id: u64`, `op: u8` (`READ`, `WRITE`, `FLUSH`), `flags: u8` (`FUA`), `count: u16`, `offset: u32` (deslocamento na região de dados, alinhado a 4 KiB), `block: u64`.
- **Conclusão** (16 bytes): `id: u64` e `status: u8` (0 ok, ou um `IoError`).
- O cliente nunca tem mais que `depth` pedidos pendentes. Por isso o anel de conclusões nunca enche, e o "descartar novos" do anel só pode atingir o cliente que passou do limite, que recebe `Full` na hora.
- No M5 o `storaged` copia entre a região do cliente e as páginas de DMA do driver (uma cópia). Mapear a região do cliente direto no domínio de DMA do dispositivo, sem cópia, fica para depois das medições (T-532). O contrato já permite, porque só fala em "região de dados".

### 5. Semântica

- **`WRITE` concluído** quer dizer que o dispositivo aceitou os dados, não que eles estão duráveis.
- **`FLUSH` concluído** quer dizer que toda escrita concluída antes da submissão do `FLUSH` está durável. É o que o commit do OptFS usa (ADR 0052, item 4: espera as escritas, depois o `FLUSH`).
- No virtio-blk o `FLUSH` vira `VIRTIO_BLK_T_FLUSH`. Sem `VIRTIO_BLK_F_FLUSH`, o dispositivo é tratado como write-through, `Info.flush` = false e o `FLUSH` conclui na hora.
- **`FUA`** torna a escrita durável na conclusão. Se o dispositivo não suporta, o `storaged` emula com escrita seguida de `FLUSH`.
- O `storaged` pode reordenar pedidos entre si, mas nunca conclui um `FLUSH` antes das escritas que ele cobre.

### 6. Agendamento

- Cada fila tem a prioridade pedida na abertura, limitada pela prioridade máxima no badge da capability, que o `svcmgr` põe a partir do manifesto do cliente.
- Filas de maior prioridade são atendidas primeiro, e dentro da fila a ordem é FIFO.
- Um pedido que espera mais de 100 ms sobe ao topo, para ninguém morrer de fome.
- Esta é a "prioridade herdada do cliente" do SDD 9.4 no M5. Herdar do `SchedContext` em tempo real exigiria kernel e fica fora.

### 7. Cache: não no `storaged`

- O `storaged` não guarda dados, só os pedidos em voo.
- O cache de blocos fica acima, no processo do sistema de arquivos, em texto claro. É uma biblioteca (`lib/obcache`) cobrada da `MemoryQuota` do `optfs` e guardada em objetos `LAZY`, para o `memd` despejar sob pressão (ADR 0038).
- Motivos:
  - Um cache abaixo da cifra guardaria texto cifrado e obrigaria a decifrar de novo a cada acerto.
  - Um cache por volume não mistura cotas.
  - Sem estado, o `storaged` fica pequeno e reinicia sem perda.

### 8. Cota por processo

- Tudo o que o cliente causa é cobrado do cliente: a região de dados e o anel de conclusões estão no `MemoryObject` dele.
- O estado do `storaged` por fila é fixo e alocado na abertura, com limite de 4 filas por sessão e 16 sessões por partição. Acima disso, `Full`.

### 9. Erros e reinício

- **Erro do dispositivo:** `Io` no pedido, e `storaged: erro de E/S disco=… bloco=…` no log.
- **O driver morre, ou o `devmgr` o reinicia (ADR 0051):** o `storaged` recebe `PeerClosed`, conclui os pedidos em voo com `Reset` e se reconecta ao novo `BlockDevice` quando o driver volta. Escrita concluída com `Reset` não tem garantia. O OptFS refaz as escritas do txg não confirmado, o que é seguro porque elas vão para blocos livres.
- **O `storaged` morre:** os clientes recebem `PeerClosed` (T-541), o `svcmgr` o reinicia e os clientes reabrem as filas. Nenhum commit confirmado se perde, porque a durabilidade só vem do `FLUSH` concluído.

### 10. `BlockDevice` (driver → `storaged`)

É o mesmo modelo de fila e o mesmo formato de registro, mais um `info()` com setores, tamanho do setor, suporte a flush e somente leitura. No M5 há uma fila por dispositivo (a fila 0 do virtio-blk). O `storaged` repassa os pedidos convertendo unidade e somando o início da partição. A T-514 implementa isso no `virtio-blk`.

### 11. GPT

O parser lê dado não confiável do disco e ganha alvo de fuzz (`gpt`, na T-529), como os parsers de dispositivo (SDD 8).

- Ele confere o CRC32 do cabeçalho e da tabela, nas cópias primária e de reserva.
- Partições sobrepostas ou fora do disco são recusadas.
- Com as duas cópias inválidas, o disco não expõe partições.

## Alternativas consideradas

- **IPC síncrono por pedido** (`read(bloco)` com resposta no buffer de IPC): mais simples, mas um pedido por vez por thread do cliente, sem profundidade de fila. Mudar depois exigiria ADR nova. Rejeitada.
- **Cache no `storaged`:** guardaria texto cifrado e misturaria cotas de volumes. Rejeitada.
- **`optfs` direto no driver:** perde GPT, agendamento e a proteção do slot ativo, e contraria o SDD 9.4. Rejeitada.
- **Sem cópia já no M5:** mapeia memória do cliente no domínio de DMA do dispositivo. Vale depois das medições, e o contrato já permite. Adiada.

## Consequências

- A T-520 implementa o `storaged` com filas, GPT e agendamento. Ela precisa de uma imagem de teste com GPT (`sys-a`, `sys-b`, `data`) gerada pelo `xtask`.
- A T-514 implementa o `BlockDevice` no `virtio-blk`.
- A T-521 passa a ser a biblioteca `lib/obcache`, testada contra um `BlockStore` falso e usada pelo `optfs` a partir da T-523.
- A T-529 ganha o alvo `gpt`.
- Qualquer mudança no que está acima exige ADR nova.
