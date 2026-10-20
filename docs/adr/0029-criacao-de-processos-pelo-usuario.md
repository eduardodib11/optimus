# ADR 0029: Criação de processos pelo usuário

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.1, 6.2, 7.2, 14.2 e T-212
- Relaciona-se com: ADR 0007 (IPC), ADR 0027, ADR 0028 (aceita), T-210, T-211
- Alterada por: ADR 0039 (`thread = 0` como "eu mesmo", `CONFIGURE_TLS`; o
  ciclo da capability da própria thread deixa de existir)

## Contexto

O T-212 pede um processo `hello` no bootfs, iniciado pelo `root`, que
conversa com ele por IPC. Para isso o `root` precisa montar um processo
inteiro a partir do anel 3, e faltam peças que o SDD só nomeia:

- `thread_configure` (nº 10) e `thread_start` (nº 11) estão na tabela da
  seção 14.2, sem registradores definidos. Hoje só o kernel liga uma thread
  a um `CapSpace` e a um `AddressSpace`, registra o buffer de IPC (6.7) e
  o endpoint de exceções (6.4, T-210).
- Um `CapSpace` novo nasce vazio. Nada na ABI põe nele a primeira
  capability: `cap_mint` (6.2) só copia dentro da tabela de quem chama, e a
  transferência por IPC (6.2) exige que o processo já tenha um endpoint.
- A seção 7.2 diz que o `root` "recebe do kernel todas as capabilities
  iniciais", mas o kernel só lhe entrega a cota raiz, o próprio espaço e a
  própria thread; o bootfs, de onde saem os executáveis, fica fora do
  alcance dele.

## Decisão

1. **`thread_configure(thread, cspace, aspace, buffer, exceção, flags)`**,
   nos registradores `rdi`, `rsi`, `rdx`, `r10`, `r8` e `r9`:
   - exige `WRITE_STATE` na thread;
   - `cspace` (com `MANAGE`) e `aspace` (com `MAP`) vêm juntos ou ambos
     nulos (handle 0); ligar a thread só vale antes de `thread_start`
     (senão `Busy`);
   - `flags` diz o que mais muda: bit 0, o buffer de IPC (endereço de uma
     página alinhada na metade de usuário, 0 tira o buffer); bit 1, o
     endpoint de exceções (handle no `CapSpace` da thread, 0 tira). Os dois
     podem mudar com a thread rodando. Bits desconhecidos dão
     `InvalidArgument`;
   - tudo é conferido antes de mudar qualquer campo, salvo que o handle de
     exceções é guardado como veio: sua validade só é conferida a cada falta
     (apagar ou revogar a capability também tira o endpoint).
2. **`thread_start(thread, rip, rsp, a0, a1, a2)`**, nos mesmos seis
   registradores: exige `START`; a thread começa em `rip` com a pilha em
   `rsp` e `a0`–`a2` em `rdi`, `rsi` e `rdx` (como a thread inicial do
   `root`).
3. **`cap_mint(origem, máscara, badge, destino)`**: `r10` passa a ser o
   `CapSpace` de destino (com `MANAGE`), ou 0 para a própria tabela, como
   hoje. Num destino diferente, a cópia é feita como um `cap_mint` local
   (mesmas regras de direitos, badge, profundidade e revogação em
   andamento, conferidas também nos ancestrais remotos) e nasce no
   destino como filha remota da origem, pela árvore de derivação entre
   `CapSpace`s da ADR 0028 (`xcdt`), como na transferência por IPC:
   revogar a origem, ou um ancestral dela, apaga a cópia e o que dela
   derivar no destino; apagar a origem não a apaga (fica um marcador).
4. **O bootfs para o `root`**: o kernel copia a imagem do bootfs (já
   verificada pelo optboot) para um `MemoryObject` e dá ao `root` uma
   capability só com `READ | MAP`. O handle vai nos 32 bits altos de `rdx`
   na entrada do `root`, junto da thread nos 32 baixos
   (`kabi::handle_pair`); `rdi` e `rsi` não mudam.

Com isso, o `root` (pelo `ostd::process`) cria `CapSpace`, `AddressSpace`,
`MemoryObject`s com os segmentos do ELF, pilha, thread e `SchedContext`,
copia para a tabela nova o que o filho precisa e inicia a thread. O buffer
de IPC é registrado pelo próprio processo, que mapeia a página e a acessa
de forma segura pelo `ostd`.

## Alternativas

- **Kernel cria o `hello` e entrega ao `root`:** dispensa a ABI nova, mas
  põe no kernel um carregador de processos para cada serviço, e o SDD
  (7.2) quer o kernel fora disso.
- **Syscall nova de cópia entre tabelas (`cap_copy`):** mais explícita,
  mas a ABI v1 tem 34 syscalls fechadas; o destino opcional de `cap_mint`
  cabe no registrador livre e mantém as mesmas regras de derivação.
- **Filho no mesmo `CapSpace` do pai:** nada a copiar, mas o filho teria
  todas as capabilities do `root`.
- **Bootfs mapeado no `root` em endereço fixo, sem capability:** mais
  simples para o `root`, mas o acesso não seria uma capability, e o `ostd`
  precisaria ler memória que não mapeou (código `unsafe` fora do contrato
  de um mapeamento).

## Consequências

- `kabi` ganha `thread::CONFIGURE_*` e `handle_pair`/`split_handle_pair`;
  o `ostd` ganha invólucros de objetos, `vm_map` com mapeamento seguro
  (`ostd::vm::Mapping`), threads e um carregador de ELF (`ostd::process`,
  com `Spec`, `Child` e `load`).
- Uma thread ligada à própria tabela, que guarda a capability dela, forma
  um ciclo de referências; o processo apaga a capability da própria thread
  quando não precisa mais dela (o `hello` faz isso logo depois de
  registrar o buffer). A ADR 0039 elimina esse ciclo: `thread = 0` vale
  como "a própria thread" em `thread_configure`.
- A seção 14.2 do SDD ganha os registradores das duas syscalls, e a 6.2 o
  destino de `cap_mint`, na próxima revisão do documento.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- A lista de ADRs relacionadas aponta a ADR 0039, que altera o item sobre a
  capability da própria thread.
- O item 1 diz que o handle de exceções não é validado na configuração.
- As consequências citam `ostd::vm::Mapping` e os nomes de `ostd::process`.
