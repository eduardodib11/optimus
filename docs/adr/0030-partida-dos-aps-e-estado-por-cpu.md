# ADR 0030: Partida dos APs e estado por CPU

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 5.1, 5.2, 6.4, 6.5, 6.8 e 6.9; backlog do M3, T-303
- Relaciona-se com: ADR 0009 (kernel não preemptível), ADR 0010 (SMP),
  ADR 0026 (mapa direto), ADR 0031 (travas e IPIs), ADR 0032 (escalonador
  SMP), ADR 0039 (runtime do `ostd`, `FS_BASE`), T-316 a T-322

## Contexto

O kernel do M2 roda só no BSP (o núcleo que o firmware entrega ao
`optboot`). A seção 6.9 resume a partida dos demais núcleos numa linha
("ACPI MADT, INIT-SIPI-SIPI") e a 6.4 reserva a faixa
`0xFFFF_E000_0000_0000` para "áreas por CPU e pilhas do kernel", sem dizer o
que há nelas. Hoje o estado de CPU é global:

- `arch/x86_64/syscall.rs` tem uma `PerCpu` estática (`this`, `kernel_rsp`
  em `gs:[8]`, `user_rsp` em `gs:[16]`), apontada por `GS_BASE`;
- `gdt.rs` tem uma GDT, uma TSS e três pilhas IST estáticas;
- `kthread.rs` guarda o rsp do ocioso em `IDLE_RSP` e todo o escalonador em
  `SCHED`; `ktime.rs` guarda o timer armado em `ARMED`;
- `apic.rs` só sabe mandar self-IPI e NMI "a todas as outras"; `acpi.rs`
  só procura o HPET;
- `kmem::init` remove a identidade da metade baixa, então nenhum código
  pode rodar em endereço físico depois do boot.

Um AP acorda em modo real, em endereço abaixo de 1 MiB, sem paginação.
Para chegar ao Rust do kernel ele precisa de código nessa faixa, de tabelas
de página com o `CR3` abaixo de 4 GiB (o modo protegido de 32 bits só
carrega 32 bits de `CR3`) e de todo o estado que o BSP já configurou para
si: GDT, TSS, IDT, MSRs, `CR0`/`CR4`/`EFER`, APIC e relógio.

## Decisão

### 1. Topologia pela MADT, lida pelo kernel

- O kernel lê a MADT (assinatura `APIC`) a partir do `acpi_rsdp` da
  `BootInfo`, com as mesmas defesas do `acpi.rs` (assinatura, tamanho,
  checksum e teto de 64 KiB). **A `BootInfo` não muda** e o `optboot` não
  conta CPUs: a lista de CPUs é dado de firmware que o kernel já sabe ler.
- Entradas usadas: tipo 0 (APIC local: id de 8 bits), tipo 9 (x2APIC: id
  de 32 bits) e tipo 5 (endereço do APIC local de 64 bits). Uma CPU entra
  só com o bit 0 (`Enabled`) ligado; o bit 1 (`Online Capable`, hotplug) é
  registrado e ignorado no M3. Ids repetidos (a mesma CPU nos tipos 0 e 9)
  contam uma vez; entradas de IOAPIC (1), ISO (2) e NMI (4 e 0xA) são
  guardadas para os drivers, sem uso no kernel.
- Cada CPU recebe um **id lógico** denso, `0..n`: o BSP (pelo id lido do
  próprio APIC) é o 0 e os demais seguem a ordem da MADT. Todo o kernel e a
  ABI (máscara de afinidade da ADR 0032) usam o id lógico; o id de APIC só
  aparece no envio de IPIs (`PerCpu::apic_id`).
- Limite `MAX_CPUS = 256` (RF-03), constante de `kabi`. CPUs além do
  limite, ou com id de APIC acima de 254 com o BSP em modo xAPIC, ficam de
  fora com aviso no log.
- A opção `smp=N` da linha de comando limita o número de CPUs ligadas (com
  `smp=1` o kernel se comporta como no M2); serve aos testes e ao
  diagnóstico.

### 2. Área por CPU

Uma `PerCpu` por CPU, `#[repr(C)]`, alinhada a 4 KiB e apontada por
`GS_BASE` no kernel (convenção atual de `syscall.S`: `KERNEL_GS_BASE`
guarda o GS do usuário e toda entrada vinda do anel 3 faz `SWAPGS`). Os três
primeiros campos mantêm os deslocamentos que o assembly já usa:

| Deslocamento | Campo | Uso |
|---|---|---|
| `gs:[0]` | `this` | endereço da própria `PerCpu` (`percpu()` lê daqui) |
| `gs:[8]` | `kernel_rsp` | topo da pilha de kernel da thread atual |
| `gs:[16]` | `user_rsp` | rascunho do rsp do usuário na entrada |
| `gs:[24]` | `cpu_id: u32`, `apic_id: u32` | ids lógico e de APIC |
| depois | `gdt`, `tss` | GDT e TSS desta CPU (item 4) |
| | `idle_rsp` | substitui `IDLE_RSP` |
| | `timer_armed`, `timer_stats` | substitui `ARMED` de `ktime.rs`; disparos |
| | `mailbox` | caixa de pedidos de IPI e de shootdown, com `need_resched` (ADR 0031) |
| | `held` | pilha de classes de trava, só consultada em debug (ADR 0031) |
| | `thread`, `panic_dump` | thread que roda e registradores salvos no congelamento (ADR 0031) |
| | `online`, `borrows` | CPU pronta; empréstimos abertos (debug) |
| | caches de frames e de objetos | só desta CPU, sem trava (T-328) |

O escalonador de cada CPU **não** mora na `PerCpu`: é um `Sched` por CPU em
`kthread::SCHEDS[cpu_id]` (o do BSP é estático), com `switch_prev` dentro
dele e os resumos atômicos `CUR_PRIO` e `NR_READY` ao lado (ADR 0032).

- O BSP usa a instância estática que já existe (ampliada), porque exceções
  podem chegar antes do alocador; os APs recebem a sua do buddy, no mapa
  direto, antes do INIT. Essa memória é do kernel no boot (como as pilhas
  IST estáticas de hoje) e sai da memória entregue à cota raiz, sem
  cobrança de cota de usuário.
- **Pilhas por CPU** numa janela fixa da faixa da seção 6.4:
  `PERCPU_WINDOW = 0xFFFF_F000_0000_0000`, 256 KiB por CPU (a da CPU `i`
  começa em `PERCPU_WINDOW + i * 256 KiB`), com quatro pilhas de 16 KiB (ociosa
  e boot, IST de falta dupla, NMI e verificação de máquina), cada uma com
  16 KiB de guarda não mapeada abaixo. As pilhas de kernel das threads
  continuam em `0xFFFF_E000_0010_0000` em diante (`kvm.rs`), sem colisão.
  Como a metade alta do PML4 tem todas as entradas criadas no boot
  (`kmem::init`), a janela aparece em todos os `AddressSpace`s.
- No topo de cada pilha IST fica o endereço da `PerCpu` dona dela. NMI e
  `#MC` não confiam em GS (podem chegar entre a entrada e o `SWAPGS`) e
  acham a `PerCpu` por `rsp` alinhado; é assim que o congelamento do pânico
  sabe em que CPU está.
- **Regra de uso:** uma referência à `PerCpu` (ou ao id lógico lido dela)
  não pode atravessar uma chamada que troque de contexto (`schedule`,
  `block_until`, `handoff`, `preempt`, `exit_current`): a thread pode voltar
  em outra CPU (ADR 0032). O acesso é por função de vida curta
  (`percpu::with(|p| ...)`) e, em debug, `schedule` confere que nenhum
  empréstimo da `PerCpu` nem dos caches por CPU está aberto (contador na
  própria `PerCpu`).

### 3. Trampolim e INIT-SIPI-SIPI

- **Memória baixa.** `kmem::init` separa, antes de entregar o mapa ao
  buddy, seis páginas consecutivas usáveis abaixo de 1 MiB e acima de
  `0x1000` (o vetor do SIPI é o número da página): código do trampolim,
  parâmetros, PML4, PDPT, PD e PT temporários. Sem essa faixa no mapa de
  memória, o kernel avisa e segue só com o BSP. As páginas ficam
  reservadas depois do boot (24 KiB), para hotplug e para a volta da
  suspensão em marcos futuros.
- **Tabelas temporárias.** O PML4 temporário copia as entradas 256 a 511
  do PML4 do kernel (a metade alta, a mesma de todos os espaços) e tem na
  entrada 0 a identidade só das páginas do trampolim: código `R+X`,
  parâmetros `R` e `NX`, nada mais. W^X vale: o BSP escreve o trampolim
  pelo mapa direto (`RW`, `NX`) e o AP o executa pela identidade. Os
  descritores da GDT do trampolim já nascem com o bit de acessado ligado: o
  salto para o código de 64 bits carrega o CS com a paginação ligada, e a
  CPU gravaria esse bit na página de parâmetros, que a identidade mapeia só
  para leitura (com `CR0.WP`, um `#PF` sem IDT: falta tripla no AP, vista em
  KVM).
- **Sequência do AP** (assembly em `arch/x86_64/ap.S`, cópia posicionável
  instalada pelo BSP):
  1. modo real: `cli`, carrega uma GDT mínima dos parâmetros e liga
     `CR0.PE`;
  2. 32 bits: `CR4.PAE` (e `PGE` como o BSP), `EFER.LME | EFER.NXE` (sem
     `NXE` as entradas `NX` da metade alta são bits reservados e dão falta),
     `CR3` temporário e `CR0.PG | CR0.WP`;
  3. 64 bits na identidade: lê dos parâmetros o `CR3` do kernel, o topo da
     pilha ociosa, o endereço da `PerCpu` e a entrada `ap_entry` na metade
     alta, salta para lá, troca para o `CR3` do kernel (sem identidade) e
     chama `ap_main(percpu)` em Rust.
- **Envio** (`apic::send_init`, `apic::send_sipi`, generalizando
  `self_ipi`): em x2APIC um `wrmsr` de 64 bits no ICR (`0x830`) com o
  destino nos 32 bits altos; em xAPIC, `ICR_HIGH` com o destino nos bits
  24–31 e depois `ICR_LOW`, esperando o bit 12 (entrega pendente) zerar
  antes de cada escrita. Sequência: INIT, 10 ms, SIPI, 200 µs, segundo SIPI
  se o AP ainda não deu sinal, e espera de até 100 ms por
  `PerCpu::online`. O AP que não responde, ou que o teste de TSC (item 5)
  recusa, recebe outro INIT para voltar a esperar SIPI sem rodar com
  parâmetros velhos. Tempos medidos pelo relógio de `ktime` (a partida vem
  depois de `ktime::init`).
- **Uma CPU por vez.** O BSP liga os APs em série, reaproveitando a página
  de parâmetros; o AP que não responde no prazo fica fora (aviso no log,
  sem pânico) e a partida segue. Partida paralela fica para quando o tempo
  de boot medir a diferença.

### 4. Inicialização completa do AP (`ap_main`)

Na ordem, com IF=0 o tempo todo:

1. GDT, TSS e `GS_BASE` da própria `PerCpu` (`PerCpu::install`: `lgdt`,
   `ltr`, `GS_BASE = percpu`, `KERNEL_GS_BASE = 0`): a GDT é por CPU porque
   o descritor da TSS tem base própria e bit de ocupada. Depois, `lidt`: a
   IDT é **uma só**, imutável depois do boot, carregada em cada CPU.
2. `CR0`, `CR4` e `EFER` com os mesmos bits do BSP (`cpustate::apply`: `WP`,
   `SMEP`, `SMAP`, `UMIP`, `NXE`, `OSXSAVE`), `XCR0` igual ao do BSP, o
   mesmo PAT, `TSC_ADJUST` do BSP e `TSC_AUX = cpu_id`. A CPU que não tiver
   um recurso que o BSP ligou, ou que pedir área de XSAVE de outro tamanho
   (`fpu::area_bytes` é global), para em `hlt` e fica fora, com aviso.
3. `STAR`, `LSTAR`, `FMASK` e `EFER.SCE` como no BSP (`syscall::init`).
4. APIC local no mesmo modo do BSP (x2APIC em todos ou em nenhum), vetor
   espúrio e timer mascarado; o 8259 só o BSP mascara. Sem o modo do BSP, a
   CPU fica fora.
5. Sinal ao BSP (`PerCpu::online`) e teste de salto do TSC com ele (item 5).
6. O BSP, depois de aceitar o AP no teste, liga o bit da CPU em `ONLINE`
   (máscara atômica de 256 bits); o AP entra no laço ocioso do escalonador
   (ADR 0032).

### 5. TSC e timer por CPU

- O relógio monotônico (seção 6.8) continua sendo o TSC calibrado no BSP;
  todas as CPUs usam o mesmo `TSC_MULT`.
- Com `IA32_TSC_ADJUST` (CPUID 7, `EBX[1]`), o AP grava nele o valor do
  BSP antes de qualquer leitura do TSC. Em seguida BSP e AP rodam o teste de
  salto: 10⁴ rodadas em que cada um lê o último TSC publicado pelo outro e o
  próprio, sob uma trava; um valor próprio menor que o publicado é salto.
  Salto acima de 1 µs (meta do T-321) é corrigido uma vez por
  `TSC_ADJUST` (soma o atraso medido, uma única vez, e mede de novo);
  persistindo, o AP fica fora. Assim, duas leituras ordenadas
  por memória compartilhada nunca andam para trás entre CPUs, que é o que
  `clock_get` promete.
- Sem TSC invariante (CPUID `0x8000_0007`, `EDX[8]`), como no TCG, o teste
  de salto decide sozinho e o kernel só avisa no log.
- O timer em modo deadline já é por CPU no hardware; `ARMED` vai para a
  `PerCpu`. No modo one-shot (TCG), os APs usam a frequência do timer do
  APIC calibrada no BSP (mesmo barramento).

### 6. `FS_BASE` e `GS_BASE` do usuário

- `CR4.FSGSBASE` fica **desligado** no M3: o usuário não escreve as bases
  diretamente, e a entrada no kernel continua com um `SWAPGS` incondicional
  por entrada vinda do anel 3.
- O GS do usuário é sempre zero: não há como mudá-lo sem `FSGSBASE`
  (carregar um seletor em GS zera a base), então nada é salvo por thread.
- O `FS_BASE` do usuário é estado **da thread**: salvo e restaurado na troca
  de contexto (`wrmsr` só quando muda) e definido por syscall. Qual syscall
  e qual registrador fica com a ADR 0039 (T-333); esta ADR só fixa que o
  valor mora na `Thread` e não na `PerCpu`. A ADR 0039 fixou a ABI
  (`CONFIGURE_TLS` em `thread_configure`); o salvamento e a restauração na
  troca de contexto entram na T-333 e ainda não existem no código.

## Alternativas

- **Número de CPUs na `BootInfo`, contado pelo `optboot`:** o `optboot`
  já lê ACPI, mas passaria a interpretar a MADT e a `BootInfo` mudaria; o
  kernel continuaria precisando dos ids de APIC. Ler a MADT no kernel
  reaproveita o `acpi.rs` e não toca a ABI de boot.
- **Partida pelo protocolo de multiprocessador do UEFI
  (`EFI_MP_SERVICES_PROTOCOL`):** some com o `ExitBootServices`; os APs
  teriam de ficar estacionados em código do `optboot`, fora do controle do
  kernel.
- **Uma GDT para todas as CPUs com N descritores de TSS:** funciona, mas
  liga a GDT ao número de CPUs e põe numa tabela global o que é de cada
  núcleo.
- **`FSGSBASE` ligado:** TLS mais barato (o usuário troca `FS` sem
  syscall), mas o usuário passa a controlar GS e toda entrada (NMI, `#MC`,
  `#DB`) precisa descobrir se já fez `SWAPGS`. Pode voltar quando o custo
  do TLS for medido.
- **`PerCpu` por `TSC_AUX` + `RDPID`:** dispensaria GS no kernel, mas
  `RDPID` não existe em toda CPU e o assembly atual já usa GS.
- **Ligar os APs em paralelo:** boot mais rápido com muitos núcleos, mas
  exige uma página de parâmetros por AP e complica o diagnóstico de quem
  não respondeu.

## Consequências

- Nenhuma mudança de ABI de usuário nesta ADR. `kabi` ganha `MAX_CPUS`; a
  máscara de CPUs e `sys_info` vêm na ADR 0032, e o `FS_BASE` na ADR 0039.
- `PERCPU`, `IDLE_RSP`, `ARMED`, a TSS e as pilhas IST estáticas deixam de
  ser globais (T-317); o BSP mantém a instância estática como CPU 0.
- O kernel passa a ter assembly de 16 e 32 bits (`ap.S`), contado nas
  ≤ 3 mil linhas de arquitetura da seção 6.
- 24 KiB abaixo de 1 MiB ficam reservados para sempre; máquinas sem
  memória livre ali sobem com um núcleo só.
- CPUs heterogêneas em recursos (por exemplo, núcleos sem `SMAP`) ficam
  fora em vez de rodar com proteção menor.

### Verificação

- Host: o parser da MADT recebe as tabelas reais do QEMU com `-smp 1, 2,
  4, 8` e tabelas estragadas (checksum, tamanho, ids repetidos, CPU
  desabilitada, id acima de 254 em xAPIC) (T-316).
- Kernel: com `-smp 4`, cada AP escreve "cpuN online" e `cpu_id()` confere
  com o APIC; 100 boots seguidos sem travar (T-318); todas as CPUs ociosas
  e estáveis por 60 s com o timer ligado (T-319); salto de TSC ≤ 1 µs e
  `clock_get` monotônico entre CPUs em 10 s (T-321).
- Revisão: nenhum estado de CPU global sobra depois do T-317.
- TLA+ não cobre a partida: ela é sequencial e verificada por teste.

### Lacunas do SDD

- A 6.9 não diz de onde vem a lista de CPUs (BootInfo ou MADT no kernel)
  nem como os ids são numerados; aqui é a MADT, com ids lógicos densos.
- A 6.4 reserva a faixa de "áreas por CPU" sem layout; o layout acima
  entra na tabela da 6.4 na próxima revisão.
- A 6.8 fala em TSC invariante, mas não em sincronização entre CPUs nem no
  que fazer quando o TSC salta; aqui a CPU com salto fica fora.
- Nada no SDD diz que `FSGSBASE` fica desligado nem onde mora o `FS_BASE`
  do usuário.
- A 6.9 e a 16.4 pedem testes SMP em AArch64; o M3 é só x86-64 (backlog,
  lacuna 12), e PSCI fica para o porte ARM.
- Não há decisão sobre hotplug de CPU (bit `Online Capable`); fica fora do
  M3.

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- A tabela da `PerCpu` espelha o código: `mailbox`, `held`, `thread`,
  caches por CPU; o escalonador fica em `kthread::SCHEDS`, não na `PerCpu`.
- O acesso é por `percpu::with`, e a conferência em debug inclui os caches.
- A GDT do trampolim já nasce com o bit de acessado (correção do #62).
- O AP recusado ou mudo recebe outro INIT.
- A ordem do `ap_main` segue o código, e quem liga o bit em `ONLINE` é o BSP.
- A correção do TSC soma o atraso medido uma única vez.
- O `FS_BASE` por thread fica marcado como T-333, ainda não implementado.
