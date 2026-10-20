# ADR 0010: SMP com filas por CPU e locks finos; M1 em um núcleo

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 6.3, 6.6, 6.9 e 20.2
- Relaciona-se com: ADR 0008 (escalonador), ADR 0009 (kernel não preemptível)

## Contexto

O Optimus vai de máquinas Lite de dois núcleos ao perfil Server com muitos
núcleos e NUMA. Adaptar um kernel feito para um núcleo ao SMP depois costuma
exigir reescrever as estruturas centrais. Por outro lado, depurar boot, memória
e escalonador já é difícil sem concorrência, e o M1 precisa sair cedo.

## Decisão

- O kernel é projetado para SMP desde o início: estado por CPU, filas do
  escalonador por CPU, cache de frames por CPU no alocador buddy.
- A sincronização usa locks por objeto (ticket spinlock), nunca um lock global.
- A ordem de aquisição é fixa e documentada: CapSpace → objeto →
  AddressSpace → fila do escalonador, verificada em debug e nos modelos. A
  ADR 0028 pôs a trava `CDT` na frente, e a ADR 0031 fixa a ordem completa.
- Balanceamento por migração periódica e no wake-up, respeitando afinidade e
  NUMA. TLB shootdown por IPI, agrupado e só para CPUs que usaram o AddressSpace.
- O M1 entrega o kernel em um núcleo; a partida dos demais (ACPI MADT ou PSCI)
  vem depois, sem mudar as estruturas de dados.

## Alternativas

- **Big Kernel Lock, como o Linux 2.0 e o FreeBSD 4:** fácil de acertar, mas
  serializa todo o kernel. A retirada no Linux levou cerca de quinze anos.
- **Kernel multikernel, uma instância por núcleo (estilo Barrelfish):** escala
  bem, mas troca memória compartilhada por mensagens entre núcleos e complica
  o IPC síncrono rápido da ADR 0007.
- **Estruturas sem lock (RCU e afins) em todo lugar:** máximo desempenho, porém
  difícil de provar e de revisar; fica para pontos medidos como gargalo.
- **SMP já no M1:** atrasaria o primeiro marco e misturaria falhas de
  concorrência com falhas básicas de boot e memória.

## Consequências

- A ordem de locks é parte do contrato do kernel e entra na revisão de código.
- O harness de testes do kernel roda os cenários de SMP em x86-64 e AArch64;
  no M3 só o x86-64 (ADR 0030), e o AArch64 fica para o porte ARM.
- O escalonador é indexado por CPU. O futex é indexado pelo endereço físico da
  palavra (ADR 0032).
- Até o SMP entrar, o código já usa locks, mesmo que nunca haja disputa.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- Ordem de travas atualizada pelas ADRs 0028 (`CDT`) e 0031 (ordem completa).
- A chave do futex passa a ser o endereço físico (ADR 0032).
- Registrado que o SMP no AArch64 fica para o porte ARM (ADR 0030).
