# Caches por CPU de frames e de objetos do heap

T-328 (ADR 0031, item 3). Código em `okernel::mm::cache` (as pilhas,
testadas no host), `kmem` (frames), `kheap` (objetos) e
`arch::x86_64::percpu` (onde cada CPU guarda as suas).

## Desenho

Cada CPU tem, na sua `PerCpu`, pilhas de endereços (`Magazine`) na frente
do buddy e do slab:

| Cache | O que guarda | Capacidade | Lote |
|---|---|---|---|
| Frames (`FrameCache`) | frames de 4 KiB (ordem 0) da faixa do buddy | 64 (256 KiB) | 32 |
| Objetos (`ObjectCache`) | uma pilha por classe do slab (16 B a 2 KiB) | 8 por classe | 4 |

- **Alocar** tira do topo da pilha. Vazia, a CPU toma a trava do alocador
  de trás (`Frames` ou `Heap`) uma vez e traz um lote.
- **Liberar** põe no topo. Cheia, a CPU devolve um lote numa tomada só e
  então põe.
- Assim cada CPU passa pela trava global no máximo uma vez por lote, e na
  maior parte das operações não toca memória compartilhada.
- Pedidos de ordem maior que 0 vão direto ao buddy. Se o buddy falha, a
  CPU devolve o próprio cache de frames e tenta de novo, porque os frames
  parados podem completar um bloco.
- Objetos grandes (acima de 2 KiB) vão direto ao heap.

### Sem trava

Só a própria CPU usa os seus caches, com IF=0 (ADR 0009), por
`percpu::with_frame_cache` e `percpu::with_object_cache`. Um sinalizador
por cache acusa pânico na reentrada, e `schedule` confere que nenhum
empréstimo atravessa uma troca de contexto. Com o cache emprestado, a CPU
pode tomar as travas de trás:

- com o de objetos, `Heap` e, por ela, `Frames` e o cache de frames;
- com o de frames, só `Frames`.

A ordem está em `docs/kernel/ordem-de-travas.md`.

### Contas

- `kmem::frame_stats` conta os frames parados nos caches como livres.
- `kheap::live_blocks` desconta os objetos parados.
- Cada `PerCpu` publica quantos itens tem (atômicos lidos por qualquer
  CPU), para essas contas não precisarem dos caches dos outros.

### Custo de memória

- Um objeto parado no cache conta como alocado para o slab e segura o slab
  dele; a capacidade pequena (8 por classe) limita isso.
- `kheap::drain_object_cache` e `kmem::drain_frame_cache` devolvem tudo o
  que está no cache da CPU que chama.

### Liberação dupla

Uma liberação dupla só é pega se o item ainda está no cache da mesma CPU
(`contains`; frames: registro de erro; objetos: `BadFree`). As que chegam
ao buddy ou ao slab continuam pegas lá.

## Testes

- **Host** (`cargo test -p okernel --lib mm::cache`): pilha, lotes,
  capacidade, uma pilha por classe e 2×10⁴ operações aleatórias contra um
  buddy simulado sem perder nem repetir item.
- **Kernel**
  - `mm.frames_concorrentes_sem_perda_nem_repeticao` (aceite): `mm.frames_ops` (10⁶ por padrão)
    alocações e liberações somadas, em todas as CPUs. Os frames passam de
    uma CPU para outra por uma troca de posições. Cada frame leva uma marca
    com o dono, e um frame com dois donos é acusado. No fim, os livres
    voltam ao valor de antes.
  - `mm.frames_escala_de_1_a_4_cpus`: a medida abaixo. Os frames voltam
    todos depois de cada medida, e os objetos vivos do heap voltam ao valor
    de antes no fim.

## Escala de 1 a 4 CPUs

Medido com o teste `mm.frames_escala_de_1_a_4_cpus`. Em cada CPU, 4×10⁴
operações: aloca 8, solta os 8, repete. Os números são de **QEMU 8.2 TCG,
sem KVM**, num host de 4 núcleos, e servem para comparar com e sem cache.
Não valem como tempo absoluto.

```
cargo xtask run --release --smp 4 --cmdline "test=kernel ktest=mm.frames_escala"
```

Operações por milissegundo, somadas as CPUs, em release com `-smp 4`, duas
execuções:

| CPUs | Frames com cache | Frames sem cache | Heap 64 B com cache | Heap 64 B sem cache |
|---|---|---|---|---|
| 1 | 7326 / 3484 | 7890 / 3751 | 3813 / 3810 | 4733 / 4718 |
| 2 | 15335 / 7303 | 1614 / 1434 | 7810 / 7844 | 1910 / 1768 |
| 3 | 19663 / 10914 | 465 / 456 | 11919 / 12283 | 578 / 532 |
| 4 | 16678 / 14828 | 150 / 135 | 13374 / 16888 | 144 / 136 |

Em debug (o kernel de teste), `-smp 4`:

| CPUs | Frames com cache | Frames sem cache | Heap 64 B com cache | Heap 64 B sem cache |
|---|---|---|---|---|
| 1 | 254 | 216 | 137 | 153 |
| 4 | 894 | 74 | 404 | 81 |

O que se lê daí:

- **Sem cache, piora com mais CPUs.** Em release, 4 CPUs fazem menos de
  um décimo do que 1 CPU faz sozinha. A trava global vira a fila, e no
  TCG o giro de uma vCPU disputa o host com a dona da trava.
- **Com cache, escala.** Com 4 CPUs, de 2 a 4 vezes o que 1 CPU faz, e
  cerca de 100 vezes o que 4 CPUs fazem sem cache.
- **Com 1 CPU, o cache não ganha** e, no heap, custa de 10% a 25%. Uma
  operação sem disputa da trava já é barata, e o cache soma o empréstimo
  e as contas.
- **Variação entre boots.** Entre as duas execuções em release, a mesma
  medida variou até 2× (frames com 1 CPU). É o ruído do TCG. Compare só
  dentro da mesma execução.

**Pendente (KVM):** medir em KVM, onde o custo de uma trava disputada e o
de uma operação local são outros. Se em KVM o cache custar mais que o
ganho com 1 CPU, ajustar capacidade e lote. Aqui não há KVM.

## Nota: páginas zeradas e o TCG

Junto com o T-328, as pilhas de kernel (`kvm::alloc_kernel_stack`) e as
páginas do heap (`kheap`) passaram a sair zeradas, como já saíam os frames
de usuário, as tabelas e as pilhas dos APs.

O motivo é o TCG. Uma página livre pode ainda ter traduções de código do
firmware, ou de código de usuário que morou nela. Enquanto alguma tradução
sobra, toda escrita na página passa pela invalidação
(`tb_invalidate_phys_range_fast`). O ping-pong de IPC com 1 CPU ficava de
8 a 15 vezes mais lento (de 90 s a 170 s em vez de 11 s) em cerca de
metade dos boots, e o teste vencia o prazo.

Isso também acontecia na `main`: 4 falhas em 8 execuções. Com as páginas
zeradas, foram 8 de 8 em 11 s a 12 s. Zerar escreve a página inteira, o
que derruba as traduções velhas de uma vez.
