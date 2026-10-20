# Fragmentação do alocador do `ostd` (2026-10-20)

- Commit: `a28b3bc` (T-334)
- Comando: `cargo test -p oalloc --release fragmentacao -- --nocapture` (e, para o teste de 4 threads, `cargo test -p oalloc --release um_milhao -- --nocapture`)
- CPU do host: Intel(R) Xeon(R) @ 2.10GHz, 4 CPUs
- Kernel do host: 6.18.44-fc-v139
- rustc: 1.97.0

Os números de fragmentação são deterministas (PRNG próprio com semente fixa, sem relógio): repetir o comando dá os mesmos valores.

## Perda por arredondamento, por pedido

Tamanho do bloco entregue para um pedido de `n` bytes, e a fração perdida (bloco − pedido) / bloco.

| Pedido | Bloco | Perda |
|---:|---:|---:|
| 1 B | 8 B | 87,5% |
| 9 B | 16 B | 43,8% |
| 65 B | 80 B | 18,8% |
| 4097 B | 5120 B | 20,0% |
| 8193 B | 65 536 B | 87,5% |
| 40 000 B | 65 536 B | 39% |
| 65 537 B | 131 072 B | 50% |
| 524 289 B | 2 031 616 B | 74,2% |

Acima de 64 B a perda por classe fica em até 20% (quatro classes por duplicação). Até 64 B as classes são lineares de 8 em 8, então a perda relativa chega a 87,5% no pior caso (1 B). Acima de 8 KiB não há classes: o pedido ocupa páginas inteiras de 64 KiB.

## Cargas mistas

Cada carga sorteia tamanhos, aloca, libera ao acaso parte dos blocos e mede no fim.

| Carga | Pedido vivo | Blocos ocupados | Mapeado | Perda de arredondamento | Mapeado / pedido |
|---|---:|---:|---:|---:|---:|
| 8–256 B | 13,6 MiB | 14,9 MiB | 18,0 MiB | 9,6% | 1,32 |
| 8 B–8 KiB | 11,5 MiB | 12,5 MiB | 16,0 MiB | 9,0% | 1,39 |
| 8 B–64 KiB | 15,5 MiB | 34,2 MiB | 38,0 MiB | 120,1% | 2,45 |
| 8–512 KiB | 23,3 MiB | 30,6 MiB | 38,0 MiB | 31,3% | 1,63 |

"Mapeado" conta segmentos de 2 MiB inteiros, incluindo o cabeçalho (página 0) e as páginas ainda não usadas.

## Retenção depois do pico

Carga de blocos de 64 B: o pico chegou a 14,0 MiB mapeados. Depois de liberar 90% dos blocos ao acaso, os 14,0 MiB continuam mapeados para 1,2 MiB vivos: cada segmento guarda ao menos um bloco, então nenhum fica vazio para ser devolvido. É o comportamento esperado de um alocador sem compactação (blocos não se movem).

## Teste de 4 threads (aceite)

`um_milhao_de_alocacoes_em_4_threads_sem_vazamento_nem_corrupcao`: 1 000 000 alocações e 1 000 000 liberações (332 854 delas feitas por outra thread, pela `thread_free`), blocos preenchidos com padrões conferidos na liberação. No fim todos os segmentos voltaram à fonte. Duração de 3,6 a 4,4 s em release.

O pico de segmentos mapeados ao mesmo tempo varia entre execuções (cerca de 100 a 210 segmentos, 200 a 420 MiB), bem acima do conjunto vivo. A causa é a ordem das liberações entre threads: blocos grandes e enormes liberados por outra thread ficam na `thread_free` da página até o dono recolhê-la, e um segmento só é devolvido quando todas as páginas voltam. Uma tentativa de recolher mais cedo na alocação de blocos grandes não reduziu o pico e foi descartada. Não afeta o aceite (sem vazamento ao fim), mas fica anotado para a T-335, quando cada thread tiver o seu heap de verdade.

## Decisão pendente

As classes de tamanho param em 8 KiB, então um pedido de 8 KiB a 64 KiB ocupa uma página inteira de 64 KiB (perda de até 87,5%, e 120% na carga de 8 B a 64 KiB acima). Opções:

1. Manter: simples, e pedidos nessa faixa são raros em serviços de microkernel.
2. Estender as classes até 32 KiB (mais três ou quatro classes por duplicação, páginas com 2 a 8 blocos).
3. Páginas médias de 512 KiB para a faixa de 8 a 64 KiB.

A recomendação é decidir com uma carga real (T-337, coleções) em vez de agora; o `oalloc` já separa a tabela de classes (`class.rs`), então trocar é local.

## Pendências de revisão para a T-337

Achados da revisão que ficam para depois, junto da T-337 (coleções, strings e aleatoriedade):

- **Ponteiro interior no 2º segmento de um bloco enorme.** O cabeçalho do segmento é achado por `ptr & !(2 MiB - 1)`; um ponteiro interior no segundo segmento de um bloco enorme (de vários segmentos) cai num "cabeçalho" que é dado do usuário. O `owns` só confere a janela. Resolver ao ter a entropia (sorteio de endereços) e um mapa de segmentos de blocos enormes.
- **Janela de `SAFETY:`.** O `xtask` aceita o comentário até 8 linhas antes do `unsafe` (sem outro `unsafe` no meio); apertar para o comentário imediatamente acima.
- **`unsafe fn` sem `# Safety`.** A política exige `// SAFETY:` em blocos e `impl`, mas não a seção `# Safety` na documentação de `unsafe fn`; acrescentar ao `xtask` junto com o `clippy::missing_safety_doc`.

## Carga de coleções (T-337, 2026-10-20)

Para a "Decisão pendente" acima. Comando: `cargo test -p oalloc --release colecoes -- --nocapture` (teste `tests_colecoes::colecoes_fragmentacao`; fora do Miri).

**Método.** Uma thread roda coleções de verdade: 60 `HashMap<u64, String>` (o do `ocoll`, de 4 a 4000 entradas, valores de 4 a 40 B), 300 `Vec<u8>` crescendo por `extend` até 300 KiB, 200 `String` crescendo por `push_str` até 40 KiB; no fim cada tipo perde metade ao acaso. Um `#[global_allocator]` de teste grava cada `alloc`/`dealloc` (o `realloc` padrão é alocar, copiar, liberar, o mesmo que o `ostd` faz) e a sequência (120 821 alocações) é reexecutada num `Heap` do `oalloc`. As colunas "Classes até 32 KiB" e "Páginas médias" calculam o custo de cada bloco vivo sob as opções 2 e 3 (classes de 4 por duplicação até 32 KiB em páginas de 64 KiB; até 64 KiB em páginas de 512 KiB), contando a sobra no fim da página; a tabela de classes **não** foi alterada. O custo "Atual" calculado (12 349 KiB) confere com o do heap real (12,05 MiB, `Stats::live_bytes`). Determinista (semente fixa; os tamanhos das tabelas não dependem da chave do `RandomState`).

Heap real no fim: 21 120 blocos vivos, 8,59 MiB pedidos, 12,05 MiB em blocos (perda de arredondamento **40,3%**), 26,0 MiB mapeados (3,0 vezes o pedido; o pico é o mesmo, porque o churn deixa segmentos meio vazios que não voltam à fonte).

| Faixa | Blocos | Pedido (KiB) | Atual (KiB) | Perda | Classes até 32 KiB (KiB) | Perda | Páginas médias (KiB) | Perda |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| até 64 B | 16789 | 586 | 634 | 8,2% | 634 | 8,2% | 634 | 8,2% |
| 65 B a 8 KiB | 4235 | 467 | 515 | 10,3% | 515 | 10,3% | 515 | 10,3% |
| 8 a 64 KiB | 63 | 1701 | 4032 | 137,0% | 2359 | 38,7% | 1867 | 9,8% |
| 64 a 512 KiB | 33 | 6041 | 7168 | 18,6% | 7168 | 18,6% | 7168 | 18,6% |
| > 512 KiB | 0 | 0 | 0 | 0,0% | 0 | 0,0% | 0 | 0,0% |
| **Total** | 21120 | 8796 | 12349 | **40,4%** | 10677 | **21,4%** | 10185 | **15,8%** |

**Leitura.** Só 63 blocos (0,3% deles) estão na faixa de 8 a 64 KiB, mas custam 33% de tudo o que o alocador entrega (4 032 de 12 349 KiB) e quase todo o desperdício de arredondamento da carga: 2,3 MiB dos 3,5 MiB perdidos. Os `Vec` e `String` que dobram a capacidade (8, 16, 32, 64 KiB) pagam uma página de 64 KiB inteira, e as tabelas do `HashMap` (40 B por balde, 2ⁿ baldes) caem na mesma faixa a partir de 256 baldes. Abaixo de 8 KiB a perda fica em torno de 8 a 10%, e a faixa de 64 a 512 KiB perde 18,6% por arredondar para páginas de 64 KiB, o que nenhuma das duas opções muda.

**Recomendação (para Eduardo decidir).** A opção 2, classes até 32 KiB: derruba a perda total de 40% para 21%, mexe só em `class.rs` (e na capacidade de uma página: 2 a 6 blocos) e não toca o formato do segmento. A opção 3 chega a 16%, mas pede um novo tipo de página no segmento (mapa de páginas, `settle`, adoção e `trim` aprendem de duas granularidades), para ganhar 5 pontos a mais numa faixa que a opção 2 já reduziu de 137% para 39%. A opção 1 (manter) só se justifica se os serviços do M3 não crescerem coleções acima de 8 KiB; esta carga mostra que um `HashMap` com cerca de 200 entradas já cruza essa linha. Nada foi alterado na tabela de classes.
