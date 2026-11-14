# T-519: onde está o tempo do IPC em KVM (2026-11-14)

Meta do SDD: ida e volta de IPC (`ipc_call` → `ipc_reply_recv`, par na mesma
CPU) com mediana ≤ 1 µs em KVM. Linha de base: [2026-11-09-608e1c9-kvm.md](2026-11-09-608e1c9-kvm.md),
1,04 µs com 1 CPU e 1,02 µs com 4 CPUs no AMD EPYC 9V45 (KVM aninhado do
runner do GitHub Actions).

## Método

Três rodadas do workflow "Bench em KVM" num ramo de experimento (não
mesclado), com o kernel de release do `main` em `26353a0` e três acréscimos
só de medida:

- **Tempo por etapa:** `LFENCE; RDTSC` em sete pontos do caminho de cada
  sentido (entrada em `syscall_handler`, antes do `invoke`, fim do caminho
  rápido, antes do `switch_context`, depois do `finish_switch`, depois do
  `ops::finish` e antes da volta ao usuário). Cada marca custa ~50 ciclos,
  que estão dentro dos números abaixo.
- **Custo isolado:** cada instrução cara do caminho medida em laço no anel
  0 (mediana de 101 lotes de 64).
- **Variantes:** a mesma ida e volta no mesmo boot com PCID ligado só
  durante a medida, sem salvar e carregar a FPU e sem tocar no `FS_BASE`.
  As duas últimas são incorretas em geral (só valem porque as threads do
  benchmark não usam FPU nem TLS) e servem para medir o teto do ganho.

O host do runner muda de uma rodada para outra: duas caíram num Intel Xeon
6975P-C (2,7 GHz) e uma num AMD EPYC 9V74, todos com KVM aninhado.

## Custo isolado (ciclos)

| Operação | Intel 6975P-C | AMD EPYC 9V74 |
|---|---:|---:|
| RMW atômico (`lock xadd`) | 18–22 | 5 |
| `lfence; rdtsc` | 49 | 48 |
| `rdmsr` do `FS_BASE` | 69 | 91 |
| `wrmsr` do `FS_BASE` | 152 | 62 |
| `xgetbv` com ECX = 1 (XINUSE) | 11 | 34 |
| `xsaveopt` + `xrstor` (áreas alternadas, como na troca) | 145 | **370** |
| só `xrstor` | 68 | 282 |
| `mov cr3` (raízes alternadas, sem PCID) | 107–252 | 127 |

A troca de FPU é o item mais caro do caminho no AMD: ≈ 740 ciclos por ida e
volta, perto de 280 ns, mais que a troca de CR3. Os programas do sistema são
compilados sem SSE (alvo `x86_64-unknown-none`), então quase sempre esse
trabalho salva e carrega o estado inicial.

Lição da rodada no AMD: ler o CR4 é interceptado pelo KVM no SVM (cada
leitura vira uma saída para o hipervisor, ≈ 14 000 ciclos no aninhado). O
experimento de PCID lia o CR4 a cada troca e levou a ida e volta a 12 µs
naquele host. O kernel não lê CR0 nem CR4 no caminho quente, e assim deve
continuar.

## Tempo por etapa (Intel 6975P-C, ciclos por sentido, média)

| Etapa | Ciclos | O que tem |
|---|---:|---|
| Volta ao usuário, usuário e entrada seguinte | ≈ 310 | `sysret`, `syscall`, `swapgs`, quadro do asm; faltas de TLB do usuário depois do `mov cr3` |
| Despacho | ≈ 50 | `current()` e `cspace()` (clones de `Arc`) |
| Caminho rápido (`fast::call` ou `fast::reply_recv`) | ≈ 375 | travas, filas do endpoint, `Reply`, doação |
| Escalonador até o `switch_context` | 510–660 | `direct_switch`, cobrança, FPU, CR3, `rdmsr` do `FS_BASE` |
| `switch_context` + `finish_switch` | ≈ 50 | |
| `ops::finish` | ≈ 25 | |
| Fim da syscall | ≈ 35 | resultado nos registradores, `kpressure::poll` |

Com PCID, a primeira etapa cai de ≈ 310 para ≈ 185 ciclos (as traduções do
usuário sobrevivem à troca), mas o `mov cr3` com etiqueta custa mais, e o
ganho líquido fica perto de 150 ciclos por ida e volta.

## Variantes (Intel 6975P-C, mediana com as marcas de tempo ligadas)

| Variante | 1 CPU | 4 CPUs | Diferença |
|---|---:|---:|---:|
| Base | 1219 ns | 1200 ns | — |
| PCID | 1162 ns | 1185 ns | −1% a −5% |
| Sem FPU | 1098 ns | 1104 ns | −8% a −10% |
| Sem `FS_BASE` | 1136 ns | 1144 ns | −5% a −7% |
| As três juntas | 1000 ns | 999 ns | −17% |

As marcas somam ≈ 700 ciclos (≈ 260 ns) por ida e volta; sem elas, a base
neste host fica perto de 950 ns.

## Conclusões

1. **FPU:** é o maior custo que não é do modelo, e o único grande que sai
   sem mudar a arquitetura: pular o `XSAVEOPT`/`XRSTOR` quando os
   registradores e a área estão no estado inicial (ADR 0058, item 1). Teto
   medido: −110 ns no Intel; no AMD, pelo custo isolado, perto de −250 ns.
2. **PCID:** rende ≈ 50 ns no Intel e muda o protocolo de shootdown (ADR
   0031, item 7). Não compensa agora; segue adiado (ADR 0058, item 3).
3. **`FS_BASE`:** o `rdmsr` da troca é necessário, porque o usuário zera o
   `FS_BASE` ao carregar um seletor em FS e o valor vazaria para a próxima
   thread (ADR 0039, item 3). Tirá-lo pediria `FSGSBASE`, que dá ao usuário
   `wrgsbase` (mudança de ABI). Fica como está (ADR 0058, item 4).
4. **Atômicos e travas:** no Intel, os 58 RMW custariam até ≈ 1100 ciclos por
   ida e volta se nenhum se sobrepusesse; no AMD, até ≈ 300. O que sobra está espalhado (doação, `Arc` da
   entrada, travas de tíquete) e é o próximo passo se a FPU não bastar
   (ADR 0058, item 2).

## Resultado do item 1 da ADR 0058 (FPU sem trabalho redundante)

`cargo xtask bench` no workflow "Bench em KVM", mediana da ida e volta de
IPC; cada par é uma rodada (1 CPU / 4 CPUs). A linha de base é a `main` em
`86565f6`, medida no mesmo dia. A mudança foi medida com o código deste PR
sobre `26353a0` (commit de experimento `60f59a5`; a diferença para a `main`
é só a T-515, fora do caminho do IPC). O host é sorteado a cada rodada.

| Host do runner | Linha de base | Com o item 1 | Variação |
|---|---:|---:|---:|
| AMD EPYC 9V74 | 891 / 901 ns; 881 / 891 ns | **640 / 640 ns** | −28% |
| AMD EPYC 9V45 | 1050 / 1010 ns | não sorteado | — |
| Intel Xeon 6975P-C | ≈ 950 ns (estimado das rodadas com marcas) | **848 / 845 ns**; 846 / 954 ns | ≈ −11% |
| Intel Xeon Platinum 8370C | não sorteado | 1180 / 1080 ns | — |

A troca entre processos caiu junto: de 395–400 ns para 270 ns no AMD 9V74.

Leitura: a meta passa com folga nos dois hosts mais comuns do runner (AMD
9V74 e Intel 6975P-C). O Intel 8370C (Ice Lake, o mais lento do sorteio)
fica acima de 1 µs mesmo com o item 1; o próximo passo para ele é o item 2
da ADR 0058. No AMD 9V45, o host da ressalva da T-430, o ganho esperado
pelo custo isolado da FPU é da ordem do medido no 9V74.

O `cargo xtask test kernel` em KVM passou com a mudança (95 testes,
`thread.fpu_inicial_nao_vaza` incluso, com XINUSE presente) no AMD 9V74 e
no Intel 6975P-C. No 8370C só o `timer.mil_no_prazo` falhou (p99 de atraso
de 517 µs, ruído do host; o teste da FPU passou). Uma versão
quebrada de propósito, que pulava o `XRSTOR` sem olhar a área de quem
entra, fez o teste falhar em KVM (499 de 500 voltas com estado errado na
thread que suja a FPU). No TCG o teste passa nas duas versões, porque o
QEMU sem KVM não zera o XINUSE como o hardware; a validação vale em KVM.
