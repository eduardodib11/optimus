# ADR 0058: Otimização do caminho rápido do IPC (plano B da T-519)

- Status: proposta
- Data: 2026-11-14
- Origem: backlog do M5, T-519 (aberta pelo Eduardo em 2026-11-14 em vez de aceitar a ressalva da T-430); SDD v1.0, seções 6.4, 6.7 e 20.3
- Relaciona-se com: ADR 0027 (registradores de mensagem), ADR 0031 (item 7, TLB e PCID), ADR 0032 (item 7, a troca), ADR 0039 (item 3, TLS)

## Contexto

A meta do SDD é a ida e volta de IPC na mesma CPU com mediana ≤ 1 µs em
KVM. O caminho rápido dedicado (T-331) e a troca direta especializada já
existem. Medida em 2026-11-09 no runner do GitHub Actions (KVM aninhado), a
mediana foi 1,04 µs no AMD EPYC 9V45, depois de 891 ns no EPYC 7763: o
mesmo código, 2% a 4% acima da meta conforme o host.

A investigação da T-519 ([relatório](../bench/2026-11-14-t519-investigacao.md))
mediu em KVM o tempo de cada etapa do caminho, o custo isolado de cada
instrução cara e variantes com PCID, sem FPU e sem `FS_BASE`. O que ela
mostrou:

- A troca de FPU (`XSAVEOPT` da que sai e `XRSTOR` da que entra) custa
  ≈ 145 ciclos por troca no Intel e ≈ 370 no AMD, o item mais caro do
  caminho no AMD. Os programas do sistema são compilados sem SSE, então na
  prática esse trabalho salva e carrega o estado inicial.
- O PCID rende ≈ 50 ns por ida e volta no Intel e exige mudar o protocolo
  de shootdown da ADR 0031.
- O `rdmsr` do `FS_BASE` (≈ 70 a 90 ciclos por troca) protege uma thread
  do `FS_BASE` zerado por outra.
- O resto é software espalhado: 58 RMW atômicos e 2746 instruções por ida
  e volta.

A ABI v1 não pode mudar (T-519, passo 3).

## Decisão

1. **FPU sem trabalho redundante.** A troca continua ansiosa (o estado de
   quem entra está nos registradores antes de voltar ao usuário; nada de
   CR0.TS nem de troca preguiçosa, que o LazyFP, CVE-2018-3665, explora).
   Muda só o trabalho que não altera nada:
   - os registradores estão no estado inicial quando o XINUSE
     (`XGETBV` com ECX = 1) é zero em todo componente do XCR0 **e** o MXCSR
     é o padrão (0x1f80), que o XINUSE do SSE não cobre em todas as CPUs;
   - nesse caso a área de quem sai recebe só o estado inicial no cabeçalho
     (`XSTATE_BV` zero e MXCSR padrão), sem `XSAVEOPT`;
   - e, se a área de quem entra também está no estado inicial, o `XRSTOR`
     é pulado, porque deixaria os registradores como já estão.
   - Sem XINUSE na CPU, a troca é a de hoje.
   - Teste: `thread.fpu_inicial_nao_vaza` alterna threads que não tocam na
     FPU, uma que suja `xmm0` e o MXCSR e outra que só muda o MXCSR; cada
     uma confere o próprio estado a cada volta.
2. **Enxugar o software, se o item 1 não bastar.** Na ordem do ganho
   medido, sem mudar o protocolo de IPC, a ordem de travas nem a spec
   `Ipc.tla`: menos clones de `Arc` na entrada e na doação, travas tomadas
   uma vez por objeto onde hoje são duas, e o `rdtsc` da cobrança só quando
   o `SchedContext` muda. Cada passo é medido em KVM contra a rodada
   anterior.
3. **PCID continua adiado** (ADR 0031, item 7). O ganho medido (≈ 50 ns no
   Intel) não paga a máscara preguiçosa e a nova prova do shootdown. Volta
   à pauta só se, depois dos itens 1 e 2, a mediana seguir acima de 1 µs
   em KVM, com emenda à ADR 0031.
4. **`FS_BASE` como está.** O `rdmsr` da troca continua: o usuário zera o
   `FS_BASE` carregando um seletor em FS, e a comparação com o valor da CPU
   impede que isso chegue à próxima thread (ADR 0039, item 3). Usar
   `RDFSBASE` pediria CR4.FSGSBASE, que também dá ao usuário `WRGSBASE` e
   obrigaria a trocar o GS do usuário por thread: mudança de ABI, fora do
   escopo da T-519.
5. **Nada de CR0 nem CR4 no caminho quente.** No SVM, ler o CR4 é
   interceptado pelo KVM (≈ 14 000 ciclos no aninhado). O caminho quente só
   lê o CR3 (não interceptado com NPT ou EPT).
6. **Aceite.** `cargo xtask bench` em KVM, pelo workflow "Bench em KVM",
   com a mediana da ida e volta abaixo de 1 µs, registrada em `docs/bench/`
   ao lado da rodada de linha de base. Como o host do runner varia (Intel
   6975P-C e 8370C, AMD EPYC 9V45 e 9V74 apareceram), o relatório diz o
   host de cada rodada. Se a meta não sair num dos hosts, o relatório
   registra, e o item 2 continua até ela sair ou até o Eduardo aceitar a
   ressalva.

## Alternativas consideradas

- **FPU preguiçosa (CR0.TS):** rejeitada; é a troca que o LazyFP explora.
- **Pular a FPU só para threads marcadas como "sem FPU":** exigiria um
  campo na ABI ou no manifesto; o XINUSE dá a mesma informação sem nada
  novo e não depende de a thread dizer a verdade.
- **PCID agora:** ganho pequeno no medido e custo alto de prova; ver item 3.
- **`FSGSBASE`:** tira o `rdmsr`, mas muda a ABI; ver item 4.
- **Aceitar a ressalva da T-430:** foi a proposta anterior; o Eduardo
  preferiu otimizar.

## Consequências

- A troca entre processos e a troca no mesmo processo também ficam mais
  baratas, porque o item 1 vale para toda troca de contexto.
- Uma thread que usa SIMD (o motor de inferência, o runtime WebAssembly)
  paga a troca de hoje mais um `XGETBV` e um `STMXCSR`, ≈ 15 a 40 ciclos.
- O `XSAVEOPT` deixa de ter como regra "o último `XRSTOR` foi desta área";
  quando não foi, ele mesmo grava tudo (o rastreio por endereço é da CPU).
- Qualquer mudança no protocolo de IPC, na ABI ou no shootdown continua
  exigindo ADR nova.
