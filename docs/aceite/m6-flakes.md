# Flakes da CI: causas e correções (T-612)

Os três flakes citados em `docs/aceite/m5.md` (seção de ressalvas) tinham
causa no código, não só em runner lento.

## 1. `smp.estresse` e `smp (2 CPUs)`: falta de memória falsa no heap

- **Sintoma.** Na CI do #228, `smp (2 CPUs)` falhou com `start_on` recusado e
  "2 falhas" no relatório do heap, com o heap quase vazio.
- **Causa.** `kheap::with_growth` (o heap cresce a janela sob demanda): quem
  terminava de crescer mandava desmapear os blocos de ordem grande que
  estavam prontos, inclusive o que outra CPU acabara de preparar para o
  pedido dela. Quatro perdas seguidas davam `OutOfMemory` sem falta de
  memória nenhuma. Uma CPU sem pedido guardado também esperava a outra sem
  atender shootdowns (IF=0), o que podia travar as duas.
- **Correção.** Cada CPU só devolve o bloco que ela mesma preparou e que
  ninguém usou; perder o bloco para outra CPU deixa de contar como falha
  (até 64 tentativas, e só a falta de frames ou de tabelas desiste antes); a
  espera por outra CPU atende pedidos de shootdown (`ksmp::ipi::poll`).
- **Evidência.** O ktest novo `heap.grandes_em_varias_cpus` (3000 alocações de
  128 KiB a 512 KiB por CPU, ordens diferentes por CPU, 4 CPUs) no `main`:
  9 e 2 falhas no heap em duas rodadas. Com a correção: 0 falhas em 6
  rodadas (4 CPUs) e em 2 (2 CPUs). `cargo xtask test smp --smp 2` e
  `--smp 4` verdes.

## 2. `timer.mil_no_prazo` sob TCG

- **Causa.** O teste arma mil `Timer`s a 20 µs de distância; o TCG leva mais
  que isso para tratar cada disparo, a fila cresce e a mediana do atraso
  passa do limite em host lento. O teste media vazão, não atraso.
- **Correção.** Sob TCG o espaçamento é 100 µs. Com KVM nada muda.

## 3. `inputd: encerrado` ausente no job `integration`

- **Causa.** Corrida no desligamento: o `svcmgr` apagava o processo do
  serviço logo depois de revogar o endpoint, antes de ele escrever a linha
  de encerramento, e o kernel podia desligar a VM antes do restante da
  serial.
- **Correção.** No desligamento o `svcmgr` espera até 50 ms que o serviço
  saia sozinho antes de apagá-lo (`retire_graceful`); a reinicialização por
  falha continua sem espera.
- **Evidência.** `cargo xtask test integration` verde (`-smp 1` e `-smp 4`,
  serviços encerrados em ordem).
