# Tarefas 001: `svcmgr`

- Status: **rascunho para revisão**
- Plano: [`plan.md`](plan.md)
- Backlog de origem: `docs/backlog/m3.md`, T-350 a T-354
- Cada tarefa cabe num PR de até 400 linhas e termina com o aceite verificável.

## Pré-requisitos (fora desta lista)

- [ ] ADR 0034 aceita (manifesto, descoberta, protocolo `root`/`svcmgr`).
- [ ] ADR 0035 aceita (eventos de morte e objeto Timer).
- [ ] T-348 e T-349 concluídas (dependências de T-354).
- [ ] T-336 concluída (`Mutex` e `Condvar` no `ostd`, usados pelo `svcmgr`).

## T-350. Compilador de manifestos

**Dep.:** T-307 (ADR 0034). **Crítico:** não. **Tamanho:** ~400 linhas.

- [ ] Ler manifesto TOML e produzir o formato binário da ADR 0034.
- [ ] Recusar dependência cíclica, com erro que nomeia o ciclo (AC-02).
- [ ] Recusar campo obrigatório ausente (`name`, `binary`, `restart`).
- [ ] Recusar valor fora do limite (`max_threads`, `ipc_rate`).
- [ ] Teste unitário para cada caso acima, escrito antes do código.
- [ ] Alvo de fuzzing para o leitor do formato binário (exigência da constituição, Art. 4.4).

**Aceite:** `cargo test -p manifest` verde; ciclo de três serviços é recusado com a mensagem certa.

## T-351. `root`: cotas e partida do `svcmgr`

**Dep.:** T-307, T-345. **Crítico:** não. **Tamanho:** ~300 linhas.

- [ ] `root` divide a memória recebida em cotas e entrega ao `svcmgr` a sua.
- [ ] `root` inicia o `svcmgr` e fica só atendendo ao `svcmgr` depois disso (SDD 7.2).
- [ ] Protocolo `root`→`svcmgr` documentado como exceção à regra de OIDL, com prazo (ADR 0034).

**Aceite:** em QEMU, o `root` inicia o `svcmgr`, que responde a um ping; o `root` recusa qualquer outro cliente.

## T-352. `svcmgr`: manifestos, grafo e partida paralela

**Dep.:** T-350, T-351, T-336. **Crítico:** não (TCB, revisão dupla). **Tamanho:** ~400 linhas.

- [ ] Ler os manifestos do bootfs (FR-01).
- [ ] Verificar o grafo na partida (FR-02).
- [ ] Lançar em paralelo quem não tem dependência pendente (FR-03, D9).
- [ ] Teste de integração: cadeia A → B → C sobe na ordem C, B, A (AC-01).

**Aceite:** AC-01 verde em QEMU com serial; nenhum `unsafe`.

## T-353. `svcmgr`: corretor de capabilities

**Dep.:** T-352. **Crítico:** não (TCB, revisão dupla). **Tamanho:** ~400 linhas.

- [ ] Entregar a cada serviço só as capabilities de `needs` (FR-04).
- [ ] Registrar `provides` e responder à descoberta por interface e versão (FR-05, D4).
- [ ] Teste: serviço que pede capability fora de `needs` recebe `AccessDenied` (AC-03).

**Aceite:** AC-03 verde; a descoberta devolve o endpoint certo para a versão pedida e erro para versão ausente.

## T-354. `svcmgr`: supervisão e reinício

**Dep.:** T-348, T-349, T-353. **Crítico:** não (TCB). **Tamanho:** ~400 linhas.

- [ ] Política `always`, `on-failure` e `never` (FR-06, AC-07).
- [ ] Recuo exponencial de 100 ms a 30 s (FR-07, D6, AC-09).
- [ ] Alerta após 5 falhas em 60 s (FR-08, D7, AC-08).
- [ ] Revogar e reemitir capabilities ao reiniciar (FR-09, D5, AC-05).
- [ ] Clientes recebem `PeerClosed` (FR-10, AC-06).
- [ ] Reinício em ≤ 100 ms após falha (NFR-01, AC-04).
- [ ] Teste de caos: matar serviços aleatoriamente sem o sistema sair do ar além de 1 s (AC-10).
- [ ] Modelo TLA+: estender `CapRevoke.tla` com reinício de processo.

**Aceite:** AC-04 a AC-10 verdes; AC-11 verde ou adiado pela ADR 0035.

## Fora desta lista

- Assinatura do manifesto (Ed25519 + ML-DSA-65): marco posterior, ADR 0034.
- Persistência do estado do `svcmgr`: fora do M3.
- Medição de perfil no primeiro boot: fora do M3.
