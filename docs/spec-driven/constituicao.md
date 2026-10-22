# Constituição do projeto

- Status: **rascunho para revisão**
- Fontes: SDD v1.0 (seções 2.1, 13, 17), `CONTRIBUTING.md`, `unsafe-allowlist.toml`, ADRs 0002, 0004, 0009, 0010, 0011, 0039

Estas regras valem para toda especificação, plano e tarefa. Violar uma regra exige ADR nova, aprovada antes do código.

## Art. 1. Segurança primeiro

1. Toda autoridade é uma capability explícita, mínima e revogável. Não existe root nem namespace global (ADR 0011).
2. Nenhum serviço recebe capability que não esteja no seu manifesto assinado.
3. A IA nunca tem capability de ação em processo que lê conteúdo externo. Planejador e leitor não agem.
4. Toda mudança em TCB (`optboot`, `okernel`, `root`, `svcmgr`, `keyd`, `policyd`, `displayd`, `updated`), `kabi`, cripto ou política exige revisão do responsável de segurança listado no `CODEOWNERS`.

## Art. 2. Kernel determinístico

1. O kernel expõe só as syscalls da ABI v1 (SDD 14.2). Nova syscall exige ADR e mudança em `kabi`.
2. Sem `panic!` em caminho de kernel. Erros são `Result` com tipos próprios (SDD 17.1).
3. Sem alocação em tratador de interrupção e no caminho rápido de IPC.
4. Operação longa é fatiada e preemptível (ADR 0009).
5. Toda memória do kernel é cobrada de uma `MemoryQuota` (ADR 0006).

## Art. 3. Linguagem e `unsafe`

1. Rust estável fixado em `rust-toolchain.toml`, edition 2024 (ADR 0002).
2. Assembly só em `arch/` (ADR 0002).
3. `#![forbid(unsafe_code)]` em toda crate, exceto as listadas em `unsafe-allowlist.toml`.
4. Todo bloco `unsafe` tem comentário `// SAFETY:` com as invariantes.
5. Subir um teto de `unsafe` é alteração visível, revisada por duas pessoas (ADR 0039).
6. Nenhuma crate externa na imagem do sistema (ADR 0003). Dependências só em `xtask`, ferramentas de host, testes, fuzzing e benchmarks.
7. Locks seguem a ordem documentada: CDT → CapSpace → objeto → AddressSpace → fila do escalonador (ADR 0010, `docs/kernel/ordem-de-travas.md`).

## Art. 4. Interfaces

1. Toda chamada entre processos passa por uma interface OIDL (SDD 4.3).
2. Todo tamanho é limitado na declaração (SDD 14.3).
3. Versões seguem semver. Método novo só em versão menor.
4. Todo parser que recebe dados de fora tem alvo de fuzzing (SDD 8.3, 17.3).

## Art. 5. Processo

1. Mudança de arquitetura exige ADR nova, aceita antes do código.
2. Uma branch curta por tarefa do backlog. PR de até 400 linhas alteradas.
3. Commits no padrão Conventional Commits, com `Signed-off-by` (DCO).
4. Testes primeiro: nenhum código entra sem teste que falhe antes (SDD 17.2 e TDD).
5. Toda falha encontrada vira teste de regressão antes da correção ser aceita (SDD 18).
6. Documentação e OIDL atualizados no mesmo PR que muda o comportamento (SDD 17.3).

## Art. 6. Definição de pronto

Uma tarefa só está pronta quando:

- código revisado e aprovado;
- testes unitários e, quando couber, de kernel ou integração, verdes;
- alvo de fuzzing para todo parser ou interface de entrada;
- orçamentos de tamanho, RAM e latência (SDD 15) mantidos no CI;
- documentação e OIDL atualizados;
- nenhum `unsafe` novo fora da allowlist.

## Art. 7. Privacidade e local por padrão

1. Nenhum dado sai da máquina sem política explícita (RNF-07).
2. Telemetria só local.
3. Dados marcados como privados nunca saem, nem para nuvem opcional (SDD 12.14).

## Art. 8. Verificação por máquina

Regra verificada pela máquina sempre que possível. O que não dá para verificar exige revisão humana dupla. Ferramentas: `cargo xtask check` (fmt, clippy, allowlist de `unsafe`), `cargo xtask test`, TLA+, Kani, Miri, fuzzing (SDD 18).

## Emendas

| Data | Emenda | ADR |
|---|---|---|
| 2026-10-22 | Criação deste documento (rascunho) | — |
