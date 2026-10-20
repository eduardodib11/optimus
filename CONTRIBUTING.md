# Contribuindo com o Optimus OS

## DCO

Todo commit precisa de `Signed-off-by`, atestando o
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

## Commits e PRs

- Mensagens no padrão [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat(kernel): ...`, `fix(optboot): ...`, `docs(adr): ...`).
- Uma branch curta por tarefa do backlog; PR pequeno, alvo de até 400 linhas alteradas.
- Mudança de arquitetura exige ADR nova aprovada antes do código.
- Mudança em TCB, `kabi`, cripto ou política exige revisão do responsável de segurança.

## Código

- Rust estável fixado em `rust-toolchain.toml`, edition 2024.
- Assembly só em `arch/`.
- Nenhuma crate externa na imagem do sistema; dependências só em `xtask`,
  ferramentas de host, testes, fuzzing e benchmarks.
- `#![forbid(unsafe_code)]` em toda crate, exceto as listadas em
  `unsafe-allowlist.toml`. Todo bloco `unsafe` tem comentário `// SAFETY:`.
  Nas crates listadas, o `unsafe` só vale nos caminhos de `[unsafe_budget]`
  (ADR 0039), cada um com teto de usos, `#![allow(unsafe_code)]` no arquivo
  raiz e uma seção `# Unsafe` na documentação do módulo; o `cargo xtask check`
  confere. Subir um teto é uma alteração visível, a revisar por duas pessoas.
  Os testes da `lib/oalloc` rodam também sob Miri (job `miri` do CI), só nos
  PRs que mudam essa crate.
- Antes do PR: `cargo xtask check` e `cargo xtask test`.

## Definição de pronto

Código revisado; testes; fuzzing para todo parser exposto; orçamentos da seção 15
do SDD mantidos; documentação e OIDL atualizados; nenhum `unsafe` novo fora da
allowlist.
