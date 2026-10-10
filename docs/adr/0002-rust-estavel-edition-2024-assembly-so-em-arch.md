# ADR 0002: Rust estável (edition 2024), assembly só em arch/

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 2.3, 16.2 e 17.1
- Relaciona-se com: ADR 0003, ADR 0025 (alvos de compilação no Rust estável)

## Contexto

Falhas de segurança de memória (uso após liberação, estouro de buffer, corrida de
dados) são a maior classe de vulnerabilidades em kernels e serviços escritos em
C. O Optimus é escrito do zero e não herda código legado, então pode escolher a
linguagem sem custo de migração. Também precisa de portabilidade: ≥ 95% do kernel
deve ser independente de arquitetura (RNF-08).

## Decisão

Todo o sistema é escrito em Rust estável, edition 2024, com a versão fixada em
`rust-toolchain.toml` e atualizada a cada 6 semanas por PR dedicado. Nightly só
em jobs de Miri e fuzzing.

Assembly (inline ou em arquivo) só existe em `kernel/okernel/arch/` e no código
de entrada do `optboot`. `#![forbid(unsafe_code)]` vale em toda crate, exceto as
listadas em `unsafe-allowlist.toml`; cada bloco `unsafe` traz `// SAFETY:` e é
revisado por duas pessoas (RNF-09). `panic = "abort"` em todo o sistema.

## Alternativas

- **C (C11/C17):** ferramental maduro e usado por seL4 e Linux, mas não impede
  falhas de memória; a segurança dependeria de disciplina e análise externa.
- **C++:** RAII e tipos ajudam, mas a linguagem continua sem garantia de memória
  e traz runtime e regras complexas para um kernel.
- **Rust nightly:** daria `build-std` e recursos instáveis, mas quebra a cada
  atualização. Ver ADR 0025 para o contorno adotado nos alvos.
- **Zig ou Ada/SPARK:** Zig ainda não é estável; SPARK é forte em prova, mas tem
  ecossistema e base de desenvolvedores pequenos.

## Consequências

- Classes inteiras de falhas de memória somem do código seguro; o `unsafe` fica
  contado e auditável no CI.
- A equipe precisa dominar Rust de sistemas (trilha de estudo na seção 17.4).
- Alvos próprios dependem de `build-std`, ainda instável; ADR 0025 resolve isso.
