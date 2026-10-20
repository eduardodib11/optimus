# ADR 0025: Alvos de compilação no Rust estável

- Status: aceita
- Data: 2026-10-10
- Relaciona-se com: ADR 0002 (Rust estável), SDD v1.0 seção 16.2

## Contexto

O SDD v1.0 define alvos próprios (`x86_64-optimus-kernel`, `x86_64-optimus`,
`aarch64-optimus-kernel`, `aarch64-optimus`) e, na ADR 0002, exige Rust estável,
com nightly só em jobs de Miri e fuzzing.

Alvos próprios são arquivos JSON de especificação. Para usá-los, o Cargo precisa
recompilar `core` e `alloc` com `-Zbuild-std`, que só existe no nightly. As duas
decisões não cabem juntas hoje.

## Decisão

Enquanto `build-std` não estiver estável, o sistema compila para alvos embutidos
no Rust estável:

| Alvo do SDD | Alvo usado |
|---|---|
| `x86_64-optimus-kernel` | `x86_64-unknown-none` |
| `x86_64-optimus` | `x86_64-unknown-none` |
| `x86_64-unknown-uefi` (optboot) | `x86_64-unknown-uefi` (sem mudança) |
| `aarch64-optimus-kernel` / `aarch64-optimus` | `aarch64-unknown-none` (quando o AArch64 entrar) |

O mapeamento fica num só lugar, nas constantes de alvo do `xtask`.

## Alternativas

- **Nightly fixado em `rust-toolchain.toml`:** permite os alvos próprios já, mas
  contraria a ADR 0002 e traz quebras a cada atualização da toolchain.
- **`RUSTC_BOOTSTRAP=1` no estável:** libera recursos instáveis num compilador
  estável. É um contorno sem garantia de compatibilidade, e por isso foi rejeitado.

## Consequências

- O alvo já fornece o modelo de código `kernel`, o código sem SSE e sem red
  zone. Por `RUSTFLAGS` no `xtask` vai só o que falta, crate por crate:
  `relocation-model=pie` no `okernel` e `static` nos binários de usuário.
- `x86_64-unknown-none` é soft-float (`rustc-abi` softfloat), o que serve ao
  kernel e ao `ostd` no M0 a M2.
- Os processos de usuário ficam soft-float até o `build-std` estabilizar. O
  `oie` (kernels SIMD de SSE2 a AMX, ADR 0021) e o `owr` (ponto flutuante,
  ADR 0016) dependem de resolver isso antes do marco deles, porque o rustc não
  deixa ligar SSE num alvo soft-float por `RUSTFLAGS`. Pendência: decisão
  futura de Eduardo, ainda não tomada.
- Quando `build-std` estabilizar, uma nova ADR troca para os alvos próprios,
  e só o `xtask` muda.

## Revisão de 2026-10-20

Mudanças em relação ao texto anterior:

- Corrigido o que o alvo `x86_64-unknown-none` já fornece (modelo `kernel`,
-   sem SSE, sem red zone) e o que vai por `RUSTFLAGS`.
- Registrada a limitação soft-float dos processos de usuário e a decisão futura
-   de Eduardo para o `oie` e o `owr`.
