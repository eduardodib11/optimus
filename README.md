# Optimus OS

Sistema operacional escrito do zero em Rust, em que o usuário conversa com uma IA
que se apresenta como o próprio sistema. Por baixo, um microkernel pequeno e
determinístico com capabilities garante segurança e desempenho.

A arquitetura está congelada no SDD v1.0; mudanças entram como nova ADR em
`docs/adr/`.

## Começando

Requisitos no host: `rustup`, QEMU (`qemu-system-x86_64`) e OVMF.

```sh
cargo xtask build    # compila kernel, optboot e bibliotecas
cargo xtask image    # monta a ESP em target/esp
cargo xtask run      # dá boot no QEMU com serial no terminal
cargo xtask test     # unitários, smoke test de boot e testes de kernel no QEMU
cargo xtask test kernel  # só os testes de kernel (harness com isa-debug-exit)
cargo xtask test smp     # testes de kernel e pânico SMP com -smp 2, 4 e 8 (--smp N: só N)
cargo xtask check    # fmt, clippy e allowlist de unsafe
cargo xtask kani     # provas Kani das capabilities (exige o Kani no host)
```

Se o OVMF não estiver num caminho conhecido, aponte `OVMF_CODE` e `OVMF_VARS`
para os arquivos `.fd`.

## Licença

Apache-2.0. Contribuições exigem DCO; veja [CONTRIBUTING.md](CONTRIBUTING.md).
