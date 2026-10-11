# ADR 0003: Tudo do zero, nenhuma crate externa na imagem

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 2.1, 7.1, 13.2 e 16.2
- Relaciona-se com: ADR 0002, ADR 0004

## Contexto

O princípio 6 pede código próprio com padrões abertos. Cada dependência que entra
na imagem do sistema é código que roda na máquina do usuário sem ter sido escrito
nem revisado pelo projeto. A cadeia de suprimentos do build é uma ameaça listada
no modelo (seção 13.2), e o orçamento de tamanho (kernel ≤ 1 MiB, Lite ≤ 64 MiB
em repouso) exige controle fino sobre o que é compilado.

## Decisão

Nenhuma crate externa entra na imagem do sistema: kernel, `optboot`, serviços,
drivers, AI Core e bibliotecas (`ostd`, `orun`, `oidl-rt` e outras) usam só
`core`, `alloc` e código do monorepo. Não existe libc no sistema base.

Dependências externas são permitidas apenas em `xtask`, `tools/` de host,
testes, fuzzing e benchmarks, sempre auditadas com `cargo-vet`. Formatos e
protocolos seguem padrões públicos (UEFI, ACPI, virtio, WASI, GGUF, TLS 1.3).
A única exceção na imagem é a cripto verificada da ADR 0004.

## Alternativas

- **Usar o ecossistema crates.io no sistema** (por exemplo `x86_64`, `spin`,
  `hashbrown`, `smoltcp`): acelera o início, mas espalha código não auditado pela
  TCB e prende o projeto a decisões e ritmos de terceiros.
- **Basear-se em projeto existente** (Redox, Theseus, Hubris): poupa anos, mas
  herda arquitetura, ABI e licenças que não seguem os princípios do Optimus.
- **Vendorizar crates externas com revisão:** reduz o risco de cadeia, mas o
  código continua sem dono no projeto e a revisão vira tarefa permanente.

## Consequências

- Controle total, auditoria completa e builds reproduzíveis com zero crates na
  imagem.
- Muito mais código a escrever: alocador, coleções, executor assíncrono, pilha de
  rede, OptFS, runtime Wasm e motor de inferência são próprios.
- Cada dependência de host continua passando pelo `cargo-vet`.
