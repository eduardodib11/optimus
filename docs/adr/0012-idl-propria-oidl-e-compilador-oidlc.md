# ADR 0012: IDL própria (OIDL) e compilador oidlc

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 4.3, 12.5, 14.3 e 14.4
- Relaciona-se com: ADR 0003 (tudo do zero), ADR 0007 (IPC), ADR 0019 (IA)

## Contexto

Toda chamada entre processos DEVE passar por uma interface declarada (seção 4.3).
O kernel só transporta rótulo, palavras e capabilities; tipos, versões e limites
ficam acima dele. A IA também precisa conhecer as mesmas operações como
ferramentas, com descrição e classe de risco. Manter os dois à mão diverge.

## Decisão

- Interfaces são escritas em arquivos `.oidl` em `idl/`, com pacote e versão
  (`package optimus.fs @1.0`).
- O compilador `oidlc` gera, a partir deles, stubs Rust de cliente e servidor,
  serialização sem cópia (layout fixo, little-endian) e os esquemas de
  ferramentas da IA (`@tool(risk = R0, desc = ...)`).
- Todo tamanho é limitado na declaração (`string<255>`, `vec<T, 4096>`).
- `handle<T>` transfere uma capability tipada pela mensagem de IPC.
- Versões seguem semver; métodos novos só em versão menor. Manifestos de serviço
  citam as interfaces que usam e oferecem (`optimus.net.Socket@1`).

## Alternativas

- **Protocol Buffers ou gRPC:** maduros, mas usam codificação variável que exige
  parse, não têm tamanhos limitados nem transferência de capabilities, e o
  compilador é uma dependência externa (ADR 0003).
- **Cap'n Proto:** sem cópia e com capabilities, mais próximo do que queremos;
  porém o formato de ponteiros é mais complexo de validar no servidor e não gera
  esquemas de ferramentas para a IA.
- **Stubs à mão ou macros Rust:** sem fonte única para a IA nem checar versões.

## Consequências

- O `oidlc` é peça central: erro nele afeta todo o sistema. Ele tem testes
  próprios e o código gerado tem fuzzing.
- Uma interface nova vira ferramenta da IA sem código extra, mas só com
  classe de risco declarada e revisada.
- Mudanças incompatíveis exigem versão maior e convivência das duas versões.
