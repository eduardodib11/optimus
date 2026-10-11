# ADR 0016: Apps de terceiros em WebAssembly, com runtime próprio owr

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 4.1, 7.3, 7.4 e 14.5
- Relaciona-se com: ADR 0003 (tudo do zero), ADR 0011 (realms), ADR 0012 (OIDL)

## Contexto

O RF-11 pede apps instaláveis, isolados e com permissões declaradas. O sistema
roda em x86-64 e AArch64, e um app de terceiro é código não confiável. Binários
nativos dependeriam de uma ABI estável de usuário e de recompilação por
arquitetura, e o isolamento ficaria só nas capabilities do processo.

## Decisão

- Apps de terceiros são componentes WebAssembly (Component Model e WASI).
- O runtime `owr` é próprio (ADR 0003) e executa cada app num realm com
  namespace, cotas e política próprios.
- O pacote `.opk` traz componentes Wasm, manifesto de permissões, assets,
  assinatura do autor e assinatura da loja. O `pkgd` instala, remove e entrega
  ao app só as capabilities que o manifesto declara e o usuário aprovou.
- Binários nativos ELF ficam reservados ao sistema (serviços, drivers, IA).

## Alternativas

- **Apps nativos ELF em processos isolados:** máximo desempenho, mas um binário
  por arquitetura, ABI de syscalls exposta a terceiros e superfície de ataque
  maior no kernel.
- **Containers no estilo Docker/OCI:** empacotam bem, mas pressupõem uma ABI
  Linux e um sistema POSIX por dentro; contrariam a ADR 0011.
- **JVM ou outro bytecode:** portátil, mas runtime grande e isolamento por
  gerenciador de segurança complexo, já abandonado pelo próprio Java.
- **Runtime Wasm existente (Wasmtime, WAMR):** maduro, mas é dependência
  externa na imagem, o que a ADR 0003 proíbe.

## Consequências

- Um app comprometido fica preso à memória linear do Wasm e às capabilities do
  seu realm.
- O mesmo `.opk` roda em todas as arquiteturas e perfis.
- Wasm custa algum desempenho, e o `owr` é um componente grande, com fuzzing.
- A oferta de apps começa pequena; a camada POSIX e a VM Linux (M15) cobrem
  programas legados.
