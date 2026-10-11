# ADR 0001: Microkernel com capabilities

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 2.1, 4, 6 e 13.2
- Relaciona-se com: ADR 0006, ADR 0007, ADR 0011, ADR 0013

## Contexto

O primeiro princípio do Optimus é que nenhum componente tem poder total, nem a IA
(RNF-01). O kernel deve ser determinístico, sem IA nem parsing de formatos
complexos, e caber em 1 MiB (RNF-04). Drivers, pilha de rede, sistema de arquivos
e AI Core são código grande e exposto a dados externos. Se rodarem no modo
privilegiado, uma falha em qualquer um deles compromete a máquina inteira.

## Decisão

O `okernel` é um microkernel. Ele oferece só sete serviços: objetos,
capabilities, memória virtual, threads, escalonamento, IPC e eventos de hardware.
Meta: ≤ 25 mil linhas de Rust portável mais ≤ 3 mil de arquitetura.

Toda autoridade é uma capability: handle de 32 bits (índice de 24 bits + geração
de 8 bits) num `CapSpace` por processo, com máscara de direitos e badge.
`cap_mint` só reduz direitos; `cap_revoke` apaga toda a árvore de derivação.
Drivers, serviços, IA e apps rodam como processos isolados, cada um com a lista
fechada de capabilities do seu manifesto assinado.

## Alternativas

- **Kernel monolítico (estilo Linux):** desempenho bom e muito driver pronto, mas
  tudo roda com privilégio total e a base de confiança tem milhões de linhas.
  Contraria os princípios 1 e 2.
- **Kernel híbrido (estilo Windows NT, XNU):** serviços separados no desenho, mas
  executados no espaço do kernel. Mantém o problema da base de confiança grande.
- **Microkernel sem capabilities (controle por ACL ou UID):** isola processos,
  mas mantém autoridade ambiente e um "root", o que permite escalada clássica.

## Consequências

- Base de confiança pequena, viável para TLA+ e provas com Kani (seção 18).
- Driver ou serviço comprometido só alcança as capabilities que recebeu.
- Quase toda operação vira IPC, que precisa ser muito rápido: ida e volta ≤ 1 µs
  (RNF-03), daí o caminho rápido da ADR 0007.
- Compatibilidade POSIX só por camada própria (ADR 0011).
