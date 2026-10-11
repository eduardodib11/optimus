# ADR 0011: Sem root e sem namespace global; capabilities de diretório

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 7.2, 7.4 e 13.2
- Relaciona-se com: ADR 0001 (capabilities), ADR 0014 (OptFS), ADR 0016 (apps)

## Contexto

No modelo POSIX, a autoridade vem de quem o processo é (UID) e o que ele vê vem
de uma árvore de arquivos global. Um processo comprometido enxerga tudo que o seu
usuário enxerga, e um bug em programa com UID 0 entrega a máquina. O RNF-01 exige
zero processos com privilégio total, e a IA, que age em nome do usuário, não pode
herdar o poder de uma conta inteira.

## Decisão

- Não existe usuário root nem UID com poder total. O processo `root` só reparte
  as capabilities iniciais e depois responde apenas ao `svcmgr`.
- Não existe árvore de arquivos global. Cada processo recebe capabilities de
  diretório para as pastas de que precisa, montadas num namespace próprio
  (`/sys`, `/data/app/<id>`, `/tmp`). O que não foi entregue não existe para ele.
- Um realm agrupa processos com namespace, cotas e política comuns. Apps, a IA e
  contêineres do Server são realms.

## Alternativas

- **Root/UID POSIX com permissões rwx e ACLs:** modelo conhecido, mas a autoridade
  é ambiente e ampla; é a origem da escalada de privilégio clássica.
- **Root com poderes divididos (capabilities do Linux, SELinux, AppArmor):**
  reduz o dano, mas é uma camada sobre o modelo global, com políticas extensas e
  difíceis de auditar.
- **Namespace global com namespaces de montagem por processo (Plan 9, Linux):**
  isola a visão, mas a autoridade continua vinda da identidade, não do objeto.

## Consequências

- Escalada de privilégio por identidade deixa de existir: não há a quem escalar.
- Programas POSIX só rodam pela camada de compatibilidade própria (olibc, M15),
  que traduz caminhos para capabilities, ou pela VM Linux do plano B.
- Todo serviço declara no manifesto as pastas de que precisa; o `svcmgr` e o
  `pkgd` entregam só essas.
