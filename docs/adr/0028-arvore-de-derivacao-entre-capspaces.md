# ADR 0028: Árvore de derivação entre CapSpaces

- Status: aceita (aprovada por Eduardo em 2026-10-11)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 6.2 e 6.9
- Relaciona-se com: ADR 0001, ADR 0007, T-204, T-208

## Contexto

A seção 6.2 diz que cada capability guarda seus filhos numa árvore de
derivação e que `cap_revoke` apaga todos os descendentes. O T-204
implementou a árvore dentro de cada `CapSpace` (elos por índice de slot), e
o T-208 transfere capabilities por IPC inserindo a cópia como raiz da
árvore do receptor. Assim, revogar a original não alcança a cópia: quem
recebeu uma capability por IPC fica com ela para sempre, o que fura a
revogação justamente no caso mais comum (o servidor que recebe acesso de um
cliente).

Ligar a cópia à original exige elos entre slots de `CapSpace`s diferentes,
e cada `CapSpace` tem a própria trava. A seção 6.9 fixa a ordem
`CapSpace → objeto → AddressSpace → fila`, sem dizer como uma operação
toca duas tabelas.

## Decisão

- A árvore continua com elos locais por índice dentro de cada `CapSpace`
  (o que o T-204 provou e mede). Uma cópia transferida por IPC vira **filha
  remota** da original: o slot dela guarda o pai remoto (`CapSpace` por
  referência fraca, índice e geração) e o slot da original guarda a lista
  de filhos remotos. O par índice e geração nunca se repete num `CapSpace`
  (o slot é aposentado na geração 255), então um elo remoto vencido é
  reconhecido sem varredura.
- Uma **trava global da árvore de derivação** (`CDT`) vem antes de todas
  as outras: `CDT → CapSpace → objeto → AddressSpace → fila`. `cap_mint`,
  `cap_delete`, `cap_revoke` e a transferência por IPC a tomam primeiro e,
  com ela, tocam um `CapSpace` por vez; nunca seguram duas travas de
  `CapSpace` ao mesmo tempo. As demais operações (`cap_info`, uso de
  capabilities) seguem só com a trava do `CapSpace`.
- `cap_revoke` percorre filhos locais e remotos, em fatias com orçamento,
  recomeçando do alvo a cada fatia como antes. A revogação apaga também a
  cópia que estiver em revogação noutro `CapSpace` (e encerra aquela
  revogação, que devolve `Revoked`). `cap_mint` e a transferência conferem
  os ancestrais através dos `CapSpace`s: dentro de uma subárvore em
  revogação dão `Busy`, e a profundidade (até 64) conta os níveis remotos.
- A cópia ocupa um slot do receptor (cobrado da cota dele); o registro do
  filho remoto é cobrado da cota de quem enviou. A transferência confere a
  origem na entrega: se a capability do remetente sumiu entre o envio e a
  entrega, a cópia não é criada.
- `cap_delete` de uma capability com descendentes remotos (ou de uma cópia
  com filhos) não pode subir os filhos para o avô sem alocar na tabela de
  outro processo. A capability vira um **marcador**: o objeto e os direitos
  saem do slot (o objeto pode morrer), mas o slot fica na árvore até os
  descendentes sumirem, sem handle utilizável. O slot é do mesmo dono, que
  já pagou por ele.

## Alternativas

- **Árvore global (MDB do seL4):** uma lista única de todos os slots em
  pré-ordem. É o modelo mais simples de raciocinar, mas troca toda a
  representação do T-204 e as provas do Kani, e cada elo passa a precisar
  de uma referência a outro `CapSpace`.
- **Subir os filhos remotos para o avô no `cap_delete`:** sem marcadores,
  mas o delete passa a alocar na tabela (e na cota) de outro processo e
  pode falhar por falta de memória alheia.
- **Revogação por indireção (capability revogável que aponta para um
  "portão"):** barata, mas só invalida a cópia na próxima vez que for usada;
  o objeto não morre e `PeerClosed` não chega a quem espera nele.
- **Segurar as travas dos dois `CapSpace`s em ordem de endereço:** funciona
  para a transferência, mas a revogação atravessa um número arbitrário de
  tabelas; a trava global é mais simples enquanto o kernel não é SMP.

## Consequências

- Revogar no remetente apaga a cópia no receptor e tudo o que derivou dela,
  como a seção 6.2 promete.
- A trava global serializa mint, delete, revoke e transferência entre
  CPUs; quando o SMP chegar (M3) pode ser trocada por travas por subárvore
  sem mudar a interface.
- Marcadores de capabilities apagadas ocupam slots até os descendentes
  remotos sumirem; um descendente num `CapSpace` que morreu sem ser apagado
  deixa o marcador até o dono revogar o ancestral ou morrer.
- A spec `CapRevoke.tla` modela a transferência entre tabelas, os marcadores
  e a revogação através dos CapSpaces.
- A seção 6.9 do SDD ganha a trava `CDT` na próxima revisão.
