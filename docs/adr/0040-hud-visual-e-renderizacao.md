# ADR 0040: HUD do Optimus: identidade visual, widgets e renderização

- Status: proposta
- Data: 2026-10-22
- Origem: protótipo visual aprovado por Eduardo em 2026-10-22 (versão 7,
  HTML/CSS/SVG, fora do repositório); SDD v1.0
- Relaciona-se com: ADR 0001 (microkernel), ADR 0003 (sem crates externas),
  ADR 0013 (drivers em usuário), ADR 0023 (a IA gera UI declarativa, a
  HUD Spec, nunca código)

## Contexto

O usuário conversa com uma IA que se apresenta como o próprio sistema. Falta
fixar como essa interface deve parecer e quais peças ela tem, antes de
qualquer código. Eduardo aprovou um protótipo estático que reúne três
referências: a interface do JARVIS (anéis concêntricos), o Optimus Prime
(azul, vermelho, prata) e um painel de vidro, com
metal em cobre e aço e janelas holográficas. O protótipo é só desenho; esta
ADR traduz o desenho em decisões para o compositor do Optimus.

## Decisão

1. **Processo.** O HUD é um processo de usuário (`hud`), que desenha no
   framebuffer entregue pelo driver gráfico em usuário (ADR 0013). Nada de
   desenho no kernel. O HUD só lê estado do sistema por IPC com capabilities
   de leitura (CPU, memória, rede, hora) e recebe da IA apenas uma HUD Spec
   declarativa (ADR 0023). A IA nunca injeta código no HUD.
2. **Sem crates externas.** Rasterização, texto e composição são próprios,
   em `no_std` + `alloc`, com `#![forbid(unsafe_code)]` salvo o acesso ao
   framebuffer, que fica numa crate pequena da `unsafe-allowlist.toml` com
   `// SAFETY:` em cada bloco. A fonte é uma fonte de pontos embutida na
   imagem (licença permissiva); as fontes do protótipo (Orbitron, Share Tech
   Mono) servem só de referência visual.
3. **Layout.** Alvo 1920x1080, com o desenho escalado proporcionalmente para
   outras resoluções (sem versão de celular no M-HUD1):
   - vidro frontal, sem inclinação e sem perspectiva: o painel é um
     retângulo reto com um reflexo diagonal suave;
   - **núcleo** circular no centro (cerca de 900 px), que é o rosto da IA;
   - cada janela e botão é desenhado como uma **caixa 3D**: face frontal de
     vidro, lateral e base visíveis por deslocamento fixo em degraus
     (5, 10 e 14 px) em tons mais escuros, e um fio de luz no topo; ao
     passar o mouse, a caixa avança (os degraus crescem);
   - colunas de janelas de vidro ao redor: Sistema (data, hora, usuário,
     rede), Notificações, Análise do sistema, Ações da IA, Arquivos, CPU/GPU,
     Rede ao longo do tempo e a fala da IA;
   - dock curvo inferior com Arquivos, Navegador, Ferramentas, Optimus,
     Comunicações e Configurações.
4. **Núcleo (rosto da IA).** Estilo JARVIS: moldura de aço e cobre e, dentro
   dela, seis camadas de anéis finos segmentados, réguas de marcações e arcos
   grossos, cada uma girando em velocidade e sentido próprios (de uma volta a
   cada 150 s no anel externo a uma volta a cada 3 s no interno), um triângulo
   girando e um reator azul-ciano pulsante no centro. A pulsação do reator
   acompanha a fala da IA (maior amplitude enquanto ela fala).
5. **Paleta.** Base em metal escuro (grafite e aço escovado) com quatro cores
   de função:
   - ciano `#2fe6ff` e `#8ff3ff`: núcleo, dados e vidro;
   - cobre `#d98a4e` e `#f2c08f`: molduras, títulos e destaques;
   - vermelho `#c8102e`: alertas e ação em risco;
   - verde `#3dffa8`: estado saudável e fala da IA.
   Texto principal `#d9f7ff`, secundário `#7fa6b5`, fundo `#04070b`.
6. **Vidro e brilho.** Janelas translúcidas (alfa em torno de 55%) sobre o
   fundo, com borda clara no topo, brilho interno suave e um desfoque barato
   (caixa 3x3 em duas passadas, só nas áreas das janelas). Brilho do núcleo por
   soma aditiva de um halo pré-calculado.
7. **Animação.** Quadro alvo de 60 por segundo; só as regiões que mudam são
   redesenhadas (retângulos sujos). Tudo que gira usa tabelas de seno e cosseno
   pré-calculadas em inteiros (sem ponto flutuante no caminho quente). Com
   "reduzir movimento" ativo, os anéis ficam parados e só o reator pulsa.
8. **Determinismo e privacidade.** Os dados exibidos vêm de leituras locais.
   Nenhum widget faz chamada de rede. A nuvem, se um dia ligada, aparece como
   um indicador explícito no painel Sistema (hoje: "0 nuvem").

## Alternativas consideradas

- **Toolkit gráfico externo:** rejeitado pela ADR 0003.
- **Interface 100% gerada pela IA:** rejeitado; só o conteúdo dos painéis é
  declarativo (ADR 0023). Moldura, núcleo e dock são fixos e escritos à mão.
- **3D real (GPU) ou perspectiva inclinada:** descartado. As caixas 3D são
  degraus 2D deslocados, baratos e sem aceleração, em qualquer hardware.

## Consequências

- Boa identidade visual sem dependências e sem IA no kernel.
- O custo de CPU do núcleo animado precisa de meta: até 10% de um núcleo a
  1080p/60 em QEMU com KVM, medido por `cargo xtask bench hud` (a criar).
- O blur e as caixas 3D exigem uma biblioteca de raster própria;
  isso vira trabalho novo no backlog (proposta: M-HUD1 com a moldura e o
  núcleo, M-HUD2 com as janelas e o dock, M-HUD3 com a HUD Spec).
- Texto e paleta ficam em arquivo de tema do `hud`, para permitir variantes
  (por exemplo, azul e vermelho do Optimus Prime) sem mudar o código.

## Decisões a aprovar

1. Aceitar a paleta e o layout acima como padrão do HUD.
2. Aceitar a meta de 10% de um núcleo a 1080p/60.
3. Aceitar a divisão em M-HUD1, M-HUD2 e M-HUD3 para o backlog.
