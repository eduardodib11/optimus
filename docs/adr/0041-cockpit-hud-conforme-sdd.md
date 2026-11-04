# ADR 0041: Cockpit do Optimus: HUD conforme o SDD v1.0

- Status: aceita (escolhida por Eduardo em 2026-11-04)
- Data: 2026-11-04
- Substitui: ADR 0040 (HUD visual e renderização, aceita em 2026-10-22)
- Origem: SDD v1.0, seção 11 (Gráficos, Holo UI e Cockpit), seções 11.1 a 11.5, e seção 20 (roadmap)
- Relaciona-se com: ADR 0001 (microkernel), ADR 0003 (sem crates externas), ADR 0013 (drivers em usuário), ADR 0023 (a IA gera UI declarativa, a HUD Spec)

## Contexto

A ADR 0040 fixou um HUD próprio: um processo `hud` que desenha direto no framebuffer, com janelas fixas escritas à mão, caixas 3D, referências a marcas (JARVIS e Optimus Prime) e fonte embutida. Essa leitura se afasta do SDD em pontos que o SDD trata como obrigatórios:

- o desenho passa pelo `displayd`, que é o único componente que pode desenhar a Faixa de Confiança (11.2);
- os painéis são montados pela IA por HUD Spec, sem janelas fixas à mão (11.4);
- o SDD pede um design original, "sem reproduzir elementos de marcas ou filmes" (seção 11);
- a fonte vem de um parser OpenType próprio com fontes OFL empacotadas (11.1);
- o Cockpit pertence à pilha gráfica dos marcos M4 em diante (gpu-virtio 2D no M4).

Esta ADR volta ao Cockpit do SDD e substitui a 0040 inteira.

## Decisão

1. **Pilha.** O Cockpit segue a pilha de 11.1: driver `gpu-virtio` (M4) ou framebuffer; abstração `gpu-hal`; renderizador `forge` (vetores, texto e efeitos, com backend de software SIMD); toolkit `holo` (UI declarativa, layout flexbox, animações e acessibilidade); compositor `displayd`; shell `cockpit`. O `cockpit` não desenha no framebuffer diretamente.
2. **Faixa de Confiança.** Só o `displayd` desenha a Faixa de Confiança. Confirmações R3, pedidos de senha e alertas de segurança aparecem só nela (11.2). Nenhum outro processo pode imitá-la.
3. **Modos.** O `cockpit` tem os modos Boot, Repouso, Conversa, Tarefa, Foco, Alerta e Resgate (11.3). No Repouso: uma esfera central que representa a IA, anéis de estado (CPU, RAM, rede e segurança), relógio e sugestões.
4. **Painéis.** Os painéis são descritos pela IA em HUD Spec validada por esquema, com os componentes permitidos na v1: text, markdown, table, list, chart, metric, progress, form, image, media, file-grid e timeline (11.4). Os dados chegam por tokens de capability de leitura. Ações de formulário viram pedidos ao `ai-exec`. Não há janelas fixas escritas à mão além da esfera, dos anéis de estado e da Faixa de Confiança.
5. **Identidade.** Paleta e formas próprias do Optimus, sem referência a marcas, filmes ou personagens. A paleta fica em arquivo de tema, para permitir variantes sem mudar o código.
6. **Texto e fontes.** Parser OpenType e rasterizador próprios, com hinting leve e cache de glifos. Shaping de latim, grego e cirílico na v1. Fontes livres com licença OFL, empacotadas na imagem.
7. **Orçamentos.** Lite: renderização por software, 2D sem desfoque, 30 fps, até 24 MiB para compositor e Cockpit. Básico: software SIMD ou GPU simples, 30 a 60 fps. JARVIS e Premium: GPU, 60 fps em 1440p, desfoques e partículas, quadro até 8 ms.
8. **Acessibilidade.** Alto contraste, redução de movimento, escala de interface de 100 a 300%, e leitor de tela integrado à voz da IA.
9. **Privacidade.** Os dados exibidos vêm de leituras locais. Nenhum widget faz chamada de rede. A nuvem, quando ligada, aparece como indicador explícito no Cockpit.
10. **Sem crates externas.** Raster, texto e composição são próprios, em `no_std` com `alloc`, com `#![forbid(unsafe_code)]` fora da crate de acesso ao framebuffer, que entra na `unsafe-allowlist.toml` com `// SAFETY:` em cada bloco (ADR 0003).
11. **Cronograma.** Nada do Cockpit entra no M3. O trabalho começa com o `displayd` e o `gpu-virtio` 2D no M4, e o Cockpit completo chega com o M8 (IA que conversa e age em VM). O backlog de cada marco é detalhado no fim do marco anterior (SDD, seção 20).

## Alternativas consideradas

- **Manter a ADR 0040:** rejeitado. Contraria 11.2, 11.4 e 11.1, e antecipa trabalho do M4.
- **HUD com desenho direto no framebuffer, sem compositor:** rejeitado. Quebra o trusted path da Faixa de Confiança.
- **3D real ou perspectiva inclinada:** descartado. O SDD pede esfera central e modos definidos; 3D exigiria GPU antes do M4.

## Consequências

- O código em `lib/ohud` e as PRs #83 e #84 (moldura e núcleo da ADR 0040) são descartados. As PRs #80, #83 e #84 são fechadas sem merge.
- O backlog de M-HUD1 a M-HUD3 sai do cronograma. Nenhum passo de HUD entra antes do M4.
- A meta de CPU do núcleo da ADR 0040 (10% de um núcleo a 1080p/60) é substituída pelos orçamentos da seção 7 acima.
- A ADR 0040 fica no repositório com o status "substituída", para registro do histórico.

## Decisões aprovadas

1. O Cockpit segue o SDD v1.0, seção 11, com a pilha de 11.1 e a HUD Spec de 11.4.
2. A ADR 0040 é substituída, e as PRs #80, #83 e #84 são fechadas.
3. Nenhum trabalho de HUD antes do M4.
