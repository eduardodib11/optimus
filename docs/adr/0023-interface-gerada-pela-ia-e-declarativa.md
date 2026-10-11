# ADR 0023: Interface gerada pela IA é declarativa (HUD Spec), nunca código

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 11.1, 11.2, 11.4 e 12.2
- Relaciona-se com: ADR 0019 (separação da IA), ADR 0020 (OPS),
  ADR 0016 (apps em Wasm)

## Contexto

No Cockpit, a própria IA monta os painéis que respondem a cada pedido. Se a
IA gerasse código de interface (HTML com scripts, Rust, Wasm), uma injeção de
prompt poderia virar código rodando no `cockpit`, imitar a Faixa de Confiança,
ler dados de outros painéis ou disparar ações sem passar pelo `ai-exec`.

## Decisão

- A IA descreve painéis em HUD Spec: JSON validado por esquema, sem código.
- O catálogo da v1 é fechado: `text`, `markdown`, `table`, `list`, `chart`
  (linha, barras, área), `metric`, `progress`, `form`, `image`, `media`,
  `file-grid` e `timeline`; `map` fica para depois da v1.
- Dados chegam por tokens de capability de leitura, não embutidos pela IA.
- Ações em formulários viram novos pedidos ao `ai-exec`, sujeitos a política.
- Só o `displayd` desenha a Faixa de Confiança; HUD Spec nunca a alcança.

## Alternativas

- **HTML/JS gerado pela IA num webview:** flexível, mas exige motor web e
  executa código vindo do modelo; scripts injetados teriam acesso à interface.
- **Código Wasm gerado pela IA em sandbox:** isola memória, mas ainda permite
  lógica arbitrária e enganos visuais; e quebra a separação de ADR 0019.
- **Só texto e voz:** seguro, mas perde tabelas, gráficos e formulários.

## Consequências

- A UI da IA é limitada ao catálogo; componente novo exige mudança no `cockpit`
  e no esquema, com revisão.
- O renderizador de HUD Spec é parser de entrada não confiável e exige fuzzing.
- Painéis ficam consistentes em estilo e acessibilidade em todos os perfis.
