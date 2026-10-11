# ADR 0020: Planos da IA em linguagem OPS, não Turing-completa

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 12.2, 12.4 a 12.6
- Relaciona-se com: ADR 0012 (OIDL), ADR 0019 (separação da IA),
  ADR 0021 (decodificação com gramática)

## Contexto

O Planejador (ADR 0019) precisa dizer ao Executor o que fazer. Esse plano é
saída de um modelo e não é confiável: pode conter erro, laço sem fim ou efeito
induzido por conteúdo externo. O Executor precisa checar o plano inteiro antes
de rodar, saber a origem de cada valor e aplicar a política a cada passo.

## Decisão

- Planos são escritos em OPS (Optimus Plan Script): linguagem pequena e tipada,
  com chamadas de ferramenta, variáveis imutáveis, `if`, `for` só sobre listas
  finitas e `ask_user`. Não há laço livre, recursão nem `eval`.
- Toda execução termina; o custo é limitado pelo tamanho das listas e do plano.
- As ferramentas são métodos OIDL com `@tool`; o `oidlc` gera o esquema que o
  Planejador vê e a ligação que o Executor chama.
- O `ai-exec` checa tipos, ferramentas e política antes de executar e rastreia a
  origem (taint) de cada variável. Regras OPL podem exigir confirmação quando um
  argumento veio de `EXTERNAL`.
- O Planejador gera OPS com decodificação restrita pela gramática.

## Alternativas

- **Python ou JavaScript gerado pela IA em sandbox:** expressivo e conhecido
  pelos modelos, mas Turing-completo: não dá para provar término nem rastrear a
  origem dos dados. A sandbox limita o dano, não a intenção.
- **JSON de chamadas de função soltas:** simples, mas sem variáveis nem
  condicionais; exige ida e volta ao modelo a cada passo, o que reabre a porta ao
  conteúdo externo.

## Consequências

- Planos são legíveis, auditáveis e reproduzíveis no `auditd`.
- O Planejador depende da gramática OPS no `oie`; modelos não conhecem OPS.
- Tarefas que precisem de cálculo livre usam a ferramenta de código em sandbox Wasm.
