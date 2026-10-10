# ADR 0019: IA fora do kernel, em Planejador, Leitor isolado e Executor

- Status: aceita
- Data: 2026-10-09
- Origem: SDD v1.0, seção 3; seções 12.1 a 12.3, 12.5 e 13.2
- Relaciona-se com: ADR 0001 (microkernel), ADR 0011 (capabilities),
  ADR 0020 (OPS), ADR 0021 (oie), ADR 0023 (HUD Spec)

## Contexto

O Optimus é uma IA que opera o computador, mas modelos de linguagem não
separam instrução de dado: um e-mail ou página pode conter texto que o modelo
segue como ordem (prompt injection). Um modelo com acesso a conteúdo externo e
a ferramentas ao mesmo tempo pode ser levado a exfiltrar dados ou agir sozinho.
Além disso, inferência é código grande e não confiável, que não cabe no kernel.

## Decisão

- O kernel não contém IA. A IA roda em processos de usuário com capabilities
  mínimas, num padrão inspirado no CaMeL:
  - `ai-router`: classifica a intenção e resolve comandos simples por gramática.
  - `ai-planner`: conversa e gera planos OPS; só fala com o `oie` e lê memória;
    não tem capability de ação e nunca vê texto `EXTERNAL` cru.
  - `ai-reader`: lê conteúdo externo e devolve dados por esquema; sem rede,
    sem memória, sem ação.
  - `ai-exec`: executor determinístico, sem modelo; interpreta OPS, aplica a
    política do `policyd`, pede confirmação e chama as ferramentas.
- Todo dado carrega etiqueta de origem (`USER`, `SYSTEM`, `LOCAL`, `EXTERNAL`,
  `AI`), propagada pelo executor.

## Alternativas

- **LLM único com ferramentas (agente clássico):** simples e rápido, mas o mesmo
  modelo que lê o conteúdo malicioso decide a ação. Filtros de prompt não dão
  garantia; rejeitado.
- **IA como serviço privilegiado ou no kernel:** amplia a base de confiança com
  código probabilístico; contraria a ADR 0001.

## Consequências

- Tarefas sobre conteúdo externo ficam mais lentas: mais chamadas ao `oie` e IPC.
- A segurança passa a depender do executor e da política, que são verificáveis.
- Ações R3 sempre exigem confirmação física no trusted path; R4 é proibido.
