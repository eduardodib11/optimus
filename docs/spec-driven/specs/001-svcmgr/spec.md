# Especificação 001: `svcmgr` (supervisor de serviços)

- Status: **rascunho para revisão**
- Marco: M3 (tarefas T-350 a T-354)
- Fontes: SDD 7.2, 14.4, 4.3, 13; PRD RF-01, RF-02, RF-12, RF-13, RNF-06; ADRs 0011, 0034 (pendente), 0035 (pendente)
- Responsável de segurança: revisão dupla obrigatória (TCB)

## 1. Contexto

O `svcmgr` é o supervisor da base de confiança. Ele lê manifestos de serviço, resolve dependências, inicia serviços em paralelo, entrega a cada um só as capabilities declaradas e reinicia quem cai. Sem ele, nenhum serviço de sistema sobe.

O `root` é o primeiro processo. Recebe do kernel todas as capabilities iniciais, divide a memória em cotas e inicia o `svcmgr`. Depois disso, só responde ao `svcmgr`.

## 2. Objetivos

1. Subir todos os serviços do bootfs e da imagem de sistema, na ordem das dependências e em paralelo quando possível.
2. Impor que cada serviço só receba as capabilities do próprio manifesto.
3. Reiniciar serviços que falharam, com recuo exponencial e alerta em caso de falha repetida.
4. Revogar e reemitir capabilities ao reiniciar, sem deixar capability do processo antigo viva.
5. Manter a TCB pequena.

## 3. Histórias de usuário

**H1. Partida do sistema.** Como desenvolvedor do sistema, quero que o `svcmgr` suba os serviços do bootfs na ordem certa, para que o sistema chegue à interface sem intervenção.

**H2. Isolamento por manifesto.** Como revisor de segurança, quero que um serviço nunca receba capability fora do manifesto assinado, para que um serviço comprometido não ganhe autoridade extra.

**H3. Recuperação.** Como usuário, quero que um serviço que cai volte sozinho, para que uma falha não derrube o sistema.

**H4. Alerta.** Como usuário, quero ser avisado se um serviço cai repetidamente, para que eu saiba que há um problema real.

**H5. Clientes reconectam.** Como desenvolvedor de cliente, quero receber `PeerClosed` quando o servidor reinicia, para que eu possa reconectar sem travar.

**H6. Descoberta por interface.** Como desenvolvedor de cliente, quero pedir ao `svcmgr` um serviço pela interface e versão que ele oferece, para não depender de nomes fixos.

## 4. Requisitos funcionais

| ID | Requisito |
|---|---|
| FR-01 | Ler manifestos do bootfs e da imagem de sistema. |
| FR-02 | Validar o grafo de dependências: deve ser acíclico. A verificação ocorre no build, e o `svcmgr` confere de novo na partida. |
| FR-03 | Iniciar serviços em paralelo respeitando as dependências. |
| FR-04 | Entregar a cada serviço somente as capabilities listadas em `needs`. |
| FR-05 | Registrar as capabilities de `provides` e permitir descoberta por nome de interface e versão. |
| FR-06 | Aplicar política de reinício `always`, `on-failure` ou `never`. |
| FR-07 | Recuo exponencial de 100 ms a 30 s entre reinícios. |
| FR-08 | Após 5 falhas em 1 minuto, registrar alerta de nível erro e emitir evento para consumidor futuro. |
| FR-09 | Ao reiniciar, revogar as capabilities do processo antigo e reemiti-las ao novo. |
| FR-10 | Notificar os clientes do serviço que caiu com `PeerClosed`. |
| FR-11 | Impor `max_threads` e `ipc_rate` do manifesto (depende da ADR 0035). |

## 5. Requisitos não funcionais

| ID | Requisito |
|---|---|
| NFR-01 | Serviço que cai é reiniciado em ≤ 100 ms após a falha detectada (RNF-06). |
| NFR-02 | Sistema volta em ≤ 1 s após matar serviços aleatoriamente (teste de caos, SDD 18). |
| NFR-03 | `svcmgr` pequeno e revisado por duas pessoas (SDD 20, nota 20). |
| NFR-04 | Nenhum `unsafe` fora da allowlist. |
| NFR-05 | Nenhuma alocação não limitada: toda memória do `svcmgr` vem da cota do `root`. |

## 6. Formato do manifesto

Conforme o SDD 14.4. O manifesto é escrito em TOML no código-fonte, compilado para binário e assinado junto com a imagem.

```toml
[service]
name = "netd"
binary = "/sys/bin/netd"
priority = 150
restart = "always"

[capabilities]
needs = ["dev:net/*", "log:write", "time:read", "mem:quota:32MiB"]
provides = ["optimus.net.Socket@1", "optimus.net.Config@1"]

[limits]
max_threads = 16
ipc_rate = 200000
```

Campos obrigatórios: `name`, `binary`, `restart`. Os demais têm valor padrão definido no plano.

## 7. Critérios de aceite

Cada critério é um teste automatizado. Nenhum é aceito só por inspeção.

| ID | Critério | Teste |
|---|---|---|
| AC-01 | Com três serviços em cadeia (A depende de B, B de C), a ordem de partida é C, B, A. | Teste de integração em QEMU com serial. |
| AC-02 | Dependência cíclica é recusada no build com erro que nomeia o ciclo. | Teste unitário do compilador de manifestos (T-350). |
| AC-03 | Serviço que pede capability fora de `needs` não recebe a capability. | Teste de integração: a chamada retorna `AccessDenied`. |
| AC-04 | Serviço que morre é reiniciado em ≤ 100 ms. | Teste de integração com medição de tempo. |
| AC-05 | Capability do processo antigo, após reinício, retorna `Revoked` ou `InvalidHandle`. | Teste de integração. |
| AC-06 | Cliente conectado recebe `PeerClosed` quando o servidor cai. | Teste de integração. |
| AC-07 | Política `never` não reinicia o serviço. | Teste unitário da máquina de estados. |
| AC-08 | Cinco falhas em um minuto geram o alerta de nível erro. | Teste unitário com relógio simulado. |
| AC-09 | Recuo sobe de 100 ms até 30 s, sem passar do teto. | Teste unitário. |
| AC-10 | Matar serviços aleatoriamente durante 10 minutos não deixa o sistema fora do ar além de 1 s. | Teste de caos (T-354 e T-329). |
| AC-11 | Manifesto com `max_threads` excedido é contido. | Depende da ADR 0035; teste de integração. |

## 8. Fora de escopo (M3)

- Assinatura do manifesto com Ed25519 e ML-DSA-65. No M3 vale só o hash do bootfs conferido pelo `optboot` (ADR 0034, a aceitar).
- Persistência do estado do `svcmgr` entre boots.
- Medição de perfil no primeiro boot (SDD 15.4), que fica para depois do M3.
- Descoberta remota entre máquinas.
- Mapeamento de arquivos e armazenamento (M5).

## 9. Premissas e dependências

- `root` e `svcmgr` existem como crates (`services/root`, a criar `services/svcmgr`).
- Eventos de morte de processo e objeto Timer (ADR 0035, T-348 e T-349). Sem eles, FR-09, FR-10 e FR-11 não têm como ser atendidos.
- OIDL (T-340 a T-347) para o protocolo de descoberta. Até lá, o protocolo `root`→`svcmgr` é a exceção documentada no SDD (item 19 do backlog).
- Ordem de locks e SMP (T-314 a T-328): o `svcmgr` roda em SMP no M3.

## 10. Perguntas em aberto

Estas perguntas precisam de resposta no plano, antes das tarefas.

1. Quem emite a capability `dev:net/*` e como ela é nomeada (ADR 0034).
2. Formato do binário compilado do manifesto e quem o gera (`tools/` ou `xtask`).
3. Como o `svcmgr` impõe `max_threads` sem objeto de processo (ADR 0035).
4. O `svcmgr` pode ser reiniciado? Se sim, quem o supervisiona? (Proposta: o `root` reinicia o `svcmgr` uma vez e depois entra em modo de falha, como o `rescue`.)
