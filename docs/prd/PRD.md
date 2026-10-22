# PRD: Optimus OS v1.0

- Status: **rascunho para revisão**
- Data: 2026-10-22
- Fontes: SDD v1.0 (`docs/sdd/optimus-os-sdd-v1.0.pdf`), ADRs 0001–0040, backlog do M3 (`docs/backlog/m3.md`)
- Relação com o SDD: este PRD descreve **o que** e **para quem**. O SDD continua sendo a fonte de verdade do **como**. Onde houver conflito, vale o SDD ou a ADR aceita posterior.

## 1. Resumo

O Optimus OS é um sistema operacional escrito do zero em Rust em que o usuário conversa com uma IA que se apresenta como o próprio sistema. Por baixo, um microkernel pequeno e determinístico, com capabilities, garante isolamento. A IA é a interface única: voz, texto e HUD são a porta de entrada, e apps e configurações viram ferramentas que ela usa sob política e confirmação.

## 2. Problema

- Sistemas operacionais de uso geral dão à aplicação e ao usuário autoridade ampla (root, namespace global, permissões ambientes). Isso facilita escalada de privilégio e exfiltração.
- Assistentes de IA atuais rodam sobre sistemas que não foram desenhados para eles. Conteúdo externo (e-mail, web, arquivos) pode sequestrar a IA (prompt injection) e agir em nome do usuário.
- Dados pessoais e memória de IA costumam sair da máquina por padrão.

## 3. Objetivos

| # | Objetivo | Medida de sucesso |
|---|---|---|
| O1 | Isolamento verificável | Nenhum processo com privilégio total; capabilities mínimas e revogáveis |
| O2 | IA útil e segura | Zero ações de risco R3 sem confirmação física; zero ações R4 pela IA |
| O3 | Privacidade local | Nenhum dado sai da máquina sem política explícita; telemetria só local |
| O4 | Leveza | Kernel ≤ 1 MiB; RAM em repouso ≤ 64 MiB no perfil Lite |
| O5 | Desempenho | IPC ida e volta ≤ 1 µs; troca de contexto ≤ 2 µs (medido em KVM) |
| O6 | Falha contida | Serviço reiniciado em ≤ 100 ms; rollback de atualização em ≤ 1 boot |

## 4. Não objetivos (fora da v1.0)

- Navegador web completo.
- Hardware de mainframe (s390x), AR/VR.
- Scripts complexos de texto (árabe, índico).
- RISC-V, GPU AMD RDNA, NPUs, Bluetooth, câmeras UVC (pós-v1).
- Compatibilidade POSIX completa (só camada própria, M15).
- Ajuste fino local de modelos (LoRA), que fica para depois da v1 e só no Premium.

## 5. Público e personas

- **Usuário final** (perfis Lite a Premium): quer conversar com o computador por voz ou texto, sem aprender menus. Precisa de controle claro sobre o que a IA pode fazer.
- **Usuário administrador de servidor** (perfil Server): operação headless, VMs e realms, Cockpit remoto.
- **Desenvolvedor do sistema** (kernel, serviços, AI Core, interface): precisa de contratos claros (OIDL, manifestos, ADRs) e de testes automatizados.
- **Revisor de segurança**: precisa de modelo de ameaças, auditoria encadeada e provas nas invariantes de capabilities.

## 6. Requisitos funcionais

Resumo dos RF do SDD (seção 2.2). Cada um é rastreável à seção do SDD indicada.

| ID | Requisito | Seção |
|---|---|---|
| RF-01 | Boot via UEFI em x86-64 e AArch64, com Secure Boot e boot medido | 5 |
| RF-02 | Processos isolados com memória virtual, threads e IPC por capabilities | 6 |
| RF-03 | 1 a 256 núcleos lógicos e NUMA | 6.9 |
| RF-04 | Dados no OptFS com criptografia, snapshots e verificação de integridade | 9.3 |
| RF-05 | Ethernet e Wi-Fi, IPv4/IPv6, TCP, UDP, DNS seguro e TLS 1.3 | 10 |
| RF-06 | Cockpit UI com aceleração por GPU ou renderização por software | 11 |
| RF-07 | Conversa por texto e voz em pt-BR e en-US, com interrupção (barge-in) | 12.9 |
| RF-08 | Planejar e executar tarefas com ferramentas do sistema, sob política e confirmação | 12 |
| RF-09 | Memória de longo prazo local, criptografada e editável pelo usuário | 12.8 |
| RF-10 | Propor melhorias de configuração e habilidades, com teste e aprovação | 12.11 |
| RF-11 | Apps em WebAssembly isolados, com permissões declaradas | 14.5, 16 |
| RF-12 | Atualização atômica A/B, assinada e com rollback | 5, 9.1, 14.5 |
| RF-13 | Modo de resgate determinístico, sem IA | 7.3, 5.5 |
| RF-14 | Operação headless no perfil Server, com Cockpit remoto | 10.4 |
| RF-15 | Máquinas virtuais e realms no perfil Server | 7.4 |

## 7. Requisitos não funcionais

| ID | Categoria | Requisito |
|---|---|---|
| RNF-01 | Segurança | Zero processos com privilégio total; superfície de rede mínima e auditada |
| RNF-02 | Segurança | Conteúdo externo nunca dispara ação R3 sem confirmação física |
| RNF-03 | Desempenho | IPC ≤ 1 µs; troca de contexto ≤ 2 µs |
| RNF-04 | Leveza | Kernel ≤ 1 MiB; RAM em repouso ≤ 64 MiB no Lite |
| RNF-05 | Responsividade | Voz ponta a ponta ≤ 800 ms no JARVIS |
| RNF-06 | Confiabilidade | Serviço reiniciado em ≤ 100 ms; rollback em ≤ 1 boot |
| RNF-07 | Privacidade | Nenhum dado sai sem política explícita |
| RNF-08 | Portabilidade | Código dependente de arquitetura isolado em `arch/`; ≥ 95% do kernel portável |
| RNF-09 | Manutenibilidade | `unsafe` só em módulos listados; cada bloco revisado por duas pessoas |
| RNF-10 | Acessibilidade | Todo fluxo operável só por voz, só por teclado ou com leitor de tela |

## 8. Perfis de hardware

| Perfil | CPU | RAM | GPU/NPU | Experiência |
|---|---|---|---|---|
| Lite | 1 núcleo | 512 MiB | não | texto e comandos de voz simples |
| Básico | 4 núcleos | 8–16 GiB | não | conversa útil, latência de segundos |
| JARVIS | 8+ núcleos | 32 GiB | GPU 16 GiB ou NPU 40+ TOPS | voz fluida, raciocínio, visão |
| Premium | 16+ núcleos | 64–128 GiB | GPU 24–48 GiB | modelos 70B, vários agentes |
| Server | 16–256 núcleos, NUMA | 64 GiB–4 TiB | opcional | headless, VMs, realms |

Um único código-fonte gera os cinco perfis por `--profile`. Metas detalhadas na seção 15 do SDD.

## 9. Princípios de produto

1. Segurança primeiro: nenhum componente tem poder total, nem a IA.
2. Kernel determinístico: sem IA, sem parsing complexo.
3. IA como interface única.
4. Local por padrão; nuvem opcional, visível e desligada de fábrica.
5. Leveza mensurável, verificada no CI.
6. Tudo do zero, com padrões abertos (UEFI, ACPI, virtio, WASI, GGUF, TLS 1.3).
7. Falha contida e recuperável; existe modo de resgate sem IA.

## 10. Experiência principal

**Fluxo de um pedido.** O usuário fala; `voiced` transcreve; `ai-router` decide entre caminho rápido e planejamento; `ai-planner` gera um plano em OPS; `ai-reader` processa conteúdo externo sem poder de ação; `ai-exec` valida o plano contra `policyd`, pede confirmação no trusted path se preciso, e chama os serviços por IPC; o resultado volta ao Cockpit como HUD Spec e ao `voiced` como fala.

**Confiança visível.** Toda confirmação de ação R3, pedido de senha e alerta de segurança aparece só na Faixa de Confiança, desenhada pelo `displayd`. A sequência Super+Esc sempre leva à tela real de bloqueio ou confirmação.

**Classes de risco da IA.** R0 livre e auditado; R1 livre e reversível; R2 livre se a origem for do usuário, com confirmação na tela se envolver conteúdo externo; R3 sempre com confirmação física (enviar mensagem, pagar, apagar definitivamente, mudar segurança, instalar app); R4 proibido para a IA (kernel, chaves, cadeia de atualização, desligar auditoria).

## 11. Métricas e critérios de aceite de produto

- Cada marco fecha com um gate. Gate 3 entrega a primeira versão que conversa e age (em VM). A v1.0 exige hardware real e as metas da seção 15.
- Gate 1 (M3): processos isolados em SMP e IPC ≤ 1 µs, medido em KVM.
- Red team de prompt injection: zero ações R3 sem confirmação; zero R4.
- Cobertura unitária ≥ 80% em kernel e `optcrypt`; fuzzing sem falha nova em 4 h por parser.

## 12. Marcos

| Fase | Marcos | Gate |
|---|---|---|
| Fundação | M0 (repositório, CI, ADRs, optboot mínimo), M1 (kernel inicial x86-64, um núcleo), M2 (capabilities, processos, IPC) | Gate 1 abre o M3 |
| Base | M3 (base e SMP: `ostd`, `svcmgr`, `oidlc`, `logd`, `memd`, `timed`, multinúcleo) | Gate 1: processos isolados em SMP, IPC ≤ 1 µs |
| Sistema | M4 a M7 (drivers, armazenamento, rede, interface) | Gate 2 |
| IA e produto | M8 a M16 (AI Core, voz, atualizações, Server, Premium) | Gate 3 e Gate 4 (v1.0) |

Estado atual do repositório (2026-10-22): backlog do M3 publicado, ADRs 0029 a 0039 aceitas, tarefas T-301 a T-312 cumpridas quanto ao aceite, T-334 (alocador do `ostd`) com relatório em `docs/bench/`. Ainda não há `svcmgr` nem `oidlc` no código.

## 13. Dependências e restrições

- Rust estável fixado em `rust-toolchain.toml`, edition 2024.
- Nenhuma crate externa na imagem do sistema. Dependências só em `xtask`, ferramentas de host, testes, fuzzing e benchmarks.
- QEMU (q35 + OVMF) para testes; KVM para medir metas de desempenho.
- Chaves de release offline (raiz em dois tokens de hardware).

## 14. Riscos

| Risco | Mitigação | Plano B |
|---|---|---|
| Escopo grande demais para a equipe | Marcos úteis desde o M8 em VM | Lançar "Optimus VM Edition" (só virtio) |
| GPU Intel Xe atrasa | Inferência por CPU otimizada; GPU no M12 | NPU ou modo híbrido com nuvem opcional |
| Prompt injection supera a política | Leitor isolado, taint, OPS, confirmação física, red team | Reduzir ferramentas R2/R3 até corrigir |
| Criptografia própria com falha | ADR 0004: código formalmente verificado, vetores, dudect | Desativar algoritmo afetado |
| Modelos locais fracos em hardware modesto | Roteador por gramática, skills, perfis honestos | Nuvem opcional com consentimento |
| Variedade de hardware real | Priorizar chipsets mais vendidos | Lista de hardware certificado |
| Wi-Fi e firmware fechados | Catálogo de firmware assinado | Adaptadores USB-Ethernet |
| Interpretador AML complexo | Isolado em `acpid`, fuzzing com tabelas reais | Modo de energia mínimo |
| Falta de apps | WebAssembly, IA gera ferramentas, camada POSIX | VM Linux para apps legados (M15) |
| Licenças de modelos mudarem | ADR 0022, revisão a cada release | Modelo equivalente permissivo |

## 15. Questões em aberto

Levantadas no backlog do M3 (seção 1). Enquanto não forem respondidas, vale o SDD.

1. Transcrever os critérios de saída do M3 e do Gate 1 (estão só na imagem do roadmap, §19) para o SDD ou uma ADR.
2. Confirmar o significado de "oidlc" no M3; o SDD não o define de forma consistente com o pedido original.
3. Definir gramática e formato de fio do OIDL (ADR 0033, já aceita; conferir o texto final).
4. Definir o protocolo do `svcmgr` como corretor de capabilities (`provides`/`needs`) e quem compila o manifesto.
5. Assinatura do manifesto no M3: só BLAKE3 conferido pelo optboot (aceitar explicitamente na ADR 0034).
6. Evento de morte de processo e objeto Timer (ADRs 0035 e 0037).
7. Primitivas do `memd` ausentes na tabela de syscalls (ADR 0038).
8. Afinidade e NUMA: sugestão de afinidade por máscara no M3, NUMA adiado.
9. AArch64: o SDD fala de testes SMP em x86-64 e AArch64, mas o M3 é só x86-64.
10. Aleatoriedade em espaço de usuário: `sys_info` ou serviço root distribuindo semente (ADR 0039).

## 16. Fora deste documento

Modelagem em `docs/prd/modelagem.md`. Especificações de funcionalidades para desenvolvimento, no formato Spec Driven Development, em `docs/spec-driven/`.
