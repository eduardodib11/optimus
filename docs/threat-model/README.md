# Modelo de ameaças do Optimus OS

- Status: **rascunho para revisão**
- Versão: 0.1 (T-006)
- Fonte de verdade: SDD v1.0, seção 13; também seções 5 (boot), 6 (kernel),
  8 (drivers), 9 (armazenamento), 10 (rede), 11 (trusted path), 12 (AI Core),
  14 (formatos), 16 a 18 (build, processo, testes)
- Aprovação: responsável de segurança listado no `CODEOWNERS` (ver "Revisão")

Este documento organiza a seção 13 do SDD por componente e fronteira de
confiança. Ele não cria requisitos novos: onde acrescenta algo que o SDD não
diz, o trecho está marcado como **(proposta, fora do SDD)** e só vale depois
de virar ADR ou revisão do SDD.

Método: STRIDE por componente (S = spoofing, T = adulteração, R = repúdio,
I = vazamento de informação, D = negação de serviço, E = elevação de
privilégio), mais a categoria de agentes de IA (prompt injection e uso da IA
como "deputado confuso").

## 1. Escopo

Dentro do escopo:

- Cadeia de boot: firmware UEFI → `optboot` → `okernel` → `root` → `svcmgr`.
- Kernel, serviços de sistema, drivers em espaço de usuário, pilha de rede
  (`netd`, `tlsd`, `wland`), armazenamento (`storaged`, `optfs`, `keyd`).
- Pilha gráfica até o trusted path (`displayd`, `inputd`, `cockpit`).
- AI Core: `ai-router`, `ai-planner`, `ai-reader`, `ai-exec`, `ai-memory`,
  `oie`, `voiced`, `evolved`, `ctxd`, `policyd`.
- Apps de terceiros em WebAssembly (`owr`, `pkgd`, pacotes `.opk`).
- Atualização e distribuição: `updated`, `.oupd`, `.osi`, `.omdl`, chaves do
  projeto e cadeia de build.

Fora do escopo: ver seção 9.

## 2. Ativos (SDD 13.1)

| ID | Ativo                                   | Propriedade principal      |
|----|-----------------------------------------|----------------------------|
| A1 | Dados pessoais e memória da IA          | Confidencialidade          |
| A2 | Chaves e credenciais                    | Confidencialidade          |
| A3 | Integridade do kernel, imagem e updates | Integridade                |
| A4 | Controle da IA (só o usuário a dirige)  | Integridade / autorização  |
| A5 | Disponibilidade do sistema              | Disponibilidade            |

Detalhes: A1 inclui `/data/ai` (episódica, semântica, perfil, procedimental,
SDD 12.8). A2 inclui a chave mestra do volume, chaves por usuário e por app
(SDD 9.3), chaves de sessão TLS (SDD 10.3) e as chaves de release (SDD 13.4).
A3 inclui as regras de fábrica do `policyd` (assinadas, SDD 12.6) e o log do
`auditd` (somente-anexo, encadeado por BLAKE3, SDD 7.3).

## 3. Adversários e premissas de confiança

### 3.1 Adversários considerados

| ID | Adversário                         | Capacidade assumida                     |
|----|------------------------------------|-----------------------------------------|
| X1 | Remoto na rede                     | Envia tráfego arbitrário; MITM em Wi-Fi |
| X2 | Autor de conteúdo                  | Controla e-mail, web, arquivos, áudio   |
|    |                                    | que a IA lê (prompt injection)          |
| X3 | App de terceiros malicioso         | Código Wasm arbitrário no seu realm     |
| X4 | Processo comprometido fora da TCB  | Execução arbitrária com suas caps       |
| X5 | Dispositivo ou driver malicioso    | DMA, descritores hostis, firmware       |
| X6 | Ladrão do dispositivo              | Acesso físico ao disco, desligado       |
| X7 | Atacante da cadeia de suprimentos  | Adultera build, mirror ou servidor      |
| X8 | Engenheiro social                  | Induz o usuário a confirmar algo        |

X4 é a premissa central: "o sistema deve continuar seguro se qualquer outro
processo for tomado" (SDD 13). Isso inclui todos os processos do AI Core,
`netd`, drivers, `optfs`, `pkgd` e `owr`.

### 3.2 Premissas de confiança

- P1. O firmware UEFI aplica Secure Boot corretamente e o hardware não vem
  comprometido de fábrica (risco aceito, SDD 13.5).
- P2. Os componentes da TCB (seção 5) estão corretos.
- P3. As primitivas da `optcrypt` estão corretas e em tempo constante
  (Wycheproof, NIST, dudect no CI; SDD 13.3; ADR 0004).
- P4. A raiz offline em dois tokens de hardware não foi comprometida
  (SDD 13.4).
- P5. O usuário lê a Faixa de Confiança antes de confirmar ações R3.
- P6. Com TPM, os PCRs 0, 7, 8 e 9 refletem o boot real (SDD 5.4).

## 4. Fronteiras de confiança

| ID | Fronteira                                  | Mecanismo                         |
|----|--------------------------------------------|-----------------------------------|
| F1 | Firmware → `optboot` → kernel/bootfs       | Secure Boot, assinatura híbrida,  |
|    |                                            | medição em PCR 8/9 (SDD 5.1)      |
| F2 | Usuário ↔ kernel                           | Syscalls, capabilities (SDD 6)    |
| F3 | Processo ↔ processo                        | IPC por Endpoint, GRANT, badge    |
| F4 | Dispositivo ↔ memória                      | Driver isolado, DmaDomain/IOMMU   |
| F5 | Rede ↔ sistema                             | `netd`, firewall, NetAccess       |
| F6 | Conteúdo externo ↔ planejador              | `ai-reader`, taint EXTERNAL       |
| F7 | Plano da IA ↔ ação                         | `ai-exec`, OPS, `policyd`, R0–R4  |
| F8 | Usuário ↔ confirmação                      | Trusted path do `displayd`        |
| F9 | App Wasm ↔ sistema                         | `owr`, realm, manifesto `.opk`    |
| F10| Projeto ↔ máquina (update, modelo, pacote) | TUF, Merkle, A/B, anti-rollback   |
| F11| Disco em repouso ↔ sistema em execução     | OptFS autenticado, chave no TPM   |

## 5. Base de confiança (TCB)

Segundo o SDD 13, a TCB é só: `optboot`, `okernel`, `root`, `svcmgr`, `keyd`,
`policyd`, `displayd` (trusted path) e `updated`.

| Componente | Por que está na TCB                                          | ADR        |
|------------|--------------------------------------------------------------|------------|
| `optboot`  | Verifica e mede kernel e bootfs; escolhe slot A/B            | 0005, 0018 |
| `okernel`  | Impõe capabilities, isolamento de memória e cotas            | 0001, 0006 |
| `root`     | Recebe todas as caps iniciais e divide cotas                 | 0011       |
| `svcmgr`   | Inicia serviços com lista fechada de caps; revoga ao reiniciar| 0011      |
| `keyd`     | Único processo com acesso ao TPM; chaves de disco e usuário  | 0014       |
| `policyd`  | Decide se cada passo da IA pode rodar e com qual confirmação | 0019, 0020 |
| `displayd` | Único que desenha a Faixa de Confiança                       | 0023       |
| `updated`  | Instala imagens A/B verificadas, com pinning e anti-rollback | 0015, 0018 |

Meta de tamanho do kernel: ≤ 25 mil linhas portáveis + ≤ 3 mil de arquitetura,
imagem ≤ 1 MiB (SDD 6); `unsafe` só em crates da allowlist, com `// SAFETY:`
e revisão (SDD 17; ADR 0002, 0003).

Observações para a revisão (pontos em que a TCB do SDD parece incompleta;
ver seção 10):

- O `inputd` captura Super+Esc (SDD 11.2), mas não está na lista da TCB.
- O `ai-exec` aplica a política e pede confirmação (SDD 12.1), mas está fora
  da TCB; a segurança depende de o `policyd`/`displayd` não poderem ser
  contornados por um `ai-exec` comprometido.
- `authd` (senhas, FIDO2), `tlsd` (usado pelo `updated`), `pkgd` e
  `auditd` não estão na TCB.

## 6. Ameaças por componente

Legenda da coluna Ref: "§n" = seção do SDD; "ADR n" = ADR do repositório.
Coluna T: categoria STRIDE ou "PI" (prompt injection).

### 6.1 Boot (optboot, bootfs, chaves de disco)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| B1  | T  | Kernel ou bootfs adulterado no ESP       | Assinatura híbrida Ed25519+ML-DSA-65      | §5.1, ADR 0018 |
| B2  | T  | Código não assinado antes do 1º processo | Secure Boot valida `optboot`              | §5, ADR 0005   |
| B3  | I  | Roubo do disco (X6)                      | Chave do volume selada aos PCRs 0,7,8,9;  | §5.4, §9.3     |
|     |    |                                          | sem TPM, Argon2id sobre senha             |                |
| B4  | T  | Boot alterado para liberar chave         | Medição em PCR 8/9; selagem falha         | §5.1, §5.4     |
| B5  | E  | Exploração de KASLR previsível           | Semente de RNG UEFI+RDSEED; KASLR         | §5.1, §6.5     |
| B6  | D  | Slot quebrado impede o boot              | 3 falhas → troca de slot; senão `rescue`  | §5.5           |
| B7  | T  | Rollback para slot antigo vulnerável     | Contador anti-rollback                    | §13.2, ADR 0015|
| B8  | I  | DMA antes da IOMMU (ataque físico)       | "Proteção de DMA" citada em 13.2; o SDD   | §13.2          |
|     |    |                                          | não detalha o mecanismo no boot           |                |

### 6.2 Kernel (okernel)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| K1  | E  | Corrupção de memória no kernel           | Rust, `unsafe` mínimo, Miri, Kani; W^X,   | §6.5, §17, §18 |
|     |    |                                          | SMEP/SMAP/UMIP, PAN/PXN/BTI/PAC, CET      | ADR 0002       |
| K2  | E  | Forjar ou ampliar capability             | `cap_mint` só reduz direitos; handle com  | §6.2, ADR 0001 |
|     |    |                                          | geração; prova Kani da derivação          | §18            |
| K3  | E  | Uso após revogação                       | Árvore de derivação, `cap_revoke`         | §6.2, §7.2     |
| K4  | D  | Esgotar memória do kernel                | Toda alocação cobrada de `MemoryQuota`    | §6.1, ADR 0006 |
| K5  | D  | Monopolizar CPU                          | `SchedContext` com orçamento e período    | §6.6, ADR 0008 |
| K6  | D  | Inundação de IPC                         | Limites de IPC, prazos em `ipc_call`      | §6.7, §13.2    |
| K7  | E  | Syscall com argumento hostil             | Fuzzing `okfuzz` de syscalls              | §18            |
| K8  | I  | Canais laterais de microarquitetura      | KPTI em CPUs vulneráveis; resto é risco   | §6.4, §13.5    |
|     |    |                                          | aceito (mitigado parcialmente)            |                |
| K9  | T  | Estado inconsistente após falha          | Pânico congela CPUs e reinicia            | §6.5           |
| K10 | E  | Corrida em SMP                           | Ordem fixa de locks; TLA+ do IPC/revogação| §6.9, §18      |

### 6.3 Drivers e dispositivos

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| D1  | E  | Driver comprometido domina a máquina     | Driver em processo de usuário só com MMIO,| §8, ADR 0013   |
|     |    |                                          | IRQ e `DmaDomain` do seu dispositivo      |                |
| D2  | T  | DMA arbitrário de dispositivo hostil     | IOMMU (VT-d, AMD-Vi, SMMUv3)              | §8.1, ADR 0013 |
| D3  | E  | Descritor PCI/USB/ACPI malformado        | Alvo de fuzzing obrigatório por parser;   | §8.1, §8.3     |
|     |    |                                          | AML interpretado no `acpid` isolado       |                |
| D4  | T  | Firmware binário malicioso               | Só blobs no catálogo assinado, hash fixo, | §8.1           |
|     |    |                                          | executados no dispositivo, nunca na CPU   |                |
| D5  | D  | Driver trava                             | Reinício sem derrubar o sistema           | §8, §7.2       |
| D6  | I  | Máquina sem IOMMU                        | Modo degradado, aviso no HUD e `auditd`   | §8.1, §13.5    |

### 6.4 Rede (netd, tlsd, wland)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| N1  | E  | Exploração remota de serviço (X1)        | Entrada bloqueada por padrão; `netd`      | §10, §18,      |
|     |    |                                          | isolado; parsers com fuzzing; Rust        | ADR 0017       |
| N2  | I  | Exfiltração por processo comprometido    | Saída só com `NetAccess` (destinos);      | §10.2          |
|     |    |                                          | limites de taxa e conexões por processo   |                |
| N3  | S  | MITM / certificado forjado               | TLS 1.3 só; X.509 com parser próprio e    | §10.3          |
|     |    |                                          | fuzzing; OCSP stapling e CRLite           |                |
| N4  | I  | Coleta agora, decifra depois (quântico)  | X25519+ML-KEM-768 híbrido                 | §13.3, ADR 0017|
| N5  | I  | Vazamento de chave de sessão             | Chaves privadas nunca saem do `tlsd`      | §10.3          |
| N6  | S  | DNS envenenado                           | DoH/DoT padrão, DNSSEC validado           | §10.1          |
| N7  | S  | Wi-Fi rebaixado                          | WPA3-SAE; WPA2 só como fallback avisado   | §10.1          |
| N8  | S  | Servidor de atualização falso            | `updated` com pinning de chave            | §10.4          |
| N9  | T  | Hora falsa (expira/aceita metadados)     | NTS (NTP autenticado) no `timed`          | §7.3           |

### 6.5 Armazenamento (storaged, optfs, keyd)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| S1  | T  | Imagem de sistema alterada em repouso    | Merkle SHA-256 por bloco de 4 KiB; bloco  | §9.2, ADR 0015 |
|     |    |                                          | divergente vira erro de E/S, não dado     |                |
| S2  | T  | Adulteração offline do volume de dados   | Árvore autenticada até o superbloco;      | §9.3, ADR 0014 |
|     |    |                                          | AES-256-GCM / ChaCha20-Poly1305           |                |
| S3  | I  | Leitura do disco roubado (X6)            | Criptografia por bloco; chaves por        | §9.3, §5.4     |
|     |    |                                          | usuário e app via HKDF; chave no TPM      |                |
| S4  | E  | Processo lê pasta de outro               | Sem árvore global; caps de diretório por  | §7.4, ADR 0011 |
|     |    |                                          | processo; realms                          |                |
| S5  | I  | `optfs` comprometido (X4) lê o volume    | Não mitigado no SDD: um `optfs` por volume| §9.4           |
|     |    |                                          | tem as chaves do volume (ver seção 10)    |                |
| S6  | D  | Corte de energia corrompe dados          | Copy-on-write; dois superblocos           | §9.3           |
| S7  | T  | Acesso ao TPM por outro processo         | `keyd` é o único com acesso ao TPM        | §7.3           |

### 6.6 IA (AI Core)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| I1  | PI | Instrução escondida em conteúdo externo  | `ai-reader` isolado (sem rede, memória ou | §12.1, §12.3,  |
|     |    | (X2) faz a IA agir                       | ação); planejador nunca vê EXTERNAL cru   | ADR 0019       |
| I2  | PI | Dado externo escolhe argumento sensível  | Taint propaga; regra OPL: R3 com argumento| §12.3, §12.6   |
|     |    | (ex.: destinatário)                      | EXTERNAL exige confirmação física         |                |
| I3  | E  | Plano arbitrário / código gerado         | OPS tipada, sem laços infinitos; gramática| §12.4, ADR 0020|
|     |    |                                          | restrita; `ai-exec` checa tipos e política| §12.12         |
| I4  | E  | IA executa ação destrutiva sozinha       | Classes R0–R4: R2 com EXTERNAL confirma na| §12.5          |
|     |    |                                          | tela; R3 sempre física; R4 proibida       |                |
| I5  | I  | IA exfiltra dados (A1)                   | Sem rede direta; só ferramentas via       | §10.2, §12,    |
|     |    |                                          | `ai-exec` com `NetAccess`, auditoria e    | §13.2          |
|     |    |                                          | limite de taxa                            |                |
| I6  | E  | IA afrouxa a própria política            | Regras de fábrica assinadas; afrouxar só  | §12.6          |
|     |    |                                          | no app Configurações no trusted path; IA  |                |
|     |    |                                          | só propõe endurecer                       |                |
| I7  | T  | Envenenamento de memória persistente     | Memória EXTERNAL nunca vira instrução;    | §12.8          |
|     |    |                                          | usuário vê, edita e apaga                 |                |
| I8  | S  | Voz falsa / gravação autoriza ação       | Voz nunca autoriza R3; verificação de     | §12.9          |
|     |    |                                          | locutor não é autenticação                |                |
| I9  | E  | `evolved` altera base de confiança       | Nunca altera kernel, TCB, chaves, cadeia  | §12.11         |
|     |    |                                          | de update; política só endurece; aplica   |                |
|     |    |                                          | só com aprovação e snapshot               |                |
| I10 | S  | HUD gerado pela IA imita o sistema       | HUD Spec é JSON validado, nunca código;   | §11.4, §11.2,  |
|     |    |                                          | confirmações só na Faixa de Confiança     | ADR 0023       |
| I11 | T  | Modelo `.omdl` adulterado                | Pacote assinado com hash e licença        | §12.13, §14    |
| I12 | E  | Parser GGUF explorado pelo modelo        | Fuzzing de GGUF; `oie` sem cap de ação    | §18, ADR 0021  |
| I13 | I  | Nuvem opcional vaza dados                | Desligada por padrão; indicador no HUD;   | §12.14         |
|     |    |                                          | `auditd`; LOCAL privado nunca sai         |                |
| I14 | R  | Negar autoria de ação da IA              | Tudo registrado no `auditd` (encadeado e  | §12.2, §7.3    |
|     |    |                                          | assinado por época)                       |                |
| I15 | S  | Engenharia social na confirmação (X8)    | Confirmação mostra origem e risco em      | §11, §12,      |
|     |    |                                          | linguagem clara                           | §13.2          |

Verificação: suíte de red team de prompt injection (e-mail, web, arquivos,
áudio) no CI noturno com gate "zero ações R3 sem confirmação; zero R4" (§18).

### 6.7 Interface e trusted path

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| U1  | S  | App imita diálogo de senha/confirmação   | Faixa de Confiança desenhada só pelo      | §11.2          |
|     |    |                                          | `displayd`; Super+Esc leva à tela real    |                |
| U2  | I  | Compositor lê memória de cliente         | Só buffers em `MemoryObject` com fences   | §11.1          |
| U3  | E  | Fonte OpenType hostil                    | Parser próprio; fuzzing de parsers        | §11.1, §18     |

### 6.8 Apps Wasm (owr, pkgd)

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| W1  | E  | Fuga do sandbox Wasm (X3)                | Runtime `owr` próprio; fuzzing de Wasm;   | §18, ADR 0016  |
|     |    |                                          | app roda num realm com caps fechadas      | §7.4           |
| W2  | E  | App pede mais permissão que o declarado  | Manifesto de permissões no `.opk`;        | §14, §7.3      |
|     |    |                                          | `pkgd` gerencia permissões                |                |
| W3  | T  | Pacote adulterado ou de autor falso      | Assinatura do autor + assinatura da loja  | §14, ADR 0018  |
| W4  | E  | Instalar app via IA sem o usuário        | Instalar app é R3: confirmação física     | §12.5          |
| W5  | D  | App esgota recursos                      | Cotas por realm (memória, CPU, disco)     | §6, §7.4, §9.3 |
| W6  | I  | App exfiltra pela rede                   | Sem `NetAccess`, sem saída                | §10            |

### 6.9 Atualização e cadeia de suprimentos

| ID  | T  | Ameaça                                   | Mitigação                                 | Ref            |
|-----|----|------------------------------------------|-------------------------------------------|----------------|
| P1  | T  | Atualização adulterada (X7)              | `.oupd` com metadados TUF; assinatura     | §13.2, §14,    |
|     |    |                                          | híbrida; raiz Merkle no manifesto do slot | ADR 0015, 0018 |
| P2  | T  | Rollback / freeze de versão              | Contador anti-rollback; TUF               | §13.2          |
| P3  | D  | Atualização quebra o sistema             | A/B: nunca escreve no slot em uso;        | §9, §5.5       |
|     |    |                                          | snapshot antes; troca de slot             |                |
| P4  | S  | Chave de release roubada                 | Intermediária online de 1 ano, rotacionada| §13.4          |
|     |    |                                          | pela raiz offline em dois tokens          |                |
| P5  | T  | Dependência maliciosa no build           | Zero crates externas na imagem            | §16, ADR 0003  |
| P6  | T  | Máquina de build comprometida            | Build reproduzível (dois builds, hash     | §16.4          |
|     |    |                                          | idêntico); release em máquinas isoladas   |                |
| P7  | T  | Toolchain adulterado                     | Rust estável fixado (`rust-toolchain`)    | §16, ADR 0025  |
| P8  | R  | Contribuição sem autoria                 | DCO; revisão humana dupla                 | §17, ADR 0024  |

## 7. Criptografia (SDD 13.3)

| Uso             | Algoritmo                                              |
|-----------------|--------------------------------------------------------|
| Assinaturas     | Ed25519 + ML-DSA-65 (híbrido)                          |
| Troca de chaves | X25519 + ML-KEM-768 (híbrido)                          |
| Cifra simétrica | AES-256-GCM; ChaCha20-Poly1305                         |
| Hash            | SHA-256, SHA-384; BLAKE3 para endereçamento interno    |
| Derivação       | HKDF-SHA-256; Argon2id para senhas                     |
| Aleatoriedade   | CSPRNG do kernel (ChaCha20), sementes RDSEED, TPM, jitter |

Toda implementação passa nos vetores Wycheproof e NIST e em testes de tempo
constante (dudect) no CI. A exceção às "zero crates" para cripto está na
ADR 0004.

## 8. Riscos aceitos (SDD 13.5)

- Canais laterais de microarquitetura (mitigados parcialmente).
- Hardware ou firmware comprometido de fábrica.
- Adversários com recursos de Estado.
- Máquinas sem IOMMU ou sem TPM: suportadas em modo degradado e avisado.

## 9. Fora de escopo

- Tudo o que está em "Riscos aceitos" (seção 8).
- Ataques físicos com o sistema ligado e desbloqueado (cold boot, sondas no
  barramento) **(proposta, fora do SDD)**: o SDD não os trata explicitamente.
- Camada POSIX (`olibc`, M15) e contêineres do Server: serão modelados quando
  o marco chegar **(proposta, fora do SDD)**.
- Virtualização (`Vcpu`/`Vm`, M14), QUIC (M14), Bluetooth, NPUs e câmeras
  (pós-v1).
- Ajuste fino local de modelos (LoRA), adiado para depois da v1 (SDD 12.11).
- Qualidade das respostas da IA (alucinação) que não leve a ação: tratada
  pela suíte de qualidade (SDD 18), não por este documento.
- Segurança da infraestrutura do projeto fora da cadeia de release (site,
  fórum, contas de mantenedores) **(proposta, fora do SDD)**.

## 10. Lacunas e questões abertas para a revisão

Pontos onde o SDD está silencioso ou ambíguo. Nenhum vira requisito sem ADR.

1. `inputd` não está na TCB, mas captura Super+Esc e alimenta a origem USER
   ("entrada direta pelo trusted input", SDD 12.3). Proposta: incluir o
   `inputd` na TCB ou documentar por que não **(proposta, fora do SDD)**.
2. `ai-exec` está fora da TCB e detém as capabilities das ferramentas. Se for
   tomado, pode chamar ferramentas sem consultar o `policyd`. Proposta: as
   ferramentas R2/R3 exigirem um token de decisão do `policyd`/`displayd`
   verificável pelo serviço que executa a ação **(proposta, fora do SDD)**.
3. "Proteção de DMA" contra roubo (13.2) não é descrita na janela entre o
   firmware e a ativação da IOMMU pelo kernel/`devmgr`.
4. `optfs` (um processo por volume, fora da TCB) vê dados em claro; o SDD não
   diz como limitar o dano de um `optfs` comprometido.
5. Quem verifica `.omdl` e `.opk` (`pkgd`? `oie`?) e contra qual raiz de
   chaves não está explícito; `pkgd` não está na TCB.
6. `auditd` não está na TCB, mas várias mitigações dependem dele (R, I5,
   I13); o SDD não diz onde fica a chave de assinatura por época.
7. `authd` (senhas, FIDO2) fica fora da TCB; não está claro como
   `displayd` e `authd` se combinam no pedido de senha.
8. 13.2 cita "contador anti-rollback" sem dizer onde ele fica (TPM NV,
   variável UEFI) nem como se comporta em máquinas sem TPM.
9. O `CODEOWNERS` atual (`* @eduardodib11`) não nomeia um responsável de
   segurança separado; ver seção 11.

## 11. Processo de revisão

- Status atual: **rascunho para revisão**.
- Aprovação: responsável de segurança listado no `CODEOWNERS` para
  `docs/threat-model/`. Enquanto não houver papel separado, é o dono padrão
  (`@eduardodib11`) **(proposta, fora do SDD: adicionar entrada específica
  `docs/threat-model/` no `CODEOWNERS`)**.
- Critério de aceite da T-006: revisado e aprovado; a aprovação muda o status
  acima para "aprovado" com data e revisor.
- Revisar este documento quando:
  - o SDD mudar a seção 13, a lista da TCB ou as classes R0–R4;
  - uma ADR nova tocar em fronteira de confiança (seção 4);
  - um componente novo entrar na imagem ou um marco listado em "fora de
    escopo" começar;
  - um reporte via `SECURITY.md` ou um achado do red team da IA revelar
    ameaça não listada (toda falha vira teste de regressão, SDD 18).
- Antes da v1.0: revisão externa de segurança (SDD 13.6).
- Reporte de falhas: canal privado do `SECURITY.md`; correção de falhas
  críticas em até 30 dias, aviso público e CVE (SDD 13.6).
- Cada ameaça tem ID estável (B1, K1, ...). IDs não são reaproveitados;
  ameaças retiradas ficam riscadas com o motivo.
