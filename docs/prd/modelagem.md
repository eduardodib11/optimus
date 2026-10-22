# Modelagem do Optimus OS

- Status: **rascunho para revisão**
- Data: 2026-10-22
- Fontes: SDD v1.0 (seções 4, 6, 7, 12, 14, 16, 19) e backlog do M3
- Os diagramas usam Mermaid e renderizam direto no GitHub e no Obsidian.

## 1. Arquitetura em camadas

Só o kernel roda em modo privilegiado. Todo o resto é processo isolado que conversa por IPC com capabilities.

```mermaid
flowchart TB
    subgraph Usuario["Usuário"]
        V[Voz] ~~~ T[Texto] ~~~ H[HUD]
    end
    subgraph UI["Interface"]
        cockpit --> displayd
        inputd
        audiod
    end
    subgraph AI["AI Core"]
        ai-router --> ai-planner
        ai-planner --> ai-exec
        ai-reader
        ai-exec --> ai-memory
        oie
        voiced
        ctxd
        evolved
    end
    subgraph Base["Base de confiança"]
        root --> svcmgr
        keyd
        policyd
        updated
    end
    subgraph Servicos["Serviços de sistema"]
        memd
        timed
        logd
        auditd
        crashd
        powerd
        authd
        pkgd
        rescue
    end
    subgraph Dados["Dispositivos, dados e rede"]
        devmgr --> drivers
        storaged --> optfs
        netd --> tlsd
        wland
    end
    subgraph K["Kernel: okernel (privilegiado)"]
        OBJ[Objetos, capabilities, memória virtual, threads, escalonamento, IPC, IRQs, timers]
    end
    Usuario --> UI
    UI --> AI
    AI --> Servicos
    Servicos --> Dados
    Dados --> K
    Base --> K
```

## 2. Fluxo de um pedido

```mermaid
sequenceDiagram
    actor U as Usuário
    participant V as voiced
    participant R as ai-router
    participant P as ai-planner
    participant Rd as ai-reader
    participant E as ai-exec
    participant Pol as policyd
    participant T as Faixa de Confiança
    participant S as Serviço alvo

    U->>V: fala (palavra de ativação)
    V->>R: texto transcrito
    alt comando simples
        R->>E: ação direta
    else pedido complexo
        R->>P: pedido + contexto confiável + memória
        P->>E: plano em OPS
    end
    opt dado externo no plano
        E->>Rd: conteúdo EXTERNAL
        Rd-->>E: campos marcados (sem ação)
    end
    E->>Pol: valida passo (tipo, ferramenta, risco)
    alt risco R3 ou origem EXTERNAL em R2
        Pol->>T: pede confirmação física
        U->>T: clique, toque ou tecla
        T-->>Pol: confirmado
    end
    E->>S: chamada OIDL por IPC
    S-->>E: resultado
    E-->>U: HUD Spec (Cockpit) e fala (voiced)
    Note over E,S: tudo registrado no auditd
```

## 3. Modelo de domínio do kernel

Objetos do kernel e relações entre eles. Toda criação debita bytes de uma `MemoryQuota`.

```mermaid
classDiagram
    class MemoryQuota {
      bytes disponíveis
      direitos: CREATE, SPLIT
    }
    class CapSpace {
      radix 2 níveis, 4096 slots por nível
      MANAGE
    }
    class Capability {
      handle u32: índice 24 bits + geração 8 bits
      direitos 32 bits
      badge 64 bits
    }
    class AddressSpace {
      MAP, UNMAP
    }
    class MemoryObject {
      READ, WRITE, EXEC, MAP
    }
    class Thread {
      START, SUSPEND, READ_STATE, WRITE_STATE
    }
    class SchedContext {
      orçamento e período
      BIND, CONFIGURE
    }
    class Endpoint {
      SEND, RECV, GRANT
    }
    class Reply {
      uso único
    }
    class Notification {
      palavra de 64 bits
      SIGNAL, WAIT
    }
    class Interrupt {
      ACK, BIND
    }
    class DmaDomain {
      MAP
    }

    CapSpace "1" o-- "*" Capability : contém
    Capability --> "1" Thread : aponta para objeto
    Capability --> "1" Endpoint : aponta para objeto
    Capability --> "1" MemoryObject : aponta para objeto
    Thread "*" --> "1" AddressSpace : executa em
    Thread "*" --> "1" SchedContext : usa orçamento
    Endpoint "1" --> "*" Reply : gera
    Notification "1" <-- "*" Interrupt : sinal
    Notification "1" <-- "*" Endpoint : sinal
    MemoryQuota "1" --> "*" MemoryObject : cobra bytes
    Interrupt "1" --> "1" DmaDomain : via driver
```

## 4. Derivação e revogação de capabilities

Regras que as provas Kani (T-204) precisam cobrir.

```mermaid
stateDiagram-v2
    [*] --> Criada: obj_create (debita MemoryQuota)
    Criada --> Derivada: cap_mint (direitos ⊆ pai, badge opcional)
    Derivada --> Derivada: cap_mint (direitos ⊆ pai)
    Criada --> Revogada: cap_revoke (raiz)
    Derivada --> Revogada: cap_revoke (descendentes em fatias preemptíveis)
    Criada --> Apagada: cap_delete
    Derivada --> Apagada: cap_delete
    Apagada --> Destruído: última cap do objeto
    Revogada --> Destruído: última cap do objeto
    Destruído --> [*]: bytes voltam à cota
```

Invariantes:
- Direitos nunca aumentam ao derivar.
- Handle com geração antiga devolve `InvalidHandle`.
- Revogação não deixa descendente vivo.

## 5. Ciclo de vida de um serviço (svcmgr)

Política de reinício: `always`, `on-failure` ou `never`, com recuo exponencial de 100 ms a 30 s e limite de 5 falhas por minuto antes de alertar.

```mermaid
stateDiagram-v2
    [*] --> Parado
    Parado --> Iniciando: dependências satisfeitas (grafo acíclico)
    Iniciando --> Rodando: processo pronto
    Iniciando --> Falhou: erro de partida
    Rodando --> Falhou: processo morreu
    Falhou --> Revogando: política permite reinício
    Falhou --> Parado: política never
    Revogando --> Iniciando: capabilities revogadas e reemitidas; clientes recebem PeerClosed
    Falhou --> Alertando: 5 falhas em 1 minuto
    Alertando --> Iniciando: recuo exponencial
    Rodando --> Parado: parada solicitada
```

## 6. Modelo de capabilities de serviço (manifesto)

O manifesto declara o que o serviço **precisa** (`needs`) e o que **oferece** (`provides`). O `svcmgr` só entrega capabilities listadas no manifesto assinado.

```mermaid
flowchart LR
    M["Manifesto TOML<br/>(compilado e assinado)"] --> SM[svcmgr]
    SM -->|valida needs| Cota[Cotas: memória, threads, ipc_rate]
    SM -->|emite| CapN["capabilities 'needs'<br/>ex.: dev:net/*, log:write, time:read"]
    SM -->|registra| CapP["capabilities 'provides'<br/>ex.: optimus.net.Socket@1"]
    CapP --> Cli[Clientes conectam por descoberta de interface e versão]
```

## 7. Escalonamento e prioridades

256 níveis, prioridade fixa e preemptiva. Round-robin dentro do nível, com fatia padrão de 5 ms.

| Faixa | Uso |
|---|---|
| 240–255 | Áudio, entrada, compositor (tempo real) |
| 200–239 | Drivers |
| 128–199 | Serviços de sistema e `ai-exec` |
| 64–127 | Apps e IA em primeiro plano |
| 1–63 | Fundo: indexação, raciocínio longo, `evolved` |
| 0 | Ocioso (`mwait` / `WFI`) |

Doação de `SchedContext` em `ipc_call`: o servidor roda com o tempo do cliente, o que evita inversão de prioridade.

## 8. Ordem de locks (SMP)

Ordem fixa para evitar deadlock. A regra entre duas filas de CPU ainda está em aberto (ADR 0031).

```mermaid
flowchart LR
    CDT[Árvore de derivação CDT] --> CS[CapSpace] --> OBJ[Objeto] --> AS[AddressSpace] --> RQ[Fila do escalonador]
```

## 9. Armazenamento

Layout do disco (GPT), imagem verificada e pilha de E/S.

```mermaid
flowchart TB
    subgraph Disco["Disco (GPT)"]
        ESP["ESP FAT32 256 MiB<br/>optboot, kernels, bootfs"]
        SA["sys-a: imagem somente leitura<br/>Merkle SHA-256 em blocos de 4 KiB"]
        SB["sys-b: imagem somente leitura"]
        DATA["data: volume OptFS criptografado"]
    end
    Drv["driver NVMe / AHCI / virtio-blk"] --> Stor[storaged: GPT, filas, E/S com prioridade do cliente]
    Stor --> OptFS["optfs: um processo por volume<br/>COW, B+ de extents, AES-256-GCM ou ChaCha20"]
    OptFS --> Cli["clientes com capability de diretório"]
```

## 10. Boot e cadeia de confiança

```mermaid
flowchart LR
    FW["Firmware UEFI<br/>Secure Boot"] --> OB["optboot<br/>verifica assinatura híbrida"]
    OB -->|mede PCR 8 e 9| TPM[(TPM 2.0)]
    OB -->|BootInfo v1| K["okernel"]
    K --> R[root]
    R --> SM[svcmgr]
    SM --> SV[Serviços e drivers]
    OB -. "3 falhas no slot ativo" .-> OTHER["troca de slot A/B"]
    OB -. "ambos falham" .-> RESC[rescue]
```

## 11. Pilha de rede

A rede é negada por padrão. Nenhum processo abre conexão sem capability `NetAccess`.

```mermaid
flowchart TB
    NIC["driver NIC<br/>anéis sem cópia"] --> NETD["netd<br/>Ethernet, ARP, IPv4/IPv6, TCP, UDP, DNS"]
    WLAN["wland<br/>WPA3-SAE"] --> NETD
    NETD --> FW{"firewall<br/>entrada bloqueada por padrão"}
    FW --> TLS["tlsd<br/>TLS 1.3 apenas<br/>X25519 + ML-KEM-768"]
    TLS --> APP["clientes com NetAccess"]
    AI["ai-exec"] -.->|pede ferramenta de rede com política| NETD
```

## 12. Política de risco da IA

```mermaid
flowchart TD
    Acao[Ação proposta pela IA] --> Tipo{Classe de risco}
    Tipo -->|R0| A0[Livre, auditado]
    Tipo -->|R1| A1[Livre, reversível]
    Tipo -->|R2| Orig{Origem}
    Orig -->|USER| A2[Livre]
    Orig -->|EXTERNAL| C2[Confirmação na tela]
    Tipo -->|R3| C3[Confirmação física na Faixa de Confiança]
    Tipo -->|R4| X4[Proibido]
```

## 13. Modelo de dados da memória da IA

| Tipo | Conteúdo | Armazenamento | Regra |
|---|---|---|---|
| Episódica | Conversas e ações, com data e origem | Log criptografado em `/data/ai/episodes` | Editável e apagável pelo usuário |
| Semântica | Fatos e documentos indexados | Índice HNSW próprio + embeddings locais | Origem EXTERNAL nunca vira instrução |
| Perfil | Preferências confirmadas pelo usuário | Registro estruturado | Só entra com confirmação |
| Procedimental | Planos OPS aprovados e bem-sucedidos | Biblioteca de skills versionada | Só entra com aprovação e teste |

## 14. Rastreabilidade entre marcos e modelos

| Modelo | Marco | Tarefas do backlog |
|---|---|---|
| Objetos e capabilities (seções 3 e 4) | M2 | T-201 a T-204 |
| Escalonamento e IPC (seção 7) | M2 e M3 | T-207, T-208, T-305, T-320 a T-328 |
| Ordem de locks (seção 8) | M3 | T-314, T-315 |
| Ciclo do serviço (seção 5) | M3 | T-348 a T-354 (eventos, Timer, `svcmgr`) |
| Contratos de interface (OIDL) | M3 | T-340 a T-347 (`oidl-rt` e `oidlc`) |
| Boot e cadeia (seção 10) | M1 e M3 | T-101 a T-103, T-211 |
| Armazenamento (seção 9) | M5 | (backlog a detalhar) |
| Rede (seção 11) | M6 | (backlog a detalhar) |
| Política de risco da IA (seção 12) | M8 e seguintes | (backlog a detalhar) |

Os números T-3xx são do `docs/backlog/m3.md`. Os marcos M4 em diante ainda não têm backlog detalhado.
