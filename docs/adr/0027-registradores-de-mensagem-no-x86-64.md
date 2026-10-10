# ADR 0027: Registradores das syscalls de IPC no x86-64

- Status: proposta
- Data: 2026-10-10
- Origem: SDD v1.0, seções 6.7 e 14.1
- Relaciona-se com: ADR 0007 (IPC), T-201, T-208

## Contexto

A seção 6.7 promete rótulo de 64 bits mais até 6 palavras de mensagem em
registradores no caminho rápido. A 14.1 fixa, no x86-64, número em `rax`,
argumentos em `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9` e "palavras extras" em
`r12`–`r15`, mas não diz onde ficam o handle do endpoint, o rótulo, o prazo,
a contagem de palavras e de capabilities. Com os seis argumentos ocupados por
esses campos, só sobram as quatro extras, e a promessa de seis palavras não
fecha. No AArch64 a 14.1 dá seis registradores de mensagem e o problema não
existe.

## Decisão

Para `ipc_call`, `ipc_send`, `ipc_recv` e `ipc_reply_recv` no x86-64:

| Registrador | Entrada | Saída |
|---|---|---|
| `rax` | número da syscall | status |
| `rdi` | handle do endpoint ou reply | badge do remetente |
| `rsi` | rótulo | rótulo |
| `rdx` | info: palavras (3 bits), caps (3 bits), flags | info |
| `r10` | prazo em ns monotônicos (0 = sem prazo) | não usado |
| `r8`, `r9`, `r12`–`r15` | palavras 0 a 5 | palavras 0 a 5 |

Os handles das capabilities transferidas ficam no cabeçalho do buffer de IPC,
que passa a ter 4 KiB menos 64 bytes para palavras (504 palavras), já que
transferir capability nunca é o caminho rápido.

## Alternativas

- **Quatro palavras no x86 e seis no ARM:** cumpre a 14.1 ao pé da letra, mas
  o mesmo serviço OIDL teria caminho rápido diferente por arquitetura.
- **Usar `rbx` e `rbp` também:** daria mais palavras, mas são registradores
  preservados pela convenção e custam salvar e restaurar na entrada.

## Consequências

- Seis palavras nas duas arquiteturas, como diz a 6.7.
- `kabi` ganha o formato do campo info e `IPC_BUFFER_WORDS` passa a 504.
- A 14.1 do SDD é atualizada na próxima revisão do documento.
