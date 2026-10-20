# ADR 0037: Escopo do `timed` no M3 (relógio de parede sem NTS)

- Status: aceita (aprovada por Eduardo em 2026-10-20)
- Data: 2026-10-11
- Origem: SDD v1.0, seções 5.2, 6.8 e 7.3; backlog do M3, T-310
- Relaciona-se com: ADR 0033 (OIDL), ADR 0034 (manifesto), ADR 0035 (Timer),
  T-358, T-359

## Contexto

O SDD dá ao `timed` três tarefas: relógio de parede, fusos horários e
sincronização por NTS (7.3). NTS exige rede e TLS (`netd`, `tlsd`,
marcos posteriores). O kernel só mantém o relógio **monotônico** (6.8,
`clock_get`). Falta decidir de onde vem a hora de parede inicial, como ela
é ajustada, e o que fica para depois.

O backlog (item 16) supõe que o `boot_time_ns` da `BootInfo` traz a hora
de parede lida do RTC pelo `optboot`. **Não traz.** No código, `boot_time_ns`
é `rdtsc` convertido em ns no momento da entrega ao kernel, ou seja,
ns desde o reset da CPU (`boot/optboot/src/main.rs`, `kabi::boot::
BootInfo::boot_time_ns`), a mesma base do `clock_get`. O `optboot` hoje não
chama `GetTime` do UEFI, e o driver de RTC por portas depende de
`IoPortRange`, que só existe como tipo.

## Decisão

### 1. Fonte da hora inicial: UEFI `GetTime` no `optboot`

- O `optboot` chama `RuntimeServices.GetTime` **antes** de
  `ExitBootServices` e lê o TSC no mesmo ponto. A `BootInfo` v1 ganha dois
  campos no fim, como a ADR 0026 fez com `direct_map_base` (nenhuma versão
  foi publicada, então não há v2; `BOOT_VERSION` continua 1):
  `wall_unix_ns: i64` (hora do RTC em ns Unix; 0 se `GetTime` falhar) e
  `wall_tsc_ns: u64` (o instante do TSC, em ns desde o reset, em que a
  leitura foi feita). `optboot` e
  `okernel` saem do mesmo build, e a tabela 5.2 do SDD ganha as duas
  linhas na próxima revisão.
- `EFI_TIME` é convertido em UTC assim: se `TimeZone` é
  `EFI_UNSPECIFIED_TIMEZONE` (0x07FF), assume-se que o RTC guarda UTC;
  senão ajusta-se o horário por `TimeZone` minutos. Resolução do RTC: 1 s.
  **O sinal desse ajuste está por conferir.** A proposta subtraía
  `TimeZone`, mas a revisão lembra que a especificação UEFI define hora
  local = UTC − `TimeZone`, o que faria o UTC sair somando. Isso não foi
  conferido na especificação. A T-358 confere o sinal na versão do UEFI
  que o `optboot` usa e ganha um teste que cobre os dois sinais de
  `TimeZone` (no OVMF do QEMU o valor costuma ser 0x07FF, e o caso não
  aparece nos testes de boot).
- O kernel expõe os dois valores por **`sys_info(classe 4, …)`** (a
  classe 1 é a de CPUs, ADR 0032; a 2 é a morte, ADR 0035; a 3 é a memória,
  ADR 0038; a 5 é a aleatoriedade, ADR 0039), sem capability,
  porque a informação não é segredo: retorna `[wall_unix_ns, wall_tsc_ns,
  flags]` (flag bit 0 = válido). Quem calcula hora de parede é só o
  `timed`.
- Fórmula: `wall(t) = wall_unix_ns + (clock_get() − wall_tsc_ns)`, sem
  correção, antes de qualquer ajuste.

### 2. Estado do `timed`

```
base_wall   : i128 ns Unix   no instante base_mono
base_mono   : u64            ns monotônicos
rate_ppm    : i32            ajuste de taxa, -500..=+500 (ns/s = ppm × 1000)
synced      : bool           já houve `set` autorizado
last_sync   : u64            monotônico do último `set`
```
`now()` = `base_wall + (mono − base_mono) × (1 + rate_ppm × 10⁻⁶)`. Hora
é **POSIX** (sem segundos intercalados; dia = 86400 s). Incerteza
devolvida: `1 s` no começo (resolução do RTC) mais `500 ppm × (agora −
last_sync)`; `u64::MAX` se `GetTime` falhou.

### 3. Interfaces OIDL (ADR 0033)

```
package optimus.time @1.0;
struct WallTime { unix_ns: i64, mono_ns: u64, uncertainty_ns: u64, synced: bool }
enum TimeError : u8 { AccessDenied, InvalidArgument, Unavailable }
enum SetMode : u8 { Slew, Step }

interface Clock {                    // manifesto: svc:optimus.time.Clock@1
    now() -> result<WallTime, TimeError>;
}
interface Admin {                    // manifesto: svc:optimus.time.Admin@1
    set(unix_ns: i64, mode: SetMode) -> result<(), TimeError>;
}
```

`Admin` é uma interface e um `Endpoint` à parte: quem só lê não recebe a
capability de escrita (4.3). No M3 só `rescue` e testes a pedem. O
chamador do `now()` identifica-se pelo badge, mas a resposta não depende
dele.

### 4. Ajuste (`set`) sem retrocesso

- `Slew`: o `timed` calcula `delta = alvo − now()` e programa `rate_ppm`
  para consumi-lo; taxa máxima ±500 ppm (0,5 ms por segundo); 1 s de
  correção leva 2000 s. Enquanto ajusta, `now()` nunca regride (taxa
  ≥ 0,9995). O `timed` reavalia a taxa quando o `Timer` (ADR 0035) de
  fim de ajuste dispara.
- `Step`: se `delta > 0`, salta para frente na hora (continua
  monotônico); se `delta < 0`, **só** é aceito com `|delta| > 1 s` e é
  registrado como `warn` no `logd` (um retrocesso visível). Para
  `|delta| ≤ 1 s`, `Step` vira `Slew`.
- O primeiro `set` depois do boot (`synced == false`) vale como `Step`
  se vier do `Admin`; marca `synced = true`.
- Valores fora de 1970-01-01 a 2200-01-01: `InvalidArgument`.

### 5. Fusos horários: fora do núcleo do M3

O `timed` do M3 responde só em UTC. Os fusos (T-359, "pode ser adiado")
ficam para o M4 (decidido em 2026-10-20) porque precisam de dados
(tzdata) e de um lugar de onde lê-los (bootfs ou imagem). O formato
previsto para o M4 é
`OTZ1`, gerado pela ferramenta de host `tools/mktz` a partir de uma
versão fixa do tzdata (versionada no repositório, hash BLAKE3 registrado):

```
Cabeçalho: magic "OTZ1", version u32=1, n_trans u32, n_types u32,
           n_chars u32, nome ≤ 63 bytes
Tipos:     n_types × { utc_offset i32 (s), dst u8, abbr_off u8 }
Transições: n_trans × { at_unix_s i64, type u8 } ordenadas
Cauda:     regra POSIX TZ ("<-03>3") para datas além da última transição
```
Interface prevista: `Zone.local(zone: string<63>, unix_s: i64) ->
result<LocalTime, TimeError>` com `LocalTime { offset_s, dst, abbr }`.
Aceite: UTC, `America/Sao_Paulo` e um fuso com horário de verão nas
datas de transição.

### 6. O que fica fora

NTS e qualquer cliente de rede; gravar o RTC; persistir o ajuste (precisa
de OptFS); segundos intercalados; leitura sem IPC (página de tempo
mapeada com seqlock, estilo vDSO); fusos (item 5); calendário e
formatação (vivem no `ostd`, sem dados); escolha entre RTC em UTC ou hora
local (item 1 assume UTC).

## Alternativas

- **Driver de RTC por portas CMOS no `timed`:** exige `IoPortRange`
  implementado (hoje só tipo), é x86-only e o `timed` ganharia um
  privilégio de hardware. `GetTime` do UEFI custa 10 linhas no `optboot`.
- **Ler o RTC no kernel:** põe um driver no kernel, contra o
  microkernel (ADR 0001).
- **Relógio de parede no kernel (`clock_get` com `REALTIME`):** o kernel
  teria de aceitar ajustes e política de salto; o monotônico simples
  continua barato no caminho rápido.
- **Começar em 1970 e esperar NTS:** deixa o sistema sem hora até a rede,
  e os logs sem sentido.
- **`set` sempre em passo:** o relógio andaria para trás e quebraria
  `Instant` e prazos baseados em hora de parede.

## Consequências

- `BootInfo` v1 com 2 campos a mais, `kabi::boot` e o `optboot` mudam; o
  teste de versão continua afirmando 1, e os de layout, de `optboot` e de
  `okernel` são atualizados.
- `sys_info` ganha a classe 4 (hora de parede do boot), sem capability.
- O `timed` do M3 é pequeno (estado de seis números e duas
  interfaces); o `Admin` abre caminho ao NTS sem mudar o protocolo.
- Hora errada por horas, se o RTC guarda hora local (máquina com
  Windows): o `set` do usuário a corrige; NTS corrige depois.
- Cada `now()` custa um IPC (alguns µs); suficiente para o M3.

## Lacunas do SDD e decisões para Eduardo

1. **Corrigida a premissa do backlog:** o `boot_time_ns` não é hora de
   parede; é preciso o campo novo na `BootInfo`.
2. **Decidido (2026-10-20):** os campos novos entram na `BootInfo` v1, sem
   v2, seguindo a ADR 0026 (nenhuma versão foi publicada), e `sys_info`
   classe 4 é pública. O `optboot` e o kernel saem do mesmo build.
3. **Decidido (2026-10-20):** RTC tratado como UTC quando o fuso é
   desconhecido. Uma máquina com Windows fica algumas horas errada até o
   primeiro `set`.
4. **Decidido (2026-10-20):** `Clock` (leitura) e `Admin` (escrita) como
   interfaces separadas: quem só lê não recebe o direito de ajustar.
5. **Decidido (2026-10-20):** fusos horários (T-359, formato `OTZ1`) no
   M4, não no M3. Precisam do tzdata e de um lugar de onde lê-lo.
6. **Decidido (2026-10-20):** limite de 500 ppm e 1 s para passo para
   trás.
7. **Por conferir na T-358:** o sinal do `TimeZone` do UEFI (item 1).

## Revisão de 2026-10-20

Mudanças em relação à proposta:

- Status passa a aceita.
- A hora de parede do boot passa a ser a classe 4 de `sys_info` (antes
  classe 3), conforme a renumeração da ADR 0035.
- Sai a frase "sys_info ganha sua primeira classe pública": a classe 1
  (CPUs) já é pública.
- A T-358 passa a conferir o sinal do `TimeZone` do UEFI e ganha um teste
  que cobre os dois sinais.
- Fusos horários ficam decididos para o M4 (antes eram uma pergunta).
- As demais decisões da seção final foram registradas como decididas.

### Revisão geral

- A `BootInfo` não vai à versão 2: os dois campos entram na v1, como na
  ADR 0026, e o teste de versão continua em 1.
- A origem não cita mais a seção 10.4 do SDD (que trata só do `updated`).
- O comentário da interface `Clock` perde a menção a `time:read`.
