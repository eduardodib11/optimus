# Benchmarks de E/S do OptFS com cache (T-610)

Data: 2026-11-16. Commit: de24447. CPU do host: Intel(R) Xeon(R) Processor @ 2.30GHz.

Disco na memória de 65536 KiB com contadores; hash SHA-256 do `optcrypt`; sem cifra. `CachedIo` de 2048 KiB na frente do disco (T-610); os contadores são os do disco de baixo, e o cache vive entre as fases, como num `optfs` de longa vida. O gate de 5% vale para as contagens de operações no dispositivo (milésimos por MiB nas fases sequenciais e por operação nas aleatórias); a vazão varia com a máquina e só informa.

| Fase | Dados | Operações | Leituras | Escritas | Flushes | MiB/s (informativo) |
|---|---:|---:|---:|---:|---:|---:|
| `seq_write` | 4096 KiB | 64 | 0 | 1079 | 2 | 2.7 |
| `seq_read` | 4096 KiB | 64 | 1078 | 0 | 0 | 6.4 |
| `rand_write` | 1024 KiB | 256 | 211 | 492 | 16 | 1.0 |
| `rand_read` | 1024 KiB | 256 | 180 | 0 | 0 | 3.5 |

## Queda com o cache

| Métrica | Sem cache | Com cache | Variação |
|---|---:|---:|---:|
| `seq_write_leituras_por_mib` | 1750 | 0 | -100% |
| `seq_read_leituras_por_mib` | 1086000 | 269500 | -75% |
| `rand_write_leituras_por_op` | 5429 | 824 | -84% |
| `rand_read_leituras_por_op` | 7218 | 703 | -90% |

<!-- metricas: seq_write_escritas_por_mib=269750 seq_write_flushes=2000 seq_read_leituras_por_mib=269500 rand_write_leituras_por_op=824 rand_write_escritas_por_op=1921 rand_write_flushes=16000 rand_read_leituras_por_op=703 -->
