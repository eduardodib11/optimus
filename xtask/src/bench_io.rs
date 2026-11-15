//! `cargo xtask bench-io`: benchmarks de E/S do `OptFS` (T-532, SDD §15).
//!
//! Roda no host, sobre um disco na memória que conta leituras, escritas e
//! `flush`: escrita e leitura sequenciais de 4 MiB e 256 acessos aleatórios
//! de 4 KiB. O gate de 5 % (SDD §15) vale para as contagens de operações no
//! dispositivo, que não dependem da máquina; a vazão em MiB/s e os tempos
//! entram no relatório só como informação, porque variam de runner para
//! runner. O relatório vai para `docs/bench/<data>-<commit>-optfs-io.md` e é
//! comparado com o anterior.

use std::fmt::Write as _;
use std::fs;
use std::time::Instant;

use super::bench::{GATE_PCT, compare, latest, meta, metrics_comment, parse_metrics};
use super::{HostSha, Result, root};
use optfs::{Allocator, BlockIo, Fs, IoError, Tx, mount};
use optfs_format::{BLOCK_SIZE, BlockPtr, Integrity, SUPERBLOCKS, Superblock};

const BLOCKS: u64 = 16384;
const FILE_BYTES: usize = 4 << 20;
const CHUNK: usize = 64 << 10;
const RAND_OPS: usize = 256;
const RAND_COMMIT_EVERY: usize = 32;
const KEY: [u8; 32] = [7; 32];
const SUFFIX: &str = "-optfs-io.md";

/// Disco na memória com contadores.
struct Mem {
    blocks: Vec<[u8; BLOCK_SIZE]>,
    reads: u64,
    writes: u64,
    flushes: u64,
}

impl Mem {
    fn new() -> Self {
        Self {
            blocks: vec![[0; BLOCK_SIZE]; usize::try_from(BLOCKS).unwrap_or(0)],
            reads: 0,
            writes: 0,
            flushes: 0,
        }
    }

    fn counts(&self) -> (u64, u64, u64) {
        (self.reads, self.writes, self.flushes)
    }
}

impl BlockIo for Mem {
    fn blocks(&self) -> u64 {
        BLOCKS
    }

    fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> std::result::Result<(), IoError> {
        let b = usize::try_from(block).map_err(|_| IoError::Io)?;
        *buf = *self.blocks.get(b).ok_or(IoError::Io)?;
        self.reads += 1;
        Ok(())
    }

    fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> std::result::Result<(), IoError> {
        let b = usize::try_from(block).map_err(|_| IoError::Io)?;
        *self.blocks.get_mut(b).ok_or(IoError::Io)? = *buf;
        self.writes += 1;
        Ok(())
    }

    fn flush(&mut self) -> std::result::Result<(), IoError> {
        self.flushes += 1;
        Ok(())
    }
}

/// Uma fase medida: operações no dispositivo e tempo.
struct Phase {
    name: &'static str,
    bytes: u64,
    ops: u64,
    reads: u64,
    writes: u64,
    flushes: u64,
    secs: f64,
}

fn e(what: &str, err: impl std::fmt::Debug) -> String {
    format!("{what}: {err:?}")
}

fn rng(s: &mut u64) -> u64 {
    *s ^= *s << 13;
    *s ^= *s >> 7;
    *s ^= *s << 17;
    *s
}

/// Formata o volume e grava o arquivo `f` vazio. Devolve o superbloco.
fn format(io: &mut Mem, h: &HostSha) -> Result<(Superblock, u64)> {
    let s1 = Superblock {
        uuid: [9; 16],
        txg: 1,
        integrity: Integrity::Hash,
        root: BlockPtr::null(),
        volume_blocks: BLOCKS,
        epochs: 0,
        free_blocks: BLOCKS,
    };
    io.write(SUPERBLOCKS[1], &s1.encode(h))
        .map_err(|x| e("sb", x))?;
    io.flush().map_err(|x| e("flush", x))?;
    let mut al = Allocator::new(BLOCKS);
    let mut tx = Tx::new(io, h, &mut al, 2, 1);
    let mut fs = Fs::create(&mut tx, KEY).map_err(|x| e("create", x))?;
    let f = fs
        .create_file(&mut tx, 1, "f")
        .map_err(|x| e("create_file", x))?;
    let mut new = s1;
    new.root = fs.root;
    new.free_blocks = tx.free_blocks();
    let sb = tx.commit(&s1, new).map_err(|x| e("commit", x))?;
    Ok((sb, f))
}

/// Abre o txg seguinte ao montado e roda `body`; se `commit`, confirma.
fn with_tx<T>(
    io: &mut Mem,
    h: &HostSha,
    commit: bool,
    body: impl FnOnce(&mut Fs, &mut Tx<'_, Mem, HostSha>) -> Result<T>,
) -> Result<T> {
    let m = mount(io, h).map_err(|x| e("mount", x))?;
    let mut al = Allocator::new(BLOCKS);
    let mut tx = Tx::new(io, h, &mut al, m.sb.txg + 1, 1);
    tx.mark_reachable(&[m.sb.root])
        .map_err(|x| e("alcançáveis", x))?;
    let mut fs = Fs::from_root(m.sb.root, KEY);
    let out = body(&mut fs, &mut tx)?;
    if commit {
        let mut new = m.sb;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        tx.commit(&m.sb, new).map_err(|x| e("commit", x))?;
    }
    Ok(out)
}

fn phase(
    name: &'static str,
    io: &mut Mem,
    bytes: u64,
    ops: u64,
    run: impl FnOnce(&mut Mem) -> Result,
) -> Result<Phase> {
    let (r0, w0, f0) = io.counts();
    let t = Instant::now();
    run(io)?;
    let secs = t.elapsed().as_secs_f64();
    let (r1, w1, f1) = io.counts();
    Ok(Phase {
        name,
        bytes,
        ops,
        reads: r1 - r0,
        writes: w1 - w0,
        flushes: f1 - f0,
        secs,
    })
}

#[allow(clippy::cast_possible_truncation)]
fn pattern(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(5).wrapping_add(seed))
        .collect()
}

fn run_phases() -> Result<Vec<Phase>> {
    let h = HostSha;
    let mut io = Mem::new();
    let (_, f) = format(&mut io, &h)?;
    let mut out = Vec::new();
    let chunk = pattern(1, CHUNK);
    out.push(phase(
        "seq_write",
        &mut io,
        FILE_BYTES as u64,
        (FILE_BYTES / CHUNK) as u64,
        |io| {
            with_tx(io, &h, true, |fs, tx| {
                for i in 0..FILE_BYTES / CHUNK {
                    fs.write(tx, f, (i * CHUNK) as u64, &chunk)
                        .map_err(|x| e("write", x))?;
                }
                Ok(())
            })
        },
    )?);
    out.push(phase(
        "seq_read",
        &mut io,
        FILE_BYTES as u64,
        (FILE_BYTES / CHUNK) as u64,
        |io| {
            with_tx(io, &h, false, |fs, tx| {
                for i in 0..FILE_BYTES / CHUNK {
                    let got = fs
                        .read(tx, f, (i * CHUNK) as u64, CHUNK)
                        .map_err(|x| e("read", x))?;
                    if got != chunk {
                        return Err("leitura sequencial diferente da escrita".into());
                    }
                }
                Ok(())
            })
        },
    )?);
    let slots = (FILE_BYTES / BLOCK_SIZE) as u64;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let page = pattern(2, BLOCK_SIZE);
    out.push(phase(
        "rand_write",
        &mut io,
        (RAND_OPS * BLOCK_SIZE) as u64,
        RAND_OPS as u64,
        |io| {
            for _ in 0..RAND_OPS / RAND_COMMIT_EVERY {
                with_tx(io, &h, true, |fs, tx| {
                    for _ in 0..RAND_COMMIT_EVERY {
                        let off = (rng(&mut seed) % slots) * BLOCK_SIZE as u64;
                        fs.write(tx, f, off, &page).map_err(|x| e("write", x))?;
                    }
                    Ok(())
                })?;
            }
            Ok(())
        },
    )?);
    out.push(phase(
        "rand_read",
        &mut io,
        (RAND_OPS * BLOCK_SIZE) as u64,
        RAND_OPS as u64,
        |io| {
            with_tx(io, &h, false, |fs, tx| {
                for _ in 0..RAND_OPS {
                    let off = (rng(&mut seed) % slots) * BLOCK_SIZE as u64;
                    fs.read(tx, f, off, BLOCK_SIZE).map_err(|x| e("read", x))?;
                }
                Ok(())
            })
        },
    )?);
    Ok(out)
}

/// Métricas do gate: operações no dispositivo por MiB (sequencial) ou por
/// operação (aleatório), em milésimos. Menor é melhor.
fn metrics(phases: &[Phase]) -> Vec<(String, u64)> {
    let mut m = Vec::new();
    for p in phases {
        let per = if p.name.starts_with("seq") {
            (p.bytes >> 20).max(1)
        } else {
            p.ops.max(1)
        };
        let unit = if p.name.starts_with("seq") {
            "mib"
        } else {
            "op"
        };
        if p.reads > 0 {
            m.push((
                format!("{}_leituras_por_{unit}", p.name),
                p.reads * 1000 / per,
            ));
        }
        if p.writes > 0 {
            m.push((
                format!("{}_escritas_por_{unit}", p.name),
                p.writes * 1000 / per,
            ));
            m.push((format!("{}_flushes", p.name), p.flushes * 1000));
        }
    }
    m
}

#[allow(clippy::cast_precision_loss)]
fn table(phases: &[Phase]) -> String {
    let mut md = String::from(
        "| Fase | Dados | Operações | Leituras | Escritas | Flushes | MiB/s (informativo) |\n\
         |---|---:|---:|---:|---:|---:|---:|\n",
    );
    for p in phases {
        let mibs = p.bytes as f64 / f64::from(1u32 << 20) / p.secs.max(1e-9);
        let _ = writeln!(
            md,
            "| `{}` | {} KiB | {} | {} | {} | {} | {mibs:.1} |",
            p.name,
            p.bytes >> 10,
            p.ops,
            p.reads,
            p.writes,
            p.flushes
        );
    }
    md
}

/// Roda os benchmarks, grava o relatório e aplica o gate de 5 %.
pub fn bench_io() -> Result {
    let phases = run_phases()?;
    let metrics = metrics(&phases);
    let meta = meta();
    let mut report = format!(
        "# Benchmarks de E/S do OptFS (T-532)\n\n\
         Data: {}. Commit: {}. CPU do host: {}.\n\n\
         Disco na memória de {} KiB com contadores; hash SHA-256 do `optcrypt`; sem cifra. \
         O gate de {GATE_PCT}% vale para as contagens de operações no dispositivo \
         (milésimos por MiB nas fases sequenciais e por operação nas aleatórias); \
         a vazão varia com a máquina e só informa.\n\n",
        meta.date,
        meta.commit,
        meta.host_cpu,
        BLOCKS * 4
    );
    report.push_str(&table(&phases));
    let dir = root().join("docs/bench");
    fs::create_dir_all(&dir).map_err(|x| format!("criando {}: {x}", dir.display()))?;
    let previous = latest(&dir, SUFFIX);
    let rows = previous
        .as_ref()
        .map(|(name, text)| (name.clone(), compare(&parse_metrics(text), &metrics)));
    if let Some((name, rows)) = &rows {
        let _ = write!(
            report,
            "\n## Comparação com `{name}`\n\n| Métrica | Antes | Agora | Variação |\n|---|---:|---:|---:|\n"
        );
        for (k, o, v, pct) in rows {
            let _ = writeln!(report, "| `{k}` | {o} | {v} | {pct:+}% |");
        }
    }
    report.push_str(&metrics_comment(&metrics));
    let file = dir.join(format!("{}-{}{SUFFIX}", meta.date, meta.commit));
    fs::write(&file, &report).map_err(|x| format!("gravando {}: {x}", file.display()))?;
    println!("{report}");
    println!("xtask: relatório em {}", file.display());
    if let Some((name, rows)) = rows {
        let worse: Vec<String> = rows
            .iter()
            .filter(|r| r.3 > i64::try_from(GATE_PCT).unwrap_or(5))
            .map(|r| format!("{} (+{}%)", r.0, r.3))
            .collect();
        if !worse.is_empty() {
            return Err(format!(
                "regressão de mais de {GATE_PCT}% em relação a {name}: {}",
                worse.join(", ")
            ));
        }
    }
    Ok(())
}
