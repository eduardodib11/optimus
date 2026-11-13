//! `mkmanifest`: compila manifestos TOML (SDD v1.0, §14.4) para o formato
//! binário `OMAN` v1 (ADR 0034, item 4) e verifica o grafo de serviços.
//!
//! O grafo é acíclico nas arestas obrigatórias: uma dependência marcada com
//! `?` é fraca e não ordena a partida. Um ciclo ou uma dependência obrigatória
//! sem provedor falha o build.
//!
//! Só ferramenta de host: nada disto entra na imagem do sistema.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// Magia do formato binário.
pub const MAGIC: [u8; 4] = *b"OMAN";
/// Versão do formato.
pub const VERSION: u32 = 1;
/// Tamanho do cabeçalho.
const HEADER_LEN: usize = 96;
/// Tamanho de um registro de necessidade.
const NEED_LEN: usize = 24;
/// Tamanho de um registro de provisão.
const PROVIDE_LEN: usize = 16;
/// Limite do corpo (tudo menos a assinatura).
const MAX_BODY: usize = 4096;
/// Máximo de necessidades e de provisões somadas.
const MAX_NEEDS: usize = 64;
const MAX_PROVIDES: usize = 32;
const MAX_TOTAL_ENTRIES: usize = 94;

/// Erro de compilação ou de verificação, com o nome do arquivo quando há.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn err<T>(msg: impl Into<String>) -> Result<T, Error> {
    Err(Error(msg.into()))
}

/// Política de reinício (§7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restart {
    /// Sempre reinicia.
    Always = 0,
    /// Reinicia só quando falha.
    OnFailure = 1,
    /// Nunca reinicia.
    Never = 2,
}

/// Tipo de necessidade (ADR 0034, item 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedKind {
    /// Interface de serviço (`svc:`).
    Svc = 1,
    /// Cota de memória (`mem:quota:`).
    Mem = 2,
    /// Dispositivo (`dev:`); as regras de `[match]` de um driver (T-401).
    Dev = 3,
    /// Diretório (`fs:`), fora do M3.
    Fs = 4,
    /// Capability de origem do kernel (`kernel:`).
    Kernel = 5,
}

/// Uma necessidade do serviço.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Need {
    /// Tipo da capability pedida.
    pub kind: NeedKind,
    /// `true` para aresta fraca (`?`), que não ordena a partida.
    pub optional: bool,
    /// Versão maior (interface) ou 0.
    pub major: u16,
    /// Versão menor mínima (interface) ou 0.
    pub minor: u16,
    /// Nome: interface, classe, diretório ou capability do kernel.
    pub name: String,
    /// Valor numérico: bytes da cota (`mem`), máscara de direitos
    /// (`kernel`) ou 0.
    pub value: u64,
}

/// Uma interface que o serviço oferece.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    /// Nome completo, ex.: `optimus.log.Log`.
    pub name: String,
    /// Versão maior.
    pub major: u16,
    /// Versão menor.
    pub minor: u16,
}

/// Manifesto já validado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// Nome do serviço, `[a-z0-9-]{1,31}`.
    pub name: String,
    /// Caminho no bootfs, ex.: `svc/netd`.
    pub binary: String,
    /// Prioridade, 1..=199 no M3.
    pub priority: u8,
    /// Política de reinício.
    pub restart: Restart,
    /// Número máximo de threads, 1..=1024.
    pub max_threads: u16,
    /// Mensagens por segundo, 0 = sem limite.
    pub ipc_rate: u32,
    /// Necessidades, na ordem do arquivo.
    pub needs: Vec<Need>,
    /// Provisões, na ordem do arquivo.
    pub provides: Vec<Provide>,
}

const SERVICE_KEYS: &[&str] = &["name", "binary", "priority", "restart"];
const CAP_KEYS: &[&str] = &["needs", "provides"];
const LIMIT_KEYS: &[&str] = &["max_threads", "ipc_rate"];
const MATCH_KEYS: &[&str] = &["pci", "class", "compatible"];

/// Lê um manifesto TOML e valida tudo o que dá para validar sem o grafo.
///
/// # Errors
/// Chave desconhecida, valor fora do limite ou nome de capability antigo.
pub fn parse(src: &str) -> Result<Manifest, Error> {
    let table: toml::Table = src.parse().map_err(|e| Error(format!("TOML: {e}")))?;
    check_keys(&table, &["service", "capabilities", "limits", "match"])?;

    let svc = section(&table, "service")?;
    check_keys(svc, SERVICE_KEYS)?;
    let name = text(svc, "name")?;
    if name.is_empty()
        || name.len() > 31
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return err(format!("nome de serviço inválido: {name:?}"));
    }
    let binary = text(svc, "binary")?;
    if binary.is_empty() || binary.len() > 63 || binary.starts_with('/') || binary.contains("..") {
        return err(format!("caminho de binário inválido: {binary:?}"));
    }
    let priority = int(svc, "priority")?;
    if !(1..=199).contains(&priority) {
        return err(format!("{name}: prioridade {priority} fora de 1..=199"));
    }
    let restart = match text(svc, "restart")?.as_str() {
        "always" => Restart::Always,
        "on-failure" => Restart::OnFailure,
        "never" => Restart::Never,
        other => return err(format!("{name}: restart desconhecido {other:?}")),
    };

    let limits = section(&table, "limits")?;
    check_keys(limits, LIMIT_KEYS)?;
    let max_threads = int(limits, "max_threads")?;
    if !(1..=1024).contains(&max_threads) {
        return err(format!(
            "{name}: max_threads {max_threads} fora de 1..=1024"
        ));
    }
    let ipc_rate = match limits.get("ipc_rate") {
        None => 0,
        Some(_) => u32::try_from(int(limits, "ipc_rate")?)
            .map_err(|_| Error(format!("{name}: ipc_rate grande demais")))?,
    };

    let caps = section(&table, "capabilities")?;
    check_keys(caps, CAP_KEYS)?;
    let mut needs = Vec::new();
    for item in strings(caps, "needs")? {
        needs.push(parse_need(&name, &item)?);
    }
    if let Some(rules) = table.get("match") {
        let rules = rules
            .as_table()
            .ok_or_else(|| Error(format!("{name}: `match` não é uma seção")))?;
        needs.extend(match_needs(&name, rules)?);
    }
    let mut provides = Vec::new();
    for item in strings(caps, "provides")? {
        provides.push(parse_provide(&name, &item)?);
    }

    let quotas = needs.iter().filter(|n| n.kind == NeedKind::Mem).count();
    if quotas != 1 {
        return err(format!(
            "{name}: exatamente uma cota `mem:quota:` é obrigatória, há {quotas}"
        ));
    }
    if needs.len() > MAX_NEEDS
        || provides.len() > MAX_PROVIDES
        || needs.len() + provides.len() > MAX_TOTAL_ENTRIES
    {
        return err(format!("{name}: entradas demais em `capabilities`"));
    }

    Ok(Manifest {
        name,
        binary,
        priority: u8::try_from(priority).map_err(|_| Error("prioridade".into()))?,
        restart,
        max_threads: u16::try_from(max_threads).map_err(|_| Error("max_threads".into()))?,
        ipc_rate,
        needs,
        provides,
    })
}

/// Seção `[match]` de um driver (ADR 0042, item 3; T-401): cada regra
/// vira uma necessidade `dev:` com o nome `pci:vvvv:dddd`,
/// `class:cc:ss[:pp]` ou `compatible:NOME`, que o `devmgr` lê com
/// `odev::Rule::parse`. O formato `OMAN` v1 não muda.
fn match_needs(service: &str, t: &toml::Table) -> Result<Vec<Need>, Error> {
    check_keys(t, MATCH_KEYS)?;
    let mut out = Vec::new();
    for key in MATCH_KEYS {
        if t.get(*key).is_none() {
            continue;
        }
        for item in strings(t, key)? {
            let name = format!("{key}:{item}");
            if odev::Rule::parse(&name).is_none() {
                return err(format!("{service}: regra de `match` inválida: {name:?}"));
            }
            out.push(Need {
                kind: NeedKind::Dev,
                optional: false,
                major: 0,
                minor: 0,
                name,
                value: 0,
            });
        }
    }
    if out.is_empty() {
        return err(format!("{service}: `match` sem regras"));
    }
    Ok(out)
}

fn check_keys(t: &toml::Table, allowed: &[&str]) -> Result<(), Error> {
    for key in t.keys() {
        if !allowed.contains(&key.as_str()) {
            return err(format!("chave desconhecida: {key:?}"));
        }
    }
    Ok(())
}

fn section<'a>(t: &'a toml::Table, key: &str) -> Result<&'a toml::Table, Error> {
    t.get(key)
        .and_then(toml::Value::as_table)
        .ok_or_else(|| Error(format!("falta a tabela [{key}]")))
}

fn text(t: &toml::Table, key: &str) -> Result<String, Error> {
    match t.get(key).and_then(toml::Value::as_str) {
        Some(s) => Ok(s.to_owned()),
        None => err(format!("falta `{key}` (texto)")),
    }
}

fn int(t: &toml::Table, key: &str) -> Result<i64, Error> {
    match t.get(key).and_then(toml::Value::as_integer) {
        Some(v) => Ok(v),
        None => err(format!("falta `{key}` (inteiro)")),
    }
}

fn strings(t: &toml::Table, key: &str) -> Result<Vec<String>, Error> {
    match t.get(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| Error(format!("`{key}` aceita só textos")))
            })
            .collect(),
        Some(_) => err(format!("`{key}` deve ser uma lista")),
    }
}

/// Lê `nome@M` ou `nome@M.m`, com `?` no fim para aresta fraca.
fn version(spec: &str) -> Result<(String, u16, u16), Error> {
    let (name, ver) = spec
        .split_once('@')
        .ok_or_else(|| Error(format!("falta a versão em {spec:?}")))?;
    let (major, minor) = match ver.split_once('.') {
        Some((a, b)) => (a, b),
        None => (ver, "0"),
    };
    let major: u16 = major
        .parse()
        .map_err(|_| Error(format!("versão inválida em {spec:?}")))?;
    let minor: u16 = minor
        .parse()
        .map_err(|_| Error(format!("versão inválida em {spec:?}")))?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
    {
        return err(format!("nome de interface inválido em {spec:?}"));
    }
    Ok((name.to_owned(), major, minor))
}

/// Converte `123`, `8KiB`, `32MiB` ou `1GiB` em bytes.
fn size_bytes(s: &str) -> Result<u64, Error> {
    let (digits, mult) = [("GiB", 1u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)]
        .iter()
        .find_map(|(suf, m)| s.strip_suffix(suf).map(|d| (d, *m)))
        .unwrap_or((s, 1));
    let n: u64 = digits
        .parse()
        .map_err(|_| Error(format!("tamanho inválido: {s:?}")))?;
    n.checked_mul(mult)
        .ok_or_else(|| Error(format!("tamanho grande demais: {s:?}")))
}

fn parse_need(service: &str, item: &str) -> Result<Need, Error> {
    let (body, optional) = match item.strip_suffix('?') {
        Some(b) => (b, true),
        None => (item, false),
    };
    let (prefix, rest) = body
        .split_once(':')
        .ok_or_else(|| Error(format!("{service}: capability sem prefixo: {item:?}")))?;
    let plain = |kind| Need {
        kind,
        optional,
        major: 0,
        minor: 0,
        name: rest.to_owned(),
        value: 0,
    };
    match prefix {
        "svc" => {
            let (name, major, minor) = version(rest)?;
            Ok(Need {
                kind: NeedKind::Svc,
                optional,
                major,
                minor,
                name,
                value: 0,
            })
        }
        "mem" => {
            let amount = rest
                .strip_prefix("quota:")
                .ok_or_else(|| Error(format!("{service}: só `mem:quota:` existe: {item:?}")))?;
            Ok(Need {
                kind: NeedKind::Mem,
                optional,
                major: 0,
                minor: 0,
                name: String::new(),
                value: size_bytes(amount)?,
            })
        }
        "dev" | "fs" => {
            if rest.is_empty() {
                return err(format!("{service}: alvo vazio em {item:?}"));
            }
            let kind = if prefix == "dev" {
                NeedKind::Dev
            } else {
                NeedKind::Fs
            };
            Ok(plain(kind))
        }
        "kernel" => match kernel_rights(rest) {
            Some(rights) => Ok(Need {
                value: u64::from(rights.bits()),
                ..plain(NeedKind::Kernel)
            }),
            _ => err(format!(
                "{service}: capability de kernel desconhecida: {item:?}"
            )),
        },
        _ => err(format!(
            "{service}: prefixo desconhecido em {item:?} (nomes antigos como log:write não existem mais)"
        )),
    }
}

/// Direitos de cada capability de origem do kernel (ADR 0034, item 4: em
/// `kernel:`, `value` é a máscara). O `svcmgr` recusa máscara 0, para que
/// nenhum serviço receba mais do que isto (menor privilégio).
///
/// - `debug`: `DebugLog` com `WRITE` (`debug_write`) e `BIND` (ADR 0036).
/// - `mem-pressure`: `Interrupt` de pressão com `BIND` e `ACK` (ADR 0038).
/// - `log`: o anel do log do kernel, `MemoryObject` com `READ` e `MAP`
///   (ADR 0036, item 6).
/// - `ecam`: a janela ECAM, `MemoryObject` de MMIO com `READ`, `WRITE` e
///   `MAP` (ADR 0043, item 1; T-402).
/// - `device`: a cota de dispositivo, `MemoryQuota` só com `CREATE` (T-402).
/// - `acpi`: a cópia da DSDT, `MemoryObject` com `READ` e `MAP` (ADR 0045,
///   item 1; T-405).
#[must_use]
pub fn kernel_rights(name: &str) -> Option<kabi::Rights> {
    use kabi::Rights;
    match name {
        "debug" => Some(Rights::WRITE.union(Rights::BIND)),
        "mem-pressure" => Some(Rights::BIND.union(Rights::ACK)),
        // `acpi` (T-405): a cópia da DSDT, para o `acpid`.
        "log" | "acpi" => Some(Rights::READ.union(Rights::MAP)),
        // T-402: a janela ECAM (para o `pcid`) e a cota de dispositivo.
        "ecam" => Some(Rights::READ.union(Rights::WRITE).union(Rights::MAP)),
        "device" => Some(Rights::CREATE),
        _ => None,
    }
}

fn parse_provide(service: &str, item: &str) -> Result<Provide, Error> {
    let (name, major, minor) = version(item).map_err(|e| Error(format!("{service}: {}", e.0)))?;
    Ok(Provide { name, major, minor })
}

/// Confere o grafo entre manifestos: nomes únicos, toda aresta obrigatória
/// tem provedor e não há ciclo nas arestas obrigatórias.
///
/// # Errors
/// Nome repetido, provedor ausente, provedor ambíguo ou ciclo.
pub fn check_graph(manifests: &[Manifest]) -> Result<(), Error> {
    let mut names = BTreeSet::new();
    for m in manifests {
        if !names.insert(m.name.as_str()) {
            return err(format!("serviço repetido: {}", m.name));
        }
    }
    // Interface -> índices dos provedores.
    let mut providers: BTreeMap<&str, Vec<(usize, &Provide)>> = BTreeMap::new();
    for (i, m) in manifests.iter().enumerate() {
        for p in &m.provides {
            providers.entry(p.name.as_str()).or_default().push((i, p));
        }
    }
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); manifests.len()];
    for (i, m) in manifests.iter().enumerate() {
        for n in m.needs.iter().filter(|n| n.kind == NeedKind::Svc) {
            let found: Vec<usize> = providers
                .get(n.name.as_str())
                .into_iter()
                .flatten()
                .filter(|(_, p)| p.major == n.major && p.minor >= n.minor)
                .map(|(j, _)| *j)
                .collect();
            match (found.len(), n.optional) {
                (1, false) => edges[i].push(found[0]),
                (1 | 0, true) => {}
                (0, false) => {
                    return err(format!(
                        "{}: nenhum provedor de {}@{}.{}",
                        m.name, n.name, n.major, n.minor
                    ));
                }
                _ => return err(format!("{}: provedor ambíguo de {}", m.name, n.name)),
            }
        }
    }
    if let Some(cycle) = find_cycle(&edges) {
        let path: Vec<&str> = cycle.iter().map(|&i| manifests[i].name.as_str()).collect();
        return err(format!("ciclo de dependências: {}", path.join(" -> ")));
    }
    Ok(())
}

/// Procura um ciclo por DFS; devolve os índices do ciclo, fechado.
fn find_cycle(edges: &[Vec<usize>]) -> Option<Vec<usize>> {
    // 0 = branco, 1 = cinza (na pilha), 2 = preto.
    fn visit(
        v: usize,
        edges: &[Vec<usize>],
        color: &mut [u8],
        stack: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        color[v] = 1;
        stack.push(v);
        for &w in &edges[v] {
            if color[w] == 1 {
                let start = stack.iter().position(|&x| x == w).unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.push(w);
                return Some(cycle);
            }
            if color[w] == 0
                && let Some(c) = visit(w, edges, color, stack)
            {
                return Some(c);
            }
        }
        stack.pop();
        color[v] = 2;
        None
    }
    let mut color = vec![0u8; edges.len()];
    for v in 0..edges.len() {
        if color[v] == 0 {
            let mut stack = Vec::new();
            if let Some(c) = visit(v, edges, &mut color, &mut stack) {
                return Some(c);
            }
        }
    }
    None
}

/// Compila um manifesto validado para o formato `OMAN` v1.
///
/// `elf` são os bytes do binário; o cabeçalho guarda o BLAKE3 deles.
/// A saída é determinística: mesma entrada, mesmos bytes. Sem assinatura
/// (`sig_alg` 0): a assinatura híbrida chega com a ADR 0018.
///
/// # Errors
/// Corpo maior que 4096 bytes.
pub fn encode(m: &Manifest, elf: &[u8]) -> Result<Vec<u8>, Error> {
    let needs_off = HEADER_LEN;
    let provides_off = needs_off + NEED_LEN * m.needs.len();
    let strings_off = provides_off + PROVIDE_LEN * m.provides.len();

    let mut strings: Vec<u8> = Vec::new();
    let mut put = |s: &str| -> (u32, u32) {
        let off = strings_off + strings.len();
        strings.extend_from_slice(s.as_bytes());
        (
            u32::try_from(off).unwrap_or(u32::MAX),
            u32::try_from(s.len()).unwrap_or(u32::MAX),
        )
    };
    let name_ref = put(&m.name);
    let binary_ref = put(&m.binary);
    let need_refs: Vec<(u32, u32)> = m.needs.iter().map(|n| put(&n.name)).collect();
    let provide_refs: Vec<(u32, u32)> = m.provides.iter().map(|p| put(&p.name)).collect();

    let body_len = strings_off + strings.len();
    let body_len = body_len.div_ceil(8) * 8;
    if body_len > MAX_BODY {
        return err(format!(
            "{}: manifesto com {body_len} bytes, o limite é {MAX_BODY}",
            m.name
        ));
    }
    let mut out = vec![0u8; body_len];
    let put_u16 =
        |out: &mut [u8], at: usize, v: u16| out[at..at + 2].copy_from_slice(&v.to_le_bytes());
    let put_u32 =
        |out: &mut [u8], at: usize, v: u32| out[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put_u64 =
        |out: &mut [u8], at: usize, v: u64| out[at..at + 8].copy_from_slice(&v.to_le_bytes());
    let fits = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);

    out[0..4].copy_from_slice(&MAGIC);
    put_u32(&mut out, 4, VERSION);
    put_u32(&mut out, 8, fits(body_len));
    put_u32(&mut out, 12, 0);
    put_u32(&mut out, 16, name_ref.0);
    put_u32(&mut out, 20, name_ref.1);
    put_u32(&mut out, 24, binary_ref.0);
    put_u32(&mut out, 28, binary_ref.1);
    out[32..64].copy_from_slice(&optcrypt::blake3::hash(elf));
    put_u16(&mut out, 64, u16::from(m.priority));
    out[66] = m.restart as u8;
    put_u16(&mut out, 68, m.max_threads);
    put_u32(&mut out, 72, m.ipc_rate);
    put_u16(
        &mut out,
        76,
        u16::try_from(m.needs.len()).unwrap_or(u16::MAX),
    );
    put_u16(
        &mut out,
        78,
        u16::try_from(m.provides.len()).unwrap_or(u16::MAX),
    );
    put_u32(&mut out, 80, fits(needs_off));
    put_u32(&mut out, 84, fits(provides_off));

    for (i, n) in m.needs.iter().enumerate() {
        let at = needs_off + NEED_LEN * i;
        out[at] = n.kind as u8;
        out[at + 1] = u8::from(n.optional);
        put_u16(&mut out, at + 2, n.minor);
        put_u16(&mut out, at + 4, n.major);
        put_u32(&mut out, at + 8, need_refs[i].0);
        put_u32(&mut out, at + 12, need_refs[i].1);
        put_u64(&mut out, at + 16, n.value);
    }
    for (i, p) in m.provides.iter().enumerate() {
        let at = provides_off + PROVIDE_LEN * i;
        put_u16(&mut out, at, p.major);
        put_u16(&mut out, at + 2, p.minor);
        put_u32(&mut out, at + 8, provide_refs[i].0);
        put_u32(&mut out, at + 12, provide_refs[i].1);
    }
    out[strings_off..strings_off + strings.len()].copy_from_slice(&strings);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOG: &str = r#"
[service]
name = "logd"
binary = "svc/logd"
priority = 150
restart = "always"
[capabilities]
needs = ["svc:optimus.time.Clock@1?", "mem:quota:8MiB"]
provides = ["optimus.log.Log@1.0"]
[limits]
max_threads = 4
ipc_rate = 10000
"#;

    fn svc(name: &str, needs: &[&str], provides: &[&str]) -> Manifest {
        let needs = needs
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        let provides = provides
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        let src = format!(
            "[service]\nname = \"{name}\"\nbinary = \"svc/{name}\"\npriority = 130\nrestart = \"on-failure\"\n\
             [capabilities]\nneeds = [{needs}, \"mem:quota:4MiB\"]\nprovides = [{provides}]\n\
             [limits]\nmax_threads = 2\n"
        );
        parse(&src).expect("manifesto de teste")
    }

    #[test]
    fn compila_e_confere_cabecalho() {
        let m = parse(LOG).expect("válido");
        assert_eq!(m.needs[1].value, 8 << 20);
        assert!(m.needs[0].optional);
        let elf = b"elf de teste";
        let bytes = encode(&m, elf).expect("cabe");
        assert_eq!(&bytes[0..4], b"OMAN");
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize,
            bytes.len()
        );
        assert_eq!(bytes[66], Restart::Always as u8);
        assert_eq!(&bytes[32..64], &optcrypt::blake3::hash(elf));
    }

    #[test]
    fn saida_e_deterministica() {
        let m = parse(LOG).expect("válido");
        assert_eq!(encode(&m, b"x").unwrap(), encode(&m, b"x").unwrap());
    }

    #[test]
    fn recusa_nomes_antigos_e_limites() {
        let antigo = LOG.replace("svc:optimus.time.Clock@1?", "log:write");
        assert!(parse(&antigo).is_err());
        assert!(parse(&LOG.replace("priority = 150", "priority = 200")).is_err());
        assert!(parse(&LOG.replace("max_threads = 4", "max_threads = 0")).is_err());
        assert!(parse(&LOG.replace("logd", "Logd")).is_err());
        assert!(parse(&LOG.replace("\"mem:quota:8MiB\"", "")).is_err());
        assert!(parse(&LOG.replace("[limits]", "[limites]")).is_err());
    }

    #[test]
    fn ciclo_falha_o_build() {
        let a = svc("a", &["svc:optimus.b.B@1"], &["optimus.a.A@1.0"]);
        let b = svc("b", &["svc:optimus.a.A@1"], &["optimus.b.B@1.0"]);
        let e = check_graph(&[a, b]).unwrap_err();
        assert!(e.0.contains("ciclo"), "{e}");
    }

    #[test]
    fn aresta_fraca_nao_forma_ciclo() {
        let a = svc("a", &["svc:optimus.b.B@1?"], &["optimus.a.A@1.0"]);
        let b = svc("b", &["svc:optimus.a.A@1"], &["optimus.b.B@1.0"]);
        assert!(check_graph(&[a, b]).is_ok());
    }

    #[test]
    fn falta_provedor_obrigatorio() {
        let a = svc("a", &["svc:optimus.z.Z@1"], &[]);
        assert!(check_graph(&[a]).unwrap_err().0.contains("nenhum provedor"));
    }

    #[test]
    fn match_vira_dev() {
        let src = LOG.replace(
            "[limits]",
            "[match]\npci = [\"1af4:1042\"]\nclass = [\"01:00:00\"]\ncompatible = [\"PNP0B00\"]\n[limits]",
        );
        let m = parse(&src).expect("válido");
        let devs: Vec<&str> = m
            .needs
            .iter()
            .filter(|n| n.kind == NeedKind::Dev)
            .map(|n| n.name.as_str())
            .collect();
        assert_eq!(
            devs,
            ["pci:1af4:1042", "class:01:00:00", "compatible:PNP0B00"]
        );
        for ruim in [
            "pci = [\"1af4\"]",
            "class = [\"1:0\"]",
            "usb = [\"1:2\"]",
            "",
        ] {
            let src = LOG.replace("[limits]", &format!("[match]\n{ruim}\n[limits]"));
            assert!(parse(&src).is_err(), "{ruim}");
        }
    }

    #[test]
    fn kernel_leva_mascara_explicita() {
        use kabi::Rights;
        let m = svc("a", &["kernel:debug", "kernel:mem-pressure"], &[]);
        assert_eq!(m.needs[0].kind, NeedKind::Kernel);
        assert_eq!(
            m.needs[0].value,
            u64::from((Rights::WRITE | Rights::BIND).bits())
        );
        assert_eq!(
            m.needs[1].value,
            u64::from((Rights::BIND | Rights::ACK).bits())
        );
    }
}
