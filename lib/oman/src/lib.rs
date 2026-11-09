//! Leitura e validação do manifesto `OMAN` v1 (ADR 0034, item 4) e a ordem
//! de partida dos serviços (T-352).
//!
//! `svcmgr` relê cada manifesto do bootfs antes de confiar nele: magia,
//! versão, limites, referências dentro do arquivo, campos reservados zero e
//! ausência de assinatura (`sig_alg` 0, até a ADR 0018). A ordem de partida
//! sai de [`levels`]: cada nível só depende de níveis anteriores, então os
//! serviços de um mesmo nível sobem em paralelo.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

/// Magia do formato.
pub const MAGIC: [u8; 4] = *b"OMAN";
/// Versão lida por este leitor.
pub const VERSION: u32 = 1;
const HEADER_LEN: usize = 96;
const NEED_LEN: usize = 24;
const PROVIDE_LEN: usize = 16;
const MAX_BODY: usize = 4096;

/// Erro de leitura ou de grafo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Magia, versão ou tamanho do arquivo não conferem.
    Format,
    /// Um campo está fora do limite do formato.
    Limit,
    /// Campo reservado diferente de zero ou assinatura presente.
    Reserved,
    /// Referência de texto fora do arquivo ou texto inválido.
    Text,
    /// Dependência obrigatória sem provedor.
    NoProvider,
    /// Ciclo nas dependências obrigatórias.
    Cycle,
}

/// Tipo de necessidade, como no formato.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeedKind {
    /// Interface de serviço.
    Svc,
    /// Cota de memória.
    Mem,
    /// Dispositivo.
    Dev,
    /// Diretório.
    Fs,
    /// Capability de origem do kernel.
    Kernel,
}

/// Uma necessidade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Need {
    /// Tipo.
    pub kind: NeedKind,
    /// Aresta fraca: não ordena a partida.
    pub optional: bool,
    /// Versão maior (interface).
    pub major: u16,
    /// Versão menor mínima (interface).
    pub minor: u16,
    /// Nome.
    pub name: String,
    /// Bytes da cota, quando `Mem`.
    pub value: u64,
}

/// Uma provisão.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provide {
    /// Nome da interface.
    pub name: String,
    /// Versão maior.
    pub major: u16,
    /// Versão menor.
    pub minor: u16,
}

/// Manifesto lido e validado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Oman {
    /// Nome do serviço.
    pub name: String,
    /// Caminho do binário no bootfs.
    pub binary: String,
    /// BLAKE3 do binário.
    pub binary_hash: [u8; 32],
    /// Prioridade, 1..=199.
    pub priority: u8,
    /// Política de reinício: 0 always, 1 on-failure, 2 never.
    pub restart: u8,
    /// Threads máximas, 1..=1024.
    pub max_threads: u16,
    /// Mensagens por segundo (0 = sem limite).
    pub ipc_rate: u32,
    /// Necessidades.
    pub needs: Vec<Need>,
    /// Provisões.
    pub provides: Vec<Provide>,
}

fn u16_at(b: &[u8], at: usize) -> Result<u16, Error> {
    let s = b.get(at..at + 2).ok_or(Error::Format)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], at: usize) -> Result<u32, Error> {
    let s = b.get(at..at + 4).ok_or(Error::Format)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], at: usize) -> Result<u64, Error> {
    let s = b.get(at..at + 8).ok_or(Error::Format)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

/// Lê `{off, len}` e devolve o texto, dentro do arquivo e em UTF-8.
fn text_at(b: &[u8], at: usize) -> Result<String, Error> {
    let off = usize::try_from(u32_at(b, at)?).map_err(|_| Error::Text)?;
    let len = usize::try_from(u32_at(b, at + 4)?).map_err(|_| Error::Text)?;
    let end = off.checked_add(len).ok_or(Error::Text)?;
    let raw = b.get(off..end).ok_or(Error::Text)?;
    let s = core::str::from_utf8(raw).map_err(|_| Error::Text)?;
    Ok(s.to_string())
}

fn reserved_zero(b: &[u8], at: usize, len: usize) -> Result<(), Error> {
    match b.get(at..at + len) {
        Some(s) if s.iter().all(|&x| x == 0) => Ok(()),
        _ => Err(Error::Reserved),
    }
}

/// Lê e valida um manifesto inteiro.
///
/// # Errors
/// Qualquer violação do formato ou dos limites da ADR 0034.
pub fn parse(b: &[u8]) -> Result<Oman, Error> {
    if b.len() < HEADER_LEN || b.get(0..4) != Some(&MAGIC) {
        return Err(Error::Format);
    }
    if u32_at(b, 4)? != VERSION || u32_at(b, 12)? != 0 {
        return Err(Error::Format);
    }
    if usize::try_from(u32_at(b, 8)?).map_err(|_| Error::Format)? != b.len() {
        return Err(Error::Format);
    }
    if b.len() > MAX_BODY {
        return Err(Error::Limit);
    }
    // Assinatura só na ADR 0018: nesta versão, `sig_alg` tem de ser 0.
    if u32_at(b, 88)? != 0 || u16_at(b, 92)? != 0 || u16_at(b, 94)? != 0 {
        return Err(Error::Reserved);
    }
    let name = text_at(b, 16)?;
    let binary = text_at(b, 24)?;
    if name.is_empty() || name.len() > 31 || binary.is_empty() || binary.len() > 63 {
        return Err(Error::Limit);
    }
    let mut binary_hash = [0u8; 32];
    binary_hash.copy_from_slice(b.get(32..64).ok_or(Error::Format)?);
    let priority = u16_at(b, 64)?;
    let restart = *b.get(66).ok_or(Error::Format)?;
    reserved_zero(b, 67, 1)?;
    let max_threads = u16_at(b, 68)?;
    reserved_zero(b, 70, 2)?;
    let ipc_rate = u32_at(b, 72)?;
    if !(1..=199).contains(&priority) || restart > 2 || !(1..=1024).contains(&max_threads) {
        return Err(Error::Limit);
    }
    let needs_n = usize::from(u16_at(b, 76)?);
    let provides_n = usize::from(u16_at(b, 78)?);
    if needs_n + provides_n > 94 || needs_n > 64 || provides_n > 32 {
        return Err(Error::Limit);
    }
    let needs_off = usize::try_from(u32_at(b, 80)?).map_err(|_| Error::Format)?;
    let provides_off = usize::try_from(u32_at(b, 84)?).map_err(|_| Error::Format)?;
    if needs_off != HEADER_LEN || provides_off != needs_off + NEED_LEN * needs_n {
        return Err(Error::Format);
    }
    let mut needs = Vec::with_capacity(needs_n);
    for i in 0..needs_n {
        let at = needs_off + NEED_LEN * i;
        let kind = match b.get(at).copied().ok_or(Error::Format)? {
            1 => NeedKind::Svc,
            2 => NeedKind::Mem,
            3 => NeedKind::Dev,
            4 => NeedKind::Fs,
            5 => NeedKind::Kernel,
            _ => return Err(Error::Format),
        };
        let flags = *b.get(at + 1).ok_or(Error::Format)?;
        if flags > 1 {
            return Err(Error::Reserved);
        }
        reserved_zero(b, at + 6, 2)?;
        needs.push(Need {
            kind,
            optional: flags == 1,
            minor: u16_at(b, at + 2)?,
            major: u16_at(b, at + 4)?,
            name: text_at(b, at + 8)?,
            value: u64_at(b, at + 16)?,
        });
    }
    let mut provides = Vec::with_capacity(provides_n);
    for i in 0..provides_n {
        let at = provides_off + PROVIDE_LEN * i;
        reserved_zero(b, at + 4, 4)?;
        provides.push(Provide {
            major: u16_at(b, at)?,
            minor: u16_at(b, at + 2)?,
            name: text_at(b, at + 8)?,
        });
    }
    Ok(Oman {
        name,
        binary,
        binary_hash,
        priority: u8::try_from(priority).map_err(|_| Error::Limit)?,
        restart,
        max_threads,
        ipc_rate,
        needs,
        provides,
    })
}

/// Ordem de partida: níveis de índices de `items`. Cada nível só depende
/// de níveis anteriores (dependência obrigatória com provedor). Os de um
/// mesmo nível podem subir em paralelo.
///
/// # Errors
/// [`Error::NoProvider`] para dependência obrigatória sem provedor e
/// [`Error::Cycle`] para ciclo nas obrigatórias.
pub fn levels(items: &[Oman]) -> Result<Vec<Vec<usize>>, Error> {
    let n = items.len();
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (i, m) in items.iter().enumerate() {
        for need in m
            .needs
            .iter()
            .filter(|x| x.kind == NeedKind::Svc && !x.optional)
        {
            let mut found = None;
            for (j, p) in items.iter().enumerate() {
                if p.provides
                    .iter()
                    .any(|q| q.name == need.name && q.major == need.major && q.minor >= need.minor)
                {
                    if found.is_some() {
                        return Err(Error::NoProvider);
                    }
                    found = Some(j);
                }
            }
            match found {
                Some(j) => deps[i].push(j),
                None => return Err(Error::NoProvider),
            }
        }
    }
    let mut placed = vec![false; n];
    let mut out: Vec<Vec<usize>> = Vec::new();
    let mut done = 0;
    while done < n {
        let level: Vec<usize> = (0..n)
            .filter(|&i| !placed[i] && deps[i].iter().all(|&d| placed[d]))
            .collect();
        if level.is_empty() {
            return Err(Error::Cycle);
        }
        for &i in &level {
            placed[i] = true;
        }
        done += level.len();
        out.push(level);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, needs: &[&str], provides: &[&str]) -> Oman {
        let mut all: Vec<&str> = needs.to_vec();
        all.push("mem:quota:4MiB");
        let needs = all
            .iter()
            .map(|s| alloc::format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        let provides = provides
            .iter()
            .map(|s| alloc::format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(",");
        let src = alloc::format!(
            "[service]\nname = \"{name}\"\nbinary = \"svc/{name}\"\npriority = 130\nrestart = \"never\"\n\
             [capabilities]\nneeds = [{needs}]\nprovides = [{provides}]\n\
             [limits]\nmax_threads = 2\n"
        );
        let m = mkmanifest::parse(&src).expect("manifesto de teste");
        let bytes = mkmanifest::encode(&m, b"elf").expect("codifica");
        parse(&bytes).expect("lê o que o compilador escreveu")
    }

    #[test]
    fn le_o_que_o_compilador_escreve() {
        let m = manifest(
            "logd",
            &["svc:optimus.time.Clock@1?"],
            &["optimus.log.Log@1.0"],
        );
        assert_eq!(m.name, "logd");
        assert_eq!(m.binary, "svc/logd");
        assert_eq!(m.needs.len(), 2);
        assert!(m.needs[0].optional);
        assert_eq!(m.needs[1].kind, NeedKind::Mem);
        assert_eq!(m.needs[1].value, 4 << 20);
        assert_eq!(m.provides[0].name, "optimus.log.Log");
    }

    #[test]
    fn recusa_lixo_e_assinatura() {
        assert_eq!(parse(&[0u8; 10]), Err(Error::Format));
        let src = "[service]\nname = \"a\"\nbinary = \"svc/a\"\npriority = 130\nrestart = \"never\"\n\
             [capabilities]\nneeds = [\"mem:quota:4MiB\"]\nprovides = []\n[limits]\nmax_threads = 2\n";
        let mut bytes = mkmanifest::encode(&mkmanifest::parse(src).unwrap(), b"e").unwrap();
        bytes[94] = 1; // sig_alg
        assert_eq!(parse(&bytes), Err(Error::Reserved));
        let mut bytes = mkmanifest::encode(&mkmanifest::parse(src).unwrap(), b"e").unwrap();
        bytes[67] = 1; // reservado
        assert_eq!(parse(&bytes), Err(Error::Reserved));
    }

    #[test]
    fn niveis_em_paralelo_e_ordem() {
        let log = manifest(
            "logd",
            &["svc:optimus.time.Clock@1"],
            &["optimus.log.Log@1.0"],
        );
        let time = manifest("timed", &[], &["optimus.time.Clock@1.0"]);
        let mem = manifest("memd", &[], &["optimus.mem.Mem@1.0"]);
        let items = [log, time, mem];
        let lv = levels(&items).expect("grafo");
        assert_eq!(lv, vec![vec![1, 2], vec![0]]);
    }

    #[test]
    fn ciclo_e_provedor_ausente() {
        let a = manifest("a", &["svc:optimus.b.B@1"], &["optimus.a.A@1.0"]);
        let b = manifest("b", &["svc:optimus.a.A@1"], &["optimus.b.B@1.0"]);
        assert_eq!(levels(&[a.clone(), b]), Err(Error::Cycle));
        assert_eq!(levels(&[a]), Err(Error::NoProvider));
    }

    /// Aceite da T-401: um driver de teste, compilado pelo `mkmanifest` e
    /// relido aqui, casa com o dispositivo certo e não com o errado.
    #[test]
    fn driver_de_teste_casa_so_com_o_seu_dispositivo() {
        use odev::{Bus, Class, Driver, Node, Outcome, Rule, best_match};
        let src = "[service]\nname = \"teste-blk\"\nbinary = \"drv/teste-blk\"\npriority = 120\n\
             restart = \"on-failure\"\n[capabilities]\nneeds = [\"mem:quota:1MiB\"]\nprovides = []\n\
             [match]\npci = [\"1af4:1042\"]\n[limits]\nmax_threads = 1\n";
        let m = mkmanifest::parse(src).expect("manifesto");
        let oman = parse(&mkmanifest::encode(&m, b"elf").expect("codifica")).expect("relê");
        let rules: Vec<Rule> = oman
            .needs
            .iter()
            .filter(|n| n.kind == NeedKind::Dev)
            .filter_map(|n| Rule::parse(&n.name))
            .collect();
        let drivers = [Driver {
            name: oman.name.clone(),
            rules,
        }];
        let node = |device| Node {
            id: 1,
            bus: Bus::Pci,
            pci_id: Some((0x1af4, device)),
            class: Some(Class {
                class: 1,
                subclass: 0,
                prog_if: 0,
            }),
            compatible: Vec::new(),
        };
        assert!(
            matches!(best_match(&drivers, &node(0x1042)), Outcome::Driver(d) if d.name == "teste-blk")
        );
        assert_eq!(best_match(&drivers, &node(0x1041)), Outcome::None);
    }

    #[test]
    fn aresta_fraca_nao_ordena() {
        let a = manifest("a", &["svc:optimus.b.B@1?"], &["optimus.a.A@1.0"]);
        let b = manifest("b", &["svc:optimus.a.A@1"], &["optimus.b.B@1.0"]);
        assert_eq!(levels(&[a, b]), Ok(vec![vec![0], vec![1]]));
    }
}
