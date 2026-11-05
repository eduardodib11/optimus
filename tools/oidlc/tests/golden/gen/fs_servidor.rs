// Gerado pelo oidlc a partir do arquivo .oidl. Não edite à mão.
//
// Layout e formato de fio: ADR 0033. Usa só `oidl_rt` e `core`.

#![allow(
    unused_parens,
    unused_variables,
    dead_code,
    clippy::double_parens,
    clippy::unreadable_literal,
    clippy::many_single_char_names,
    clippy::doc_markdown,
    clippy::unnecessary_wraps,
    clippy::too_many_arguments,
    clippy::trivially_copy_pass_by_ref,
    clippy::manual_let_else,
    clippy::elidable_lifetime_names,
    clippy::needless_lifetimes,
    clippy::explicit_auto_deref,
    clippy::needless_pass_by_value,
    reason = "código gerado: estilo e campos que um serviço pode não usar"
)]

use oidl_rt::{Error, Reader, Writer};

/// Contexto de uma chamada: o badge do remetente (ADR 0027).
pub struct Contexto {
    /// Badge do endpoint que chamou.
    pub badge: u64,
}

/// Mensagem recebida.
pub struct Entrada<'a> {
    /// Rótulo de 64 bits (ADR 0033, seção 2).
    pub rotulo: u64,
    /// Badge do remetente.
    pub badge: u64,
    /// Corpo recebido.
    pub corpo: &'a [u8],
    /// Capabilities recebidas, na ordem dos `handle` dos parâmetros.
    pub caps: &'a [u64],
}

/// Resposta a ser enviada: rótulo, bytes do corpo e capabilities.
pub struct Despacho {
    /// Rótulo da resposta.
    pub rotulo: u64,
    /// Bytes escritos no buffer de saída.
    pub corpo: usize,
    /// Capabilities escritas em `caps_out`.
    pub caps: usize,
}

const fn rotulo_resposta(tipo: u8, codigo: u16) -> u64 {
    ((tipo as u64 & 0b11) << 62) | codigo as u64
}

/// Erro de protocolo (ADR 0033, seção 2): 1 UnknownInterface, 2 UnknownMethod,
/// 3 VersionTooOld, 4 BadMessage, 5 TooLarge.
fn protocolo(codigo: u16) -> Option<Despacho> {
    Some(Despacho {
        rotulo: rotulo_resposta(2, codigo),
        corpo: 0,
        caps: 0,
    })
}

/// Struct `DirEntry`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry<'a> {
    /// Campo `name`.
    pub name: &'a str,
    /// Campo `kind`.
    pub kind: EntryKind,
    /// Campo `size`.
    pub size: u64,
    /// Campo `modified`.
    pub modified: i64,
}

fn enc_dir_entry<'a>(w: &mut Writer<'_>, v: &DirEntry<'a>, base: usize) -> Result<(), Error> {
    w.seek(base);
    w.string(v.name, 255)?;
    w.seek(base + 8);
    w.u8((&v.kind).0)?;
    w.seek(base + 16);
    w.u64(v.size)?;
    w.seek(base + 24);
    w.i64(v.modified)?;
    Ok(())
}

/// Struct `DirPage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirPage<'a> {
    /// Campo `entries`.
    pub entries: &'a [DirEntry<'a>],
    /// Campo `next`.
    pub next: u64,
}

fn enc_dir_page<'a>(w: &mut Writer<'_>, v: &DirPage<'a>, base: usize) -> Result<(), Error> {
    let off1 = {
        w.seek(base);
        w.vec((v.entries).len(), 32, 8)?
    };
    for (i1, el) in (v.entries).iter().enumerate() {
        let at2 = off1 + i1 * 32;
        enc_dir_entry(w, el, at2)?;
    }
    w.seek(base + 8);
    w.u64(v.next)?;
    Ok(())
}

/// Enumeração `EntryKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryKind(pub u8);

impl EntryKind {
    /// Variante `File`.
    pub const File: EntryKind = EntryKind(0);
    /// Variante `Dir`.
    pub const Dir: EntryKind = EntryKind(1);
    /// Variante `Link`.
    pub const Link: EntryKind = EntryKind(2);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<EntryKind> {
        match v {
            0 | 1 | 2 => Some(EntryKind(v)),
            _ => None,
        }
    }
}

/// Enumeração `FsError`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FsError(pub u8);

impl FsError {
    /// Variante `NotFound`.
    pub const NotFound: FsError = FsError(0);
    /// Variante `NotDirectory`.
    pub const NotDirectory: FsError = FsError(1);
    /// Variante `Io`.
    pub const Io: FsError = FsError(2);
    /// Converte o valor de fio; `None` se fora do conjunto.
    pub fn from_raw(v: u8) -> Option<FsError> {
        match v {
            0 | 1 | 2 => Some(FsError(v)),
            _ => None,
        }
    }
}

/// Conjunto de bits `OpenFlags`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenFlags(pub u8);

impl OpenFlags {
    /// Bit `Read`.
    pub const Read: OpenFlags = OpenFlags(1);
    /// Bit `Write`.
    pub const Write: OpenFlags = OpenFlags(2);
    /// Bit `Create`.
    pub const Create: OpenFlags = OpenFlags(4);
    /// Converte o valor de fio; `None` se houver bit não declarado.
    pub const fn from_raw(v: u8) -> Option<OpenFlags> {
        if v as u64 & !7u64 == 0 {
            Some(OpenFlags(v))
        } else {
            None
        }
    }
}

/// Identificador da interface `File` (ADR 0033, seção 2).
pub const ID_FILE: u32 = 0x74672843;

/// Interface `File`: implemente para servir.
pub trait File {
    /// Método `size` (ordinal 0).
    fn size(&mut self, ctx: &Contexto) -> Result<u64, FsError>;
}

fn resp_ok_file_0(saida: &mut [u8], v: &u64) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 8)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u64((*v))?;
    }
    Ok(escritor.finish())
}

fn resp_err_file_0(saida: &mut [u8], v: &FsError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `File`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_file<S: File>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_FILE {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if !e.corpo.is_empty() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.size(&ctx) {
                Ok(x) => match resp_ok_file_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_file_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        _ => protocolo(2),
    }
}

/// Identificador da interface `Directory` (ADR 0033, seção 2).
pub const ID_DIRECTORY: u32 = 0xA17CD8BB;

/// Interface `Directory`: implemente para servir.
pub trait Directory {
    /// Método `list` (ordinal 0).
    fn list(&mut self, ctx: &Contexto, path: &str, cursor: u64) -> Result<DirPage<'_>, FsError>;
    /// Método `trash` (ordinal 1).
    fn trash(&mut self, ctx: &Contexto, path: &str) -> Result<(), FsError>;
    /// Método `open` (ordinal 2).
    fn open(&mut self, ctx: &Contexto, path: &str, flags: OpenFlags) -> Result<u64, FsError>;
}

fn pedido_directory_0<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str, u64), Error> {
    let _ = caps;
    Ok((r.string(1024)?, r.u64()?))
}

fn resp_ok_directory_0(saida: &mut [u8], v: &DirPage<'_>) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 16)?;
    {
        let w = &mut escritor;
        enc_dir_page(w, v, 0)?;
    }
    Ok(escritor.finish())
}

fn resp_err_directory_0(saida: &mut [u8], v: &FsError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_directory_1<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str,), Error> {
    let _ = caps;
    Ok((r.string(1024)?,))
}

fn resp_ok_directory_1(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_directory_1(saida: &mut [u8], v: &FsError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

fn pedido_directory_2<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<(&'a str, OpenFlags), Error> {
    let _ = caps;
    Ok((
        r.string(1024)?,
        OpenFlags::from_raw(r.u8()?).ok_or(Error::BadMessage)?,
    ))
}

fn resp_ok_directory_2(saida: &mut [u8]) -> Result<usize, Error> {
    let w = Writer::new(saida, 0)?;
    Ok(w.finish())
}

fn resp_err_directory_2(saida: &mut [u8], v: &FsError) -> Result<usize, Error> {
    let mut escritor = Writer::new(saida, 1)?;
    {
        let w = &mut escritor;
        w.seek(0);
        w.u8((v).0)?;
    }
    Ok(escritor.finish())
}

/// Despacha uma mensagem para `Directory`; `None` quando não há resposta (oneway).
#[allow(clippy::too_many_lines)]
pub fn despacha_directory<S: Directory>(
    s: &mut S,
    versao_menor: u16,
    e: &Entrada<'_>,
    saida: &mut [u8],
    caps_out: &mut [u64],
) -> Option<Despacho> {
    if (e.rotulo >> 32) as u32 != ID_DIRECTORY {
        return protocolo(1);
    }
    let _ = (&saida, &caps_out);
    match (e.rotulo & 0xFFFF) as u16 {
        0 => {
            if e.corpo.len() as u64 > 1040 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 16) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_path, p_cursor) = match pedido_directory_0(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.list(&ctx, p_path, p_cursor) {
                Ok(x) => match resp_ok_directory_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_directory_0(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        1 => {
            if e.corpo.len() as u64 > 1032 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 8) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_path,) = match pedido_directory_1(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.trash(&ctx, p_path) {
                Ok(()) => match resp_ok_directory_1(saida) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(0, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
                Err(x) => match resp_err_directory_1(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        2 => {
            if e.corpo.len() as u64 > 1040 {
                return protocolo(5);
            }
            let mut r = match Reader::new(e.corpo, 12) {
                Ok(r) => r,
                Err(_) => return protocolo(4),
            };
            let (p_path, p_flags) = match pedido_directory_2(&mut r, e.caps) {
                Ok(x) => x,
                Err(_) => return protocolo(4),
            };
            if r.finish().is_err() {
                return protocolo(4);
            }
            let ctx = Contexto { badge: e.badge };
            match s.open(&ctx, p_path, p_flags) {
                Ok(x) => {
                    if caps_out.is_empty() {
                        return protocolo(5);
                    }
                    caps_out[0] = x;
                    match resp_ok_directory_2(saida) {
                        Ok(n) => Some(Despacho {
                            rotulo: rotulo_resposta(0, 0),
                            corpo: n,
                            caps: 1,
                        }),
                        Err(_) => protocolo(5),
                    }
                }
                Err(x) => match resp_err_directory_2(saida, &x) {
                    Ok(n) => Some(Despacho {
                        rotulo: rotulo_resposta(1, 0),
                        corpo: n,
                        caps: 0,
                    }),
                    Err(_) => protocolo(5),
                },
            }
        }
        _ => protocolo(2),
    }
}
