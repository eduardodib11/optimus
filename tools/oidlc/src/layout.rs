//! Layout de fio do OIDL (ADR 0033, seções 3 a 5; T-343).
//!
//! Para cada mensagem, o `oidlc` calcula onde fica cada campo da cabeça, o
//! tamanho da cabeça e o pior caso do corpo, somando a cauda dos `string` e
//! dos `vec`. Com isso ele recusa, em tempo de compilação, método cujo corpo
//! possa passar de 4032 bytes, e diz por onde a mensagem viaja (registradores
//! ou buffer). `handle<T>` não ocupa bytes: vai nas capabilities.

use crate::ast::{Decl, Field, File, Method, Prim, Repr, Type};
use crate::lexer::Pos;

/// Maior corpo de mensagem (ADR 0033, seção 4): 4 KiB menos o cabeçalho.
pub const MAX_CORPO: u64 = 4032;
/// Palavras de corpo que cabem nos seis registradores de IPC (ADR 0027).
pub const PALAVRAS_REGISTRADORES: u64 = 6;
/// Palavras de corpo no buffer de IPC (4 KiB menos 64 bytes de cabeçalho).
pub const PALAVRAS_BUFFER: u64 = 504;
/// Registradores que levam as palavras, na ordem (ADR 0027).
pub const REGISTRADORES: [&str; 6] = ["r8", "r9", "r12", "r13", "r14", "r15"];

/// Tamanho e alinhamento de um tipo no corpo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Medida {
    /// Bytes ocupados na cabeça.
    pub tamanho: u64,
    /// Alinhamento em bytes.
    pub alinhamento: u64,
}

/// Campo com o deslocamento calculado dentro da cabeça.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Campo {
    /// Nome do campo ou parâmetro.
    pub nome: String,
    /// Deslocamento a partir do início da cabeça.
    pub deslocamento: u64,
    /// Medida do campo.
    pub medida: Medida,
}

/// Layout de uma sequência de campos (parâmetros ou struct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cabeca {
    /// Campos na ordem da declaração.
    pub campos: Vec<Campo>,
    /// Tamanho da cabeça, arredondado ao maior alinhamento.
    pub tamanho: u64,
    /// Pior caso do corpo: cabeça, caudas e enchimento, em bytes.
    pub pior_caso: u64,
}

/// Como uma mensagem de corpo `n` bytes viaja (ADR 0033, seção 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// Corpo nos registradores: `palavras` de 8 bytes (≤ 6).
    Registradores {
        /// Palavras de 8 bytes do corpo.
        palavras: u64,
    },
    /// Corpo no buffer de IPC: `palavras` (≤ 504).
    Buffer {
        /// Palavras de 8 bytes do corpo.
        palavras: u64,
    },
}

/// Escolhe o transporte para um corpo de `bytes` (múltiplo de 8).
#[must_use]
pub fn via(bytes: u64) -> Via {
    let palavras = bytes / 8;
    if palavras <= PALAVRAS_REGISTRADORES {
        Via::Registradores { palavras }
    } else {
        Via::Buffer { palavras }
    }
}

/// Erro de layout: posição e mensagem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErroLayout {
    /// Onde o erro foi achado.
    pub pos: Pos,
    /// Mensagem.
    pub msg: String,
}

/// Calculador de layout sobre um arquivo já checado pela análise semântica.
pub struct Layouts<'a> {
    file: &'a File,
}

impl<'a> Layouts<'a> {
    /// Prepara o cálculo para `file`.
    #[must_use]
    pub fn new(file: &'a File) -> Self {
        Self { file }
    }

    /// Medida de um tipo na cabeça. `handle<T>` e `()` ocupam zero bytes.
    ///
    /// # Errors
    ///
    /// Tipo sem layout conhecido nesta compilação (externo, não resolvido).
    pub fn medida(&self, t: &Type) -> Result<Medida, String> {
        let m = |tamanho, alinhamento| {
            Ok(Medida {
                tamanho,
                alinhamento,
            })
        };
        match t {
            Type::Unit | Type::Handle(_) => m(0, 1),
            Type::Prim(p, _) => Ok(prim(*p)),
            Type::String(_) | Type::Vec(..) => m(8, 4),
            Type::Named(id) => self.nomeado(&id.name, 0),
        }
    }

    fn nomeado(&self, nome: &str, prof: u32) -> Result<Medida, String> {
        if prof > 64 {
            return Err(format!("'{nome}': alias demais"));
        }
        let simples = nome.rsplit_once('.').map_or(nome, |(p, s)| {
            if p == self.file.package.name.name {
                s
            } else {
                nome
            }
        });
        if simples == "Timestamp" {
            return Ok(prim(Prim::I64));
        }
        for d in &self.file.decls {
            match d {
                Decl::Enum(e) if e.name.name == simples => return Ok(repr(e.repr)),
                Decl::Flags(f) if f.name.name == simples => return Ok(repr(f.repr)),
                Decl::Alias(a) if a.name.name == simples => {
                    return self.medida_prof(&a.ty, prof + 1);
                }
                Decl::Struct(s) if s.name.name == simples => {
                    return self.cabeca_de(&s.fields).map(|c| Medida {
                        tamanho: c.tamanho,
                        alinhamento: self.alinha_de(&s.fields, prof + 1),
                    });
                }
                _ => {}
            }
        }
        Err(format!("'{nome}' não tem layout nesta compilação"))
    }

    fn medida_prof(&self, t: &Type, prof: u32) -> Result<Medida, String> {
        match t {
            Type::Named(id) => self.nomeado(&id.name, prof),
            outro => self.medida(outro),
        }
    }

    fn alinha_de(&self, campos: &[Field], prof: u32) -> u64 {
        campos
            .iter()
            .filter_map(|c| self.medida_prof(&c.ty, prof).ok())
            .map(|m| m.alinhamento)
            .max()
            .unwrap_or(1)
    }

    /// Layout de uma sequência de campos, a partir do deslocamento zero.
    ///
    /// # Errors
    ///
    /// Campo sem layout conhecido.
    pub fn cabeca_de(&self, campos: &[Field]) -> Result<Cabeca, String> {
        let mut out = Vec::with_capacity(campos.len());
        let mut cursor = 0u64;
        let mut align = 1u64;
        let mut pior = 0u64;
        for c in campos {
            let m = self.medida(&c.ty)?;
            cursor = arredonda(cursor, m.alinhamento);
            out.push(Campo {
                nome: c.name.name.clone(),
                deslocamento: cursor,
                medida: m,
            });
            cursor += m.tamanho;
            align = align.max(m.alinhamento);
            pior += self.cauda_max(&c.ty)?;
        }
        let tamanho = arredonda(cursor, align);
        // O corpo termina arredondado a 8 bytes (ADR 0033, seção 3, item 4).
        Ok(Cabeca {
            campos: out,
            tamanho,
            pior_caso: arredonda(tamanho, 8) + pior,
        })
    }

    /// Pior caso, em bytes, da cauda que um valor de tipo `t` pode ocupar.
    fn cauda_max(&self, t: &Type) -> Result<u64, String> {
        match t {
            Type::String(n) => Ok(arredonda(n.value, 8)),
            Type::Vec(elem, n) => {
                let m = self.medida(elem)?;
                let regiao = arredonda(n.value.saturating_mul(m.tamanho), 8);
                let filhos = n.value.saturating_mul(self.cauda_max(elem)?);
                Ok(regiao.saturating_add(filhos))
            }
            Type::Named(id) => self.cauda_nomeada(&id.name, 0),
            _ => Ok(0),
        }
    }

    fn cauda_nomeada(&self, nome: &str, prof: u32) -> Result<u64, String> {
        if prof > 64 {
            return Err(format!("'{nome}': tipo recursivo"));
        }
        let simples = nome.rsplit_once('.').map_or(nome, |(p, s)| {
            if p == self.file.package.name.name {
                s
            } else {
                nome
            }
        });
        for d in &self.file.decls {
            match d {
                Decl::Alias(a) if a.name.name == simples => {
                    return self.cauda_prof(&a.ty, prof + 1);
                }
                Decl::Struct(s) if s.name.name == simples => {
                    let mut soma = 0u64;
                    for c in &s.fields {
                        soma = soma.saturating_add(self.cauda_prof(&c.ty, prof + 1)?);
                    }
                    return Ok(soma);
                }
                _ => {}
            }
        }
        Ok(0)
    }

    fn cauda_prof(&self, t: &Type, prof: u32) -> Result<u64, String> {
        match t {
            Type::Named(id) => self.cauda_nomeada(&id.name, prof),
            Type::String(n) => Ok(arredonda(n.value, 8)),
            Type::Vec(elem, n) => {
                let m = self.medida_prof(elem, prof)?;
                let regiao = arredonda(n.value.saturating_mul(m.tamanho), 8);
                Ok(regiao.saturating_add(n.value.saturating_mul(self.cauda_prof(elem, prof)?)))
            }
            _ => Ok(0),
        }
    }

    /// Pior caso do pedido e da resposta de um método.
    ///
    /// # Errors
    ///
    /// Campo sem layout conhecido.
    pub fn metodo(&self, m: &Method) -> Result<(Cabeca, Option<(Cabeca, Cabeca)>), String> {
        let pedido = self.cabeca_de(&m.params)?;
        let resposta = match &m.ret {
            Some(r) => {
                let ok = self.cabeca_de(&[Field {
                    name: m.name.clone(),
                    ty: r.ok.clone(),
                }])?;
                let err = self.cabeca_de(&[Field {
                    name: m.name.clone(),
                    ty: r.err.clone(),
                }])?;
                Some((ok, err))
            }
            None => None,
        };
        Ok((pedido, resposta))
    }

    /// Erros de tamanho: corpo do pedido ou da resposta acima de [`MAX_CORPO`].
    #[must_use]
    pub fn confere_tamanhos(&self) -> Vec<ErroLayout> {
        let mut erros = Vec::new();
        for d in &self.file.decls {
            let Decl::Interface(i) = d else { continue };
            for m in &i.methods {
                let (pedido, resposta) = match self.metodo(m) {
                    Ok(x) => x,
                    Err(msg) => {
                        erros.push(ErroLayout {
                            pos: m.name.pos,
                            msg,
                        });
                        continue;
                    }
                };
                if pedido.pior_caso > MAX_CORPO {
                    erros.push(ErroLayout {
                        pos: m.name.pos,
                        msg: format!(
                            "pedido de '{}' pode ter {} bytes; o máximo é {MAX_CORPO}",
                            m.name.name, pedido.pior_caso
                        ),
                    });
                }
                if let Some((ok, err)) = resposta {
                    for (nome, c) in [("sucesso", ok), ("erro", err)] {
                        if c.pior_caso > MAX_CORPO {
                            erros.push(ErroLayout {
                                pos: m.name.pos,
                                msg: format!("resposta de '{}' ({nome}) pode ter {} bytes; o máximo é {MAX_CORPO}", m.name.name, c.pior_caso),
                            });
                        }
                    }
                }
            }
        }
        erros
    }
}

fn prim(p: Prim) -> Medida {
    let (tamanho, alinhamento) = match p {
        Prim::Bool | Prim::U8 | Prim::I8 => (1, 1),
        Prim::U16 | Prim::I16 => (2, 2),
        Prim::U32 | Prim::I32 => (4, 4),
        Prim::U64 | Prim::I64 => (8, 8),
    };
    Medida {
        tamanho,
        alinhamento,
    }
}

fn repr(r: Repr) -> Medida {
    let t = match r {
        Repr::U8 => 1,
        Repr::U16 => 2,
        Repr::U32 => 4,
    };
    Medida {
        tamanho: t,
        alinhamento: t,
    }
}

fn arredonda(n: u64, a: u64) -> u64 {
    n.div_ceil(a).saturating_mul(a)
}
