//! Parser de descida recursiva do OIDL (ADR 0033, seção 1).

use crate::ast::{
    Alias, Annotation, Decl, Enum, Field, File, Flags, Ident, Interface, Lit, Method, Package,
    Prim, Repr, Ret, Risk, Struct, Type, Variant, Version,
};
use crate::lexer::{Error, Pos, Tok, Token, lex};

/// Palavras que não podem ser nomes de declaração, campo ou método. As de
/// declaração (`enum`, `flags`, `struct`...) só valem na posição do topo, então
/// `flags: OpenFlags` é um campo válido.
const RESERVADAS: &[&str] = &[
    "oneway", "result", "string", "vec", "handle", "bool", "u8", "u16", "u32", "u64", "i8", "i16",
    "i32", "i64",
];

/// Lê um arquivo `.oidl` inteiro.
///
/// # Errors
///
/// Primeiro erro de léxico ou de sintaxe, com linha e coluna.
pub fn parse(src: &str) -> Result<File, Error> {
    let mut p = Parser {
        toks: lex(src)?,
        i: 0,
    };
    let package = p.package()?;
    let mut decls = Vec::new();
    while !p.at_eof() {
        decls.push(p.decl()?);
    }
    Ok(File { package, decls })
}

struct Parser {
    toks: Vec<Token>,
    i: usize,
}

impl Parser {
    fn tok(&self) -> &Tok {
        &self.toks[self.i].tok
    }

    fn pos(&self) -> Pos {
        self.toks[self.i].pos
    }

    fn at_eof(&self) -> bool {
        matches!(self.tok(), Tok::Eof)
    }

    fn advance(&mut self) {
        if !self.at_eof() {
            self.i += 1;
        }
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, Error> {
        Err(Error {
            pos: self.pos(),
            msg: msg.into(),
        })
    }

    /// Erro "esperado X, achei Y" na posição do token atual.
    fn esperado<T>(&self, o_que: &str) -> Result<T, Error> {
        let achei = match self.tok() {
            Tok::Ident(s) => format!("'{s}'"),
            Tok::Int(n) => format!("o número {n}"),
            Tok::Str(_) => "um texto".into(),
            Tok::Punct(c) => format!("'{c}'"),
            Tok::Arrow => "'->'".into(),
            Tok::Eof => "fim do arquivo".into(),
        };
        self.err(format!("esperado {o_que}, achei {achei}"))
    }

    fn is_punct(&self, c: char) -> bool {
        matches!(self.tok(), Tok::Punct(p) if *p == c)
    }

    fn is_kw(&self, kw: &str) -> bool {
        matches!(self.tok(), Tok::Ident(s) if s == kw)
    }

    fn punct(&mut self, c: char) -> Result<(), Error> {
        if self.is_punct(c) {
            self.advance();
            Ok(())
        } else {
            self.esperado(&format!("'{c}'"))
        }
    }

    fn kw(&mut self, kw: &str) -> Result<(), Error> {
        if self.is_kw(kw) {
            self.advance();
            Ok(())
        } else {
            self.esperado(&format!("'{kw}'"))
        }
    }

    /// Identificador simples, fora das palavras reservadas.
    fn name(&mut self) -> Result<Ident, Error> {
        let pos = self.pos();
        match self.tok().clone() {
            Tok::Ident(s) if !RESERVADAS.contains(&s.as_str()) => {
                self.advance();
                Ok(Ident { name: s, pos })
            }
            Tok::Ident(s) => self.err(format!("'{s}' é palavra reservada")),
            _ => self.esperado("um identificador"),
        }
    }

    /// Caminho pontuado (`optimus.fs.File`), usado em tipos.
    fn path(&mut self) -> Result<Ident, Error> {
        let first = self.name()?;
        let mut name = first.name;
        while self.is_punct('.') {
            self.advance();
            name.push('.');
            name.push_str(&self.name()?.name);
        }
        Ok(Ident {
            name,
            pos: first.pos,
        })
    }

    fn int(&mut self) -> Result<Lit, Error> {
        let pos = self.pos();
        match *self.tok() {
            Tok::Int(value) => {
                self.advance();
                Ok(Lit { value, pos })
            }
            _ => self.esperado("um número"),
        }
    }

    /// Lista não vazia separada por vírgulas, sem vírgula final.
    fn list<T>(
        &mut self,
        mut item: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<Vec<T>, Error> {
        let mut out = vec![item(self)?];
        while self.is_punct(',') {
            self.advance();
            out.push(item(self)?);
        }
        Ok(out)
    }

    fn package(&mut self) -> Result<Package, Error> {
        self.kw("package")?;
        let name = self.path()?;
        self.punct('@')?;
        let major = self.int()?;
        self.punct('.')?;
        let minor = self.int()?;
        self.punct(';')?;
        let version = Version {
            major: u32::try_from(major.value).or_else(|_| self.err("versão grande demais"))?,
            minor: u32::try_from(minor.value).or_else(|_| self.err("versão grande demais"))?,
            pos: major.pos,
        };
        Ok(Package { name, version })
    }

    fn decl(&mut self) -> Result<Decl, Error> {
        if self.is_kw("type") {
            self.advance();
            let name = self.name()?;
            self.punct('=')?;
            let ty = self.ty(false)?;
            self.punct(';')?;
            return Ok(Decl::Alias(Alias { name, ty }));
        }
        if self.is_kw("open") {
            self.advance();
            self.kw("enum")?;
            return self.enum_body(true).map(Decl::Enum);
        }
        if self.is_kw("enum") {
            self.advance();
            return self.enum_body(false).map(Decl::Enum);
        }
        if self.is_kw("flags") {
            self.advance();
            return self.flags_body().map(Decl::Flags);
        }
        if self.is_kw("struct") {
            self.advance();
            return self.struct_body().map(Decl::Struct);
        }
        if self.is_kw("interface") {
            self.advance();
            return self.interface_body().map(Decl::Interface);
        }
        self.esperado("uma declaração (type, enum, flags, struct ou interface)")
    }

    fn repr(&mut self) -> Result<Repr, Error> {
        self.punct(':')?;
        let r = match self.tok() {
            Tok::Ident(s) if s == "u8" => Repr::U8,
            Tok::Ident(s) if s == "u16" => Repr::U16,
            Tok::Ident(s) if s == "u32" => Repr::U32,
            _ => return self.err("tipo-base deve ser u8, u16 ou u32"),
        };
        self.advance();
        Ok(r)
    }

    fn variant(&mut self, valor_obrigatorio: bool) -> Result<Variant, Error> {
        let name = self.name()?;
        let value = if self.is_punct('=') {
            self.advance();
            Some(self.int()?)
        } else if valor_obrigatorio {
            return Err(Error {
                pos: name.pos,
                msg: format!("bit '{}' sem valor (use '= n')", name.name),
            });
        } else {
            None
        };
        Ok(Variant { name, value })
    }

    fn enum_body(&mut self, open: bool) -> Result<Enum, Error> {
        let name = self.name()?;
        let repr = self.repr()?;
        self.punct('{')?;
        let variants = self.list(|p| p.variant(false))?;
        self.punct('}')?;
        Ok(Enum {
            name,
            repr,
            open,
            variants,
        })
    }

    fn flags_body(&mut self) -> Result<Flags, Error> {
        let name = self.name()?;
        let repr = self.repr()?;
        self.punct('{')?;
        let bits = self.list(|p| p.variant(true))?;
        self.punct('}')?;
        Ok(Flags { name, repr, bits })
    }

    fn struct_body(&mut self) -> Result<Struct, Error> {
        let name = self.name()?;
        self.punct('{')?;
        let fields = self.list(Self::field)?;
        self.punct('}')?;
        Ok(Struct { name, fields })
    }

    fn field(&mut self) -> Result<Field, Error> {
        let name = self.name()?;
        self.punct(':')?;
        let ty = self.ty(false)?;
        Ok(Field { name, ty })
    }

    fn interface_body(&mut self) -> Result<Interface, Error> {
        let name = self.name()?;
        self.punct('{')?;
        let mut methods = Vec::new();
        while !self.is_punct('}') {
            methods.push(self.method()?);
        }
        self.punct('}')?;
        Ok(Interface { name, methods })
    }

    fn method(&mut self) -> Result<Method, Error> {
        let mut annotations = Vec::new();
        while self.is_punct('@') {
            annotations.push(self.annotation()?);
        }
        let oneway = if self.is_kw("oneway") {
            self.advance();
            true
        } else {
            false
        };
        let name = self.name()?;
        self.punct('(')?;
        let params = if self.is_punct(')') {
            Vec::new()
        } else {
            self.list(Self::field)?
        };
        self.punct(')')?;
        let ret = if matches!(self.tok(), Tok::Arrow) {
            if oneway {
                return self.err("método oneway não tem '->'");
            }
            self.advance();
            Some(self.ret()?)
        } else {
            None
        };
        self.punct(';')?;
        Ok(Method {
            annotations,
            oneway,
            name,
            params,
            ret,
        })
    }

    fn annotation(&mut self) -> Result<Annotation, Error> {
        let pos = self.pos();
        self.punct('@')?;
        self.kw("tool")?;
        self.punct('(')?;
        self.kw("risk")?;
        self.punct('=')?;
        let risk = match self.tok() {
            Tok::Ident(s) => match s.as_str() {
                "R0" => Risk::R0,
                "R1" => Risk::R1,
                "R2" => Risk::R2,
                "R3" => Risk::R3,
                "R4" => Risk::R4,
                _ => return self.err("risco deve ser R0 a R4"),
            },
            _ => return self.esperado("R0 a R4"),
        };
        self.advance();
        self.punct(',')?;
        self.kw("desc")?;
        self.punct('=')?;
        let desc = match self.tok().clone() {
            Tok::Str(s) => {
                self.advance();
                s
            }
            _ => return self.esperado("um texto com a descrição"),
        };
        self.punct(')')?;
        Ok(Annotation::Tool { risk, desc, pos })
    }

    fn ret(&mut self) -> Result<Ret, Error> {
        self.kw("result")?;
        self.punct('<')?;
        let ok = self.ty(true)?;
        self.punct(',')?;
        let err = self.ty(false)?;
        self.punct('>')?;
        Ok(Ret { ok, err })
    }

    /// Tipo. `()` só é aceito quando `unit_ok` (sucesso de `result`).
    fn ty(&mut self, unit_ok: bool) -> Result<Type, Error> {
        if self.is_punct('(') {
            let start = self.pos();
            self.advance();
            self.punct(')')?;
            return if unit_ok {
                Ok(Type::Unit)
            } else {
                Err(Error {
                    pos: start,
                    msg: "'()' só vale como sucesso de result".into(),
                })
            };
        }
        let pos = self.pos();
        let Tok::Ident(word) = self.tok().clone() else {
            return self.esperado("um tipo");
        };
        let prim = match word.as_str() {
            "u8" => Some(Prim::U8),
            "u16" => Some(Prim::U16),
            "u32" => Some(Prim::U32),
            "u64" => Some(Prim::U64),
            "i8" => Some(Prim::I8),
            "i16" => Some(Prim::I16),
            "i32" => Some(Prim::I32),
            "i64" => Some(Prim::I64),
            "bool" => Some(Prim::Bool),
            _ => None,
        };
        if let Some(p) = prim {
            self.advance();
            return Ok(Type::Prim(p, pos));
        }
        match word.as_str() {
            "string" => {
                self.advance();
                self.punct('<')?;
                let max = self.int()?;
                self.punct('>')?;
                Ok(Type::String(max))
            }
            "vec" => {
                self.advance();
                self.punct('<')?;
                let elem = self.ty(false)?;
                self.punct(',')?;
                let max = self.int()?;
                self.punct('>')?;
                Ok(Type::Vec(Box::new(elem), max))
            }
            "handle" => {
                self.advance();
                self.punct('<')?;
                let target = self.path()?;
                self.punct('>')?;
                Ok(Type::Handle(target))
            }
            _ => Ok(Type::Named(self.path()?)),
        }
    }
}
