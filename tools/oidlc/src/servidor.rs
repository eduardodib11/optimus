//! Gerador do servidor OIDL (T-344; ADR 0033, seções 2, 3 e 7).
//!
//! Para cada interface sai um `trait` com um método por `fn`, uma função
//! `despacha_<INTERFACE>` que confere o rótulo, valida e decodifica o pedido e
//! codifica a resposta, e as funções de codificação e decodificação dos
//! tipos. O código gerado usa só `oidl_rt` e `core`: serve a `no_std`.
//!
//! Limites desta versão do gerador: parâmetro com `vec` ainda não é
//! suportado (a decodificação de elementos com `string` dentro exige o
//! buffer de validação que o `oidl-rt` ainda não tem). `vec` em resposta é
//! suportado: o servidor escreve os elementos em ordem.

use std::fmt::Write as _;

use crate::ast::{Decl, Field, File, Method, Prim, Repr, Type};
use crate::ids::interface_id;
use crate::layout::Layouts;
use crate::lexer::{Error, Pos};

/// Modo de uso de um tipo: afeta o lifetime e a forma do tipo em Rust.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Modo {
    /// Campo de struct: empréstimos usam `'a`.
    Campo,
    /// Parâmetro ou retorno de método: lifetime elidido (`'_`).
    Elidido,
}

/// Gera o módulo de servidor de `file`.
///
/// # Errors
///
/// Tipo sem layout, parâmetro com `vec` ou `handle` fora da forma suportada.
pub fn gera_servidor(file: &File) -> Result<String, Vec<Error>> {
    let mut g = Gen {
        file,
        lay: Layouts::new(file),
        out: String::new(),
        erros: Vec::new(),
        n: 0,
    };
    g.prelude();
    g.tipos();
    g.interfaces();
    if g.erros.is_empty() {
        Ok(g.out)
    } else {
        Err(g.erros)
    }
}

struct Gen<'a> {
    file: &'a File,
    lay: Layouts<'a>,
    out: String,
    erros: Vec<Error>,
    n: usize,
}

impl Gen<'_> {
    fn pkg(&self) -> &str {
        &self.file.package.name.name
    }

    fn fresco(&mut self) -> usize {
        self.n += 1;
        self.n
    }

    fn erro(&mut self, pos: Pos, msg: impl Into<String>) {
        self.erros.push(Error {
            pos,
            msg: msg.into(),
        });
    }

    /// Declaração pelo nome, com o prefixo do próprio pacote tirado.
    fn decl(&self, nome: &str) -> Option<&Decl> {
        let simples = match nome.rsplit_once('.') {
            Some((p, s)) if p == self.pkg() => s,
            _ => nome,
        };
        self.file.decls.iter().find(|d| nome_decl(d) == simples)
    }

    /// Se o tipo nomeado precisa de `'a` (guarda empréstimo de corpo).
    fn tem_vida(&self, nome: &str) -> bool {
        match self.decl(nome) {
            Some(Decl::Struct(s)) => s.fields.iter().any(|c| ty_tem_vida(self, &c.ty)),
            Some(Decl::Alias(a)) => ty_tem_vida(self, &a.ty),
            _ => false,
        }
    }

    /// Tipo Rust de `t`. `None` se não há forma para ele (interface, externo).
    fn rs(&mut self, t: &Type, modo: Modo) -> Option<String> {
        let lt = match modo {
            Modo::Campo => "'a",
            Modo::Elidido => "'_",
        };
        Some(match t {
            Type::Unit => "()".into(),
            Type::Prim(p, _) => prim_rs(*p).into(),
            Type::String(_) => {
                if modo == Modo::Campo {
                    "&'a str".into()
                } else {
                    "&str".into()
                }
            }
            Type::Vec(elem, _) => {
                let e = self.rs(elem, modo)?;
                if modo == Modo::Campo {
                    format!("&'a [{e}]")
                } else {
                    format!("&[{e}]")
                }
            }
            Type::Handle(_) => "u64".into(),
            Type::Named(id) => return self.rs_nomeado(&id.name, modo, lt),
        })
    }

    fn rs_nomeado(&mut self, nome: &str, modo: Modo, lt: &str) -> Option<String> {
        if nome == "Timestamp" || nome.ends_with(".Timestamp") && !self.decl_local(nome) {
            return Some("i64".into());
        }
        let simples = match nome.rsplit_once('.') {
            Some((p, s)) if p == self.pkg() => s.to_string(),
            _ => nome.to_string(),
        };
        match self.decl(nome)? {
            Decl::Enum(_) | Decl::Flags(_) => Some(simples),
            Decl::Struct(_) => Some(if self.tem_vida(nome) {
                format!("{simples}<{lt}>")
            } else {
                simples
            }),
            Decl::Alias(a) => {
                let ty = a.ty.clone();
                self.rs(&ty, modo)
            }
            Decl::Interface(_) => None,
        }
    }

    fn decl_local(&self, nome: &str) -> bool {
        self.file.decls.iter().any(|d| nome_decl(d) == nome)
    }

    fn prelude(&mut self) {
        self.out.push_str(
            "// Gerado pelo oidlc a partir do arquivo .oidl. Não edite à mão.\n\
             //\n\
             // Layout e formato de fio: ADR 0033. Usa só `oidl_rt` e `core`.\n\n\
             #![allow(unused_parens, unused_variables, dead_code, clippy::double_parens, clippy::unreadable_literal, clippy::many_single_char_names, clippy::doc_markdown, clippy::unnecessary_wraps, clippy::too_many_arguments, clippy::trivially_copy_pass_by_ref, clippy::manual_let_else, clippy::elidable_lifetime_names, clippy::needless_lifetimes, clippy::explicit_auto_deref, clippy::needless_pass_by_value, reason = \"código gerado: estilo e campos que um serviço pode não usar\")]\n\n\
             use oidl_rt::{Error, Reader, Writer};\n\n\
             /// Contexto de uma chamada: o badge do remetente (ADR 0027).\n\
             pub struct Contexto {\n    /// Badge do endpoint que chamou.\n    pub badge: u64,\n}\n\n\
             /// Mensagem recebida.\n\
             pub struct Entrada<'a> {\n    /// Rótulo de 64 bits (ADR 0033, seção 2).\n    pub rotulo: u64,\n    /// Badge do remetente.\n    pub badge: u64,\n    /// Corpo recebido.\n    pub corpo: &'a [u8],\n    /// Capabilities recebidas, na ordem dos `handle` dos parâmetros.\n    pub caps: &'a [u64],\n}\n\n\
             /// Resposta a ser enviada: rótulo, bytes do corpo e capabilities.\n\
             pub struct Despacho {\n    /// Rótulo da resposta.\n    pub rotulo: u64,\n    /// Bytes escritos no buffer de saída.\n    pub corpo: usize,\n    /// Capabilities escritas em `caps_out`.\n    pub caps: usize,\n}\n\n\
             const fn rotulo_resposta(tipo: u8, codigo: u16) -> u64 {\n    ((tipo as u64 & 0b11) << 62) | codigo as u64\n}\n\n\
             /// Erro de protocolo (ADR 0033, seção 2): 1 UnknownInterface, 2 UnknownMethod,\n\
             /// 3 VersionTooOld, 4 BadMessage, 5 TooLarge.\n\
             fn protocolo(codigo: u16) -> Option<Despacho> {\n    Some(Despacho { rotulo: rotulo_resposta(2, codigo), corpo: 0, caps: 0 })\n}\n\n",
        );
    }

    fn tipos(&mut self) {
        let decls: Vec<Decl> = self.file.decls.clone();
        for d in &decls {
            match d {
                Decl::Enum(e) => {
                    let nome = e.name.name.clone();
                    let repr = repr_rs(e.repr);
                    let _ = writeln!(
                        self.out,
                        "/// Enumeração `{nome}`.\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct {nome}(pub {repr});\n\nimpl {nome} {{"
                    );
                    let mut prox = 0u64;
                    let mut valores = Vec::new();
                    for v in &e.variants {
                        let val = v.value.map_or(prox, |l| l.value);
                        prox = val.saturating_add(1);
                        let _ = writeln!(
                            self.out,
                            "    /// Variante `{}`.\n    pub const {}: {nome} = {nome}({val});",
                            v.name.name, v.name.name
                        );
                        valores.push(val);
                    }
                    let _ = writeln!(
                        self.out,
                        "    /// Converte o valor de fio; `None` se fora do conjunto."
                    );
                    if e.open {
                        let _ = writeln!(
                            self.out,
                            "    pub const fn from_raw(v: {repr}) -> Option<{nome}> {{\n        Some({nome}(v))\n    }}"
                        );
                    } else {
                        let lista: Vec<String> = valores.iter().map(u64::to_string).collect();
                        let _ = writeln!(
                            self.out,
                            "    pub fn from_raw(v: {repr}) -> Option<{nome}> {{\n        match v {{\n            {} => Some({nome}(v)),\n            _ => None,\n        }}\n    }}",
                            lista.join(" | ")
                        );
                    }
                    self.out.push_str("}\n\n");
                }
                Decl::Flags(f) => {
                    let nome = f.name.name.clone();
                    let repr = repr_rs(f.repr);
                    let mascara: u64 = f.bits.iter().filter_map(|b| b.value.map(|l| l.value)).sum();
                    let _ = writeln!(
                        self.out,
                        "/// Conjunto de bits `{nome}`.\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct {nome}(pub {repr});\n\nimpl {nome} {{"
                    );
                    for b in &f.bits {
                        if let Some(l) = b.value {
                            let _ = writeln!(
                                self.out,
                                "    /// Bit `{}`.\n    pub const {}: {nome} = {nome}({});",
                                b.name.name, b.name.name, l.value
                            );
                        }
                    }
                    let _ = writeln!(
                        self.out,
                        "    /// Converte o valor de fio; `None` se houver bit não declarado.\n    pub const fn from_raw(v: {repr}) -> Option<{nome}> {{\n        if v as u64 & !{mascara}u64 == 0 {{ Some({nome}(v)) }} else {{ None }}\n    }}\n}}\n"
                    );
                }
                Decl::Alias(_) | Decl::Interface(_) => {}
                Decl::Struct(s) => {
                    let nome = s.name.name.clone();
                    let lt = if self.tem_vida(&nome) { "<'a>" } else { "" };
                    let mut campos = String::new();
                    for c in &s.fields {
                        let Some(ty) = self.rs(&c.ty, Modo::Campo) else {
                            self.erro(
                                s.name.pos,
                                format!("campo '{}' de '{nome}' não tem tipo Rust", c.name.name),
                            );
                            continue;
                        };
                        let _ = writeln!(
                            campos,
                            "    /// Campo `{}`.\n    pub {}: {ty},",
                            c.name.name, c.name.name
                        );
                    }
                    let _ = writeln!(
                        self.out,
                        "/// Struct `{nome}`.\n#[derive(Clone, Copy, Debug, PartialEq, Eq)]\npub struct {nome}{lt} {{\n{campos}}}\n"
                    );
                    self.enc_struct(&nome, &s.fields.clone(), lt);
                }
            }
        }
    }

    /// `fn enc_<S>`: escreve os campos da struct a partir de `base`.
    fn enc_struct(&mut self, nome: &str, campos: &[Field], lt: &str) {
        let corpo = self.campos_enc(campos, "base", "v");
        let genericos = if lt.is_empty() { "" } else { "<'a>" };
        let sn = snake(nome);
        let _ = writeln!(
            self.out,
            "fn enc_{sn}{genericos}(w: &mut Writer<'_>, v: &{nome}{lt}, base: usize) -> Result<(), Error> {{\n{corpo}    Ok(())\n}}\n"
        );
    }

    /// Código que escreve `campos` de `v` (uma referência) a partir de `base`.
    fn campos_enc(&mut self, campos: &[Field], base: &str, v: &str) -> String {
        let mut s = String::new();
        let Ok(cab) = self.lay.cabeca_de(campos) else {
            self.erro(Pos { line: 1, col: 1 }, "layout de struct indisponível");
            return s;
        };
        for (c, campo) in cab.campos.iter().zip(campos) {
            let off = c.deslocamento;
            let at = if off == 0 {
                base.to_string()
            } else {
                format!("{base} + {off}")
            };
            let val = format!("&{v}.{}", campo.name.name);
            s.push_str(&self.enc(&campo.ty, &val, &at));
        }
        s
    }

    /// Código que escreve um valor (`val`, referência) de tipo `t` em `at`.
    fn enc(&mut self, t: &Type, val: &str, at: &str) -> String {
        match t {
            Type::Unit | Type::Handle(_) => String::new(),
            Type::Prim(p, _) => {
                let (m, cast) = prim_fio(*p);
                let v = valor(val);
                let expr = if cast.is_empty() {
                    v
                } else {
                    format!("({v}) as {cast}")
                };
                format!("    w.seek({at});\n    w.{m}({expr})?;\n")
            }
            Type::String(n) => format!(
                "    w.seek({at});\n    w.string({}, {})?;\n",
                valor(val),
                n.value
            ),
            Type::Vec(elem, n) => {
                let k = self.fresco();
                let esz = self.lay.medida(elem).map_or(0, |m| m.tamanho);
                let inner = self.enc(elem, "el", "at2");
                let lista = valor(val);
                format!(
                    "    let off{k} = {{ w.seek({at}); w.vec(({lista}).len(), {esz}, {})? }};\n    for (i{k}, el) in ({lista}).iter().enumerate() {{\n        let at2 = off{k} + i{k} * {esz};\n{}    }}\n",
                    n.value,
                    indenta(&inner)
                )
            }
            Type::Named(id) => self.enc_nomeado(&id.name, val, at),
        }
    }

    fn enc_nomeado(&mut self, nome: &str, val: &str, at: &str) -> String {
        if nome == "Timestamp" {
            return format!("    w.seek({at});\n    w.i64({})?;\n", valor(val));
        }
        match self.decl(nome) {
            Some(Decl::Enum(e)) => {
                let m = repr_metodo(e.repr);
                format!("    w.seek({at});\n    w.{m}(({val}).0)?;\n")
            }
            Some(Decl::Flags(f)) => {
                let m = repr_metodo(f.repr);
                format!("    w.seek({at});\n    w.{m}(({val}).0)?;\n")
            }
            Some(Decl::Struct(s)) => {
                let sn = snake(&s.name.name);
                format!("    enc_{sn}(w, {val}, {at})?;\n")
            }
            Some(Decl::Alias(a)) => {
                let ty = a.ty.clone();
                self.enc(&ty, val, at)
            }
            _ => {
                let msg = format!("tipo '{nome}' sem codificação");
                self.erro(Pos { line: 1, col: 1 }, msg);
                String::new()
            }
        }
    }

    /// Código que lê um valor de tipo `t` do leitor `r`, sequencialmente.
    fn dec(&mut self, t: &Type) -> Result<String, String> {
        Ok(match t {
            Type::Unit => "()".into(),
            Type::Prim(p, _) => dec_prim(*p),
            Type::String(n) => format!("r.string({})?", n.value),
            Type::Vec(..) => return Err("parâmetro com vec".into()),
            Type::Handle(_) => {
                "{ let h = caps.get(ci).copied().ok_or(Error::BadMessage)?; ci += 1; h }".into()
            }
            Type::Named(id) => return self.dec_nomeado(&id.name),
        })
    }

    fn dec_nomeado(&mut self, nome: &str) -> Result<String, String> {
        if nome == "Timestamp" {
            return Ok("r.i64()?".into());
        }
        let simples = match nome.rsplit_once('.') {
            Some((p, s)) if p == self.pkg() => s.to_string(),
            _ => nome.to_string(),
        };
        match self.decl(nome) {
            Some(Decl::Enum(e)) => {
                let _ = e;
                Ok(format!(
                    "{simples}::from_raw({}).ok_or(Error::BadMessage)?",
                    repr_leitura(self.decl(nome))
                ))
            }
            Some(Decl::Flags(_)) => Ok(format!(
                "{simples}::from_raw({}).ok_or(Error::BadMessage)?",
                repr_leitura(self.decl(nome))
            )),
            Some(Decl::Struct(s)) => {
                let campos = s.fields.clone();
                let mut partes = Vec::new();
                for c in &campos {
                    partes.push(format!("{}: {}", c.name.name, self.dec(&c.ty)?));
                }
                Ok(format!("{simples} {{ {} }}", partes.join(", ")))
            }
            Some(Decl::Alias(a)) => {
                let ty = a.ty.clone();
                self.dec(&ty)
            }
            _ => Err(format!("tipo '{nome}' sem decodificação")),
        }
    }
}

fn nome_decl(d: &Decl) -> &str {
    match d {
        Decl::Alias(a) => &a.name.name,
        Decl::Enum(e) => &e.name.name,
        Decl::Flags(f) => &f.name.name,
        Decl::Struct(s) => &s.name.name,
        Decl::Interface(i) => &i.name.name,
    }
}

fn ty_tem_vida(g: &Gen<'_>, t: &Type) -> bool {
    match t {
        Type::String(_) | Type::Vec(..) => true,
        Type::Named(id) => g.tem_vida(&id.name),
        _ => false,
    }
}

fn prim_rs(p: Prim) -> &'static str {
    match p {
        Prim::U8 => "u8",
        Prim::U16 => "u16",
        Prim::U32 => "u32",
        Prim::U64 => "u64",
        Prim::I8 => "i8",
        Prim::I16 => "i16",
        Prim::I32 => "i32",
        Prim::I64 => "i64",
        Prim::Bool => "bool",
    }
}

fn repr_rs(r: Repr) -> &'static str {
    match r {
        Repr::U8 => "u8",
        Repr::U16 => "u16",
        Repr::U32 => "u32",
    }
}

fn repr_metodo(r: Repr) -> &'static str {
    match r {
        Repr::U8 => "u8",
        Repr::U16 => "u16",
        Repr::U32 => "u32",
    }
}

/// Lê o tipo-base de um enum/flags do leitor, como `r.uN()?`.
fn repr_leitura(d: Option<&Decl>) -> String {
    let r = match d {
        Some(Decl::Enum(e)) => e.repr,
        Some(Decl::Flags(f)) => f.repr,
        _ => Repr::U8,
    };
    format!("r.{}()?", repr_metodo(r))
}

/// Método do `Writer` e cast, para um primitivo.
fn prim_fio(p: Prim) -> (&'static str, &'static str) {
    match p {
        Prim::U8 => ("u8", ""),
        Prim::U16 => ("u16", ""),
        Prim::U32 => ("u32", ""),
        Prim::U64 => ("u64", ""),
        Prim::I8 => ("u8", "u8"),
        Prim::I16 => ("u16", "u16"),
        Prim::I32 => ("u32", "u32"),
        Prim::I64 => ("i64", ""),
        Prim::Bool => ("bool", ""),
    }
}

fn dec_prim(p: Prim) -> String {
    match p {
        Prim::U8 => "r.u8()?".into(),
        Prim::U16 => "r.u16()?".into(),
        Prim::U32 => "r.u32()?".into(),
        Prim::U64 => "r.u64()?".into(),
        Prim::I8 => "r.u8()? as i8".into(),
        Prim::I16 => "r.u16()? as i16".into(),
        Prim::I32 => "r.u32()? as i32".into(),
        Prim::I64 => "r.i64()?".into(),
        Prim::Bool => "r.bool()?".into(),
    }
}

/// Nome em `snake_case` para as funções geradas (`DirEntry` vira `dir_entry`).
fn snake(nome: &str) -> String {
    let mut out = String::new();
    for (i, c) in nome.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Expressão de valor de uma referência `val`: `&x.f` vira `x.f`; `r` vira `(*r)`.
fn valor(val: &str) -> String {
    match val.strip_prefix('&') {
        Some(resto) => resto.to_string(),
        None => format!("(*{val})"),
    }
}

/// Indenta um bloco de código gerado em mais um nível.
fn indenta(s: &str) -> String {
    let mut out = String::new();
    for l in s.lines() {
        out.push_str("    ");
        out.push_str(l);
        out.push('\n');
    }
    out
}

impl Gen<'_> {
    /// Uma `trait`, funções de decodificação e de resposta e `despacha_<I>`
    /// por interface.
    fn interfaces(&mut self) {
        let decls: Vec<Decl> = self.file.decls.clone();
        for d in &decls {
            let Decl::Interface(i) = d else { continue };
            let nome = i.name.name.clone();
            let id = interface_id(self.pkg(), &nome, self.file.package.version.major);
            let up = nome.to_uppercase();
            let sn = snake(&nome);
            let _ = writeln!(
                self.out,
                "/// Identificador da interface `{nome}` (ADR 0033, seção 2).\npub const ID_{up}: u32 = {id:#010X};\n"
            );

            let mut trait_src =
                format!("/// Interface `{nome}`: implemente para servir.\npub trait {nome} {{\n");
            let mut resto = String::new();
            for (ordinal, m) in i.methods.iter().enumerate() {
                self.metodo(&snake(&nome), m, ordinal, &mut trait_src, &mut resto);
            }
            trait_src.push_str("}\n\n");
            self.out.push_str(&trait_src);
            self.out.push_str(&resto);
            self.despacho(&nome, &up, &sn, i.methods.as_slice());
        }
    }

    /// Assinatura na `trait`, decodificação de pedido e de resposta de um método.
    #[allow(clippy::too_many_lines)]
    fn metodo(
        &mut self,
        iface: &str,
        m: &Method,
        ordinal: usize,
        trait_src: &mut String,
        resto: &mut String,
    ) {
        let nome = m.name.name.clone();
        let mut params = Vec::new();
        let mut tipos_pedido = Vec::new();
        for p in &m.params {
            match self.rs(&p.ty, Modo::Elidido) {
                Some(t) => params.push(format!("{}: {t}", p.name.name)),
                None => self.erro(
                    p.name.pos,
                    format!("parâmetro '{}' de '{nome}' sem tipo Rust", p.name.name),
                ),
            }
            if let Type::Vec(..) = p.ty {
                self.erro(
                    p.name.pos,
                    format!(
                        "parâmetro '{}' de '{nome}' com vec ainda não é suportado",
                        p.name.name
                    ),
                );
            }
            if let Some(t) = self.rs(&p.ty, Modo::Campo) {
                tipos_pedido.push(t);
            }
        }
        let ret_tipo = match &m.ret {
            Some(r) => {
                let ok = self.rs(&r.ok, Modo::Elidido).unwrap_or_else(|| "()".into());
                let err = self
                    .rs(&r.err, Modo::Elidido)
                    .unwrap_or_else(|| "()".into());
                format!(" -> Result<{ok}, {err}>")
            }
            None => String::new(),
        };
        let mut assinatura = String::from("(&mut self, ctx: &Contexto");
        for p in &params {
            assinatura.push_str(", ");
            assinatura.push_str(p);
        }
        assinatura.push(')');
        let _ = writeln!(
            trait_src,
            "    /// Método `{nome}` (ordinal {ordinal}).\n    fn {nome}{assinatura}{ret_tipo};"
        );

        // Decodificação do pedido: `pedido_<n><'a>(r, caps)`.
        if !m.params.is_empty() {
            let mut partes = Vec::new();
            let mut usa_caps = false;
            for p in &m.params {
                if matches!(p.ty, Type::Handle(_)) {
                    usa_caps = true;
                }
                match self.dec(&p.ty) {
                    Ok(e) => partes.push(e),
                    Err(msg) => self.erro(p.name.pos, format!("'{nome}': {msg}")),
                }
            }
            let tipos = tipos_pedido.join(", ");
            let ci = if usa_caps {
                "    let mut ci = 0usize;\n"
            } else {
                ""
            };
            let _ = writeln!(
                resto,
                "fn pedido_{iface}_{ordinal}<'a>(r: &mut Reader<'a>, caps: &[u64]) -> Result<({tipos},), Error> {{\n{ci}    let _ = caps;\n    Ok(({},))\n}}\n",
                partes.join(", ")
            );
        }

        // Respostas: `resp_ok_<n>` e `resp_err_<n>`.
        if let Some(r) = &m.ret {
            let cab_ok = self
                .lay
                .cabeca_de(&[Field {
                    name: m.name.clone(),
                    ty: r.ok.clone(),
                }])
                .map_or(0, |c| c.tamanho);
            let cab_err = self
                .lay
                .cabeca_de(&[Field {
                    name: m.name.clone(),
                    ty: r.err.clone(),
                }])
                .map_or(0, |c| c.tamanho);
            for (lado, ty, cab) in [("ok", &r.ok, cab_ok), ("err", &r.err, cab_err)] {
                let corpo = self.enc(ty, "v", "0");
                let rust = self.rs(ty, Modo::Elidido).unwrap_or_else(|| "()".into());
                let sem_valor = matches!(ty, Type::Unit | Type::Handle(_));
                if sem_valor {
                    let _ = writeln!(
                        resto,
                        "fn resp_{lado}_{iface}_{ordinal}(saida: &mut [u8]) -> Result<usize, Error> {{\n    let w = Writer::new(saida, 0)?;\n    Ok(w.finish())\n}}\n"
                    );
                } else {
                    let _ = writeln!(
                        resto,
                        "fn resp_{lado}_{iface}_{ordinal}(saida: &mut [u8], v: &{rust}) -> Result<usize, Error> {{\n    let mut escritor = Writer::new(saida, {cab})?;\n    {{\n        let w = &mut escritor;\n{}    }}\n    Ok(escritor.finish())\n}}\n",
                        indenta(corpo.trim_end_matches('\n')) + "\n"
                    );
                }
            }
        }
    }

    /// `despacha_<I>`: confere o rótulo, valida o pedido, chama o método e
    /// codifica a resposta.
    fn despacho(&mut self, nome: &str, up: &str, sn: &str, metodos: &[Method]) {
        let minor = self.file.package.version.minor;
        let mut braços = String::new();
        for (ordinal, m) in metodos.iter().enumerate() {
            let chamada_args: Vec<String> = m
                .params
                .iter()
                .map(|p| format!("p_{}", p.name.name))
                .collect();
            let mut s = format!("        {ordinal} => {{\n");
            if minor > 0 {
                let _ = writeln!(
                    s,
                    "            if versao_menor < {minor} {{\n                return protocolo(3);\n            }}"
                );
            }
            let args = if chamada_args.is_empty() {
                String::new()
            } else {
                format!(", {}", chamada_args.join(", "))
            };
            if m.params.is_empty() {
                s.push_str("            if !e.corpo.is_empty() {\n                return protocolo(4);\n            }\n");
            } else {
                let cab = self
                    .lay
                    .metodo(m)
                    .map_or((0, 0), |(p, _)| (p.tamanho, p.pior_caso));
                let _ = writeln!(
                    s,
                    "            if e.corpo.len() as u64 > {} {{\n                return protocolo(5);\n            }}\n            let mut r = match Reader::new(e.corpo, {}) {{\n                Ok(r) => r,\n                Err(_) => return protocolo(4),\n            }};\n            let ({},) = match pedido_{sn}_{ordinal}(&mut r, e.caps) {{\n                Ok(x) => x,\n                Err(_) => return protocolo(4),\n            }};\n            if r.finish().is_err() {{\n                return protocolo(4);\n            }}",
                    cab.1,
                    cab.0,
                    chamada_args.join(", ")
                );
            }
            let _ = writeln!(s, "            let ctx = Contexto {{ badge: e.badge }};");
            let chamada = format!("s.{}(&ctx{args})", m.name.name);
            match &m.ret {
                None => {
                    let _ = writeln!(
                        s,
                        "            let _ = {chamada};\n            None\n        }}"
                    );
                }
                Some(r) => {
                    let ok_handle = matches!(r.ok, Type::Handle(_));
                    let ok_unit = matches!(r.ok, Type::Unit);
                    let braco_ok = if ok_unit {
                        format!(
                            "Ok(()) => match resp_ok_{sn}_{ordinal}(saida) {{\n                    Ok(n) => Some(Despacho {{ rotulo: rotulo_resposta(0, 0), corpo: n, caps: 0 }}),\n                    Err(_) => protocolo(5),\n                }},"
                        )
                    } else if ok_handle {
                        format!(
                            "Ok(x) => {{\n                    if caps_out.is_empty() {{\n                        return protocolo(5);\n                    }}\n                    caps_out[0] = x;\n                    match resp_ok_{sn}_{ordinal}(saida) {{\n                        Ok(n) => Some(Despacho {{ rotulo: rotulo_resposta(0, 0), corpo: n, caps: 1 }}),\n                        Err(_) => protocolo(5),\n                    }}\n                }},"
                        )
                    } else {
                        format!(
                            "Ok(x) => match resp_ok_{sn}_{ordinal}(saida, &x) {{\n                    Ok(n) => Some(Despacho {{ rotulo: rotulo_resposta(0, 0), corpo: n, caps: 0 }}),\n                    Err(_) => protocolo(5),\n                }},"
                        )
                    };
                    let _ = writeln!(
                        s,
                        "            match {chamada} {{\n                {braco_ok}\n                Err(x) => match resp_err_{sn}_{ordinal}(saida, &x) {{\n                    Ok(n) => Some(Despacho {{ rotulo: rotulo_resposta(1, 0), corpo: n, caps: 0 }}),\n                    Err(_) => protocolo(5),\n                }},\n            }}\n        }}"
                    );
                }
            }
            braços.push_str(&s);
        }
        let _ = writeln!(
            self.out,
            "/// Despacha uma mensagem para `{nome}`; `None` quando não há resposta (oneway).\n#[allow(clippy::too_many_lines)]\npub fn despacha_{sn}<S: {nome}>(s: &mut S, versao_menor: u16, e: &Entrada<'_>, saida: &mut [u8], caps_out: &mut [u64]) -> Option<Despacho> {{\n    if (e.rotulo >> 32) as u32 != ID_{up} {{\n        return protocolo(1);\n    }}\n    let _ = (&saida, &caps_out);\n    match (e.rotulo & 0xFFFF) as u16 {{\n{braços}        _ => protocolo(2),\n    }}\n}}\n"
        );
    }
}

/// Passa o código gerado pelo `rustfmt` do toolchain (a mesma formatação do
/// resto do repositório). Sem `rustfmt`, devolve o código como veio.
#[must_use]
pub fn formata(src: &str) -> String {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    let Ok(mut filho) = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    else {
        return src.to_string();
    };
    if let Some(mut entrada) = filho.stdin.take() {
        let _ = entrada.write_all(src.as_bytes());
    }
    match filho.wait_with_output() {
        Ok(saida) if saida.status.success() => {
            String::from_utf8(saida.stdout).unwrap_or_else(|_| src.to_string())
        }
        _ => src.to_string(),
    }
}

/// Gera o módulo de cliente de `file` (T-345): para cada interface, uma
/// struct `<Interface>Cliente` com um método por método da interface. Cada
/// método codifica o pedido, chama pelo `ostd::ipc::call_corpo` e decodifica
/// a resposta (ok ou erro, pelo tipo do rótulo).
///
/// Limites desta versão: parâmetros só de tipos por valor (primitivos,
/// `string`, `enum`, `flags` e tipos com `Timestamp`); `handle`, `vec`,
/// `struct` como parâmetro e `oneway` ainda não têm cliente.
///
/// # Errors
///
/// Tipo sem layout, parâmetro fora dos tipos por valor, `handle` na resposta.
pub fn gera_cliente(file: &File) -> Result<String, Vec<Error>> {
    let mut g = Gen {
        file,
        lay: Layouts::new(file),
        out: String::new(),
        erros: Vec::new(),
        n: 0,
    };
    g.prelude_cliente();
    g.tipos();
    g.clientes();
    if g.erros.is_empty() {
        Ok(g.out)
    } else {
        Err(g.erros)
    }
}

impl Gen<'_> {
    fn prelude_cliente(&mut self) {
        self.out.push_str(
            "// Gerado pelo oidlc a partir do arquivo .oidl. Não edite à mão.\n\
             //\n\
             // Cliente de IPC (T-345): cada chamada usa `ostd::ipc::call_corpo`.\n\n\
             #![allow(unused_parens, unused_variables, dead_code, clippy::double_parens, clippy::unreadable_literal, clippy::many_single_char_names, clippy::doc_markdown, clippy::unnecessary_wraps, clippy::too_many_arguments, clippy::trivially_copy_pass_by_ref, clippy::manual_let_else, clippy::elidable_lifetime_names, clippy::needless_lifetimes, clippy::explicit_auto_deref, clippy::needless_pass_by_value, reason = \"código gerado: estilo e campos que um serviço pode não usar\")]\n\n\
             use oidl_rt::{Error, Reader, Writer};\n\n\
             /// Erro de codificação ou decodificação vira erro de IPC.\n\
             fn erro_oidl(_: Error) -> ostd::kabi::Error {\n    ostd::kabi::Error::InvalidArgument\n}\n\n",
        );
    }

    /// Um tipo passa por valor no pedido se é primitivo, texto ou um enum,
    /// flags ou apelido deles (o codificador lê esses tipos por referência).
    fn por_valor(&self, t: &Type) -> bool {
        match t {
            Type::Prim(..) | Type::String(_) => true,
            Type::Named(id) => match self.decl(&id.name) {
                Some(Decl::Enum(_) | Decl::Flags(_)) => true,
                Some(Decl::Alias(a)) => self.por_valor(&a.ty),
                _ => id.name == "Timestamp",
            },
            Type::Unit | Type::Vec(..) | Type::Handle(_) => false,
        }
    }

    fn clientes(&mut self) {
        let decls: Vec<Decl> = self.file.decls.clone();
        let minor = u16::try_from(self.file.package.version.minor).unwrap_or(u16::MAX);
        for d in &decls {
            let Decl::Interface(i) = d else { continue };
            let nome = i.name.name.clone();
            let id = interface_id(self.pkg(), &nome, self.file.package.version.major);
            let sn = snake(&nome);
            let mut metodos = String::new();
            let mut auxiliares = String::new();
            for (ordinal, m) in i.methods.iter().enumerate() {
                let ordinal = u16::try_from(ordinal).unwrap_or(u16::MAX);
                self.metodo_cliente(&sn, id, minor, ordinal, m, &mut metodos, &mut auxiliares);
            }
            let _ = writeln!(
                self.out,
                "/// Cliente da interface `{nome}` (T-345).\npub struct {nome}Cliente {{\n    /// Endpoint para onde as chamadas vão.\n    pub ep: ostd::kabi::Handle,\n}}\n\nimpl {nome}Cliente {{\n    /// Cliente para `ep`.\n    #[must_use]\n    pub const fn new(ep: ostd::kabi::Handle) -> Self {{\n        Self {{ ep }}\n    }}\n{metodos}}}\n"
            );
            self.out.push_str(&auxiliares);
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn metodo_cliente(
        &mut self,
        sn: &str,
        id: u32,
        minor: u16,
        ordinal: u16,
        m: &Method,
        metodos: &mut String,
        aux: &mut String,
    ) {
        let nome = m.name.name.clone();
        let Some(ret) = &m.ret else {
            self.erro(
                m.name.pos,
                format!("'{nome}': método sem resultado não tem cliente ainda"),
            );
            return;
        };
        if m.oneway {
            self.erro(
                m.name.pos,
                format!("'{nome}': oneway não tem cliente ainda"),
            );
            return;
        }
        let (pedido, resposta) = match self.lay.metodo(m) {
            Ok((p, Some((ok, err)))) => (p, (ok, err)),
            Ok((_, None)) => return,
            Err(msg) => {
                self.erro(m.name.pos, format!("'{nome}': {msg}"));
                return;
            }
        };
        let (cab_ok, cab_err) = resposta;
        let mut assinatura_pub = String::new();
        let mut assinatura_aux = String::new();
        let mut chamada = String::new();
        for p in &m.params {
            if !self.por_valor(&p.ty) {
                self.erro(
                    p.name.pos,
                    format!(
                        "parâmetro '{}' de '{nome}' não é de tipo por valor",
                        p.name.name
                    ),
                );
                return;
            }
            let Some(rust) = self.rs(&p.ty, Modo::Elidido) else {
                self.erro(
                    p.name.pos,
                    format!("parâmetro '{}' de '{nome}' sem tipo Rust", p.name.name),
                );
                return;
            };
            let _ = write!(assinatura_pub, ", {}: {rust}", p.name.name);
            let _ = write!(assinatura_aux, ", {}: &{rust}", p.name.name);
            let _ = write!(chamada, ", &{}", p.name.name);
        }
        let mut enc = String::new();
        if let Ok(cab) = self.lay.cabeca_de(&m.params) {
            for (c, p) in cab.campos.iter().zip(&m.params) {
                let at = c.deslocamento.to_string();
                enc.push_str(&self.enc(&p.ty, &p.name.name, &at));
            }
        }
        let mutavel = if m.params.is_empty() { "" } else { "mut " };
        let _ = writeln!(
            aux,
            "fn codifica_{sn}_{ordinal}(saida: &mut [u8]{assinatura_aux}) -> Result<usize, Error> {{\n    let {mutavel}w = Writer::new(saida, {})?;\n{enc}    Ok(w.finish())\n}}\n",
            pedido.tamanho
        );

        let ok_rust = match &m.ret {
            Some(r) if matches!(r.ok, Type::Unit) => "()".to_string(),
            Some(r) => match self.rs(&r.ok, Modo::Elidido) {
                Some(t) => t,
                None => return self.erro(m.name.pos, format!("'{nome}': resposta sem tipo Rust")),
            },
            None => "()".to_string(),
        };
        let err_rust = match &m.ret {
            Some(r) if matches!(r.err, Type::Unit) => "()".to_string(),
            Some(r) => match self.rs(&r.err, Modo::Elidido) {
                Some(t) => t,
                None => return self.erro(m.name.pos, format!("'{nome}': erro sem tipo Rust")),
            },
            None => "()".to_string(),
        };
        if matches!(ret.ok, Type::Handle(_)) || matches!(ret.err, Type::Handle(_)) {
            self.erro(
                m.name.pos,
                format!("'{nome}': resposta com handle ainda não tem cliente"),
            );
            return;
        }
        for (lado, ty, cab, rust) in [
            ("ok", &ret.ok, cab_ok.tamanho, &ok_rust),
            ("err", &ret.err, cab_err.tamanho, &err_rust),
        ] {
            let corpo = if matches!(ty, Type::Unit) {
                String::from("    let _ = corpo;\n")
            } else {
                match self.dec(ty) {
                    Ok(e) => format!("    let v = {e};\n"),
                    Err(msg) => return self.erro(m.name.pos, format!("'{nome}': {msg}")),
                }
            };
            let valor = if matches!(ty, Type::Unit) {
                "Ok(())"
            } else {
                "Ok(v)"
            };
            let mutavel_r = if matches!(ty, Type::Unit) { "" } else { "mut " };
            let _ = writeln!(
                aux,
                "fn decodifica_{lado}_{sn}_{ordinal}(corpo: &[u8]) -> Result<{rust}, Error> {{\n    let {mutavel_r}r = Reader::new(corpo, {cab})?;\n{corpo}    r.finish()?;\n    {valor}\n}}\n"
            );
        }

        let rotulo = crate::ids::rotulo_pedido(id, minor, ordinal);
        let tam_pedido = tamanho_buffer(pedido.tamanho, pedido.pior_caso);
        let tam_resposta = tamanho_buffer(cab_ok.tamanho, cab_ok.pior_caso)
            .max(tamanho_buffer(cab_err.tamanho, cab_err.pior_caso));
        let _ = writeln!(
            metodos,
            "    /// Método `{nome}` (ordinal {ordinal}).\n    pub fn {nome}(&self, buf: &mut ostd::ipc::Buffer{assinatura_pub}) -> Result<Result<{ok_rust}, {err_rust}>, ostd::kabi::Error> {{\n        let mut pedido = [0u8; {tam_pedido}];\n        let n = codifica_{sn}_{ordinal}(&mut pedido{chamada}).map_err(erro_oidl)?;\n        let mut saida = [0u8; {tam_resposta}];\n        let (rotulo, m) = ostd::ipc::call_corpo(self.ep, buf, {rotulo:#018X}, &pedido[..n], &mut saida, 0)?;\n        if rotulo >> 62 == 0 {{\n            Ok(Ok(decodifica_ok_{sn}_{ordinal}(&saida[..m]).map_err(erro_oidl)?))\n        }} else {{\n            Ok(Err(decodifica_err_{sn}_{ordinal}(&saida[..m]).map_err(erro_oidl)?))\n        }}\n    }}\n"
        );
    }
}

/// Tamanho de buffer para um corpo: o maior entre a cabeça e o pior caso,
/// arredondado a 8 bytes.
fn tamanho_buffer(cabeca: u64, pior: u64) -> u64 {
    cabeca.max(pior).div_ceil(8) * 8
}
