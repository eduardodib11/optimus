//! Esquemas de ferramentas para a IA (T-346; ADR 0033, `@tool`).
//!
//! Só entram os métodos com `@tool(risk, desc)`: a IA só chama o que o
//! protocolo declarou como ferramenta, com a classe de risco revisada. A saída
//! é um JSON estável, com um item por método na ordem da declaração.

use crate::ast::{Annotation, Decl, Field, File, Method, Prim, Risk, Type};
use crate::lexer::{Error, Pos};
use std::fmt::Write;

/// Valor JSON mínimo, para não depender de crate externa na ferramenta.
enum Json {
    Nulo,
    Bool(bool),
    Int(i128),
    Texto(String),
    Lista(Vec<Json>),
    Objeto(Vec<(String, Json)>),
}

/// Gera os esquemas das ferramentas de `file`, em JSON com dois espaços.
///
/// # Errors
///
/// Tipo sem forma de esquema (interface como valor, nome externo).
pub fn gera_esquemas(file: &File) -> Result<String, Vec<Error>> {
    let mut ferramentas = Vec::new();
    let mut erros = Vec::new();
    for d in &file.decls {
        let Decl::Interface(i) = d else { continue };
        for m in &i.methods {
            let Some((risco, desc)) = ferramenta(m) else {
                continue;
            };
            let nome = format!("{}.{}.{}", file.package.name.name, i.name.name, m.name.name);
            let mut ctx = Ctx {
                file,
                erros: &mut erros,
            };
            let entrada = ctx.objeto_params(&m.params);
            let saida = match &m.ret {
                Some(r) => ctx.tipo(&r.ok, m.name.pos),
                None => Json::Nulo,
            };
            let erro = match &m.ret {
                Some(r) => ctx.tipo(&r.err, m.name.pos),
                None => Json::Nulo,
            };
            ferramentas.push(Json::Objeto(vec![
                ("nome".into(), Json::Texto(nome)),
                ("descricao".into(), Json::Texto(desc)),
                ("risco".into(), Json::Texto(risco)),
                ("entrada".into(), entrada),
                ("saida".into(), saida),
                ("erro".into(), erro),
            ]));
        }
    }
    if !erros.is_empty() {
        return Err(erros);
    }
    let raiz = Json::Objeto(vec![
        (
            "pacote".into(),
            Json::Texto(format!(
                "{}@{}.{}",
                file.package.name.name, file.package.version.major, file.package.version.minor
            )),
        ),
        ("ferramentas".into(), Json::Lista(ferramentas)),
    ]);
    let mut out = String::new();
    escreve(&raiz, 0, &mut out);
    out.push('\n');
    Ok(out)
}

/// Risco e descrição do método, se ele é ferramenta.
fn ferramenta(m: &Method) -> Option<(String, String)> {
    let a = m.annotations.first()?;
    let Annotation::Tool { risk, desc, .. } = a;
    Some((risco_texto(*risk).to_string(), desc.clone()))
}

fn risco_texto(r: Risk) -> &'static str {
    match r {
        Risk::R0 => "R0",
        Risk::R1 => "R1",
        Risk::R2 => "R2",
        Risk::R3 => "R3",
        Risk::R4 => "R4",
    }
}

struct Ctx<'a> {
    file: &'a File,
    erros: &'a mut Vec<Error>,
}

impl Ctx<'_> {
    fn objeto_params(&mut self, params: &[Field]) -> Json {
        let mut props = Vec::new();
        let mut req = Vec::new();
        for p in params {
            props.push((p.name.name.clone(), self.tipo(&p.ty, p.name.pos)));
            req.push(Json::Texto(p.name.name.clone()));
        }
        Json::Objeto(vec![
            ("tipo".into(), Json::Texto("object".into())),
            ("propriedades".into(), Json::Objeto(props)),
            ("obrigatorios".into(), Json::Lista(req)),
            ("adicionais".into(), Json::Bool(false)),
        ])
    }

    /// Esquema JSON de um tipo.
    fn tipo(&mut self, t: &Type, pos: Pos) -> Json {
        match t {
            Type::Unit => Json::Nulo,
            Type::Prim(p, _) => prim(*p),
            Type::String(n) => Json::Objeto(vec![
                ("tipo".into(), Json::Texto("string".into())),
                ("tamanhoMaximo".into(), Json::Int(i128::from(n.value))),
            ]),
            Type::Vec(e, n) => {
                let items = self.tipo(e, pos);
                Json::Objeto(vec![
                    ("tipo".into(), Json::Texto("array".into())),
                    ("itens".into(), items),
                    ("tamanhoMaximo".into(), Json::Int(i128::from(n.value))),
                ])
            }
            Type::Handle(_) => Json::Objeto(vec![
                ("tipo".into(), Json::Texto("string".into())),
                (
                    "descricao".into(),
                    Json::Texto("referência a objeto (capability); não é valor livre".into()),
                ),
            ]),
            Type::Named(id) => self.nomeado(&id.name, pos),
        }
    }

    fn nomeado(&mut self, nome: &str, pos: Pos) -> Json {
        let simples = match nome.rsplit_once('.') {
            Some((p, s)) if p == self.file.package.name.name => s,
            _ => nome,
        };
        let local = self.file.decls.iter().any(|d| nome_decl(d) == simples);
        if simples == "Timestamp" && !local {
            return Json::Objeto(vec![
                ("tipo".into(), Json::Texto("integer".into())),
                (
                    "descricao".into(),
                    Json::Texto("nanossegundos desde 1970-01-01 UTC".into()),
                ),
            ]);
        }
        let decl = self.file.decls.iter().find(|d| nome_decl(d) == simples);
        match decl {
            Some(Decl::Enum(e)) => {
                let valores: Vec<Json> = e
                    .variants
                    .iter()
                    .map(|v| Json::Texto(v.name.name.clone()))
                    .collect();
                let mut campos = vec![
                    ("tipo".into(), Json::Texto("string".into())),
                    ("valores".into(), Json::Lista(valores)),
                ];
                if e.open {
                    campos.push((
                        "descricao".into(),
                        Json::Texto("enumeração aberta: valores novos podem aparecer".into()),
                    ));
                }
                Json::Objeto(campos)
            }
            Some(Decl::Flags(f)) => {
                let bits: Vec<Json> = f
                    .bits
                    .iter()
                    .map(|b| Json::Texto(b.name.name.clone()))
                    .collect();
                Json::Objeto(vec![
                    ("tipo".into(), Json::Texto("array".into())),
                    (
                        "itens".into(),
                        Json::Objeto(vec![
                            ("tipo".into(), Json::Texto("string".into())),
                            ("valores".into(), Json::Lista(bits)),
                        ]),
                    ),
                    ("unicos".into(), Json::Bool(true)),
                ])
            }
            Some(Decl::Struct(s)) => {
                let campos = s.fields.clone();
                self.objeto_params(&campos)
            }
            Some(Decl::Alias(a)) => {
                let ty = a.ty.clone();
                self.tipo(&ty, pos)
            }
            _ => {
                self.erros.push(Error {
                    pos,
                    msg: format!("tipo '{nome}' sem esquema"),
                });
                Json::Nulo
            }
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

fn prim(p: Prim) -> Json {
    let (tipo, min, max): (&str, i128, i128) = match p {
        Prim::Bool => return Json::Objeto(vec![("tipo".into(), Json::Texto("boolean".into()))]),
        Prim::U8 => ("integer", 0, i128::from(u8::MAX)),
        Prim::U16 => ("integer", 0, i128::from(u16::MAX)),
        Prim::U32 => ("integer", 0, i128::from(u32::MAX)),
        Prim::U64 => ("integer", 0, i128::from(u64::MAX)),
        Prim::I8 => ("integer", i128::from(i8::MIN), i128::from(i8::MAX)),
        Prim::I16 => ("integer", i128::from(i16::MIN), i128::from(i16::MAX)),
        Prim::I32 => ("integer", i128::from(i32::MIN), i128::from(i32::MAX)),
        Prim::I64 => ("integer", i128::from(i64::MIN), i128::from(i64::MAX)),
    };
    Json::Objeto(vec![
        ("tipo".into(), Json::Texto(tipo.into())),
        ("minimo".into(), Json::Int(min)),
        ("maximo".into(), Json::Int(max)),
    ])
}

/// Escreve `j` com dois espaços por nível.
fn escreve(j: &Json, nivel: usize, out: &mut String) {
    let pad = "  ".repeat(nivel + 1);
    let fim = "  ".repeat(nivel);
    match j {
        Json::Nulo => out.push_str("null"),
        Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Json::Int(n) => out.push_str(&n.to_string()),
        Json::Texto(s) => escreve_texto(s, out),
        Json::Lista(v) if v.is_empty() => out.push_str("[]"),
        Json::Lista(v) => {
            out.push_str("[\n");
            for (i, x) in v.iter().enumerate() {
                out.push_str(&pad);
                escreve(x, nivel + 1, out);
                if i + 1 < v.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&fim);
            out.push(']');
        }
        Json::Objeto(v) if v.is_empty() => out.push_str("{}"),
        Json::Objeto(v) => {
            out.push_str("{\n");
            for (i, (k, x)) in v.iter().enumerate() {
                out.push_str(&pad);
                escreve_texto(k, out);
                out.push_str(": ");
                escreve(x, nivel + 1, out);
                if i + 1 < v.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&fim);
            out.push('}');
        }
    }
}

fn escreve_texto(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
