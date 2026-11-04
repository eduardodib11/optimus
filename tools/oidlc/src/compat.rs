//! Verificador de compatibilidade entre duas versões do mesmo pacote (ADR 0033,
//! seção 8; T-342). Regras:
//!
//! - Mudança de versão maior: livre (a interface nova ganha outro id).
//! - Versão menor: só acréscimo. Método novo entra no fim da interface; tipo
//!   novo; variante nova só em `enum` que era `open`. Qualquer outra mudança,
//!   inclusive mudar campo de struct (muda o layout), é incompatível.
//! - Acréscimo exige que a versão menor tenha subido.

use std::collections::HashMap;

use crate::ast::{Decl, Method, Prim, Type};
use crate::lexer::{Error, Pos};

/// Compara uma declaração de `antiga` com a de `nova`. Devolve `true` se a
/// mudança é só acréscimo (exige versão menor nova).
fn compara(d: &Decl, n: &Decl, erros: &mut Vec<Error>) -> bool {
    let nome = nome_decl(d);
    let mut aditivo = false;
    match (d, n) {
        (Decl::Alias(a), Decl::Alias(b)) if canon(&a.ty) != canon(&b.ty) => {
            incompativel(erros, b_pos(n), nome, "mudou de tipo");
        }
        (Decl::Struct(a), Decl::Struct(b)) => {
            if a.fields.len() != b.fields.len()
                || a.fields
                    .iter()
                    .zip(&b.fields)
                    .any(|(x, y)| x.name.name != y.name.name || canon(&x.ty) != canon(&y.ty))
            {
                incompativel(erros, b_pos(n), nome, "mudou os campos (muda o layout)");
            }
        }
        (Decl::Enum(a), Decl::Enum(b)) => {
            if a.repr != b.repr {
                incompativel(erros, b_pos(n), nome, "mudou o tipo-base");
            }
            let mut ok = true;
            for v in &a.variants {
                let vb = b.variants.iter().find(|x| x.name.name == v.name.name);
                if vb.is_none_or(|x| x.value.map(|l| l.value) != v.value.map(|l| l.value)) {
                    ok = false;
                }
            }
            if !ok {
                incompativel(erros, b_pos(n), nome, "removeu ou mudou uma variante");
            }
            if b.variants.len() > a.variants.len() {
                if a.open {
                    aditivo = true;
                } else {
                    incompativel(
                        erros,
                        b_pos(n),
                        nome,
                        "acrescentou variante em enum que não é 'open'",
                    );
                }
            }
        }
        (Decl::Flags(a), Decl::Flags(b)) => {
            let igual = a.repr == b.repr
                && a.bits.len() == b.bits.len()
                && a.bits.iter().zip(&b.bits).all(|(x, y)| {
                    x.name.name == y.name.name
                        && x.value.map(|l| l.value) == y.value.map(|l| l.value)
                });
            if !igual {
                incompativel(erros, b_pos(n), nome, "mudou os bits");
            }
        }
        (Decl::Interface(a), Decl::Interface(b)) => {
            for (i, m) in a.methods.iter().enumerate() {
                match b.methods.get(i) {
                    Some(mb) if assinatura(m) == assinatura(mb) => {}
                    Some(mb) => incompativel(
                        erros,
                        mb.name.pos,
                        nome,
                        &format!("mudou o método '{}'", m.name.name),
                    ),
                    None => incompativel(
                        erros,
                        b_pos(n),
                        nome,
                        &format!("removeu o método '{}'", m.name.name),
                    ),
                }
            }
            if b.methods.len() > a.methods.len() {
                aditivo = true;
            }
        }
        _ => incompativel(erros, b_pos(n), nome, "mudou de tipo de declaração"),
    }
    aditivo
}

/// Compara `antiga` com `nova` e devolve as mudanças incompatíveis.
#[must_use]
pub fn check_compat(antiga: &crate::ast::File, nova: &crate::ast::File) -> Vec<Error> {
    let mut erros = Vec::new();
    let (va, vn) = (antiga.package.version, nova.package.version);
    let pos = nova.package.version.pos;
    if antiga.package.name.name != nova.package.name.name {
        erros.push(Error {
            pos: nova.package.name.pos,
            msg: "o pacote mudou de nome".into(),
        });
        return erros;
    }
    if (vn.major, vn.minor) < (va.major, va.minor) {
        erros.push(Error {
            pos,
            msg: "a versão nova é menor que a antiga".into(),
        });
        return erros;
    }
    if vn.major != va.major {
        return erros;
    }
    let mut aditivo = false;
    let novos: HashMap<&str, &Decl> = nova.decls.iter().map(|d| (nome_decl(d), d)).collect();
    let velhos: HashMap<&str, &Decl> = antiga.decls.iter().map(|d| (nome_decl(d), d)).collect();

    for d in &antiga.decls {
        let nome = nome_decl(d);
        let Some(n) = novos.get(nome) else {
            erros.push(Error {
                pos: pos_decl(d),
                msg: format!("'{nome}' foi removido"),
            });
            continue;
        };
        aditivo |= compara(d, n, &mut erros);
    }
    for d in &nova.decls {
        if !velhos.contains_key(nome_decl(d)) {
            aditivo = true;
        }
    }
    if aditivo && vn.minor == va.minor {
        erros.push(Error {
            pos,
            msg: "acréscimo sem subir a versão menor".into(),
        });
    }
    erros
}

fn incompativel(erros: &mut Vec<Error>, pos: Pos, nome: &str, o_que: &str) {
    erros.push(Error {
        pos,
        msg: format!("incompatível: '{nome}' {o_que}"),
    });
}

fn b_pos(d: &Decl) -> Pos {
    pos_decl(d)
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

fn pos_decl(d: &Decl) -> Pos {
    match d {
        Decl::Alias(a) => a.name.pos,
        Decl::Enum(e) => e.name.pos,
        Decl::Flags(f) => f.name.pos,
        Decl::Struct(s) => s.name.pos,
        Decl::Interface(i) => i.name.pos,
    }
}

/// Assinatura de método sem posições: nome, parâmetros, retorno, `oneway`.
fn assinatura(m: &Method) -> String {
    let params: Vec<String> = m
        .params
        .iter()
        .map(|p| format!("{}:{}", p.name.name, canon(&p.ty)))
        .collect();
    let ret = m.ret.as_ref().map_or("-".into(), |r| {
        format!("result<{},{}>", canon(&r.ok), canon(&r.err))
    });
    format!(
        "{}{}({})->{ret}",
        if m.oneway { "oneway " } else { "" },
        m.name.name,
        params.join(",")
    )
}

/// Forma canônica de um tipo, sem posições, para comparar.
fn canon(t: &Type) -> String {
    match t {
        Type::Unit => "()".into(),
        Type::Prim(p, _) => nome_prim(*p).into(),
        Type::String(n) => format!("string<{}>", n.value),
        Type::Vec(e, n) => format!("vec<{},{}>", canon(e), n.value),
        Type::Named(id) => id.name.clone(),
        Type::Handle(id) => format!("handle<{}>", id.name),
    }
}

fn nome_prim(p: Prim) -> &'static str {
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
