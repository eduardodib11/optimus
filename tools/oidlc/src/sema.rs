//! Análise semântica do OIDL (T-342; ADR 0033, seções 1, 4 e 8).
//!
//! Confere o que a gramática não vê: nomes resolvidos e únicos, limites
//! positivos, `handle<T>` só onde a ADR 0033 permite, até 4 capabilities por
//! método, métodos `oneway` sem resposta, tipos que se contêm sem fim e os
//! valores de `enum` e `flags` dentro do tipo-base. Também tem o verificador
//! de compatibilidade entre duas versões (`check-compat`).
//!
//! `Timestamp` é o apelido predefinido de `optimus.core` (`i64`, ns UTC). Um
//! nome pontuado cujo prefixo é outro pacote é externo: é aceito, e a checagem
//! dele fica com o pacote dono.

use std::collections::{HashMap, HashSet};

use crate::ast::{Annotation, Decl, Enum, Field, File, Flags, Interface, Method, Repr, Type};
use crate::lexer::{Error, Pos};

/// Objetos do kernel que `handle<T>` pode nomear (ADR 0033, seção 1).
const OBJETOS_KERNEL: &[&str] = &[
    "MemoryObject",
    "Notification",
    "Endpoint",
    "Reply",
    "MemoryQuota",
    "CapSpace",
    "AddressSpace",
    "Thread",
    "SchedContext",
];

/// Máximo de capabilities por método, pedido e resposta somados (ADR 0033, seção 4).
const MAX_CAPS: usize = 4;

/// Máximo de métodos por interface: o ordinal cabe em 16 bits (ADR 0033, seção 2).
const MAX_METODOS: usize = 1 << 16;

/// Tipo declarado no arquivo, com a posição do nome.
#[derive(Clone, Copy)]
enum Kind<'a> {
    Alias,
    Enum,
    Flags,
    Struct(&'a crate::ast::Struct),
    Interface,
}

/// Confere o arquivo e devolve todos os erros, na ordem em que aparecem.
/// Lista vazia significa que o arquivo está semanticamente correto.
#[must_use]
pub fn analyze(file: &File) -> Vec<Error> {
    let mut sema = Sema {
        pkg: &file.package.name.name,
        decls: HashMap::new(),
        errs: Vec::new(),
    };
    for d in &file.decls {
        let (name, kind) = match d {
            Decl::Alias(a) => (&a.name, Kind::Alias),
            Decl::Enum(e) => (&e.name, Kind::Enum),
            Decl::Flags(f) => (&f.name, Kind::Flags),
            Decl::Struct(s) => (&s.name, Kind::Struct(s)),
            Decl::Interface(i) => (&i.name, Kind::Interface),
        };
        if sema.decls.insert(name.name.as_str(), kind).is_some() {
            sema.erro(
                name.pos,
                format!("'{}' declarado mais de uma vez", name.name),
            );
        }
    }
    for d in &file.decls {
        match d {
            Decl::Alias(a) => sema.tipo(&a.ty, Ctx::Campo),
            Decl::Enum(e) => sema.enumeracao(e),
            Decl::Flags(f) => sema.bits(f),
            Decl::Struct(s) => sema.campos(&s.fields, "campo"),
            Decl::Interface(i) => sema.interface(i),
        }
    }
    sema.ciclos();
    sema.errs
}

/// Onde um tipo aparece: afeta o que `handle<T>` pode fazer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    /// Parâmetro de método (o `handle` é o topo do campo).
    Parametro,
    /// Sucesso de `result` (o `handle` é o tipo de topo).
    Sucesso,
    /// Campo de struct, erro de `result`, elemento de `vec`, alias.
    Campo,
}

struct Sema<'a> {
    pkg: &'a str,
    decls: HashMap<&'a str, Kind<'a>>,
    errs: Vec<Error>,
}

impl<'a> Sema<'a> {
    fn erro(&mut self, pos: Pos, msg: impl Into<String>) {
        self.errs.push(Error {
            pos,
            msg: msg.into(),
        });
    }

    fn enumeracao(&mut self, e: &Enum) {
        let max = repr_max(e.repr);
        let mut proximo: u64 = 0;
        let mut vistos = HashSet::new();
        self.nomes_unicos(e.variants.iter().map(|x| &x.name), "variante");
        for v in &e.variants {
            let valor = v.value.map_or(proximo, |l| l.value);
            if valor > max {
                let pos = v.value.map_or(v.name.pos, |l| l.pos);
                self.erro(
                    pos,
                    format!("valor {valor} não cabe no tipo-base de '{}'", e.name.name),
                );
            }
            if !vistos.insert(valor) {
                self.erro(
                    v.name.pos,
                    format!("valor {valor} repetido em '{}'", e.name.name),
                );
            }
            proximo = valor.saturating_add(1);
        }
    }

    fn bits(&mut self, f: &Flags) {
        let max = repr_max(f.repr);
        let mut vistos = HashSet::new();
        for b in &f.bits {
            let Some(l) = b.value else { continue };
            if l.value == 0 || !l.value.is_power_of_two() || l.value > max {
                self.erro(
                    l.pos,
                    format!(
                        "bit de '{}' deve ser uma potência de dois que caiba no tipo-base",
                        f.name.name
                    ),
                );
            } else if !vistos.insert(l.value) {
                self.erro(
                    l.pos,
                    format!("bit {} repetido em '{}'", l.value, f.name.name),
                );
            }
        }
        self.nomes_unicos(f.bits.iter().map(|x| &x.name), "bit");
    }

    fn campos(&mut self, campos: &[Field], o_que: &str) {
        self.nomes_unicos(campos.iter().map(|c| &c.name), o_que);
        for c in campos {
            self.tipo(&c.ty, Ctx::Campo);
        }
    }

    fn nomes_unicos<'b>(
        &mut self,
        nomes: impl Iterator<Item = &'b crate::ast::Ident>,
        o_que: &str,
    ) {
        let mut vistos = HashSet::new();
        for n in nomes {
            if !vistos.insert(n.name.as_str()) {
                let msg = format!("{o_que} '{}' repetido", n.name);
                self.erro(n.pos, msg);
            }
        }
    }

    fn interface(&mut self, i: &Interface) {
        if i.methods.len() > MAX_METODOS {
            self.erro(
                i.name.pos,
                format!(
                    "'{}' tem métodos demais (máximo {MAX_METODOS})",
                    i.name.name
                ),
            );
        }
        self.nomes_unicos(i.methods.iter().map(|m| &m.name), "método");
        for m in &i.methods {
            self.metodo(m);
        }
    }

    fn metodo(&mut self, m: &Method) {
        let tools = m
            .annotations
            .iter()
            .filter(|a| matches!(a, Annotation::Tool { .. }))
            .count();
        if tools > 1 {
            self.erro(
                m.name.pos,
                format!("método '{}' com @tool repetido", m.name.name),
            );
        }
        self.nomes_unicos(m.params.iter().map(|p| &p.name), "parâmetro");
        let mut caps = 0;
        for p in &m.params {
            self.tipo(&p.ty, Ctx::Parametro);
            caps += conta_handles(&p.ty);
        }
        match &m.ret {
            Some(r) => {
                self.tipo(&r.ok, Ctx::Sucesso);
                self.tipo(&r.err, Ctx::Campo);
                caps += conta_handles(&r.ok) + conta_handles(&r.err);
            }
            None if !m.oneway => self.erro(
                m.name.pos,
                format!(
                    "método '{}' sem resultado: declare '-> result<T, E>' ou marque 'oneway'",
                    m.name.name
                ),
            ),
            None => {}
        }
        if caps > MAX_CAPS {
            self.erro(
                m.name.pos,
                format!(
                    "método '{}' passa do limite de {MAX_CAPS} capabilities ({caps} handle)",
                    m.name.name
                ),
            );
        }
    }

    /// Confere um tipo. `ctx` diz se um `handle` é permitido aqui.
    fn tipo(&mut self, t: &Type, ctx: Ctx) {
        match t {
            Type::Unit | Type::Prim(..) => {}
            Type::String(max) => {
                if max.value == 0 {
                    self.erro(
                        max.pos,
                        "string<0> não guarda nada; o limite deve ser maior que zero",
                    );
                }
            }
            Type::Vec(elem, max) => {
                if max.value == 0 {
                    self.erro(
                        max.pos,
                        "vec<T, 0> não guarda nada; o limite deve ser maior que zero",
                    );
                }
                if contem_handle(elem) {
                    self.erro(
                        max.pos,
                        "handle não pode aparecer dentro de vec (ADR 0033, seção 1)",
                    );
                }
                self.tipo(elem, Ctx::Campo);
            }
            Type::Named(id) => self.nome(&id.name, id.pos),
            Type::Handle(alvo) => {
                if ctx == Ctx::Campo {
                    self.erro(
                        alvo.pos,
                        "handle só pode ser parâmetro ou o sucesso de um result",
                    );
                }
                self.alvo_handle(&alvo.name, alvo.pos);
            }
        }
    }

    fn nome(&mut self, nome: &str, pos: Pos) {
        if self.resolve_local(nome).is_some() || self.externo(nome) || nome == "Timestamp" {
            return;
        }
        self.erro(pos, format!("tipo desconhecido '{nome}'"));
    }

    fn alvo_handle(&mut self, nome: &str, pos: Pos) {
        if self.externo(nome) || OBJETOS_KERNEL.contains(&nome) {
            return;
        }
        match self.decls.get(nome) {
            Some(Kind::Interface) => {}
            Some(_) => self.erro(pos, format!("handle<{nome}>: '{nome}' não é interface")),
            None => self.erro(pos, format!("handle<{nome}>: tipo desconhecido")),
        }
    }

    /// Nome pontuado de outro pacote: prefixo diferente do pacote deste arquivo.
    fn externo(&self, nome: &str) -> bool {
        nome.rsplit_once('.')
            .is_some_and(|(prefixo, _)| prefixo != self.pkg)
    }

    /// Nome local: sem ponto, ou com o prefixo do próprio pacote.
    fn resolve_local(&self, nome: &str) -> Option<Kind<'a>> {
        let simples = simples_local(self.pkg, nome);
        if simples.contains('.') {
            return None;
        }
        self.decls.get(simples).copied()
    }

    /// Recusa struct que contenha a si mesma por valor (direta, por alias ou
    /// por `vec`): o tamanho máximo não teria limite.
    fn ciclos(&mut self) {
        let mut nomes: Vec<&str> = self.decls.keys().copied().collect();
        nomes.sort_unstable();
        let mut estado: HashMap<String, u8> = HashMap::new();
        for nome in nomes {
            let mut caminho = Vec::new();
            if let Some(pos) = self.visita(nome, &mut estado, &mut caminho) {
                self.erro(
                    pos,
                    format!("'{nome}' contém a si mesmo: tipo recursivo sem limite"),
                );
            }
        }
    }

    /// DFS sobre structs: `1` marca o caminho em curso e `2` o que já foi
    /// visto. Achar um `1` de novo é ciclo; devolve a posição da struct.
    fn visita(
        &self,
        nome: &str,
        estado: &mut HashMap<String, u8>,
        caminho: &mut Vec<String>,
    ) -> Option<Pos> {
        match estado.get(nome) {
            Some(1) => return self.pos_de(nome),
            Some(_) => return None,
            None => {}
        }
        let Some(Kind::Struct(s)) = self.resolve_local(nome) else {
            estado.insert(nome.to_string(), 2);
            return None;
        };
        estado.insert(nome.to_string(), 1);
        caminho.push(nome.to_string());
        let mut achado = None;
        for c in &s.fields {
            for dep in dependencias(&c.ty) {
                let simples = simples_local(self.pkg, dep);
                if let Some(p) = self.visita(simples, estado, caminho) {
                    achado.get_or_insert(p);
                }
            }
        }
        caminho.pop();
        estado.insert(nome.to_string(), 2);
        achado
    }

    fn pos_de(&self, nome: &str) -> Option<Pos> {
        match self.resolve_local(nome)? {
            Kind::Struct(s) => Some(s.name.pos),
            _ => None,
        }
    }
}

/// Nome local sem o prefixo do pacote, ou o próprio nome se for externo.
fn simples_local<'b>(pkg: &str, nome: &'b str) -> &'b str {
    match nome.rsplit_once('.') {
        Some((prefixo, s)) if prefixo == pkg => s,
        _ => nome,
    }
}

/// Dependências por valor de um tipo: nomes de struct, alias e elementos de `vec`.
fn dependencias(t: &Type) -> Vec<&str> {
    match t {
        Type::Named(id) => vec![id.name.as_str()],
        Type::Vec(elem, _) => dependencias(elem),
        _ => Vec::new(),
    }
}

fn repr_max(r: Repr) -> u64 {
    match r {
        Repr::U8 => u64::from(u8::MAX),
        Repr::U16 => u64::from(u16::MAX),
        Repr::U32 => u64::from(u32::MAX),
    }
}

fn conta_handles(t: &Type) -> usize {
    match t {
        Type::Handle(_) => 1,
        _ => 0,
    }
}

fn contem_handle(t: &Type) -> bool {
    match t {
        Type::Handle(_) => true,
        Type::Vec(e, _) => contem_handle(e),
        _ => false,
    }
}
