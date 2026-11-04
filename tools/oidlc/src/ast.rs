//! AST do OIDL (ADR 0033, seção 1). Espelha a gramática; a semântica
//! (nomes, limites, semver) fica para a T-342.

use crate::lexer::Pos;

/// Arquivo `.oidl` inteiro.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    /// Cabeçalho `package nome @maior.menor;`.
    pub package: Package,
    /// Declarações, na ordem do arquivo.
    pub decls: Vec<Decl>,
}

/// Cabeçalho do pacote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Nome pontuado, como `optimus.fs`.
    pub name: Ident,
    /// Versão `maior.menor`.
    pub version: Version,
}

/// Versão semântica do pacote (só maior e menor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    /// Número maior.
    pub major: u32,
    /// Número menor.
    pub minor: u32,
    /// Posição do número maior.
    pub pos: Pos,
}

/// Identificador, ou caminho pontuado (`optimus.fs.File`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ident {
    /// Texto, com os pontos quando houver.
    pub name: String,
    /// Posição do primeiro caractere.
    pub pos: Pos,
}

/// Inteiro literal (limite de `string`, `vec`, valor de enumeração).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lit {
    /// Valor.
    pub value: u64,
    /// Posição.
    pub pos: Pos,
}

/// Declaração de topo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decl {
    /// `type nome = tipo;`
    Alias(Alias),
    /// `enum` ou `open enum`.
    Enum(Enum),
    /// `flags`.
    Flags(Flags),
    /// `struct`.
    Struct(Struct),
    /// `interface`.
    Interface(Interface),
}

/// Apelido de tipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    /// Nome novo.
    pub name: Ident,
    /// Tipo que ele nomeia.
    pub ty: Type,
}

/// Tipo-base de `enum` e `flags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repr {
    /// `u8`.
    U8,
    /// `u16`.
    U16,
    /// `u32`.
    U32,
}

/// Enumeração. `open` marca a versão menor que pode acrescentar variantes
/// (ADR 0033, seção 8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enum {
    /// Nome.
    pub name: Ident,
    /// Tipo-base.
    pub repr: Repr,
    /// Se a enumeração é `open`.
    pub open: bool,
    /// Variantes; o valor é opcional e o semântico o completa.
    pub variants: Vec<Variant>,
}

/// Conjunto de bits. Cada bit tem valor explícito.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flags {
    /// Nome.
    pub name: Ident,
    /// Tipo-base.
    pub repr: Repr,
    /// Bits.
    pub bits: Vec<Variant>,
}

/// Variante de enumeração ou bit de `flags`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variant {
    /// Nome.
    pub name: Ident,
    /// Valor explícito, se houver.
    pub value: Option<Lit>,
}

/// Estrutura com campos nomeados.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Struct {
    /// Nome.
    pub name: Ident,
    /// Campos, na ordem da declaração (ela define o layout).
    pub fields: Vec<Field>,
}

/// Campo de estrutura ou parâmetro de método.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    /// Nome.
    pub name: Ident,
    /// Tipo.
    pub ty: Type,
}

/// Interface: conjunto de métodos.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Nome.
    pub name: Ident,
    /// Métodos, na ordem da declaração (o ordinal sai daqui).
    pub methods: Vec<Method>,
}

/// Método de interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Method {
    /// Anotações antes do método.
    pub annotations: Vec<Annotation>,
    /// `oneway`: sem resposta.
    pub oneway: bool,
    /// Nome.
    pub name: Ident,
    /// Parâmetros.
    pub params: Vec<Field>,
    /// `-> result<T, E>`, se houver.
    pub ret: Option<Ret>,
}

/// Retorno `result<T, E>`. `T` pode ser `()` ([`Type::Unit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ret {
    /// Tipo de sucesso.
    pub ok: Type,
    /// Tipo de erro.
    pub err: Type,
}

/// Anotação de método.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Annotation {
    /// `@tool(risk = R0..R4, desc = "...")`.
    Tool {
        /// Classe de risco.
        risk: Risk,
        /// Descrição para a IA.
        desc: String,
        /// Posição da anotação.
        pos: Pos,
    },
}

/// Classe de risco de uma ferramenta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Risk {
    /// R0.
    R0,
    /// R1.
    R1,
    /// R2.
    R2,
    /// R3.
    R3,
    /// R4.
    R4,
}

/// Tipo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// `()`; só como sucesso de `result`.
    Unit,
    /// Primitivo.
    Prim(Prim, Pos),
    /// Nome de tipo declarado (ou pontuado, de outro pacote).
    Named(Ident),
    /// `string<N>`.
    String(Lit),
    /// `vec<T, N>`.
    Vec(Box<Type>, Lit),
    /// `handle<T>`: `T` é uma interface ou tipo de objeto do kernel.
    Handle(Ident),
}

/// Tipo primitivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prim {
    /// `u8`.
    U8,
    /// `u16`.
    U16,
    /// `u32`.
    U32,
    /// `u64`.
    U64,
    /// `i8`.
    I8,
    /// `i16`.
    I16,
    /// `i32`.
    I32,
    /// `i64`.
    I64,
    /// `bool`.
    Bool,
}
