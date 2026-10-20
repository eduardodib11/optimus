//! Política de `unsafe` do `cargo xtask check` (SDD v1.0, seção 17.1; ADR
//! 0039, item 1).
//!
//! `unsafe-allowlist.toml` tem duas partes:
//!
//! - `crates`: crates autorizadas a ter `unsafe`; todas as outras precisam
//!   de `#![forbid(unsafe_code)]`;
//! - `[unsafe_budget]`: tetos de blocos `unsafe` por **caminho** (crate ou
//!   módulo). O `unsafe` (bloco, `impl`, `fn`, `trait`, `extern`) e o
//!   `allow(unsafe_code)` só valem dentro desses caminhos. Cada caminho
//!   precisa de `#![allow(unsafe_code)]` no arquivo raiz do módulo e de uma
//!   seção `# Unsafe` na documentação dele, e todo bloco ou `impl` `unsafe`
//!   leva um comentário `// SAFETY:`.
//!
//! São varridos `lib/ostd/src/**/*.rs` e os caminhos do orçamento. Sem
//! crates externas, então o TOML (só duas formas) e os tokens do Rust (só o
//! que importa: identificadores, comentários e literais) são lidos aqui.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use super::{Result, root};

/// Árvore do `ostd`, varrida inteira mesmo fora do orçamento.
const SCANNED_TREES: &[&str] = &["lib/ostd/src"];

/// Conteúdo de `unsafe-allowlist.toml`.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Allowlist {
    /// Crates autorizadas a ter `unsafe`.
    pub crates: Vec<String>,
    /// Teto de usos de `unsafe` por caminho.
    pub budget: Vec<(String, usize)>,
}

/// Lê `unsafe-allowlist.toml`: `crates = [ "a", "b" ]` (em várias linhas, se
/// quiser) e a tabela `[unsafe_budget]` com `"caminho" = N`. Comentários
/// começam em `#`.
pub fn parse_allowlist(text: &str) -> Result<Allowlist> {
    let mut out = Allowlist::default();
    let mut table = "";
    let mut in_crates = false;
    for (n, raw) in text.lines().enumerate() {
        let at = |msg: &str| format!("unsafe-allowlist.toml:{}: {msg}", n + 1);
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if in_crates {
            in_crates = !take_strings(line, &mut out.crates).map_err(|e| at(&e))?;
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if name.trim() != "unsafe_budget" {
                return Err(at(&format!("tabela desconhecida [{name}]")));
            }
            table = "unsafe_budget";
        } else if table.is_empty() {
            let rest = line
                .strip_prefix("crates")
                .map(str::trim_start)
                .and_then(|l| l.strip_prefix('='))
                .map(str::trim_start)
                .and_then(|l| l.strip_prefix('['))
                .ok_or_else(|| at("esperava `crates = [`"))?;
            in_crates = !take_strings(rest, &mut out.crates).map_err(|e| at(&e))?;
        } else {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| at("esperava `\"caminho\" = N`"))?;
            let mut keys = Vec::new();
            let closed = take_strings(&format!("{key}]"), &mut keys).map_err(|e| at(&e))?;
            let [key] = keys.as_slice() else {
                return Err(at("esperava um caminho entre aspas"));
            };
            if !closed {
                return Err(at("caminho mal formado"));
            }
            let ceiling = value
                .trim()
                .parse::<usize>()
                .map_err(|_| at("o teto deve ser um inteiro"))?;
            if out.budget.iter().any(|(k, _)| k == key) {
                return Err(at(&format!("caminho repetido: {key}")));
            }
            out.budget.push((key.clone(), ceiling));
        }
    }
    if in_crates {
        return Err("unsafe-allowlist.toml: `crates = [` sem `]`".into());
    }
    Ok(out)
}

/// A linha sem o comentário (`#` fora de aspas).
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '#' if !quoted => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Junta em `out` as strings entre aspas de `line`, separadas por vírgula, até
/// um `]`; devolve se o `]` apareceu.
fn take_strings(line: &str, out: &mut Vec<String>) -> std::result::Result<bool, String> {
    let mut rest = line.trim();
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        if let Some(after) = rest.strip_prefix(']') {
            return if after.trim().is_empty() {
                Ok(true)
            } else {
                Err("texto depois de `]`".into())
            };
        }
        if rest.is_empty() {
            return Ok(false);
        }
        let body = rest
            .strip_prefix('"')
            .ok_or("esperava uma string entre aspas")?;
        let (value, after) = body
            .split_once('"')
            .ok_or("string sem aspas de fechamento")?;
        out.push(value.to_string());
        rest = after.trim_start();
        if let Some(more) = rest.strip_prefix(',') {
            rest = more;
        } else if !rest.is_empty() && !rest.starts_with(']') {
            return Err("esperava `,` ou `]` depois da string".into());
        }
    }
}

// ---- leitura dos tokens ----

#[derive(Debug, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char),
    /// Literal (caractere ou número): conteúdo descartado.
    Lit,
    /// Literal de texto; guarda só se o conteúdo tem `.rs`.
    Str(bool),
}

struct Comment {
    /// Linha em que termina (1 é a primeira).
    end: usize,
    /// O que vem depois de `//` (ou o corpo de `/* */`).
    text: String,
}

/// O que interessa de um arquivo `.rs`.
#[derive(Debug, Default)]
#[allow(clippy::struct_excessive_bools)] // cada flag é um fato independente do arquivo
pub struct Scan {
    /// Linha e se precisa de `// SAFETY:` (bloco ou `impl`) de cada `unsafe`.
    uses: Vec<(usize, bool)>,
    /// Linha de cada `allow(unsafe_code)` ou `expect(unsafe_code)`.
    allows: Vec<usize>,
    /// Há `#![allow(unsafe_code)]` (atributo interno).
    inner_allow: bool,
    /// Há `#![deny(unsafe_code)]` ou `#![forbid(unsafe_code)]`.
    inner_deny: bool,
    /// Há `#![forbid(unsafe_code)]` (atributo interno, fora de comentários e
    /// strings).
    pub inner_forbid: bool,
    /// Linha de cada `#[path ...]`, que esconderia arquivos da varredura.
    path_attrs: Vec<usize>,
    /// Linha de cada `include!` que menciona um arquivo `.rs`.
    includes: Vec<usize>,
    /// Há uma seção `# Unsafe` nos comentários de documentação internos.
    unsafe_doc: bool,
    /// Linhas dos comentários com `SAFETY:`.
    safety: Vec<usize>,
    /// Linhas que só têm comentário (sem código).
    comment_lines: BTreeSet<usize>,
    /// Linhas que começam um atributo (`#[...]`), que pode vir entre a
    /// documentação e o item.
    attr_lines: BTreeSet<usize>,
    /// Linhas de documentação com `# Safety`.
    doc_safety: BTreeSet<usize>,
    /// Linha de cada declaração `unsafe fn nome`.
    unsafe_fns: Vec<usize>,
}

fn tokenize(src: &str) -> (Vec<(Tok, usize)>, Vec<Comment>) {
    let chars: Vec<char> = src.chars().collect();
    let (mut toks, mut comments) = (Vec::new(), Vec::new());
    let (mut i, mut line) = (0, 1);
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if c == '\n' {
            line += 1;
            i += 1;
        } else if c.is_whitespace() {
            i += 1;
        } else if c == '/' && next == Some('/') {
            let start = i + 2;
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            comments.push(Comment {
                end: line,
                text: chars[start..i].iter().collect(),
            });
        } else if c == '/' && next == Some('*') {
            // Comentário de bloco, aninhável.
            let (start, mut depth) = (i + 2, 1);
            i += 2;
            while i < chars.len() && depth > 0 {
                match (chars[i], chars.get(i + 1)) {
                    ('/', Some('*')) => {
                        depth += 1;
                        i += 2;
                    }
                    ('*', Some('/')) => {
                        depth -= 1;
                        i += 2;
                    }
                    ('\n', _) => {
                        line += 1;
                        i += 1;
                    }
                    _ => i += 1,
                }
            }
            let end = i.saturating_sub(2).max(start);
            comments.push(Comment {
                end: line,
                text: chars[start..end].iter().collect(),
            });
        } else if c == '"' {
            let start = i + 1;
            i = skip_string(&chars, i + 1, &mut line);
            toks.push((Tok::Str(has_rs(&chars[start..i])), line));
        } else if c == '\'' {
            // Caractere (`'x'`, `'\n'`) ou lifetime (`'a`).
            if next == Some('\\') {
                // Pula `'`, `\` e o caractere escapado; o resto (`\u{..}`,
                // `\x41`) vai até o `'` de fechamento.
                i += 3;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
                i += 1;
                toks.push((Tok::Lit, line));
            } else if chars.get(i + 2) == Some(&'\'') {
                i += 3;
                toks.push((Tok::Lit, line));
            } else {
                i += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            let raw = matches!(ident.as_str(), "r" | "br" | "cr");
            let hashes = chars[i..].iter().take_while(|&&h| h == '#').count();
            if raw && chars.get(i + hashes) == Some(&'"') {
                let start = i + hashes + 1;
                i = skip_raw_string(&chars, start, hashes, &mut line);
                toks.push((Tok::Str(has_rs(&chars[start..i.min(chars.len())])), line));
            } else if matches!(ident.as_str(), "b" | "c") && chars.get(i) == Some(&'"') {
                let start = i + 1;
                i = skip_string(&chars, i + 1, &mut line);
                toks.push((Tok::Str(has_rs(&chars[start..i])), line));
            } else {
                toks.push((Tok::Ident(ident), line));
            }
        } else if c.is_ascii_digit() {
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            toks.push((Tok::Lit, line));
        } else {
            toks.push((Tok::Punct(c), line));
            i += 1;
        }
    }
    (toks, comments)
}

/// O texto (de uma string) contém `.rs`?
fn has_rs(text: &[char]) -> bool {
    text.windows(3).any(|w| w == ['.', 'r', 's'])
}

/// Pula o corpo de uma string que já abriu; devolve o índice depois do `"`.
fn skip_string(chars: &[char], mut i: usize, line: &mut usize) -> usize {
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if chars.get(i + 1) == Some(&'\n') {
                    *line += 1;
                }
                i += 2;
            }
            '"' => return i + 1,
            c => {
                if c == '\n' {
                    *line += 1;
                }
                i += 1;
            }
        }
    }
    i
}

/// Pula o corpo de uma string crua (`r#"..."#`).
fn skip_raw_string(chars: &[char], mut i: usize, hashes: usize, line: &mut usize) -> usize {
    while i < chars.len() {
        if chars[i] == '\n' {
            *line += 1;
        }
        if chars[i] == '"' && chars[i + 1..].iter().take_while(|&&h| h == '#').count() >= hashes {
            return i + 1 + hashes;
        }
        i += 1;
    }
    i
}

/// Lê os tokens de `src` e junta o que a política precisa.
pub fn scan(src: &str) -> Scan {
    let (toks, comments) = tokenize(src);
    let mut out = Scan::default();
    let ident = |k: usize, name: &str| matches!(toks.get(k), Some((Tok::Ident(s), _)) if s == name);
    for (k, (tok, line)) in toks.iter().enumerate() {
        let Tok::Ident(name) = tok else { continue };
        if name == "unsafe" {
            let needs_safety =
                matches!(toks.get(k + 1), Some((Tok::Punct('{'), _))) || ident(k + 1, "impl");
            out.uses.push((*line, needs_safety));
            if ident(k + 1, "fn") && matches!(toks.get(k + 2), Some((Tok::Ident(_), _))) {
                out.unsafe_fns.push(*line);
            }
        } else if name == "path"
            && k >= 2
            && toks[k - 1].0 == Tok::Punct('[')
            && toks[k - 2].0 == Tok::Punct('#')
        {
            out.path_attrs.push(*line);
        } else if name == "include" && matches!(toks.get(k + 1), Some((Tok::Punct('!'), _))) {
            // Procura uma string com `.rs` até fechar o parêntese de abertura.
            let mut depth = 0_usize;
            for (t, _) in &toks[k + 2..] {
                match t {
                    Tok::Punct('(' | '[' | '{') => depth += 1,
                    Tok::Punct(')' | ']' | '}') => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            break;
                        }
                    }
                    Tok::Str(true) => {
                        out.includes.push(*line);
                        break;
                    }
                    _ => {}
                }
            }
        } else if name == "unsafe_code" {
            // Procura, para trás, o começo do atributo (`[`) e o que o abre.
            let open = toks[..k]
                .iter()
                .rposition(|(t, _)| matches!(t, Tok::Punct('[')));
            let Some(open) = open else { continue };
            let inner = open >= 2
                && toks[open - 1].0 == Tok::Punct('!')
                && toks[open - 2].0 == Tok::Punct('#');
            let words = |names: &[&str]| {
                toks[open..k]
                    .iter()
                    .any(|(t, _)| matches!(t, Tok::Ident(s) if names.contains(&s.as_str())))
            };
            if words(&["allow", "expect"]) {
                out.allows.push(*line);
                out.inner_allow |= inner;
            } else if words(&["deny", "forbid"]) {
                out.inner_deny |= inner;
                out.inner_forbid |= inner && words(&["forbid"]);
            }
        }
    }
    let code_lines: BTreeSet<usize> = toks.iter().map(|(_, l)| *l).collect();
    for (k, (tok, line)) in toks.iter().enumerate() {
        let first = k == 0 || toks[k - 1].1 != *line;
        if first && *tok == Tok::Punct('#') {
            out.attr_lines.insert(*line);
        }
    }
    for c in &comments {
        if !code_lines.contains(&c.end) {
            out.comment_lines.insert(c.end);
        }
        if c.text.trim() == "/ # Safety" || c.text.trim() == "/# Safety" {
            out.doc_safety.insert(c.end);
        }
        if c.text.contains("SAFETY:") {
            out.safety.push(c.end);
        }
        // `//! # Unsafe`: documentação interna.
        if c.text
            .strip_prefix('!')
            .is_some_and(|t| t.trim() == "# Unsafe")
        {
            out.unsafe_doc = true;
        }
    }
    out
}

// ---- a política ----

/// Contagem de um caminho do orçamento.
#[derive(Debug, PartialEq, Eq)]
pub struct Usage {
    /// Caminho (chave de `[unsafe_budget]`).
    pub path: String,
    /// Usos de `unsafe` encontrados.
    pub used: usize,
    /// Teto.
    pub ceiling: usize,
}

/// A chave do orçamento a que `file` pertence (a mais específica).
fn budget_of<'a>(allow: &'a Allowlist, file: &str) -> Option<&'a str> {
    allow
        .budget
        .iter()
        .map(|(k, _)| k.as_str())
        .filter(|k| {
            file == *k
                || file
                    .strip_prefix(*k)
                    .is_some_and(|rest| rest.starts_with('/'))
                || file.strip_suffix(".rs") == Some(*k)
        })
        .max_by_key(|k| k.len())
}

/// O `unsafe` desta linha tem um `// SAFETY:` no bloco de comentários
/// imediatamente acima: sem linha em branco ou código no meio, e um
/// comentário de várias linhas vale se alguma delas tem `SAFETY:`.
fn documented(scan: &Scan, line: usize) -> bool {
    let mut l = line;
    while l > 1 && scan.comment_lines.contains(&(l - 1)) {
        l -= 1;
        if scan.safety.contains(&l) {
            return true;
        }
    }
    false
}

/// A `unsafe fn` desta linha tem `# Safety` na documentação logo acima
/// (atributos podem vir entre a documentação e a função).
fn has_safety_doc(scan: &Scan, line: usize) -> bool {
    let mut l = line;
    while l > 1 && (scan.comment_lines.contains(&(l - 1)) || scan.attr_lines.contains(&(l - 1))) {
        l -= 1;
        if scan.doc_safety.contains(&l) {
            return true;
        }
    }
    false
}

type Scans<'a> = BTreeMap<&'a str, Scan>;

/// Confere a política sobre `files` (caminho relativo com `/` e conteúdo).
/// Devolve os usos por caminho do orçamento, ou todos os problemas
/// encontrados, um por linha.
pub fn check_sources(
    allow: &Allowlist,
    files: &[(String, String)],
) -> std::result::Result<Vec<Usage>, String> {
    let mut problems = Vec::new();
    let scans: Scans = files.iter().map(|(p, s)| (p.as_str(), scan(s))).collect();
    let used = check_files(allow, &scans, &mut problems);
    check_roots(allow, &scans, &used, &mut problems);
    if problems.is_empty() {
        Ok(allow
            .budget
            .iter()
            .map(|(k, c)| Usage {
                path: k.clone(),
                used: used[k.as_str()],
                ceiling: *c,
            })
            .collect())
    } else {
        Err(problems.join("\n"))
    }
}

/// `unsafe` e `allow(unsafe_code)` só dentro do orçamento, e com `SAFETY`.
/// Devolve os usos contados por caminho do orçamento.
fn check_files<'a>(
    allow: &'a Allowlist,
    scans: &Scans,
    problems: &mut Vec<String>,
) -> BTreeMap<&'a str, usize> {
    let mut used: BTreeMap<&str, usize> =
        allow.budget.iter().map(|(k, _)| (k.as_str(), 0)).collect();
    for (&path, sc) in scans {
        for line in &sc.path_attrs {
            problems.push(format!(
                "{path}:{line}: `#[path]` esconde arquivos da varredura de `unsafe`; use módulos comuns"
            ));
        }
        for line in &sc.includes {
            problems.push(format!(
                "{path}:{line}: `include!` de arquivo `.rs` esconde código da varredura de `unsafe`"
            ));
        }
        let Some(key) = budget_of(allow, path) else {
            for (line, _) in &sc.uses {
                problems.push(format!(
                    "{path}:{line}: `unsafe` fora dos caminhos de [unsafe_budget] em unsafe-allowlist.toml"
                ));
            }
            for line in &sc.allows {
                problems.push(format!(
                    "{path}:{line}: `allow(unsafe_code)` fora dos caminhos de [unsafe_budget] em unsafe-allowlist.toml"
                ));
            }
            continue;
        };
        *used.get_mut(key).unwrap() += sc.uses.len();
        for &(line, needs_safety) in &sc.uses {
            if needs_safety && !documented(sc, line) {
                problems.push(format!(
                    "{path}:{line}: bloco `unsafe` sem comentário `// SAFETY:` imediatamente acima"
                ));
            }
        }
        for &line in &sc.unsafe_fns {
            if !has_safety_doc(sc, line) {
                problems.push(format!(
                    "{path}:{line}: `unsafe fn` sem a seção `# Safety` na documentação"
                ));
            }
        }
    }
    used
}

/// Tetos, arquivo raiz de cada módulo do orçamento (`allow` e `# Unsafe`) e
/// `deny(unsafe_code)` na raiz das crates que só têm `unsafe` em módulos.
fn check_roots(
    allow: &Allowlist,
    scans: &Scans,
    used: &BTreeMap<&str, usize>,
    problems: &mut Vec<String>,
) {
    for (key, ceiling) in &allow.budget {
        let count = used[key.as_str()];
        if count > *ceiling {
            problems.push(format!(
                "{key}: {count} usos de `unsafe`, teto {ceiling} em unsafe-allowlist.toml (subir o teto é uma mudança visível a revisar)"
            ));
        }
        let candidates = [
            format!("{key}/mod.rs"),
            format!("{key}.rs"),
            format!("{key}/src/lib.rs"),
        ];
        let found = candidates
            .iter()
            .find_map(|c| scans.get(c.as_str()).map(|s| (c, s)));
        let Some((root, sc)) = found else {
            problems.push(format!(
                "{key}: sem arquivo raiz do módulo ({}) entre os arquivos varridos",
                candidates.join(", ")
            ));
            continue;
        };
        if !sc.inner_allow {
            problems.push(format!(
                "{root}: falta `#![allow(unsafe_code)]` no arquivo raiz do módulo"
            ));
        }
        if !sc.unsafe_doc {
            problems.push(format!(
                "{root}: falta a seção `# Unsafe` (com as invariantes) na documentação `//!` do módulo"
            ));
        }
    }
    for krate in &allow.crates {
        let inside = allow.budget.iter().any(|(k, _)| {
            k.strip_prefix(krate.as_str())
                .is_some_and(|r| r.starts_with('/'))
        });
        let roots = [
            format!("{krate}/src/lib.rs"),
            format!("{krate}/src/main.rs"),
        ];
        let found = roots
            .iter()
            .find_map(|r| scans.get(r.as_str()).map(|s| (r, s)));
        if let Some((root, sc)) = found
            && inside
            && !sc.inner_deny
        {
            problems.push(format!(
                "{root}: a crate só tem `unsafe` em módulos do orçamento; falta `#![deny(unsafe_code)]` na raiz"
            ));
        }
    }
}

/// Os `.rs` sob `dir` (relativo à raiz do repositório), com o conteúdo.
fn collect(dir: &str, out: &mut BTreeMap<String, String>) -> Result {
    let base = root();
    let mut stack = vec![base.join(dir)];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).map_err(|e| format!("{}: {e}", path.display()))? {
                let entry = entry.map_err(|e| e.to_string())?;
                if entry.file_name() != "target" {
                    stack.push(entry.path());
                }
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            let rel = rel_path(&base, &path);
            let text = fs::read_to_string(&path).map_err(|e| format!("{rel}: {e}"))?;
            out.insert(rel, text);
        }
    }
    Ok(())
}

fn rel_path(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// A regra de `unsafe` sobre o repositório: crates fora da allowlist com
/// `#![forbid(unsafe_code)]` e a política de orçamento (`check_sources`).
pub fn check(crate_roots: &[&str]) -> Result {
    let text =
        fs::read_to_string(root().join("unsafe-allowlist.toml")).map_err(|e| e.to_string())?;
    let allow = parse_allowlist(&text)?;
    for file in crate_roots {
        let dir = file.split("/src/").next().unwrap_or(file);
        let src = fs::read_to_string(root().join(file)).map_err(|e| e.to_string())?;
        if !allow.crates.iter().any(|c| c == dir) && !scan(&src).inner_forbid {
            return Err(format!(
                "{file}: falta #![forbid(unsafe_code)] (ou inclua {dir} em unsafe-allowlist.toml)"
            ));
        }
    }
    let mut files = BTreeMap::new();
    for tree in SCANNED_TREES
        .iter()
        .copied()
        .chain(allow.budget.iter().map(|(k, _)| k.as_str()))
    {
        if root().join(tree).exists() {
            collect(tree, &mut files)?;
        } else if !root().join(format!("{tree}.rs")).exists() {
            return Err(format!(
                "unsafe-allowlist.toml: o caminho {tree} não existe"
            ));
        } else {
            let file = format!("{tree}.rs");
            let src = fs::read_to_string(root().join(&file)).map_err(|e| e.to_string())?;
            files.insert(file, src);
        }
    }
    let files: Vec<(String, String)> = files.into_iter().collect();
    let usage = check_sources(&allow, &files)?;
    for u in &usage {
        println!("xtask: unsafe {}: {} de {}", u.path, u.used, u.ceiling);
    }
    println!("xtask: allowlist de unsafe ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOML: &str = r#"
# comentário
crates = [
    "kernel/okernel",   # o kernel
    "lib/ostd",
    "lib/oalloc",
]

[unsafe_budget]
"lib/ostd/src/arch" = 3
"lib/oalloc" = 4   # núcleo
"#;

    fn allow() -> Allowlist {
        parse_allowlist(TOML).unwrap()
    }

    fn file(path: &str, text: &str) -> (String, String) {
        (path.into(), text.into())
    }

    const ARCH_ROOT: &str = "//! Código de máquina.\n//!\n//! # Unsafe\n//!\n//! Invariantes.\n#![allow(unsafe_code)]\n";
    const OSTD_ROOT: &str = "#![deny(unsafe_code)]\npub mod arch;\n";
    const OALLOC_ROOT: &str = "//! # Unsafe\n#![allow(unsafe_code)]\n";

    /// Os três arquivos raiz em ordem, mais `extra`.
    fn tree(extra: &[(String, String)]) -> Vec<(String, String)> {
        let mut files = vec![
            file("lib/ostd/src/lib.rs", OSTD_ROOT),
            file("lib/ostd/src/arch/mod.rs", ARCH_ROOT),
            file("lib/oalloc/src/lib.rs", OALLOC_ROOT),
        ];
        files.extend_from_slice(extra);
        files
    }

    #[test]
    fn le_a_allowlist() {
        let a = allow();
        assert_eq!(a.crates, ["kernel/okernel", "lib/ostd", "lib/oalloc"]);
        assert_eq!(
            a.budget,
            [
                ("lib/ostd/src/arch".to_string(), 3),
                ("lib/oalloc".to_string(), 4)
            ]
        );
        assert_eq!(
            parse_allowlist("crates = [\"a\", \"b\"]\n").unwrap().crates,
            ["a", "b"]
        );
    }

    #[test]
    fn rejeita_allowlist_mal_formada() {
        for bad in [
            "crates = [\"a\"\n",
            "crates = \"a\"\n",
            "[outra]\n",
            "crates = []\n[unsafe_budget]\n\"a\" = x\n",
            "crates = []\n[unsafe_budget]\na = 1\n",
            "crates = []\n[unsafe_budget]\n\"a\" = 1\n\"a\" = 2\n",
            "crates = [\"a\" \"b\"]\n",
        ] {
            assert!(parse_allowlist(bad).is_err(), "devia recusar {bad:?}");
        }
    }

    #[test]
    fn a_leitura_ignora_comentarios_textos_e_literais() {
        let src = r##"
// unsafe { no comentário }
/* unsafe /* aninhado */ ainda comentário */
const A: &str = "unsafe { no texto \" }";
const B: &str = r#"unsafe { cru "aspas" }"#;
const C: char = '\'';
fn f<'a>(x: &'a u8) -> &'a u8 { x }
unsafe fn real() {}
"##;
        let sc = scan(src);
        assert_eq!(sc.uses, [(8, false)], "só o `unsafe fn` conta");
    }

    #[test]
    fn conta_blocos_impls_e_fns() {
        let src = "unsafe impl Send for A {}\nunsafe fn f() {}\nfn g() {\n    unsafe { h() }\n}\nunsafe extern \"C\" {}\n";
        let sc = scan(src);
        assert_eq!(
            sc.uses.iter().map(|u| u.1).collect::<Vec<_>>(),
            [true, false, true, false]
        );
    }

    #[test]
    fn dentro_do_orcamento_passa() {
        let extra = [
            file(
                "lib/ostd/src/arch/x86_64.rs",
                "// SAFETY: ok.\nunsafe { a() }\n// SAFETY: ok.\nunsafe { b() }\n",
            ),
            file(
                "lib/oalloc/src/heap.rs",
                "// SAFETY: ok.\nlet x = unsafe { c() };\n",
            ),
            file("lib/ostd/src/vm.rs", "pub fn seguro() {}\n"),
        ];
        let usage = check_sources(&allow(), &tree(&extra)).unwrap();
        assert_eq!(
            usage,
            [
                Usage {
                    path: "lib/ostd/src/arch".into(),
                    used: 2,
                    ceiling: 3
                },
                Usage {
                    path: "lib/oalloc".into(),
                    used: 1,
                    ceiling: 4
                },
            ]
        );
    }

    #[test]
    fn unsafe_fora_do_orcamento_falha() {
        // A prova de que o `xtask check` recusa: um `unsafe` em módulo do
        // `ostd` que não está na lista.
        let extra = [file(
            "lib/ostd/src/vm.rs",
            "pub fn f() {\n    // SAFETY: documentado, mas no lugar errado.\n    unsafe { g() }\n}\n",
        )];
        let err = check_sources(&allow(), &tree(&extra)).unwrap_err();
        assert!(err.contains("lib/ostd/src/vm.rs:3"), "{err}");
        assert!(err.contains("fora dos caminhos"), "{err}");
    }

    #[test]
    fn allow_de_unsafe_code_fora_do_orcamento_falha() {
        for attr in [
            "#![allow(unsafe_code)]",
            "#[allow(dead_code, unsafe_code)]",
            "#![cfg_attr(not(test), allow(unsafe_code))]",
            "#[expect(unsafe_code)]",
        ] {
            let extra = [file(
                "lib/ostd/src/sync.rs",
                &format!("{attr}\nmod m {{}}\n"),
            )];
            let err = check_sources(&allow(), &tree(&extra)).unwrap_err();
            assert!(err.contains("lib/ostd/src/sync.rs:1"), "{attr}: {err}");
        }
        // `deny` e `forbid` valem em qualquer lugar.
        let extra = [file("lib/ostd/src/sync.rs", "#![forbid(unsafe_code)]\n")];
        check_sources(&allow(), &tree(&extra)).unwrap();
    }

    #[test]
    fn path_e_include_de_rs_sao_recusados() {
        for (src, what) in [
            ("#[path = \"x.rs\"]\nmod m;\n", "#[path]"),
            ("include!(\"x.rs\");\n", "include!"),
            ("include!(concat!(env!(\"D\"), \"/x.rs\"));\n", "include!"),
        ] {
            let extra = [file("lib/ostd/src/sync.rs", src)];
            let err = check_sources(&allow(), &tree(&extra)).unwrap_err();
            assert!(err.contains("lib/ostd/src/sync.rs:1"), "{src}: {err}");
            assert!(err.contains(what), "{src}: {err}");
        }
        // Em comentário ou string, ou `include_str!`, não conta.
        let extra = [file(
            "lib/ostd/src/sync.rs",
            "// #[path = \"x.rs\"]\nconst S: &str = \"include!(\\\"x.rs\\\")\";\nconst T: &str = include_str!(\"x.txt\");\n",
        )];
        check_sources(&allow(), &tree(&extra)).unwrap();
        // Também dentro de um caminho do orçamento.
        let extra = [file(
            "lib/oalloc/src/heap.rs",
            "#[path = \"y.rs\"]\nmod m;\n",
        )];
        assert!(check_sources(&allow(), &tree(&extra)).is_err());
    }

    #[test]
    fn forbid_so_conta_como_atributo() {
        assert!(scan("#![forbid(unsafe_code)]\n").inner_forbid);
        assert!(scan("#![forbid(unsafe_code)]").inner_forbid);
        assert!(!scan("// #![forbid(unsafe_code)]\n").inner_forbid);
        assert!(!scan("/* #![forbid(unsafe_code)] */\n").inner_forbid);
        assert!(!scan("const S: &str = \"#![forbid(unsafe_code)]\";\n").inner_forbid);
        assert!(!scan("#![deny(unsafe_code)]\n").inner_forbid);
        assert!(!scan("#[forbid(unsafe_code)]\nfn f() {}\n").inner_forbid);
    }

    #[test]
    fn acima_do_teto_falha() {
        let blocks = "// SAFETY: ok.\nunsafe { a() }\n".repeat(4);
        let extra = [file("lib/ostd/src/arch/x86_64.rs", &blocks)];
        let err = check_sources(&allow(), &tree(&extra)).unwrap_err();
        assert!(
            err.contains("lib/ostd/src/arch: 4 usos de `unsafe`, teto 3"),
            "{err}"
        );
    }

    #[test]
    fn bloco_sem_safety_falha() {
        let extra = [file(
            "lib/oalloc/src/heap.rs",
            "// SAFETY: o primeiro.\nunsafe { a() }\nunsafe { b() }\n// comum\nunsafe impl Send for A {}\n",
        )];
        let err = check_sources(&allow(), &tree(&extra)).unwrap_err();
        // Um comentário não serve a dois blocos.
        assert!(err.contains("heap.rs:3"), "{err}");
        assert!(err.contains("heap.rs:5"), "{err}");
        assert!(!err.contains("heap.rs:2"), "{err}");
        // `unsafe fn` (com `# Safety`) e `unsafe extern` não pedem comentário.
        let extra = [file(
            "lib/oalloc/src/heap.rs",
            "/// # Safety\nunsafe fn f() {}\nunsafe extern \"C\" {}\n",
        )];
        check_sources(&allow(), &tree(&extra)).unwrap();
    }

    #[test]
    fn safety_so_vale_imediatamente_acima() {
        let check = |body: &str| {
            let extra = [file("lib/oalloc/src/heap.rs", body)];
            check_sources(&allow(), &tree(&extra))
        };
        // Comentário de várias linhas colado ao `unsafe`: vale.
        check("// SAFETY: primeira linha\n// e a continuação.\nunsafe { a() }\n").unwrap();
        // A continuação do comentário não precisa repetir `SAFETY:` e a
        // linha em branco entre os dois quebra a ligação.
        let err = check("// SAFETY: solto.\n\nunsafe { a() }\n").unwrap_err();
        assert!(err.contains("heap.rs:3"), "{err}");
        // Código entre o comentário e o `unsafe` (a janela antiga de 8
        // linhas aceitava).
        let err = check("// SAFETY: longe.\nlet x = 1;\nunsafe { a() }\n").unwrap_err();
        assert!(err.contains("heap.rs:3"), "{err}");
        // Comentário no fim da linha, ou depois do `unsafe`, não vale.
        let err = check("unsafe { a() } // SAFETY: depois.\n").unwrap_err();
        assert!(err.contains("heap.rs:1"), "{err}");
        let err = check("unsafe {\n    // SAFETY: dentro.\n    a()\n}\n").unwrap_err();
        assert!(err.contains("heap.rs:1"), "{err}");
        // Comentário de código anterior com `SAFETY:` não passa adiante.
        let err = check("a(); // SAFETY: do outro.\nunsafe { b() }\n").unwrap_err();
        assert!(err.contains("heap.rs:2"), "{err}");
    }

    #[test]
    fn unsafe_fn_exige_secao_safety() {
        let check = |body: &str| {
            let extra = [file("lib/oalloc/src/heap.rs", body)];
            check_sources(&allow(), &tree(&extra))
        };
        check("/// Faz.\n///\n/// # Safety\n///\n/// Contrato.\npub unsafe fn f() {}\n").unwrap();
        // Atributos entre a documentação e a função não atrapalham.
        check("/// # Safety\n#[inline]\n#[must_use]\nunsafe fn f() {}\n").unwrap();
        let err = check("/// Faz.\npub unsafe fn f() {}\n").unwrap_err();
        assert!(
            err.contains("heap.rs:2: `unsafe fn` sem a seção `# Safety`"),
            "{err}"
        );
        let err = check("unsafe fn f() {}\n").unwrap_err();
        assert!(err.contains("heap.rs:1"), "{err}");
        // Linha em branco entre a seção e a função, ou `// Safety` comum.
        let err = check("/// # Safety\n\nunsafe fn f() {}\n").unwrap_err();
        assert!(err.contains("heap.rs:3"), "{err}");
        // Tipo de ponteiro de função e `unsafe extern`/`impl` não são declarações.
        check("type F = Option<unsafe fn(usize)>;\nunsafe extern \"C\" {}\n").unwrap();
        // Também nos métodos de `impl`, onde a trait manda.
        let err = check("impl A {\n    unsafe fn g(&self) {}\n}\n").unwrap_err();
        assert!(err.contains("heap.rs:2"), "{err}");
    }

    #[test]
    fn modulo_do_orcamento_exige_allow_e_secao_unsafe() {
        let mut files = tree(&[]);
        files[1].1 = "//! # Unsafe\n".into();
        let err = check_sources(&allow(), &files).unwrap_err();
        assert!(
            err.contains("arch/mod.rs: falta `#![allow(unsafe_code)]`"),
            "{err}"
        );
        files[1].1 = "#![allow(unsafe_code)]\n//! Sem a seção.\n".into();
        let err = check_sources(&allow(), &files).unwrap_err();
        assert!(
            err.contains("arch/mod.rs: falta a seção `# Unsafe`"),
            "{err}"
        );
        files.remove(1);
        let err = check_sources(&allow(), &files).unwrap_err();
        assert!(err.contains("sem arquivo raiz"), "{err}");
    }

    #[test]
    fn crate_com_unsafe_so_em_modulos_nega_o_resto() {
        let mut files = tree(&[]);
        files[0].1 = "pub mod arch;\n".into();
        let err = check_sources(&allow(), &files).unwrap_err();
        assert!(err.contains("falta `#![deny(unsafe_code)]`"), "{err}");
    }

    #[test]
    fn o_repositorio_respeita_a_politica() {
        let roots: Vec<&str> = crate::CRATES.iter().map(|(_, f, _)| *f).collect();
        let roots: Vec<&str> = roots
            .into_iter()
            .chain(["xtask/src/main.rs", "tools/mkobfs/src/main.rs"])
            .collect();
        check(&roots).unwrap();
    }
}
