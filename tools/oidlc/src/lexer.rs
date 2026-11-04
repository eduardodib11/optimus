//! Léxico do OIDL (ADR 0033, seção 1).
//!
//! Palavras-chave não são tokens próprios: o parser as reconhece pelo texto,
//! o que mantém o léxico pequeno. Comentários são `//` até o fim da linha.

use std::fmt;

/// Posição no arquivo, em linhas e colunas a partir de 1. A coluna conta
/// caracteres Unicode, não bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pos {
    /// Linha, a partir de 1.
    pub line: u32,
    /// Coluna, a partir de 1.
    pub col: u32,
}

/// Token do OIDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tok {
    /// Identificador ou palavra-chave.
    Ident(String),
    /// Inteiro decimal sem sinal.
    Int(u64),
    /// Texto entre aspas, já com as sequências de escape resolvidas.
    Str(String),
    /// Pontuação de um caractere: `{ } ( ) < > , ; : = @ .`.
    Punct(char),
    /// Seta `->`.
    Arrow,
    /// Fim do arquivo.
    Eof,
}

/// Token com a posição do primeiro caractere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// O token em si.
    pub tok: Tok,
    /// Onde ele começa.
    pub pos: Pos,
}

/// Erro de léxico ou de sintaxe, com a posição em que foi achado.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    /// Onde o erro foi achado.
    pub pos: Pos,
    /// Mensagem em português, sem a posição.
    pub msg: String,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: erro: {}", self.pos.line, self.pos.col, self.msg)
    }
}

/// Separa `src` em tokens. O último é sempre [`Tok::Eof`].
///
/// # Errors
///
/// Caractere fora do alfabeto, texto sem fecha-aspas, escape desconhecido e
/// inteiro que não cabe em `u64`.
pub fn lex(src: &str) -> Result<Vec<Token>, Error> {
    let mut lx = Lexer {
        src: src.chars().collect(),
        i: 0,
        pos: Pos { line: 1, col: 1 },
    };
    let mut out = Vec::new();
    loop {
        lx.skip_blanks();
        let pos = lx.pos;
        let Some(c) = lx.peek(0) else {
            out.push(Token { tok: Tok::Eof, pos });
            return Ok(out);
        };
        let tok = match c {
            'a'..='z' | 'A'..='Z' | '_' => {
                Tok::Ident(lx.take_while(|c| c.is_ascii_alphanumeric() || c == '_'))
            }
            '0'..='9' => lx.int(pos)?,
            '"' => lx.string(pos)?,
            '-' if lx.peek(1) == Some('>') => {
                lx.bump();
                lx.bump();
                Tok::Arrow
            }
            '{' | '}' | '(' | ')' | '<' | '>' | ',' | ';' | ':' | '=' | '@' | '.' => {
                lx.bump();
                Tok::Punct(c)
            }
            outro => {
                return Err(Error {
                    pos,
                    msg: format!("caractere inesperado '{outro}'"),
                });
            }
        };
        out.push(Token { tok, pos });
    }
}

struct Lexer {
    src: Vec<char>,
    i: usize,
    pos: Pos,
}

impl Lexer {
    fn peek(&self, k: usize) -> Option<char> {
        self.src.get(self.i + k).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = *self.src.get(self.i)?;
        self.i += 1;
        if c == '\n' {
            self.pos.line += 1;
            self.pos.col = 1;
        } else {
            self.pos.col += 1;
        }
        Some(c)
    }

    fn take_while(&mut self, ok: impl Fn(char) -> bool) -> String {
        let mut s = String::new();
        while let Some(c) = self.peek(0).filter(|&c| ok(c)) {
            s.push(c);
            self.bump();
        }
        s
    }

    fn skip_blanks(&mut self) {
        loop {
            match self.peek(0) {
                Some(c) if c.is_whitespace() => {
                    self.bump();
                }
                Some('/') if self.peek(1) == Some('/') => {
                    while self.peek(0).is_some_and(|c| c != '\n') {
                        self.bump();
                    }
                }
                _ => return,
            }
        }
    }

    fn int(&mut self, pos: Pos) -> Result<Tok, Error> {
        let digits = self.take_while(|c| c.is_ascii_digit());
        digits.parse::<u64>().map(Tok::Int).map_err(|_| Error {
            pos,
            msg: "inteiro grande demais".into(),
        })
    }

    fn string(&mut self, pos: Pos) -> Result<Tok, Error> {
        self.bump(); // aspas de abertura
        let mut s = String::new();
        loop {
            match self.bump() {
                None | Some('\n') => {
                    return Err(Error {
                        pos,
                        msg: "texto sem fecha-aspas".into(),
                    });
                }
                Some('"') => return Ok(Tok::Str(s)),
                Some('\\') => {
                    let esc_pos = self.pos;
                    match self.bump() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        _ => {
                            return Err(Error {
                                pos: esc_pos,
                                msg: "escape inválido (use \\n, \\t, \\\" ou \\\\)".into(),
                            });
                        }
                    }
                }
                Some(c) => s.push(c),
            }
        }
    }
}
