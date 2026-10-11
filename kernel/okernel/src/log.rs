//! Níveis de log e leitura de `log=` da linha de comando (SDD v1.0, seção 5.2).
//!
//! A saída fica no binário do kernel (serial em `arch`); aqui só a parte
//! portável, testada no host.

#![forbid(unsafe_code)]

use core::fmt;

/// Nível de uma mensagem; quanto menor, mais grave.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Level {
    /// Falha que impede uma operação.
    Error = 1,
    /// Algo inesperado, mas recuperável.
    Warn = 2,
    /// Marcos normais do boot e da operação.
    Info = 3,
    /// Detalhes para diagnóstico.
    Debug = 4,
    /// Rastro fino.
    Trace = 5,
}

impl Level {
    /// Todos os níveis, do mais grave ao mais detalhado.
    pub const ALL: [Self; 5] = [
        Self::Error,
        Self::Warn,
        Self::Info,
        Self::Debug,
        Self::Trace,
    ];

    /// Nome usado em `log=` e no prefixo das linhas.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Nível pelo nome.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.name() == name)
    }

    /// Nível pelo valor numérico de `repr(u8)`.
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|&l| l as u8 == value)
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.name())
    }
}

/// Valor de `chave=` na linha de comando, se houver (a última ocorrência vale).
#[must_use]
pub fn option<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    cmdline
        .split_ascii_whitespace()
        .rev()
        .filter_map(|word| word.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Nível pedido por `log=` na linha de comando, ou `default`.
#[must_use]
pub fn level_from_cmdline(cmdline: &str, default: Level) -> Level {
    option(cmdline, "log")
        .and_then(Level::parse)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn niveis_ordenados_e_nomeados() {
        assert!(Level::Error < Level::Warn && Level::Debug < Level::Trace);
        for l in Level::ALL {
            assert_eq!(Level::parse(l.name()), Some(l));
            assert_eq!(Level::from_u8(l as u8), Some(l));
        }
        assert_eq!(Level::parse("INFO"), None);
        assert_eq!(Level::from_u8(0), None);
        assert_eq!(format!("[{:5}]", Level::Warn), "[warn ]");
    }

    #[test]
    fn le_log_da_cmdline() {
        assert_eq!(level_from_cmdline("", Level::Info), Level::Info);
        assert_eq!(
            level_from_cmdline("profile=lite log=debug", Level::Info),
            Level::Debug
        );
        assert_eq!(
            level_from_cmdline("log=trace log=warn", Level::Info),
            Level::Warn
        );
        assert_eq!(level_from_cmdline("log=xyz", Level::Info), Level::Info);
        assert_eq!(option("rescue test=fault", "test"), Some("fault"));
        assert_eq!(option("rescue", "rescue"), None);
    }
}
