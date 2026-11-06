//! Posição de leitura do `logd` no anel do kernel (ADR 0036, item 6).
//!
//! O kernel sobrescreve o mais antigo e não conhece o `head`. O `logd`
//! guarda a posição fora do anel e, depois de copiar cada registro, relê o
//! `tail`: se o kernel já andou mais que `data_len` além do início da cópia,
//! o registro pode ter sido coberto, então a cópia é descartada, a perda é
//! contada e a leitura recomeça em `tail − data_len`, alinhada ao próximo
//! início de registro (registros têm 8 bytes de alinhamento e não
//! atravessam o fim do vetor, como no `ostd::ring`).
//!
//! Tudo aqui é aritmética sobre posições absolutas (crescem sem dar a
//! volta); quem lê a memória é o binário.

/// Alinhamento dos registros no anel.
pub const ALIGN: u64 = 8;

/// O que fazer com a cópia de um registro que começava em `pos`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// A cópia vale; a próxima leitura começa em `next`.
    Keep {
        /// Posição seguinte.
        next: u64,
    },
    /// A cópia pode ter sido coberta: descartar, contar `lost_bytes` e
    /// recomeçar em `resume`.
    Overrun {
        /// Posição em que a leitura recomeça.
        resume: u64,
        /// Bytes pulados (para o contador de perdas).
        lost_bytes: u64,
    },
}

/// Cursor do `logd` sobre o anel do kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Próxima posição a ler.
    pub pos: u64,
    data_len: u64,
    /// Registros descartados por sobrescrita.
    pub overruns: u64,
}

impl Cursor {
    /// Cursor no começo de um anel com `data_len` bytes de dados.
    #[must_use]
    pub const fn new(data_len: u64) -> Self {
        Self {
            pos: 0,
            data_len,
            overruns: 0,
        }
    }

    /// Onde começar quando o kernel está em `tail`: se a posição atual já
    /// foi coberta, pula para o registro válido mais antigo.
    pub fn start(&mut self, tail: u64) -> u64 {
        if tail.saturating_sub(self.pos) > self.data_len {
            self.overruns += 1;
            self.pos = align_up(tail - self.data_len);
        }
        self.pos
    }

    /// Fecha a leitura de um registro de `len` bytes (arredondado) que
    /// começava em [`Cursor::pos`], com `tail` relido depois da cópia.
    pub fn finish(&mut self, len: u64, tail_after: u64) -> Verdict {
        let start = self.pos;
        if tail_after.saturating_sub(start) > self.data_len {
            let resume = align_up(tail_after - self.data_len);
            self.overruns += 1;
            self.pos = resume;
            return Verdict::Overrun {
                resume,
                lost_bytes: resume - start,
            };
        }
        self.pos = start + align_up(len);
        Verdict::Keep { next: self.pos }
    }

    /// Bytes ainda não lidos até `tail` (0 se em dia).
    #[must_use]
    pub const fn pending(&self, tail: u64) -> u64 {
        tail.saturating_sub(self.pos)
    }

    /// Deslocamento de uma posição dentro do vetor de dados.
    #[must_use]
    pub const fn offset(&self, pos: u64) -> u64 {
        pos % self.data_len
    }
}

const fn align_up(x: u64) -> u64 {
    x.div_ceil(ALIGN) * ALIGN
}

#[cfg(test)]
mod tests;
