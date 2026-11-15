//! Acesso a blocos de 4 KiB.

use optfs_format::BLOCK_SIZE;

/// Erro de E/S.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IoError {
    /// O dispositivo falhou ou o bloco está fora do volume.
    Io,
    /// O conteúdo lido não confere (superbloco, ponteiro).
    Integrity,
    /// Pedido inválido (bloco reservado ou fora da área alocável).
    BadRequest,
    /// Sem blocos livres.
    Full,
}

/// Dispositivo de blocos com a semântica da ADR 0056, item 5: `write`
/// concluído não é durável, `flush` concluído torna duráveis todas as
/// escritas anteriores.
pub trait BlockIo {
    /// Tamanho do volume em blocos.
    fn blocks(&self) -> u64;
    /// Lê o bloco `block`.
    ///
    /// # Errors
    /// [`IoError::Io`] se o dispositivo falha.
    fn read(&mut self, block: u64, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), IoError>;
    /// Escreve o bloco `block`.
    ///
    /// # Errors
    /// [`IoError::Io`] se o dispositivo falha.
    fn write(&mut self, block: u64, buf: &[u8; BLOCK_SIZE]) -> Result<(), IoError>;
    /// Torna duráveis as escritas já concluídas.
    ///
    /// # Errors
    /// [`IoError::Io`] se o dispositivo falha.
    fn flush(&mut self) -> Result<(), IoError>;
}
