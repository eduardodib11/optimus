//! Commit atômico e montagem (ADR 0052, itens 4 e 6).

use crate::io::{BlockIo, IoError};
use optfs_format::{BLOCK_SIZE, FIRST_ALLOC, SUPERBLOCKS, Sha256, Superblock};

/// Resultado de [`mount`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mounted {
    /// O superbloco escolhido.
    pub sb: Superblock,
    /// Se o outro superbloco falhou na conferência (o de maior txg
    /// rasgado, depois de uma queda: o chamador registra
    /// `optfs: superbloco txg=N inválido, montado txg=M`).
    pub other_invalid: bool,
}

/// Escolhe o superbloco válido de maior txg.
///
/// # Errors
/// [`IoError::Integrity`] se nenhum dos dois é válido; [`IoError::Io`]
/// se a leitura falha em ambos.
pub fn mount(io: &mut impl BlockIo, h: &impl Sha256) -> Result<Mounted, IoError> {
    let mut found: [Option<Superblock>; 2] = [None, None];
    let mut io_err = 0;
    for (i, slot) in SUPERBLOCKS.iter().enumerate() {
        let mut b = [0u8; BLOCK_SIZE];
        match io.read(*slot, &mut b) {
            Ok(()) => found[i] = Superblock::decode(&b, h).ok(),
            Err(_) => io_err += 1,
        }
    }
    let valid = |s: &&Superblock| s.volume_blocks == io.blocks();
    let best = found.iter().flatten().filter(valid).max_by_key(|s| s.txg);
    match best {
        Some(sb) => Ok(Mounted {
            sb: *sb,
            other_invalid: found.iter().flatten().filter(valid).count() < 2,
        }),
        None if io_err == 2 => Err(IoError::Io),
        None => Err(IoError::Integrity),
    }
}

/// Confirma o txg `prev.txg + 1`: grava `blocks` (nós e dados novos),
/// `flush`, grava o superbloco novo no bloco `2 + txg % 2`, `flush`.
/// Só depois do segundo `flush` o txg vale; uma falha antes deixa o
/// superbloco antigo em vigor.
///
/// `new` traz o superbloco novo sem txg (ele é calculado aqui) e o
/// chamador já pôs nele a raiz e a contagem de livres.
///
/// # Errors
/// [`IoError::BadRequest`] se algum bloco cai fora da área alocável (o
/// superbloco ativo e o de reserva nunca são tocados pelos dados);
/// [`IoError::Io`] se o dispositivo falha.
pub fn commit<'a>(
    io: &mut impl BlockIo,
    h: &impl Sha256,
    prev: &Superblock,
    mut new: Superblock,
    blocks: impl IntoIterator<Item = (u64, &'a [u8; BLOCK_SIZE])>,
) -> Result<Superblock, IoError> {
    // O txg vem do disco: no limite do `u64` não há próximo commit.
    let txg = prev.txg.checked_add(1).ok_or(IoError::Full)?;
    let end = io.blocks();
    for (n, data) in blocks {
        if n < FIRST_ALLOC || n >= end.saturating_sub(1) {
            return Err(IoError::BadRequest);
        }
        io.write(n, data)?;
    }
    io.flush()?;
    new.txg = txg;
    new.volume_blocks = prev.volume_blocks;
    new.uuid = prev.uuid;
    io.write(SUPERBLOCKS[(new.txg % 2) as usize], &new.encode(h))?;
    io.flush()?;
    Ok(new)
}
