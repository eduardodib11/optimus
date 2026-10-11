//! BLAKE3 (hash, hash com chave e derivação de chave), na forma da
//! implementação de referência da especificação: compressão de 7 rodadas
//! sobre blocos de 64 bytes, pedaços (chunks) de 1 KiB e árvore binária de
//! valores de encadeamento mantida numa pilha.
//!
//! Provisória até a ADR 0004 (veja a documentação da crate).

/// Bytes da saída padrão.
pub const OUT_LEN: usize = 32;
/// Bytes da chave de [`Hasher::new_keyed`].
pub const KEY_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
/// [`BLOCK_LEN`] como palavra do bloco de compressão.
const BLOCK_WORD: u32 = 64;
const CHUNK_LEN: usize = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Profundidade máxima da árvore: 2^54 pedaços cobrem 2^64 bytes.
const MAX_DEPTH: usize = 54;

type Words8 = [u32; 8];
type Words16 = [u32; 16];

/// Função de mistura G sobre as colunas/diagonais `a`, `b`, `c` e `d`.
#[allow(clippy::many_single_char_names, reason = "nomes da especificação")]
fn g(s: &mut Words16, [a, b, c, d]: [usize; 4], mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn round(s: &mut Words16, m: &Words16) {
    g(s, [0, 4, 8, 12], m[0], m[1]);
    g(s, [1, 5, 9, 13], m[2], m[3]);
    g(s, [2, 6, 10, 14], m[4], m[5]);
    g(s, [3, 7, 11, 15], m[6], m[7]);
    g(s, [0, 5, 10, 15], m[8], m[9]);
    g(s, [1, 6, 11, 12], m[10], m[11]);
    g(s, [2, 7, 8, 13], m[12], m[13]);
    g(s, [3, 4, 9, 14], m[14], m[15]);
}

fn permute(m: &mut Words16) {
    *m = core::array::from_fn(|i| m[MSG_PERMUTATION[i]]);
}

/// Metade baixa e alta de um contador de 64 bits.
#[allow(
    clippy::cast_possible_truncation,
    reason = "divide o contador em palavras"
)]
const fn split(counter: u64) -> (u32, u32) {
    (counter as u32, (counter >> 32) as u32)
}

fn compress(cv: &Words8, block: &Words16, counter: u64, block_len: u32, flags: u32) -> Words16 {
    let (lo, hi) = split(counter);
    let mut s = [
        cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7], IV[0], IV[1], IV[2], IV[3], lo, hi,
        block_len, flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        round(&mut s, &m);
        if r < 6 {
            permute(&mut m);
        }
    }
    for i in 0..8 {
        s[i] ^= s[i + 8];
        s[i + 8] ^= cv[i];
    }
    s
}

fn first_8(words: Words16) -> Words8 {
    core::array::from_fn(|i| words[i])
}

fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0; N];
    for (w, chunk) in out.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    out
}

/// Um nó ainda não comprimido: vira valor de encadeamento ou, na raiz, saída.
struct Output {
    cv: Words8,
    block: Words16,
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> Words8 {
        first_8(compress(
            &self.cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }

    fn root_bytes(&self, out: &mut [u8]) {
        for (counter, block) in (0u64..).zip(out.chunks_mut(2 * OUT_LEN)) {
            let words = compress(
                &self.cv,
                &self.block,
                counter,
                self.block_len,
                self.flags | ROOT,
            );
            for (word, dst) in words.iter().zip(block.chunks_mut(4)) {
                dst.copy_from_slice(&word.to_le_bytes()[..dst.len()]);
            }
        }
    }
}

fn parent(left: Words8, right: Words8, key: Words8, flags: u32) -> Output {
    let block = core::array::from_fn(|i| if i < 8 { left[i] } else { right[i - 8] });
    Output {
        cv: key,
        block,
        counter: 0,
        block_len: BLOCK_WORD,
        flags: PARENT | flags,
    }
}

struct ChunkState {
    cv: Words8,
    counter: u64,
    block: [u8; BLOCK_LEN],
    block_len: usize,
    blocks_compressed: usize,
    flags: u32,
}

impl ChunkState {
    const fn new(key: Words8, counter: u64, flags: u32) -> Self {
        Self {
            cv: key,
            counter,
            block: [0; BLOCK_LEN],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    const fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed + self.block_len
    }

    const fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len == BLOCK_LEN {
                let words = le_words(&self.block);
                let flags = self.flags | self.start_flag();
                self.cv = first_8(compress(&self.cv, &words, self.counter, BLOCK_WORD, flags));
                self.blocks_compressed += 1;
                self.block = [0; BLOCK_LEN];
                self.block_len = 0;
            }
            let take = (BLOCK_LEN - self.block_len).min(input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
        }
    }

    #[allow(clippy::cast_possible_truncation, reason = "block_len ≤ 64")]
    fn output(&self) -> Output {
        Output {
            cv: self.cv,
            block: le_words(&self.block),
            counter: self.counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }
}

/// Estado incremental do BLAKE3.
pub struct Hasher {
    chunk: ChunkState,
    key: Words8,
    stack: [Words8; MAX_DEPTH],
    stack_len: usize,
    flags: u32,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    const fn with(key: Words8, flags: u32) -> Self {
        Self {
            chunk: ChunkState::new(key, 0, flags),
            key,
            stack: [[0; 8]; MAX_DEPTH],
            stack_len: 0,
            flags,
        }
    }

    /// Modo hash.
    #[must_use]
    pub const fn new() -> Self {
        Self::with(IV, 0)
    }

    /// Modo hash com chave (MAC).
    #[must_use]
    pub fn new_keyed(key: &[u8; KEY_LEN]) -> Self {
        Self::with(le_words(key), KEYED_HASH)
    }

    /// Modo derivação de chave, com o contexto fixo `context`.
    #[must_use]
    pub fn new_derive_key(context: &str) -> Self {
        let mut ctx = Self::with(IV, DERIVE_KEY_CONTEXT);
        ctx.update(context.as_bytes());
        let mut key = [0; KEY_LEN];
        ctx.finalize_xof(&mut key);
        Self::with(le_words(&key), DERIVE_KEY_MATERIAL)
    }

    fn push(&mut self, cv: Words8) {
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
    }

    fn pop(&mut self) -> Words8 {
        self.stack_len -= 1;
        self.stack[self.stack_len]
    }

    /// Junta o valor de um pedaço completo à árvore: cada zero no fim de
    /// `total` (pedaços até aqui) fecha uma subárvore completa.
    fn add_chunk(&mut self, mut cv: Words8, mut total: u64) {
        while total & 1 == 0 {
            cv = parent(self.pop(), cv, self.key, self.flags).chaining_value();
            total >>= 1;
        }
        self.push(cv);
    }

    /// Soma `input` ao que já foi lido.
    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        while !input.is_empty() {
            if self.chunk.len() == CHUNK_LEN {
                let cv = self.chunk.output().chaining_value();
                let total = self.chunk.counter + 1;
                self.add_chunk(cv, total);
                self.chunk = ChunkState::new(self.key, total, self.flags);
            }
            let take = (CHUNK_LEN - self.chunk.len()).min(input.len());
            self.chunk.update(&input[..take]);
            input = &input[take..];
        }
        self
    }

    /// Saída de tamanho qualquer (XOF) em `out`; o estado não muda.
    pub fn finalize_xof(&self, out: &mut [u8]) {
        let mut node = self.chunk.output();
        for i in (0..self.stack_len).rev() {
            node = parent(self.stack[i], node.chaining_value(), self.key, self.flags);
        }
        node.root_bytes(out);
    }

    /// Saída padrão de 32 bytes.
    #[must_use]
    pub fn finalize(&self) -> [u8; OUT_LEN] {
        let mut out = [0; OUT_LEN];
        self.finalize_xof(&mut out);
        out
    }
}

/// BLAKE3 de `data` (32 bytes).
#[must_use]
pub fn hash(data: &[u8]) -> [u8; OUT_LEN] {
    Hasher::new().update(data).finalize()
}

#[cfg(test)]
mod tests;
