//! `oidl-rt`: primitivas de leitura e escrita do formato de fio do OIDL
//! (ADR 0033, T-340).
//!
//! O código gerado pelo `oidlc` usa estas primitivas para montar e ler os
//! corpos das mensagens. Um corpo tem uma cabeça de tamanho fixo (escalares
//! e ponteiros de `string` e `vec`) seguida de uma cauda com os bytes
//! apontados. A cauda é canônica: cada região começa exatamente onde a
//! anterior terminou, arredondada a 8 bytes. Assim a decodificação é uma
//! passada só e não aceita sobreposição nem sobra.
//!
//! Ler não aloca e não entra em pânico: corpo fora do formato vira
//! [`Error::BadMessage`]. Escrever num buffer fixo devolve
//! [`Error::TooLarge`] quando o valor não cabe.
//!
//! Os elementos de um `vec` são lidos e escritos depois de [`Reader::seek`]
//! ou [`Writer::seek`] para a posição da região, na ordem da ADR 0033.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[cfg(test)]
mod tests;

/// Erros de leitura e escrita (códigos 4 e 5 da ADR 0033).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Corpo fora do formato: limite estourado, UTF-8 inválido, `bool`
    /// diferente de 0 e 1, região fora do lugar ou corpo com sobra.
    BadMessage,
    /// Valor maior que o limite declarado ou que o buffer.
    TooLarge,
}

/// Resultado de leitura e escrita.
pub type Result<T> = core::result::Result<T, Error>;

/// Arredonda para cima, para múltiplo de 8. `None` se estourar `usize`.
fn round8(n: usize) -> Option<usize> {
    n.checked_add(7).map(|v| v & !7)
}

/// Ponteiro de `string` ou `vec` na cabeça: deslocamento e contagem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ptr {
    off: u32,
    len: u32,
}

/// Região validada na cauda: deslocamento do primeiro elemento e contagem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elems {
    off: usize,
    count: usize,
}

impl Elems {
    /// Deslocamento do primeiro elemento no corpo.
    #[must_use]
    pub const fn off(&self) -> usize {
        self.off
    }

    /// Número de elementos.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }
}

/// Leitor de um corpo: cabeça pela posição, cauda pelo cursor canônico.
#[derive(Debug)]
pub struct Reader<'a> {
    body: &'a [u8],
    pos: usize,
    tail: usize,
}

impl<'a> Reader<'a> {
    /// Abre `body`, cuja cabeça tem `head_len` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo não tem tamanho múltiplo de 8 ou se
    /// a cabeça não cabe nele.
    pub fn new(body: &'a [u8], head_len: usize) -> Result<Self> {
        if !body.len().is_multiple_of(8) {
            return Err(Error::BadMessage);
        }
        let tail = round8(head_len).ok_or(Error::BadMessage)?;
        if tail > body.len() {
            return Err(Error::BadMessage);
        }
        Ok(Self { body, pos: 0, tail })
    }

    /// Move a cabeça para `pos`, para ler os elementos de uma região.
    pub const fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Lê `N` bytes alinhados a `N` na cabeça. O enchimento é ignorado.
    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let start = self.pos.next_multiple_of(N);
        let end = start.checked_add(N).ok_or(Error::BadMessage)?;
        let bytes: [u8; N] = self
            .body
            .get(start..end)
            .ok_or(Error::BadMessage)?
            .try_into()
            .map_err(|_| Error::BadMessage)?;
        self.pos = end;
        Ok(bytes)
    }

    /// Lê um `u8`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes.
    pub fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.take()?))
    }

    /// Lê um `u16`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes.
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take()?))
    }

    /// Lê um `u32`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes.
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take()?))
    }

    /// Lê um `u64`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes.
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take()?))
    }

    /// Lê um `i64`.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes.
    pub fn i64(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.take()?))
    }

    /// Lê um `bool`, que só pode ser 0 ou 1.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se o corpo acabar antes ou o byte não for 0 ou 1.
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::BadMessage),
        }
    }

    /// Lê o ponteiro da cabeça.
    fn ptr(&mut self) -> Result<Ptr> {
        Ok(Ptr {
            off: self.u32()?,
            len: self.u32()?,
        })
    }

    /// Valida a região de `p` com elementos de `elem` bytes: tem de começar
    /// no cursor, caber no corpo e avança o cursor pelo arredondamento de 8.
    fn region(&mut self, p: Ptr, elem: usize) -> Result<Elems> {
        let off = usize::try_from(p.off).map_err(|_| Error::BadMessage)?;
        let count = usize::try_from(p.len).map_err(|_| Error::BadMessage)?;
        let bytes = count.checked_mul(elem).ok_or(Error::BadMessage)?;
        let end = off.checked_add(bytes).ok_or(Error::BadMessage)?;
        if off != self.tail || end > self.body.len() {
            return Err(Error::BadMessage);
        }
        self.tail = round8(end).ok_or(Error::BadMessage)?;
        Ok(Elems { off, count })
    }

    /// Lê uma `string<max>`: a região UTF-8 de `p` na cauda.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se a região estiver fora do lugar, passar de
    /// `max` bytes ou não for UTF-8 válido.
    pub fn string(&mut self, max: usize) -> Result<&'a str> {
        let p = self.ptr()?;
        let e = self.region(p, 1)?;
        if e.count > max {
            return Err(Error::BadMessage);
        }
        let bytes = self
            .body
            .get(e.off..e.off + e.count)
            .ok_or(Error::BadMessage)?;
        core::str::from_utf8(bytes).map_err(|_| Error::BadMessage)
    }

    /// Lê o cabeçalho de um `vec<T, max>` com elementos de `elem` bytes. Os
    /// elementos ficam na região devolvida; leia-os com [`Reader::seek`].
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se a região estiver fora do lugar ou passar de
    /// `max` elementos.
    pub fn vec(&mut self, max: usize, elem: usize) -> Result<Elems> {
        let p = self.ptr()?;
        let e = self.region(p, elem)?;
        if e.count > max {
            return Err(Error::BadMessage);
        }
        Ok(e)
    }

    /// Confere que o corpo acabou exatamente no fim da cauda canônica.
    ///
    /// # Errors
    ///
    /// [`Error::BadMessage`] se sobrou byte depois da última região.
    pub fn finish(self) -> Result<()> {
        if self.tail == self.body.len() {
            Ok(())
        } else {
            Err(Error::BadMessage)
        }
    }
}

/// Escritor de um corpo de tamanho fixo. Zera o buffer ao abrir, então o
/// enchimento sai zero.
#[derive(Debug)]
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
    tail: usize,
}

impl<'a> Writer<'a> {
    /// Abre `buf` para um corpo cuja cabeça tem `head_len` bytes.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se a cabeça não cabe no buffer.
    pub fn new(buf: &'a mut [u8], head_len: usize) -> Result<Self> {
        let tail = round8(head_len).ok_or(Error::TooLarge)?;
        if tail > buf.len() {
            return Err(Error::TooLarge);
        }
        buf.fill(0);
        Ok(Self { buf, pos: 0, tail })
    }

    /// Move a cabeça para `pos`, para escrever os elementos de uma região.
    pub const fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Escreve `bytes` em `at`.
    fn write_at(&mut self, at: usize, bytes: &[u8]) -> Result<()> {
        let end = at.checked_add(bytes.len()).ok_or(Error::TooLarge)?;
        self.buf
            .get_mut(at..end)
            .ok_or(Error::TooLarge)?
            .copy_from_slice(bytes);
        Ok(())
    }

    /// Escreve `N` bytes na cabeça, alinhados a `N`.
    fn put<const N: usize>(&mut self, bytes: [u8; N]) -> Result<()> {
        let start = self.pos.next_multiple_of(N);
        self.write_at(start, &bytes)?;
        self.pos = start + N;
        Ok(())
    }

    /// Reserva `n` bytes no fim da cauda e devolve o deslocamento.
    fn reserve(&mut self, n: usize) -> Result<usize> {
        let off = self.tail;
        let end = off.checked_add(n).ok_or(Error::TooLarge)?;
        let next = round8(end).ok_or(Error::TooLarge)?;
        if next > self.buf.len() {
            return Err(Error::TooLarge);
        }
        self.tail = next;
        Ok(off)
    }

    /// Escreve o ponteiro `off`/`len` na cabeça.
    fn put_ptr(&mut self, off: usize, len: usize) -> Result<()> {
        self.put(
            u32::try_from(off)
                .map_err(|_| Error::TooLarge)?
                .to_le_bytes(),
        )?;
        self.put(
            u32::try_from(len)
                .map_err(|_| Error::TooLarge)?
                .to_le_bytes(),
        )
    }

    /// Escreve um `u8`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn u8(&mut self, v: u8) -> Result<()> {
        self.put(v.to_le_bytes())
    }

    /// Escreve um `u16`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn u16(&mut self, v: u16) -> Result<()> {
        self.put(v.to_le_bytes())
    }

    /// Escreve um `u32`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn u32(&mut self, v: u32) -> Result<()> {
        self.put(v.to_le_bytes())
    }

    /// Escreve um `u64`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn u64(&mut self, v: u64) -> Result<()> {
        self.put(v.to_le_bytes())
    }

    /// Escreve um `i64`.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn i64(&mut self, v: i64) -> Result<()> {
        self.put(v.to_le_bytes())
    }

    /// Escreve um `bool` como 0 ou 1.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se não couber no buffer.
    pub fn bool(&mut self, v: bool) -> Result<()> {
        self.u8(u8::from(v))
    }

    /// Escreve uma `string<max>`: os bytes vão para a cauda e o ponteiro
    /// para a cabeça.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se `s` passar de `max` bytes ou não couber.
    pub fn string(&mut self, s: &str, max: usize) -> Result<()> {
        if s.len() > max {
            return Err(Error::TooLarge);
        }
        let off = self.reserve(s.len())?;
        self.write_at(off, s.as_bytes())?;
        self.put_ptr(off, s.len())
    }

    /// Escreve o ponteiro de um `vec<T, max>` com `count` elementos de
    /// `elem` bytes e reserva a região, zerada. Devolve o deslocamento dela:
    /// escreva os elementos com [`Writer::seek`].
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] se `count` passar de `max` ou a região não couber.
    pub fn vec(&mut self, count: usize, elem: usize, max: usize) -> Result<usize> {
        if count > max {
            return Err(Error::TooLarge);
        }
        let bytes = count.checked_mul(elem).ok_or(Error::TooLarge)?;
        let off = self.reserve(bytes)?;
        self.put_ptr(off, count)?;
        Ok(off)
    }

    /// Fecha o corpo e devolve o tamanho em bytes, múltiplo de 8.
    #[must_use]
    pub const fn finish(self) -> usize {
        self.tail
    }
}
