//! Leitura mínima das tabelas ACPI (T-109): RSDP, XSDT/RSDT e HPET.
//!
//! Só o necessário para achar o HPET (e, depois, a MADT do SMP). Toda tabela
//! tem assinatura, tamanho e checksum conferidos antes do uso; tamanhos e
//! contagens têm teto, contra firmware corrompido. A memória física é lida
//! por [`PhysRead`], que o kernel implementa sobre o mapa direto.

#![forbid(unsafe_code)]

/// Leitura de memória física.
pub trait PhysRead {
    /// Preenche `buf` a partir de `phys`; `false` se a faixa não for legível.
    fn read(&mut self, phys: u64, buf: &mut [u8]) -> bool;
}

/// Erros da leitura das tabelas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// Memória ilegível.
    Unreadable,
    /// Assinatura errada.
    BadSignature,
    /// Checksum não fecha em zero.
    BadChecksum,
    /// Tamanho fora do esperado.
    BadLength,
    /// Tabela pedida não existe.
    NotFound,
    /// O HPET não está em espaço de memória.
    NotMemoryMapped,
}

/// Maior tabela aceita (bytes).
const MAX_TABLE: usize = 64 << 10;
/// Cabeçalho comum das tabelas de sistema.
const HEADER: usize = 36;

fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(word)
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut word = [0; 8];
    word.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(word)
}

/// Endereço da raiz (XSDT, ou RSDT em ACPI 1.0) e se as entradas são de 64 bits.
fn root(mem: &mut impl PhysRead, rsdp: u64) -> Result<(u64, bool), AcpiError> {
    let mut buf = [0u8; 36];
    if !mem.read(rsdp, &mut buf[..20]) {
        return Err(AcpiError::Unreadable);
    }
    if &buf[..8] != b"RSD PTR " {
        return Err(AcpiError::BadSignature);
    }
    if !checksum_ok(&buf[..20]) {
        return Err(AcpiError::BadChecksum);
    }
    if buf[15] < 2 {
        return Ok((u64::from(u32_at(&buf, 16)), false));
    }
    if !mem.read(rsdp, &mut buf) {
        return Err(AcpiError::Unreadable);
    }
    if u32_at(&buf, 20) < 36 || !checksum_ok(&buf) {
        return Err(AcpiError::BadChecksum);
    }
    Ok((u64_at(&buf, 24), true))
}

/// Lê e confere a tabela em `phys` com assinatura `sig` para `out`;
/// devolve o tamanho.
fn table(
    mem: &mut impl PhysRead,
    phys: u64,
    sig: [u8; 4],
    out: &mut [u8],
) -> Result<usize, AcpiError> {
    let mut header = [0u8; HEADER];
    if !mem.read(phys, &mut header) {
        return Err(AcpiError::Unreadable);
    }
    if header[..4] != sig {
        return Err(AcpiError::BadSignature);
    }
    let len = usize::try_from(u32_at(&header, 4)).map_err(|_| AcpiError::BadLength)?;
    if !(HEADER..=MAX_TABLE.min(out.len())).contains(&len) {
        return Err(AcpiError::BadLength);
    }
    if !mem.read(phys, &mut out[..len]) {
        return Err(AcpiError::Unreadable);
    }
    if !checksum_ok(&out[..len]) {
        return Err(AcpiError::BadChecksum);
    }
    Ok(len)
}

/// Acha a tabela `sig` pela raiz do RSDP e a copia para `out`; devolve o
/// tamanho. `out` precisa ter ao menos [`HEADER`] bytes; tabelas maiores que
/// `out` dão [`AcpiError::BadLength`].
///
/// # Errors
///
/// RSDP ou raiz inválidos, ou tabela ausente ou inválida.
pub fn find(
    mem: &mut impl PhysRead,
    rsdp: u64,
    sig: &[u8; 4],
    out: &mut [u8],
) -> Result<usize, AcpiError> {
    let (root_addr, wide) = root(mem, rsdp)?;
    let mut root_table = [0u8; 4096];
    let root_sig = if wide { b"XSDT" } else { b"RSDT" };
    let len = table(mem, root_addr, *root_sig, &mut root_table)?;
    let entry = if wide { 8 } else { 4 };
    for at in (HEADER..len - (len - HEADER) % entry).step_by(entry) {
        let addr = if wide {
            u64_at(&root_table, at)
        } else {
            u64::from(u32_at(&root_table, at))
        };
        let mut sig_buf = [0u8; 4];
        if mem.read(addr, &mut sig_buf) && &sig_buf == sig {
            return table(mem, addr, *sig, out);
        }
    }
    Err(AcpiError::NotFound)
}

/// Endereço físico dos registradores do HPET.
///
/// # Errors
///
/// Tabela HPET ausente, inválida ou fora do espaço de memória.
pub fn hpet_base(mem: &mut impl PhysRead, rsdp: u64) -> Result<u64, AcpiError> {
    let mut buf = [0u8; 56];
    let len = find(mem, rsdp, b"HPET", &mut buf)?;
    if len < 52 {
        return Err(AcpiError::BadLength);
    }
    // Generic Address Structure no deslocamento 40: espaço 0 = memória.
    if buf[40] != 0 {
        return Err(AcpiError::NotMemoryMapped);
    }
    Ok(u64_at(&buf, 44))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Memória física falsa: blocos de bytes em endereços.
    #[derive(Default)]
    struct Fake(BTreeMap<u64, Vec<u8>>);

    impl PhysRead for Fake {
        fn read(&mut self, phys: u64, buf: &mut [u8]) -> bool {
            let Some((&base, bytes)) = self.0.range(..=phys).next_back() else {
                return false;
            };
            let at = usize::try_from(phys - base).unwrap();
            match bytes.get(at..at + buf.len()) {
                Some(src) => {
                    buf.copy_from_slice(src);
                    true
                }
                None => false,
            }
        }
    }

    fn fix_checksum(bytes: &mut [u8], at: usize, range: usize) {
        bytes[at] = 0;
        let sum = bytes[..range].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        bytes[at] = sum.wrapping_neg();
    }

    fn sdt(sig: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; HEADER];
        t[..4].copy_from_slice(&sig);
        t.extend_from_slice(body);
        let len = u32::try_from(t.len()).unwrap();
        t[4..8].copy_from_slice(&len.to_le_bytes());
        let n = t.len();
        fix_checksum(&mut t, 9, n);
        t
    }

    fn hpet_body(space: u8, base: u64) -> Vec<u8> {
        let mut body = vec![0u8; 20];
        body[4] = space;
        body[8..16].copy_from_slice(&base.to_le_bytes());
        body
    }

    /// RSDP 2.0 em 0xe0000 -> XSDT em 0x1000 -> [FACP falsa, HPET].
    fn machine(hpet: Vec<u8>) -> Fake {
        let mut mem = Fake::default();
        let mut rsdp = vec![0u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
        fix_checksum(&mut rsdp, 8, 20);
        fix_checksum(&mut rsdp, 32, 36);
        mem.0.insert(0xe_0000, rsdp);
        let mut entries = Vec::new();
        entries.extend_from_slice(&0x2000u64.to_le_bytes());
        entries.extend_from_slice(&0x3000u64.to_le_bytes());
        mem.0.insert(0x1000, sdt(*b"XSDT", &entries));
        mem.0.insert(0x2000, sdt(*b"FACP", &[0; 8]));
        mem.0.insert(0x3000, hpet);
        mem
    }

    #[test]
    fn acha_o_hpet_pela_xsdt() {
        let mut mem = machine(sdt(*b"HPET", &hpet_body(0, 0xfed0_0000)));
        assert_eq!(hpet_base(&mut mem, 0xe_0000), Ok(0xfed0_0000));
        let mut out = [0u8; 64];
        assert_eq!(find(&mut mem, 0xe_0000, b"FACP", &mut out), Ok(44));
        assert_eq!(
            find(&mut mem, 0xe_0000, b"APIC", &mut out),
            Err(AcpiError::NotFound)
        );
    }

    #[test]
    fn recusa_tabelas_estragadas() {
        let mut bad = sdt(*b"HPET", &hpet_body(0, 0xfed0_0000));
        bad[50] ^= 1;
        assert_eq!(
            hpet_base(&mut machine(bad), 0xe_0000),
            Err(AcpiError::BadChecksum)
        );
        let io = sdt(*b"HPET", &hpet_body(1, 0x40));
        assert_eq!(
            hpet_base(&mut machine(io), 0xe_0000),
            Err(AcpiError::NotMemoryMapped)
        );
        let mut mem = machine(sdt(*b"HPET", &hpet_body(0, 1)));
        assert_eq!(hpet_base(&mut mem, 0x1000), Err(AcpiError::BadSignature));
        assert_eq!(hpet_base(&mut mem, 0x9000), Err(AcpiError::Unreadable));
        mem.0.get_mut(&0xe_0000).unwrap()[30] ^= 1;
        assert_eq!(hpet_base(&mut mem, 0xe_0000), Err(AcpiError::BadChecksum));
    }

    #[test]
    fn acpi_1_usa_a_rsdt() {
        let mut mem = Fake::default();
        let mut rsdp = vec![0u8; 20];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
        fix_checksum(&mut rsdp, 8, 20);
        mem.0.insert(0xe_0000, rsdp);
        mem.0
            .insert(0x1000, sdt(*b"RSDT", &0x3000u32.to_le_bytes()));
        mem.0
            .insert(0x3000, sdt(*b"HPET", &hpet_body(0, 0xfed0_0000)));
        assert_eq!(hpet_base(&mut mem, 0xe_0000), Ok(0xfed0_0000));
    }
}
