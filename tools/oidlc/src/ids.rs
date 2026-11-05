//! Identificadores de interface e rótulos de IPC (ADR 0033, seção 2).
//!
//! `interface_id` são os quatro primeiros bytes, em little-endian, de
//! `BLAKE3("<pacote>.<Interface>@<maior>")`. A versão maior entra no hash, então
//! `@1` e `@2` convivem no mesmo endpoint.

/// Rótulo de pedido: `interface_id` (32 bits altos), versão menor mínima (16
/// bits) e ordinal do método (16 bits baixos).
#[must_use]
pub const fn rotulo_pedido(interface_id: u32, minor_min: u16, metodo: u16) -> u64 {
    ((interface_id as u64) << 32) | ((minor_min as u64) << 16) | (metodo as u64)
}

/// Rótulo de resposta: tipo nos bits 61..62 (0 `Ok`, 1 `Err`, 2 protocolo) e
/// código nos 16 bits baixos (zero para `Ok` e `Err`).
#[must_use]
pub const fn rotulo_resposta(tipo: u8, codigo: u16) -> u64 {
    ((tipo as u64 & 0b11) << 62) | (codigo as u64)
}

/// `interface_id` de `<pacote>.<Interface>@<maior>`.
#[must_use]
pub fn interface_id(pacote: &str, interface: &str, maior: u32) -> u32 {
    let texto = format!("{pacote}.{interface}@{maior}");
    let hash = blake3::hash(texto.as_bytes());
    let b = hash.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vetor_da_adr_0033() {
        // ADR 0033, seção 6: optimus.fs.Directory@1 começa por bb d8 7c a1.
        assert_eq!(interface_id("optimus.fs", "Directory", 1), 0xA17C_D8BB);
    }

    #[test]
    fn maior_entra_no_hash() {
        assert_ne!(
            interface_id("optimus.fs", "Directory", 1),
            interface_id("optimus.fs", "Directory", 2)
        );
    }

    #[test]
    fn rotulos_da_adr() {
        // trash é o método 1 de optimus.fs.Directory@1, minor_min 0.
        assert_eq!(rotulo_pedido(0xA17C_D8BB, 0, 1), 0xA17C_D8BB_0000_0001);
        assert_eq!(rotulo_pedido(0xA17C_D8BB, 0, 0), 0xA17C_D8BB_0000_0000);
        // Err(NotDirectory): tipo 1 no bit 62, código zero.
        assert_eq!(rotulo_resposta(1, 0), 0x4000_0000_0000_0000);
    }
}
