//! Máscara de direitos de 32 bits de uma capability (seções 6.1 e 6.2).

use core::ops::{BitAnd, BitOr};

use crate::UnknownValue;

/// Conjunto de direitos de uma capability.
///
/// Os nomes vêm da tabela 6.1; um mesmo bit vale para todo tipo de objeto (ex.
/// `MAP` em `AddressSpace`, `MemoryObject` e `DmaDomain`). Os bits seguem a
/// ordem da primeira aparição na tabela (definido aqui, o SDD não fixa).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rights(u32);

impl Rights {
    /// Nenhum direito.
    pub const NONE: Self = Self(0);
    /// Todos os direitos definidos.
    pub const ALL: Self = Self((1 << 22) - 1);

    /// Os bits crus.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Converte bits crus; `None` se houver bit não definido.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Verdadeiro se `self` tem todos os direitos de `other`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// União de direitos.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Interseção de direitos.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Direitos de uma cópia feita por `cap_mint` com máscara `mask`.
    ///
    /// O resultado está sempre contido em `self`: direitos nunca aumentam.
    #[must_use]
    pub const fn derive(self, mask: Self) -> Self {
        self.intersection(mask)
    }
}

/// Define as constantes de direitos com doc em uma linha cada.
macro_rules! rights {
    ($($name:ident = $bit:literal => $doc:literal,)+) => {
        impl Rights {
            $(#[doc = $doc] pub const $name: Self = Self(1 << $bit);)+
        }
    };
}

rights! {
    CREATE = 0 => "Criar objetos debitando a cota (`MemoryQuota`).",
    SPLIT = 1 => "Dividir a cota (`MemoryQuota`).",
    MAP = 2 => "Mapear (`AddressSpace`, `MemoryObject`, `DmaDomain`, `Vm`).",
    UNMAP = 3 => "Desmapear (`AddressSpace`).",
    MANAGE = 4 => "Gerenciar slots (`CapSpace`).",
    START = 5 => "Iniciar (`Thread`).",
    SUSPEND = 6 => "Suspender (`Thread`).",
    READ_STATE = 7 => "Ler registradores (`Thread`).",
    WRITE_STATE = 8 => "Escrever registradores (`Thread`).",
    BIND = 9 => "Ligar (`SchedContext`, `Interrupt`), ligar a morte a uma `Notification` (`Thread`, `CapSpace`) e armar, rearmar e desarmar (`Timer`; ADR 0035).",
    CONFIGURE = 10 => "Configurar (`SchedContext`).",
    READ = 11 => "Ler (`MemoryObject`, `IoPortRange`).",
    WRITE = 12 => "Escrever (`MemoryObject`, `IoPortRange`).",
    EXEC = 13 => "Executar (`MemoryObject`).",
    SEND = 14 => "Enviar (`Endpoint`, `Reply`).",
    RECV = 15 => "Receber (`Endpoint`).",
    GRANT = 16 => "Transferir capabilities por IPC (`Endpoint`).",
    SIGNAL = 17 => "Sinalizar (`Notification`).",
    WAIT = 18 => "Esperar (`Notification`).",
    ACK = 19 => "Reconhecer IRQ (`Interrupt`).",
    RUN = 20 => "Executar a VM (`Vcpu`, `Vm`).",
    DESTROY = 21 => "Destruir o objeto com `cap_delete(DESTROY)` (`CapSpace`, `Thread`, `Endpoint`; ADR 0035).",
}

impl BitOr for Rights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        self.union(rhs)
    }
}

impl BitAnd for Rights {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        self.intersection(rhs)
    }
}

impl TryFrom<u64> for Rights {
    type Error = UnknownValue;

    /// Recusa bits fora dos 32 baixos ou não definidos.
    fn try_from(raw: u64) -> Result<Self, UnknownValue> {
        u32::try_from(raw)
            .ok()
            .and_then(Self::from_bits)
            .ok_or(UnknownValue(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_estaveis() {
        assert_eq!(Rights::CREATE.bits(), 1);
        assert_eq!(Rights::MAP.bits(), 1 << 2);
        assert_eq!(Rights::SEND.bits(), 1 << 14);
        assert_eq!(Rights::GRANT.bits(), 1 << 16);
        assert_eq!(Rights::RUN.bits(), 1 << 20);
        assert_eq!(Rights::DESTROY.bits(), 1 << 21);
        assert_eq!(Rights::ALL.bits(), 0x3F_FFFF);
    }

    #[test]
    fn derivacao_so_reduz() {
        let pai = Rights::SEND | Rights::RECV;
        for mask in [
            0,
            1,
            0xFFFF,
            0x1F_FFFF,
            Rights::GRANT.bits() | Rights::SEND.bits(),
        ] {
            let filho = pai.derive(Rights::from_bits(mask).unwrap());
            assert!(pai.contains(filho));
        }
        assert_eq!(pai.derive(Rights::SEND | Rights::GRANT), Rights::SEND);
        assert_eq!(pai.derive(Rights::NONE), Rights::NONE);
        assert!(!pai.contains(Rights::GRANT));
        assert!(pai.contains(Rights::NONE));
    }

    #[test]
    fn conversao_de_registrador() {
        let r = Rights::READ | Rights::WRITE;
        assert_eq!(Rights::try_from(u64::from(r.bits())), Ok(r));
        assert!(Rights::try_from(1 << 21).is_ok());
        assert!(Rights::try_from(1 << 22).is_err());
        assert!(Rights::try_from(1 << 32).is_err());
        assert_eq!(Rights::from_bits(u32::MAX), None);
    }
}
