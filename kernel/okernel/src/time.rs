//! Aritmética do relógio monotônico (T-109; SDD v1.0, seção 6.8).
//!
//! O relógio do kernel conta nanossegundos a partir do TSC: `ns = (ticks ×
//! mult) >> 32`, com `mult` calculado uma vez na calibragem. Sem divisão no
//! caminho quente e sem estouro por séculos (o produto é feito em 128 bits).

#![forbid(unsafe_code)]

/// Nanossegundos por segundo.
pub const NS_PER_SEC: u64 = 1_000_000_000;
/// Femtossegundos por nanossegundo (o HPET anuncia o período em fs).
pub const FS_PER_NS: u64 = 1_000_000;
const SHIFT: u32 = 32;

/// Conversão entre contagens de um contador de frequência fixa e ns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scale {
    mult: u64,
}

impl Scale {
    /// Escala de um contador de `hz` contagens por segundo; `None` se `hz` for zero.
    #[must_use]
    pub fn from_hz(hz: u64) -> Option<Self> {
        let mult = (u128::from(NS_PER_SEC) << SHIFT).checked_div(u128::from(hz))?;
        Some(Self {
            mult: u64::try_from(mult).ok()?,
        })
    }

    /// O multiplicador (ns por contagem, em ponto fixo 32.32), para guardar
    /// numa atômica.
    #[must_use]
    pub const fn mult(self) -> u64 {
        self.mult
    }

    /// Escala de um multiplicador de [`Self::mult`]; `None` se for zero.
    #[must_use]
    pub const fn from_mult(mult: u64) -> Option<Self> {
        if mult == 0 { None } else { Some(Self { mult }) }
    }

    /// Contagens para ns (satura em `u64::MAX`, meio milênio).
    #[must_use]
    pub fn ticks_to_ns(self, ticks: u64) -> u64 {
        let ns = (u128::from(ticks) * u128::from(self.mult)) >> SHIFT;
        u64::try_from(ns).unwrap_or(u64::MAX)
    }

    /// Ns para contagens, arredondando para cima (um prazo nunca dispara cedo).
    #[must_use]
    pub fn ns_to_ticks(self, ns: u64) -> u64 {
        let ticks = (u128::from(ns) << SHIFT).div_ceil(u128::from(self.mult.max(1)));
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }
}

/// Frequência de um contador que andou `ticks` em `ns` nanossegundos.
#[must_use]
pub fn hz_from(ticks: u64, ns: u64) -> Option<u64> {
    let hz = (u128::from(ticks) * u128::from(NS_PER_SEC)).checked_div(u128::from(ns))?;
    u64::try_from(hz).ok()
}

/// Contagens do HPET para ns, dado o período em femtossegundos.
#[must_use]
pub fn hpet_ticks_to_ns(ticks: u64, period_fs: u64) -> u64 {
    let ns = u128::from(ticks) * u128::from(period_fs) / u128::from(FS_PER_NS);
    u64::try_from(ns).unwrap_or(u64::MAX)
}

/// Desvio de `measured` em relação a `reference`, em partes por milhão.
#[must_use]
pub fn deviation_ppm(measured: u64, reference: u64) -> u64 {
    let diff = u128::from(measured.abs_diff(reference)) * 1_000_000;
    u64::try_from(diff.checked_div(u128::from(reference)).unwrap_or(u128::MAX)).unwrap_or(u64::MAX)
}

/// Relógio monotônico sobre um contador que só cresce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    /// Contagem do instante zero.
    pub base: u64,
    /// Escala do contador.
    pub scale: Scale,
}

impl Clock {
    /// Ns desde `base` para a contagem `now` (contagens anteriores dão zero).
    #[must_use]
    pub fn ns(&self, now: u64) -> u64 {
        self.scale.ticks_to_ns(now.saturating_sub(self.base))
    }

    /// Contagem do contador no instante `ns`.
    #[must_use]
    pub fn ticks_at(&self, ns: u64) -> u64 {
        self.base.saturating_add(self.scale.ns_to_ticks(ns))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escala_ida_e_volta() {
        for hz in [1_000_000, 14_318_180, 2_995_200_000, 5_000_000_000] {
            let s = Scale::from_hz(hz).unwrap();
            assert!(s.ticks_to_ns(hz).abs_diff(NS_PER_SEC) <= 1, "{hz}");
            let ticks = s.ns_to_ticks(1_500_000);
            assert!(s.ticks_to_ns(ticks) >= 1_500_000);
            assert!(s.ticks_to_ns(ticks - 1) < 1_500_000 + 1);
        }
        assert_eq!(Scale::from_hz(0), None);
        let s = Scale::from_hz(2_000_000_000).unwrap();
        assert_eq!(Scale::from_mult(s.mult()), Some(s));
        assert_eq!(Scale::from_mult(0), None);
        // Um ano de TSC a 3 GHz sem estouro, com erro relativo ínfimo.
        let s = Scale::from_hz(3_000_000_000).unwrap();
        let year = 365 * 24 * 3600 * NS_PER_SEC;
        assert!(deviation_ppm(s.ticks_to_ns(3 * year), year) < 1);
        assert_eq!(Scale::from_hz(1).unwrap().ticks_to_ns(u64::MAX), u64::MAX);
    }

    #[test]
    fn calibragem_e_desvio() {
        assert_eq!(hz_from(30_000_000, 10_000_000), Some(3_000_000_000));
        assert_eq!(hz_from(1, 0), None);
        // HPET do QEMU: 10 ns por contagem.
        assert_eq!(hpet_ticks_to_ns(100_000_000, 10_000_000), NS_PER_SEC);
        assert_eq!(deviation_ppm(1_001_000, 1_000_000), 1000);
        assert_eq!(deviation_ppm(999_000, 1_000_000), 1000);
        assert_eq!(deviation_ppm(5, 0), u64::MAX);
    }

    #[test]
    fn relogio_monotonico() {
        let clock = Clock {
            base: 1000,
            scale: Scale::from_hz(1_000_000_000).unwrap(),
        };
        assert_eq!(clock.ns(10), 0);
        assert_eq!(clock.ns(1000 + 5_000), 5_000);
        assert_eq!(clock.ticks_at(5_000), 6_000);
        let mut last = 0;
        for t in (0..100_000).step_by(7) {
            let ns = clock.ns(t);
            assert!(ns >= last);
            last = ns;
        }
    }
}
