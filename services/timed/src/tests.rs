//! Testes no host do núcleo do `timed`.

use super::*;

const S: u64 = 1_000_000_000;
/// 2026-11-05T12:30:15Z.
const T0: i64 = 1_793_881_815_000_000_000;

fn booted() -> Clock {
    Clock::from_boot(T0, 5 * S, true)
}

#[test]
fn hora_do_boot_avanca_com_o_monotonico() {
    let c = booted();
    let w = c.now(7 * S).unwrap();
    assert_eq!(w.unix_ns, T0 + 2_000_000_000);
    assert!(!w.synced);
    assert!(w.uncertainty_ns >= RTC_RESOLUTION_NS);
    assert!(
        c.now(3 * S).unwrap().unix_ns == T0,
        "antes do boot não regride"
    );
}

#[test]
fn sem_rtc_e_indisponivel_ate_o_set() {
    let mut c = Clock::from_boot(0, 5 * S, false);
    assert_eq!(c.now(6 * S), Err(TimeError::Unavailable));
    assert_eq!(c.set(T0, SetMode::Slew, 6 * S), Ok(Adjust::Stepped));
    assert_eq!(c.now(6 * S).unwrap().unix_ns, T0);
}

#[test]
fn primeiro_set_salta_mesmo_para_tras() {
    let mut c = booted();
    let back = T0 - 1_000;
    assert_eq!(c.set(back, SetMode::Slew, 5 * S), Ok(Adjust::SteppedBack));
    assert_eq!(c.now(5 * S).unwrap().unix_ns, back);
}

#[test]
fn slew_para_tras_nunca_regride_e_chega_ao_alvo() {
    let mut c = booted();
    c.set(T0, SetMode::Step, 5 * S).unwrap();
    // 0,4 s atrasado: Step pequeno para trás vira Slew.
    let target = T0 - 400_000_000;
    let Adjust::Slewing(end) = c.set(target, SetMode::Step, 5 * S).unwrap() else {
        panic!("devia virar Slew");
    };
    assert_eq!(end - 5 * S, 800 * S, "0,4 s a 500 ppm leva 800 s");
    let mut last = i64::MIN;
    let mut mono = 5 * S;
    while mono <= end + S {
        let now = c.now(mono).unwrap().unix_ns;
        assert!(now >= last, "regrediu em {mono}");
        last = now;
        mono += 7_919_000; // passo primo, ~8 ms
    }
    // Depois do ajuste, a hora é a do alvo mais o tempo decorrido.
    let after = end + 10 * S;
    let want = i128::from(target) + i128::from(after - 5 * S);
    assert!((i128::from(c.now(after).unwrap().unix_ns) - want).abs() <= 1);
}

#[test]
fn slew_para_frente_acelera_sem_saltar() {
    let mut c = booted();
    c.set(T0, SetMode::Step, 5 * S).unwrap();
    let Adjust::Slewing(end) = c.set(T0 + 1_000_000, SetMode::Slew, 5 * S).unwrap() else {
        panic!("devia ser Slew");
    };
    assert_eq!(end - 5 * S, 2 * S, "1 ms a 500 ppm leva 2 s");
    assert_eq!(c.now(5 * S).unwrap().unix_ns, T0, "sem salto no início");
    assert_eq!(c.now(end).unwrap().unix_ns, T0 + 2_001_000_000);
}

#[test]
fn step_grande_para_tras_e_aceito_e_sinalizado() {
    let mut c = booted();
    c.set(T0, SetMode::Step, 5 * S).unwrap();
    assert_eq!(
        c.set(T0 - 5_000_000_000, SetMode::Step, 5 * S),
        Ok(Adjust::SteppedBack)
    );
    assert_eq!(c.set(T0, SetMode::Step, 5 * S), Ok(Adjust::Stepped));
}

#[test]
fn faixa_e_incerteza() {
    let mut c = booted();
    assert_eq!(
        c.set(-1, SetMode::Step, 5 * S),
        Err(TimeError::InvalidArgument)
    );
    assert_eq!(
        c.set(MAX_UNIX_NS, SetMode::Step, 5 * S),
        Err(TimeError::InvalidArgument)
    );
    c.set(T0, SetMode::Step, 5 * S).unwrap();
    let w = c.now(5 * S + 1000 * S).unwrap();
    assert!(w.synced);
    assert_eq!(w.uncertainty_ns, 500_000_000, "500 ppm em 1000 s");
}

mod zone_tests {
    use crate::zone::{HEADER_LEN, LocalTime, Zone, ZoneError};

    /// Monta um blob OTZ1: tipos `(offset, dst, abreviação)`, transições e cauda.
    fn blob(name: &str, types: &[(i32, bool, &str)], trans: &[(i64, u8)], tail: &str) -> Vec<u8> {
        let mut chars = Vec::new();
        let mut tb = Vec::new();
        for (off, dst, abbr) in types {
            tb.extend_from_slice(&off.to_le_bytes());
            tb.push(u8::from(*dst));
            tb.push(u8::try_from(chars.len()).unwrap());
            chars.extend_from_slice(abbr.as_bytes());
            chars.push(0);
        }
        let mut b = b"OTZ1".to_vec();
        for n in [1, trans.len(), types.len(), chars.len()] {
            b.extend_from_slice(&u32::try_from(n).unwrap().to_le_bytes());
        }
        let mut nm = [0u8; 64];
        nm[..name.len()].copy_from_slice(name.as_bytes());
        b.extend_from_slice(&nm);
        assert_eq!(b.len(), HEADER_LEN);
        b.extend(tb);
        b.extend(chars);
        for (at, t) in trans {
            b.extend_from_slice(&at.to_le_bytes());
            b.push(*t);
        }
        b.push(u8::try_from(tail.len()).unwrap());
        b.extend_from_slice(tail.as_bytes());
        b
    }

    fn at(z: &Zone<'_>, t: i64) -> (i32, bool, String) {
        let l: LocalTime = z.local(t).unwrap();
        (
            l.offset_s,
            l.dst,
            String::from_utf8(l.abbr().to_vec()).unwrap(),
        )
    }

    #[test]
    fn utc_e_sao_paulo() {
        let b = blob("UTC", &[(0, false, "UTC")], &[], "UTC0");
        let z = Zone::parse(&b).unwrap();
        assert_eq!(z.name(), b"UTC");
        assert_eq!(at(&z, 1_700_000_000), (0, false, "UTC".into()));
        // São Paulo: sem verão desde 2019 (última transição 2019-02-17 02:00Z).
        let b = blob(
            "America/Sao_Paulo",
            &[(-10_800, false, "-03"), (-7_200, true, "-02")],
            &[(1_550_372_400, 0)],
            "<-03>3",
        );
        let z = Zone::parse(&b).unwrap();
        assert_eq!(at(&z, 1_700_000_000), (-10_800, false, "-03".into()));
        assert_eq!(at(&z, 1_000_000_000), (-10_800, false, "-03".into()));
    }

    #[test]
    fn verao_nas_datas_de_transicao() {
        // Nova York, cauda POSIX. 2024: verão começa em 2024-03-10 07:00Z e
        // termina em 2024-11-03 06:00Z.
        let b = blob(
            "America/New_York",
            &[(-18_000, false, "EST"), (-14_400, true, "EDT")],
            &[(0, 0)],
            "EST5EDT,M3.2.0,M11.1.0",
        );
        let z = Zone::parse(&b).unwrap();
        assert_eq!(at(&z, 1_710_053_999), (-18_000, false, "EST".into()));
        assert_eq!(at(&z, 1_710_054_000), (-14_400, true, "EDT".into()));
        assert_eq!(at(&z, 1_730_613_599), (-14_400, true, "EDT".into()));
        assert_eq!(at(&z, 1_730_613_600), (-18_000, false, "EST".into()));
        // Hemisfério sul (Sydney, 2024): verão de out. a abr.; julho é padrão.
        let b = blob(
            "Australia/Sydney",
            &[(36_000, false, "AEST"), (39_600, true, "AEDT")],
            &[(0, 0)],
            "AEST-10AEDT,M10.1.0,M4.1.0/3",
        );
        let z = Zone::parse(&b).unwrap();
        assert_eq!(at(&z, 1_720_000_000), (36_000, false, "AEST".into()));
        assert_eq!(at(&z, 1_705_000_000), (39_600, true, "AEDT".into()));
    }

    #[test]
    fn transicoes_da_tabela_e_antes_da_primeira() {
        let b = blob(
            "X",
            &[(3600, false, "A"), (7200, true, "B")],
            &[(100, 1), (200, 0)],
            "",
        );
        let z = Zone::parse(&b).unwrap();
        assert_eq!(at(&z, 50).0, 3600);
        assert_eq!(at(&z, 100).0, 7200);
        assert_eq!(at(&z, 199).0, 7200);
        assert_eq!(at(&z, 200).0, 3600);
        assert_eq!(at(&z, 9_999).0, 3600);
    }

    #[test]
    fn blobs_ruins_dao_erro() {
        let b = blob("X", &[(0, false, "A")], &[(0, 0)], "");
        assert!(Zone::parse(&b).is_ok());
        for n in 0..b.len() {
            assert_eq!(Zone::parse(&b[..n]).unwrap_err(), ZoneError::Malformed);
        }
        let mut ruim = b.clone();
        ruim[HEADER_LEN + 5] = 9; // abbr_off fora das abreviações
        assert_eq!(Zone::parse(&ruim).unwrap_err(), ZoneError::Malformed);
        let b = blob("X", &[(0, false, "A")], &[(0, 0)], "EST5EDT,J60,J300");
        assert_eq!(
            Zone::parse(&b).unwrap().local(1).unwrap_err(),
            ZoneError::Unsupported
        );
        let b = blob("X", &[(0, false, "A")], &[(0, 0)], "E");
        assert_eq!(
            Zone::parse(&b).unwrap().local(1).unwrap_err(),
            ZoneError::Malformed
        );
    }
}
