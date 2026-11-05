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
