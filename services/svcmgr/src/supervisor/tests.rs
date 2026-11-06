//! Testes do supervisor.

use super::*;

const MS: u64 = 1_000_000;
const S: u64 = 1_000 * MS;

#[test]
fn recuos_dobram_de_100_ms_a_30_s() {
    let mut sup = Supervisor::new(&[Policy::Always]);
    let mut now = 0;
    let mut seen = Vec::new();
    // Falhas espaçadas de 20 s: nunca mais de 5 por minuto.
    for _ in 0..12 {
        sup.started(0, now);
        now += 20 * S;
        match sup.exited(0, Exit::Failed, now) {
            Action::Restart { at_ns, backoff_ns } => {
                assert_eq!(at_ns, now + backoff_ns);
                seen.push(backoff_ns / MS);
                now = at_ns;
            }
            other => panic!("devia reiniciar: {other:?}"),
        }
    }
    assert_eq!(
        seen,
        [
            100, 200, 400, 800, 1600, 3200, 6400, 12800, 25600, 30000, 30000, 30000
        ]
    );
}

#[test]
fn execucao_estavel_zera_o_recuo() {
    let mut sup = Supervisor::new(&[Policy::OnFailure]);
    sup.started(0, 0);
    sup.exited(0, Exit::Failed, S);
    sup.started(0, 2 * S);
    assert!(
        matches!(sup.exited(0, Exit::Failed, 3 * S), Action::Restart { backoff_ns, .. } if backoff_ns == 200 * MS)
    );
    sup.started(0, 4 * S);
    let after = 4 * S + STABLE_NS;
    assert!(
        matches!(sup.exited(0, Exit::Failed, after), Action::Restart { backoff_ns, .. } if backoff_ns == 100 * MS)
    );
}

#[test]
fn seis_falhas_em_um_minuto_geram_o_alerta() {
    let mut sup = Supervisor::new(&[Policy::Always]);
    let mut now = 0;
    for i in 0..5 {
        sup.started(0, now);
        now += S;
        assert!(
            matches!(sup.exited(0, Exit::Failed, now), Action::Restart { .. }),
            "falha {i}"
        );
    }
    sup.started(0, now);
    assert_eq!(
        sup.exited(0, Exit::Failed, now + S),
        Action::Alert { failures: 6 }
    );
    assert_eq!(sup.state(0), Some(State::Failed));
    assert!(sup.due(u64::MAX).is_empty());
}

#[test]
fn falhas_fora_da_janela_nao_contam() {
    let mut sup = Supervisor::new(&[Policy::Always]);
    for i in 0..20 {
        let now = i * 13 * S;
        sup.started(0, now);
        assert!(matches!(
            sup.exited(0, Exit::Failed, now + S),
            Action::Restart { .. }
        ));
    }
}

#[test]
fn politicas() {
    let mut sup = Supervisor::new(&[Policy::Always, Policy::OnFailure, Policy::Never]);
    for id in 0..3 {
        sup.started(id, 0);
    }
    assert!(matches!(
        sup.exited(0, Exit::Clean, S),
        Action::Restart { .. }
    ));
    assert_eq!(sup.exited(1, Exit::Clean, S), Action::Stop);
    assert_eq!(sup.state(1), Some(State::Stopped));
    assert_eq!(sup.exited(2, Exit::Failed, S), Action::Stop);
    assert_eq!(Policy::from_manifest(9), Policy::Never);
}

#[test]
fn reinicios_vencidos_em_ordem() {
    let mut sup = Supervisor::new(&[Policy::Always, Policy::Always]);
    sup.started(0, 0);
    sup.started(1, 0);
    sup.exited(0, Exit::Failed, S);
    assert_eq!(sup.next_due(), Some(S + 100 * MS));
    assert!(sup.due(S).is_empty());
    assert_eq!(sup.due(S + 100 * MS), [0]);
}

#[test]
fn morte_induzida_volta_ja_sem_contar_falha() {
    let mut sup = Supervisor::new(&[Policy::OnFailure]);
    for i in 0..(MAX_FAILURES as u64 * 4) {
        sup.started(0, i * MS);
        sup.induced(0, i * MS);
        assert_eq!(sup.due(i * MS), [0]);
    }
    // Nenhuma falha contada: a primeira de verdade ainda tem o recuo mínimo.
    sup.started(0, S);
    assert_eq!(
        sup.exited(0, Exit::Failed, S),
        Action::Restart {
            at_ns: S + BACKOFF_MIN_NS,
            backoff_ns: BACKOFF_MIN_NS
        }
    );
}
