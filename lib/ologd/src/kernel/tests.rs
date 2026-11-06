//! Testes do cursor do anel do kernel.

use super::*;

#[test]
fn leitura_em_dia() {
    let mut c = Cursor::new(64);
    assert_eq!(c.start(40), 0);
    assert_eq!(c.finish(20, 40), Verdict::Keep { next: 24 });
    assert_eq!(c.pending(40), 16);
    assert_eq!(c.overruns, 0);
}

#[test]
fn coberto_antes_de_comecar_pula_para_o_mais_antigo() {
    let mut c = Cursor::new(64);
    assert_eq!(c.start(203), 144);
    assert_eq!(c.overruns, 1);
    assert_eq!(c.offset(144), 16);
}

#[test]
fn coberto_durante_a_copia_descarta() {
    let mut c = Cursor::new(64);
    c.start(56);
    // O kernel escreveu 80 bytes enquanto o logd copiava: o início foi
    // coberto.
    assert_eq!(
        c.finish(16, 136),
        Verdict::Overrun {
            resume: 72,
            lost_bytes: 72
        }
    );
    assert_eq!(c.pos, 72);
    assert_eq!(c.finish(8, 136), Verdict::Keep { next: 80 });
}

#[test]
fn exatamente_cheio_ainda_vale() {
    let mut c = Cursor::new(64);
    assert_eq!(c.start(64), 0);
    assert_eq!(c.finish(8, 64), Verdict::Keep { next: 8 });
}
