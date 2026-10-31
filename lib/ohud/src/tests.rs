use crate::tema::{FUNDO, VIDRO_BORDA};
use crate::{Tela, cor, desenha_moldura};

const LARGURA: usize = 1920;
const ALTURA: usize = 1080;

#[test]
fn mistura_respeita_a_opacidade() {
    let mut t = Tela::nova(1, 1, 0xFF00_0000);
    t.sobrepoe(0, 0, cor(0x00, 0x00FF_FFFF));
    assert_eq!(t.pixel(0, 0), Some(0xFF00_0000), "alfa 0 não mexe no pixel");
    t.sobrepoe(0, 0, cor(0xFF, 0x002F_E6FF));
    assert_eq!(t.pixel(0, 0), Some(0xFF2F_E6FF), "alfa cheio troca a cor");
    t.sobrepoe(0, 0, cor(0x80, 0x00FF_FFFF));
    // O verde do ciano (0xE6) sobe ao misturar branco por cima.
    let verde = |p: Option<u32>| p.map_or(0, |p| (p >> 8) & 0xFF);
    assert!(verde(t.pixel(0, 0)) > 0xE6, "o branco clareia o ciano");
}

#[test]
fn fora_da_tela_nao_pinta_nem_falha() {
    let mut t = Tela::nova(4, 4, FUNDO);
    t.sobrepoe(-1, 0, 0xFF2F_E6FF);
    t.sobrepoe(4, 0, 0xFF2F_E6FF);
    assert_eq!(t.pixel(-1, 0), None);
    assert!(t.pixels().iter().all(|&p| p == FUNDO));
}

#[test]
fn moldura_tem_borda_e_deixa_a_margem_limpa() {
    let mut t = Tela::nova(LARGURA, ALTURA, FUNDO);
    desenha_moldura(&mut t, 24);
    assert_eq!(t.pixel(0, 0), Some(FUNDO), "a margem fica do fundo");
    let borda = t.pixel(24, 500);
    assert_ne!(borda, Some(FUNDO));
    assert_ne!(borda, t.pixel(100, 500), "a borda é diferente do vidro");
    let mut esperado = Tela::nova(1, 1, FUNDO);
    esperado.sobrepoe(0, 0, cor(0x55, VIDRO_BORDA));
    assert_eq!(borda, esperado.pixel(0, 0), "a borda é VIDRO_BORDA a 33%");
}

#[test]
fn moldura_e_determinista() {
    let render = || {
        let mut t = Tela::nova(LARGURA, ALTURA, FUNDO);
        desenha_moldura(&mut t, 24);
        t.pixels().to_vec()
    };
    assert!(render() == render(), "mesma entrada, mesmo quadro");
}
