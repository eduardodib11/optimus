use crate::tema::{CIANO, FUNDO, VIDRO_BORDA};
// Cores e tela dos testes; a tabela e o desenho são checados por valores.
use crate::trig::{ESCALA, Trig};
use crate::{Nucleo, Tela, cor, desenha_moldura};

const LARGURA: usize = 1920;
const ALTURA: usize = 1080;

#[test]
fn seno_e_cosseno_de_quartos_de_volta() {
    let t = Trig::new();
    let tolerancia = ESCALA / 200;
    assert!(t.seno(0).abs() <= tolerancia);
    assert!((t.seno(360) - ESCALA).abs() <= tolerancia);
    assert!((t.cosseno(0) - ESCALA).abs() <= tolerancia);
    assert!((t.seno(1080) + ESCALA).abs() <= tolerancia);
    // Passo negativo e acima de uma volta caem no mesmo lugar.
    assert_eq!(t.seno(-1080), t.seno(360));
    assert_eq!(t.seno(1440 + 360), t.seno(360));
}

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
    t.sobrepoe(-1, 0, CIANO);
    t.sobrepoe(4, 0, CIANO);
    assert_eq!(t.pixel(-1, 0), None);
    assert!(t.pixels().iter().all(|&p| p == FUNDO));
}

#[test]
fn moldura_tem_borda_e_deixa_a_margem_limpa() {
    let mut t = Tela::nova(LARGURA, ALTURA, FUNDO);
    desenha_moldura(&mut t, 24);
    assert_eq!(t.pixel(0, 0), Some(FUNDO), "a margem fica do fundo");
    let borda = t.pixel(24, 500);
    let dentro = t.pixel(100, 500);
    assert_ne!(borda, Some(FUNDO));
    assert_ne!(borda, dentro, "a borda é diferente do vidro");
    let esperado = Tela::nova(1, 1, FUNDO);
    let mut esperado = esperado;
    esperado.sobrepoe(0, 0, cor(0x55, VIDRO_BORDA));
    assert_eq!(borda, esperado.pixel(0, 0), "a borda é VIDRO_BORDA a 33%");
}

#[test]
fn nucleo_e_centrado_e_nao_passa_do_raio() {
    let mut t = Tela::nova(LARGURA, ALTURA, FUNDO);
    let (cx, cy) = (LARGURA as i32 / 2, ALTURA as i32 / 2);
    Nucleo::new(360).desenha(&mut t, cx, cy, 0, 255);
    // O centro é o reator (tom claro), o ponto a 400 px não tem nada.
    assert_eq!(t.pixel(cx, cy), Some(0xFFFF_FFFF));
    assert_ne!(t.pixel(cx + 150, cy), Some(FUNDO));
    assert_eq!(t.pixel(cx + 400, cy), Some(FUNDO));
    assert_eq!(t.pixel(cx, cy + 400), Some(FUNDO));
}

#[test]
fn reator_apagado_some_com_a_opacidade() {
    let (cx, cy) = (LARGURA as i32 / 2, ALTURA as i32 / 2);
    let mut aceso = Tela::nova(LARGURA, ALTURA, FUNDO);
    let mut apagado = Tela::nova(LARGURA, ALTURA, FUNDO);
    Nucleo::new(360).desenha(&mut aceso, cx, cy, 0, 255);
    Nucleo::new(360).desenha(&mut apagado, cx, cy, 0, 0);
    let (a, b) = (aceso.pixel(cx + 38, cy), apagado.pixel(cx + 38, cy));
    assert_ne!(a, b, "o reator muda com a opacidade");
}

#[test]
fn quadro_inteiro_e_determinista_e_os_anéis_giram() {
    let (cx, cy) = (LARGURA as i32 / 2, ALTURA as i32 / 2);
    let render = |tempo_ms| {
        let mut t = Tela::nova(LARGURA, ALTURA, FUNDO);
        desenha_moldura(&mut t, 24);
        Nucleo::new(360).desenha(&mut t, cx, cy, tempo_ms, 128);
        t.pixels().to_vec()
    };
    let (um, outro) = (render(1_000), render(1_000));
    assert!(um == outro, "mesmo instante, mesmo quadro");
    assert!(um != render(2_000), "tempos diferentes mudam o quadro");
}
