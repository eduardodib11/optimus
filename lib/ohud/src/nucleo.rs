//! Núcleo do HUD: o rosto da IA, anéis de aço e cobre girando sobre um reator
//! (ADR 0040, item 4). Os raios vêm do desenho de referência de 430 pixels e
//! são escalados pelo raio externo pedido.

use crate::pincel::Pincel;
use crate::tela::{Tela, cor};
use crate::tema::{
    ACO, ACO_CLARO, BRANCO, BRANCO_AZULADO, CIANO, CIANO_CLARO, CIANO_ESCURO, COBRE, COBRE_CLARO,
    NUCLEO_ESCURO, NUCLEO_FUNDO, PAINEL, REATOR,
};
use crate::trig::{PASSOS, Trig};

/// Raio externo do anel de referência; os demais raios são proporcionais.
const REFERENCIA: i32 = 430;

/// Núcleo do HUD, com a tabela trigonométrica pronta.
pub struct Nucleo {
    trig: Trig,
    raio: i32,
}

impl Nucleo {
    /// Núcleo de raio externo `raio` pixels (ADR 0040: 360 em 1920x1080).
    #[must_use]
    pub fn new(raio: i32) -> Self {
        Self {
            trig: Trig::new(),
            raio,
        }
    }

    /// Desenha o núcleo centrado em (`cx`, `cy`) no instante `tempo_ms`.
    /// `reator` (0 a 255) é a opacidade do centro; a fala da IA o acende.
    pub fn desenha(&self, tela: &mut Tela, cx: i32, cy: i32, tempo_ms: u64, reator: u8) {
        let escala = |v: i32| v * self.raio / REFERENCIA;
        let espessura = |v: i32| (v * self.raio / REFERENCIA).max(1);
        let gira = |periodo_ms: u64, sentido: i64| giro(tempo_ms, periodo_ms, sentido);
        let mut p = Pincel {
            tela,
            trig: &self.trig,
            cx,
            cy,
        };

        // Moldura externa: traço de aço, anel de cobre, anel de aço e o brilho.
        p.tracejado(
            escala(430),
            espessura(3),
            gira(40_000, 1),
            &[(35, 1), (5, 1)],
            ACO_CLARO,
        );
        p.tracejado(escala(400), espessura(26), 0, &[(74, 10), (26, 10)], COBRE);
        p.arco(escala(368), espessura(10), 0, PASSOS, ACO);
        p.tracejado(escala(335), espessura(12), 0, &[(120, 15), (51, 15)], CIANO);
        p.tracejado(
            escala(300),
            espessura(20),
            gira(26_000, -1),
            &[(72, 11), (30, 11)],
            COBRE,
        );

        // Régua de marcações a cada 3 graus; a cada 30 graus, marca maior.
        let rotacao = gira(40_000, 1);
        for i in 0..120 {
            let passo = i * 12 + rotacao;
            if i % 10 == 0 {
                p.radial(escala(272), escala(292), passo, COBRE_CLARO);
            } else {
                p.radial(escala(272), escala(283), passo, CIANO_CLARO);
            }
        }

        // Casco do núcleo e disco interno com o halo ciano.
        p.disco(escala(268), NUCLEO_ESCURO);
        p.arco(escala(268), espessura(6), 0, PASSOS, ACO);
        p.disco(escala(250), NUCLEO_FUNDO);
        p.halo(escala(250), cor(0x59, CIANO));

        // Engrenagens internas, cada uma com velocidade e sentido próprios.
        let f = gira(150_000, 1);
        p.arco(escala(238), espessura(1), 0, PASSOS, cor(0x80, CIANO));
        for i in 0..120 {
            p.radial(escala(226), escala(235), i * 12 + f, CIANO_CLARO);
        }
        p.arco(escala(246), espessura(3), f, f + gr(70), CIANO);
        p.arco(escala(246), espessura(3), f + gr(100), f + gr(170), CIANO);
        p.arco(escala(246), espessura(3), f + gr(200), f + gr(290), CIANO);

        let f = gira(35_000, -1);
        p.arco(escala(205), espessura(10), f, f + gr(110), CIANO);
        p.arco(
            escala(205),
            espessura(10),
            f + gr(130),
            f + gr(200),
            CIANO_CLARO,
        );
        p.arco(escala(205), espessura(10), f + gr(230), f + gr(340), CIANO);
        p.tracejado(escala(192), espessura(1), f, &[(3, 2)], CIANO);

        let f = gira(20_000, 1);
        for i in 0..72 {
            p.radial(escala(160), escala(174), i * 20 + f, BRANCO);
        }
        p.arco(escala(156), espessura(2), 0, PASSOS, CIANO_ESCURO);

        let f = gira(10_000, -1);
        p.arco(escala(132), espessura(6), f + gr(10), f + gr(80), BRANCO);
        p.arco(escala(132), espessura(6), f + gr(100), f + gr(190), CIANO);
        p.arco(
            escala(132),
            espessura(6),
            f + gr(215),
            f + gr(350),
            CIANO_CLARO,
        );

        p.tracejado(
            escala(108),
            espessura(14),
            gira(5_500, 1),
            &[(5, 3)],
            cor(0xD9, CIANO),
        );
        p.tracejado(
            escala(88),
            espessura(2),
            gira(3_000, -1),
            &[(20, 8), (4, 8)],
            BRANCO_AZULADO,
        );

        // Triângulo girando, com vértices a 78 pixels de referência.
        let f = gira(15_000, 1);
        let t = &self.trig;
        let vs = [-360, 120, 600].map(|a| t.ponto(cx, cy, escala(78), f + a));
        for (a, b) in [(0, 1), (1, 2), (2, 0)] {
            p.linha(vs[a], vs[b], CIANO_CLARO);
        }

        // Centro: painel, reator (acendido pela fala) e o ponto branco.
        p.disco(escala(70), PAINEL);
        p.arco(escala(70), espessura(3), 0, PASSOS, CIANO);
        p.disco(escala(52), cor(reator, REATOR));
        p.disco(escala(30), BRANCO);
    }
}

/// Passo (quartos de grau) de um anel que dá uma volta a cada `periodo_ms`;
/// `sentido` -1 inverte o giro.
fn giro(tempo_ms: u64, periodo_ms: u64, sentido: i64) -> i32 {
    let passos = tempo_ms as i64 * i64::from(PASSOS) / periodo_ms as i64;
    (passos * sentido).rem_euclid(i64::from(PASSOS)) as i32
}

/// Converte graus em quartos de grau.
const fn gr(graus: i32) -> i32 {
    graus * (PASSOS / 360)
}
