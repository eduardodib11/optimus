use crate::ps2::{Key, Keyboard, Mouse, MouseDecoder, Source, source};
use crate::rtc::{self, Cmos};

/// CMOS simulado: valores fixos, com `uip` leituras de "atualização em curso".
struct Fake {
    regs: [u8; 256],
    uip: u32,
    /// Quantas leituras de segundos ainda mudam o valor (chip virando o relógio).
    flips: u32,
}

impl Cmos for Fake {
    fn read(&mut self, reg: u8) -> u8 {
        if reg == rtc::STATUS_A && self.uip > 0 {
            self.uip -= 1;
            return 0x80;
        }
        if reg == 0 && self.flips > 0 {
            self.flips -= 1;
            return self.regs[0].wrapping_add(1);
        }
        self.regs[usize::from(reg)]
    }
}

fn cmos(f: impl FnOnce(&mut [u8; 256])) -> Fake {
    let mut regs = [0; 256];
    f(&mut regs);
    Fake {
        regs,
        uip: 0,
        flips: 0,
    }
}

#[test]
fn rtc_bcd_24h() {
    // 2024-03-10 07:30:45 UTC = 1710055845.
    let mut c = cmos(|r| {
        r[0x00] = 0x45;
        r[0x02] = 0x30;
        r[0x04] = 0x07;
        r[0x07] = 0x10;
        r[0x08] = 0x03;
        r[0x09] = 0x24;
        r[0x32] = 0x20;
        r[0x0B] = 0x02;
    });
    assert_eq!(
        rtc::read_unix(&mut c, rtc::CENTURY_DEFAULT),
        Some(1_710_055_845)
    );
}

#[test]
fn rtc_binario_12h_e_espera() {
    // 2000-01-01 12:00:00 (12 PM, binário, 12 h) = 946728000; sem século.
    let mut c = cmos(|r| {
        r[0x04] = 0x0C | 0x80;
        r[0x07] = 1;
        r[0x08] = 1;
        r[0x09] = 0;
        r[0x0B] = 0x04;
    });
    c.uip = 3;
    assert_eq!(rtc::read_unix(&mut c, 0), Some(946_728_000));
    // 12 AM vira 0 h.
    c.regs[0x04] = 12;
    assert_eq!(rtc::read_unix(&mut c, 0), Some(946_684_800));
}

#[test]
fn rtc_instavel_ou_invalido() {
    let mut c = cmos(|r| {
        r[0x07] = 0x10;
        r[0x08] = 0x03;
        r[0x0B] = 0x02;
    });
    c.flips = 1; // a primeira leitura difere da segunda: repete e estabiliza
    assert!(rtc::read_unix(&mut c, 0).is_some());
    c.uip = 1_000;
    assert_eq!(rtc::read_unix(&mut c, 0), None);
    let mut zerado = cmos(|r| r[0x0B] = 0x02); // dia 0, mês 0
    assert_eq!(rtc::read_unix(&mut zerado, 0), None);
    let mut bcd_ruim = cmos(|r| {
        r[0x00] = 0x6A;
        r[0x07] = 1;
        r[0x08] = 1;
        r[0x0B] = 0x02;
    });
    assert_eq!(rtc::read_unix(&mut bcd_ruim, 0), None);
}

#[test]
fn teclado_conjunto_1() {
    let mut k = Keyboard::default();
    assert_eq!(
        k.feed(0x1E),
        Some(Key {
            code: 0x1E,
            pressed: true
        })
    );
    assert_eq!(
        k.feed(0x9E),
        Some(Key {
            code: 0x1E,
            pressed: false
        })
    );
    assert_eq!(k.feed(0xE0), None);
    assert_eq!(
        k.feed(0x48),
        Some(Key {
            code: Key::EXTENDED | 0x48,
            pressed: true
        })
    );
    assert_eq!(k.feed(0xFA), None); // ACK
    let pause = [0xE1, 0x1D, 0x45, 0xE1, 0x9D, 0xC5];
    let out: Vec<_> = pause.iter().filter_map(|b| k.feed(*b)).collect();
    assert_eq!(
        out,
        [Key {
            code: Key::PAUSE,
            pressed: true
        }]
    );
    assert_eq!(k.feed(0x1E).map(|x| x.code), Some(0x1E)); // voltou ao normal
}

#[test]
fn mouse_pacotes_e_ressincronizacao() {
    let mut m = MouseDecoder::default();
    assert_eq!(m.feed(0x00), None); // lixo sem o bit 3: descartado
    assert_eq!((m.feed(0x09), m.feed(5)), (None, None));
    assert_eq!(
        m.feed(3),
        Some(Mouse {
            dx: 5,
            dy: 3,
            buttons: 1
        })
    );
    // Negativos: bits de sinal 4 e 5; botão direito.
    assert_eq!(m.feed(0x3A), None);
    assert_eq!(m.feed(0xFB), None);
    assert_eq!(
        m.feed(0xFE),
        Some(Mouse {
            dx: -5,
            dy: -2,
            buttons: 2
        })
    );
    // Estouro: descartado.
    m.feed(0x49);
    m.feed(1);
    assert_eq!(m.feed(1), None);
}

#[test]
fn origem_do_byte() {
    assert_eq!(source(0x00), Source::None);
    assert_eq!(source(0x01), Source::Keyboard);
    assert_eq!(source(0x21), Source::Mouse);
    assert_eq!(source(0x20), Source::None);
}
