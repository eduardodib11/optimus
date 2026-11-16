//! Os sockets contra uma segunda pilha, ligadas por uma "rede" de mentira.

use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use super::*;
use crate::eth::Mac;
use crate::ip4::Config;
use crate::stack::NoUpper;

const CLI: Ip4 = [10, 0, 2, 15];
const SRV: Ip4 = [10, 0, 2, 2];
const BADGE: u64 = (1 << 32) | 7;

/// Anéis de mentira: o teste escreve no `tx` e lê o `rx`.
#[derive(Default)]
struct Mem {
    tx: VecDeque<(u16, Vec<u8>)>,
    rx: Vec<(u16, Vec<u8>)>,
    rx_bytes: usize,
    cap: usize,
    corrupt: bool,
}

#[derive(Clone)]
struct Fake(Rc<RefCell<Mem>>);

impl Fake {
    fn new(cap: usize) -> Self {
        Self(Rc::new(RefCell::new(Mem {
            cap,
            ..Mem::default()
        })))
    }

    fn send(&self, data: &[u8]) {
        self.0.borrow_mut().tx.push_back((KIND_DATA, data.to_vec()));
    }

    fn events(&self) -> Vec<(u8, u8)> {
        let m = self.0.borrow();
        m.rx.iter()
            .filter(|(k, _)| *k == KIND_EVENT)
            .map(|(_, d)| (d[0], d[1]))
            .collect()
    }

    fn data(&self) -> Vec<u8> {
        let m = self.0.borrow();
        m.rx.iter()
            .filter(|(k, _)| *k == KIND_DATA)
            .flat_map(|(_, d)| d.clone())
            .collect()
    }

    /// O cliente lê (e esvazia) o `rx`.
    fn drain(&self) -> Vec<u8> {
        let d = self.data();
        let mut m = self.0.borrow_mut();
        m.rx.retain(|(k, _)| *k != KIND_DATA);
        m.rx_bytes = 0;
        d
    }
}

impl Rings for Fake {
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, RingError> {
        let mut m = self.0.borrow_mut();
        if m.corrupt {
            return Err(RingError);
        }
        Ok(m.tx.pop_front().map(|(k, d)| {
            buf[..d.len()].copy_from_slice(&d);
            (k, d.len())
        }))
    }

    fn fits(&mut self, len: usize) -> bool {
        let m = self.0.borrow();
        m.rx_bytes + len <= m.cap
    }

    fn push(&mut self, kind: u16, data: &[u8]) -> bool {
        if !self.fits(data.len()) {
            return false;
        }
        let mut m = self.0.borrow_mut();
        m.rx_bytes += data.len();
        m.rx.push((kind, data.to_vec()));
        true
    }
}

#[derive(Default)]
struct Wire(Vec<Vec<u8>>);

impl Link for Wire {
    fn send(&mut self, frame: &[u8]) -> bool {
        self.0.push(frame.to_vec());
        true
    }
}

/// Registra as decisões.
#[derive(Default)]
struct Log(Vec<(u32, Proto, Ip4, u16, bool)>);

impl Audit for Log {
    fn decision(&mut self, client: u32, proto: Proto, ip: Ip4, port: u16, ok: bool, _: &str) {
        self.0.push((client, proto, ip, port, ok));
    }
}

/// O outro lado: eco de UDP (porta 7) e de TCP (porta 7).
#[derive(Default)]
struct Echo {
    udp: Vec<(Ip4, u16, u16, Vec<u8>)>,
}

impl Upper for Echo {
    fn udp(&mut self, src: Ip4, sport: u16, dport: u16, data: &[u8]) -> bool {
        self.udp.push((src, sport, dport, data.to_vec()));
        true
    }
}

struct Net {
    a: Stack,
    b: Stack,
    wa: Wire,
    wb: Wire,
    echo: Echo,
    listen: usize,
    conns: Vec<usize>,
    t: Table<Fake>,
    now: u64,
}

impl Net {
    fn new() -> Self {
        let mut a = Stack::new(Mac([2, 0, 0, 0, 0, 1]));
        let mut b = Stack::new(Mac([2, 0, 0, 0, 0, 2]));
        let cfg = |ip| Config {
            ip,
            mask: [255, 255, 255, 0],
            gateway: SRV,
        };
        let (mut wa, mut wb) = (Wire::default(), Wire::default());
        a.set_config(&mut wa, cfg(CLI));
        b.set_config(&mut wb, cfg(SRV));
        let listen = b.tcp.listen(7, 4).unwrap();
        Self {
            a,
            b,
            wa,
            wb,
            echo: Echo::default(),
            listen,
            conns: Vec::new(),
            t: Table::new(),
            now: 1_000_000,
        }
    }

    fn allow(&mut self, text: &str) {
        let p = Policy::parse(text).unwrap();
        self.t.set_policy(&mut self.a, BADGE, p, self.now);
    }

    /// Roda `ms` milissegundos: os sockets, as duas pilhas e os quadros.
    fn run(&mut self, ms: u64) {
        for _ in 0..ms {
            self.now += 1_000_000;
            self.t.pump(&mut self.a, &mut self.wa, self.now);
            self.a.tick(&mut self.wa, self.now);
            self.b.tick(&mut self.wb, self.now);
            while let Some(c) = self.b.tcp.accept(self.listen) {
                self.conns.push(c);
            }
            let mut buf = [0u8; 4096];
            for &c in &self.conns {
                while let Ok(Read::Data(n)) = self.b.tcp.read(c, &mut buf) {
                    let _ = self.b.tcp.write(c, &buf[..n], self.now);
                }
            }
            // UDP: o eco devolve o datagrama.
            for (src, sport, dport, d) in core::mem::take(&mut self.echo.udp) {
                let _ = self
                    .b
                    .send_udp(&mut self.wb, dport, src, sport, &d, self.now);
            }
            self.b.flush_tcp(&mut self.wb, self.now);
            for f in core::mem::take(&mut self.wa.0) {
                self.b.input(&mut self.wb, &mut self.echo, &f, self.now);
            }
            for f in core::mem::take(&mut self.wb.0) {
                self.a.input(&mut self.wa, &mut self.t, &f, self.now);
            }
        }
    }
}

fn open(n: &mut Net, proto: Proto) -> (u32, Fake) {
    let r = Fake::new(8192);
    let id = n.t.open(BADGE, proto, |_| Ok(r.clone())).unwrap();
    (id, r)
}

fn connect(n: &mut Net, id: u32, port: u16) -> Result<(), Error> {
    let mut log = Log::default();
    n.t.connect(&mut n.a, &mut log, BADGE, id, SRV, port, n.now, 0x1234)
}

#[test]
fn sem_politica_nao_abre_socket() {
    let mut n = Net::new();
    assert_eq!(
        n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).err(),
        Some(Error::Denied)
    );
    n.t.set_policy(&mut n.a, BADGE, Policy::DENY, n.now);
    assert_eq!(
        n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).err(),
        Some(Error::Denied)
    );
    assert!(n.t.knows(BADGE) && !n.t.knows(BADGE + 1 + (1 << 32)));
}

#[test]
fn tcp_com_politica_conecta_e_ecoa() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:7");
    let (id, r) = open(&mut n, Proto::Tcp);
    assert_eq!(connect(&mut n, id, 7), Ok(()));
    n.run(50);
    assert_eq!(r.events(), [(EV_CONNECTED, 0)]);
    let dados: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    r.send(&dados[..1500]);
    r.send(&dados[1500..]);
    n.run(200);
    assert_eq!(r.drain(), dados);
}

#[test]
fn destino_fora_da_politica_e_negado_e_auditado() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:7;connect=udp:10.0.2.3:53");
    let (id, _) = open(&mut n, Proto::Tcp);
    let mut log = Log::default();
    let mut go = |n: &mut Net, ip, port| {
        n.t.connect(&mut n.a, &mut log, BADGE, id, ip, port, n.now, 1)
    };
    assert_eq!(go(&mut n, SRV, 8), Err(Error::Denied));
    assert_eq!(go(&mut n, [10, 0, 2, 3], 7), Err(Error::Denied));
    assert_eq!(go(&mut n, [0; 4], 7), Err(Error::BadRequest));
    assert_eq!(go(&mut n, [255; 4], 7), Err(Error::BadRequest));
    // O que a política nega não gerou SYN nenhum.
    assert!(n.a.tcp.pop_out().is_none());
    assert_eq!(go(&mut n, SRV, 7), Ok(()));
    assert_eq!(go(&mut n, SRV, 7), Err(Error::Busy));
    let ok: Vec<bool> = log.0.iter().map(|d| d.4).collect();
    assert_eq!(ok, [false, false, false, false, true]);
    assert_eq!(log.0[0], (7, Proto::Tcp, SRV, 8, false));
}

#[test]
fn udp_vai_e_volta_so_do_par_conectado() {
    let mut n = Net::new();
    n.allow("connect=udp:10.0.2.2:7");
    let (id, r) = open(&mut n, Proto::Udp);
    assert_eq!(connect(&mut n, id, 7), Ok(()));
    r.send(b"ola");
    n.run(100);
    assert_eq!(r.drain(), b"ola");
    // Datagrama de outra porta de origem não entra.
    let lport = n.t.socks[0].as_ref().unwrap().lport;
    assert!(!n.t.udp(SRV, 9999, lport, b"intruso"));
    assert!(n.t.udp(SRV, 7, lport, b"certo"));
    assert_eq!(r.drain(), b"certo");
}

#[test]
fn conexao_recusada_vira_evento_de_erro() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:*");
    let (id, r) = open(&mut n, Proto::Tcp);
    assert_eq!(connect(&mut n, id, 8), Ok(()));
    n.run(200);
    assert_eq!(r.events(), [(EV_ERROR, EV_ERR_REFUSED)]);
}

#[test]
fn limite_de_sockets_e_de_outro_cliente() {
    let mut n = Net::new();
    n.allow("connect=tcp:*:*;conns=2");
    let (a, _) = open(&mut n, Proto::Tcp);
    let (b, _) = open(&mut n, Proto::Tcp);
    assert_eq!(
        n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).err(),
        Some(Error::Limit)
    );
    n.t.close(&mut n.a, BADGE, a, n.now).unwrap();
    assert!(n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).is_ok());
    // Outro serviço não mexe nos sockets do primeiro.
    let outro = (1 << 32) | 9;
    n.t.set_policy(
        &mut n.a,
        outro,
        Policy::parse("connect=tcp:*:*").unwrap(),
        n.now,
    );
    let mut log = Log::default();
    let r = n.t.connect(&mut n.a, &mut log, outro, b, SRV, 7, n.now, 1);
    assert_eq!(r, Err(Error::BadRequest));
    assert_eq!(
        n.t.close(&mut n.a, outro, b, n.now).err(),
        Some(Error::BadRequest)
    );
    // Número que não existe.
    assert_eq!(
        n.t.close(&mut n.a, BADGE, 99, n.now).err(),
        Some(Error::BadRequest)
    );
}

#[test]
fn geracao_nova_do_cliente_fecha_o_que_ficou() {
    let mut n = Net::new();
    n.allow("connect=tcp:*:*;conns=1");
    let _ = open(&mut n, Proto::Tcp);
    assert_eq!(
        n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).err(),
        Some(Error::Limit)
    );
    // O cliente reiniciou: geração 2, mesma política.
    let novo = (2 << 32) | 7;
    assert!(!n.t.knows(novo));
    n.t.set_policy(
        &mut n.a,
        novo,
        Policy::parse("connect=tcp:*:*;conns=1").unwrap(),
        n.now,
    );
    assert!(n.t.open(novo, Proto::Tcp, |_| Ok(Fake::new(64))).is_ok());
    // O badge velho não vale mais.
    assert_eq!(
        n.t.open(BADGE, Proto::Tcp, |_| Ok(Fake::new(64))).err(),
        Some(Error::Denied)
    );
}

#[test]
fn anel_cheio_fecha_a_janela_e_nada_se_perde() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:7");
    let r = Fake::new(2000);
    let id = n.t.open(BADGE, Proto::Tcp, |_| Ok(r.clone())).unwrap();
    assert_eq!(connect(&mut n, id, 7), Ok(()));
    n.run(50);
    let dados: Vec<u8> = (0..6000u32).map(|i| (i * 7 % 253) as u8).collect();
    for c in dados.chunks(1000) {
        r.send(c);
    }
    let mut got = Vec::new();
    for _ in 0..100 {
        n.run(20);
        // O cliente só lê de vez em quando: o anel (2000 bytes) enche e o TCP
        // segura o resto.
        assert!(r.data().len() <= 2000);
        got.extend(r.drain());
    }
    assert_eq!(got, dados);
}

#[test]
fn close_depois_de_dados_nao_lidos_reinicia() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:7");
    let (id, r) = open(&mut n, Proto::Tcp);
    assert_eq!(connect(&mut n, id, 7), Ok(()));
    n.run(50);
    r.send(b"abc");
    n.run(30);
    let rings = n.t.close(&mut n.a, BADGE, id, n.now).unwrap();
    drop(rings);
    n.run(300);
    // O socket e a conexão se foram dos dois lados.
    assert!(n.t.socks.iter().all(Option::is_none));
    assert!(n.a.tcp.pop_out().is_none());
}

#[test]
fn anel_de_transmissao_corrompido_derruba_so_aquele_socket() {
    let mut n = Net::new();
    n.allow("connect=tcp:10.0.2.2:7");
    let (id, r) = open(&mut n, Proto::Tcp);
    let (_, bom) = open(&mut n, Proto::Tcp);
    assert_eq!(connect(&mut n, id, 7), Ok(()));
    n.run(50);
    r.0.borrow_mut().corrupt = true;
    n.run(5);
    assert!(r.events().contains(&(EV_ERROR, EV_ERR_RING)));
    assert!(bom.events().is_empty());
    let _ = NoUpper;
}
