//! Testes do TCP sobre uma rede simulada com perda, atraso e reordenação.

use alloc::vec::Vec;

use super::wire::{self, ACK, FIN, RST, SYN};
use super::{ConnId, Error, Read, State, Tcp};

const A: [u8; 4] = [10, 0, 2, 15];
const B: [u8; 4] = [10, 0, 2, 2];
const MS: u64 = 1_000_000;

/// Gerador congruencial: o teste precisa ser repetível.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u32 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        u32::try_from(self.0 >> 33).unwrap_or(0)
    }

    fn pct(&mut self, p: u32) -> bool {
        self.next() % 100 < p
    }
}

/// Dois pontos ligados por um fio que perde, atrasa e reordena.
struct Net {
    a: Tcp,
    b: Tcp,
    now: u64,
    wire: Vec<(u64, bool, Vec<u8>)>,
    rng: Rng,
    loss: u32,
    reorder: u32,
    delay: u64,
    /// Quantos segmentos cada lado mandou e quantos se perderam.
    sent: usize,
    lost: usize,
    /// Descarta tudo (peer morto).
    cut: bool,
}

impl Net {
    fn new() -> Self {
        let mut a = Tcp::new([1; 16]);
        let mut b = Tcp::new([2; 16]);
        a.set_ip(A);
        b.set_ip(B);
        Self {
            a,
            b,
            now: 1_000 * MS,
            wire: Vec::new(),
            rng: Rng(7),
            loss: 0,
            reorder: 0,
            delay: 5 * MS,
            sent: 0,
            lost: 0,
            cut: false,
        }
    }

    fn collect(&mut self) {
        while let Some(o) = self.a.pop_out() {
            self.launch(true, o.data);
        }
        while let Some(o) = self.b.pop_out() {
            self.launch(false, o.data);
        }
    }

    /// `to_b`: o segmento vai de A para B.
    fn launch(&mut self, to_b: bool, data: Vec<u8>) {
        self.sent += 1;
        if self.cut || self.rng.pct(self.loss) {
            self.lost += 1;
            return;
        }
        let mut at = self.now + self.delay;
        if self.rng.pct(self.reorder) {
            at += u64::from(self.rng.next() % 20) * MS;
        }
        self.wire.push((at, to_b, data));
    }

    fn deliver(&mut self) {
        let now = self.now;
        let mut due: Vec<(u64, bool, Vec<u8>)> = Vec::new();
        let mut keep = Vec::new();
        for w in self.wire.drain(..) {
            if w.0 <= now {
                due.push(w);
            } else {
                keep.push(w);
            }
        }
        self.wire = keep;
        due.sort_by_key(|w| w.0);
        for (_, to_b, data) in due {
            if to_b {
                self.b.input(A, B, &data, now);
            } else {
                self.a.input(B, A, &data, now);
            }
        }
    }

    /// Um milissegundo de simulação.
    fn tick(&mut self) {
        self.now += MS;
        self.a.poll(self.now);
        self.b.poll(self.now);
        self.collect();
        self.deliver();
        self.collect();
    }

    fn run_ms(&mut self, ms: u64) {
        for _ in 0..ms {
            self.tick();
        }
    }

    /// Roda até `f` ser verdadeira (ou estourar `max_ms`).
    fn until(&mut self, max_ms: u64, f: impl Fn(&mut Net) -> bool) -> bool {
        for _ in 0..max_ms {
            if f(self) {
                return true;
            }
            self.tick();
        }
        f(self)
    }

    /// Abre uma conexão de A para a escuta de B na porta 80.
    fn open(&mut self) -> (ConnId, ConnId) {
        let l = self.b.listen(80, 4).unwrap();
        let a = self.a.connect(B, 80, self.now, 1234).unwrap();
        self.collect();
        assert!(self.until(5_000, |n| n.a.state(a) == Some(State::Established)));
        self.run_ms(50);
        let b = self.b.accept(l).expect("conexão aceita");
        assert_eq!(self.b.state(b), Some(State::Established));
        (a, b)
    }
}

/// Dados de teste que denunciam troca de ordem ou perda.
fn pattern(n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| u8::try_from((i * 7 + i / 251) % 256).unwrap())
        .collect()
}

/// Manda `data` de `from` (em `tcp_a` quando `a_sends`) até o fim e lê do outro lado.
fn transfer(net: &mut Net, a: ConnId, b: ConnId, data: &[u8], max_ms: u64) -> Vec<u8> {
    let mut sent = 0;
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..max_ms {
        if sent < data.len() {
            let n = net.a.write(a, &data[sent..], net.now).unwrap();
            sent += n;
        }
        while let Read::Data(n) = net.b.read(b, &mut buf).unwrap() {
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
        net.tick();
    }
    got
}

#[test]
fn abertura_em_tres_vias() {
    let mut net = Net::new();
    let (a, b) = net.open();
    assert_eq!(net.a.state(a), Some(State::Established));
    assert_eq!(net.b.state(b), Some(State::Established));
    assert_eq!(net.b.accept(0), None);
}

#[test]
fn dados_nos_dois_sentidos() {
    let mut net = Net::new();
    let (a, b) = net.open();
    net.a.write(a, b"ola", net.now).unwrap();
    net.b.write(b, b"mundo!", net.now).unwrap();
    net.run_ms(50);
    let mut buf = [0u8; 16];
    assert_eq!(net.b.read(b, &mut buf), Ok(Read::Data(3)));
    assert_eq!(&buf[..3], b"ola");
    assert_eq!(net.a.read(a, &mut buf), Ok(Read::Data(6)));
    assert_eq!(&buf[..6], b"mundo!");
    assert_eq!(net.a.read(a, &mut buf), Ok(Read::WouldBlock));
}

#[test]
fn transferencia_grande_sem_perda() {
    let mut net = Net::new();
    let (a, b) = net.open();
    let data = pattern(1 << 20);
    let got = transfer(&mut net, a, b, &data, 20_000);
    assert_eq!(got.len(), data.len());
    assert_eq!(got, data);
    assert_eq!(net.lost, 0);
}

#[test]
fn transferencia_com_perda_e_reordenacao() {
    let mut net = Net::new();
    net.loss = 5;
    net.reorder = 20;
    let (a, b) = net.open();
    let data = pattern(300_000);
    let got = transfer(&mut net, a, b, &data, 600_000);
    assert_eq!(
        got.len(),
        data.len(),
        "perdeu {} de {} segmentos",
        net.lost,
        net.sent
    );
    assert_eq!(got, data);
    assert!(net.lost > 0);
}

#[test]
fn transferencia_com_perda_pesada() {
    let mut net = Net::new();
    net.loss = 20;
    net.reorder = 30;
    let (a, b) = net.open();
    let data = pattern(50_000);
    let got = transfer(&mut net, a, b, &data, 1_200_000);
    assert_eq!(got, data);
}

#[test]
fn syn_perdido_e_retransmitido() {
    let mut net = Net::new();
    net.b.listen(80, 4).unwrap();
    net.cut = true;
    let a = net.a.connect(B, 80, net.now, 1).unwrap();
    net.collect();
    net.run_ms(300);
    assert_eq!(net.a.state(a), Some(State::SynSent));
    net.cut = false;
    assert!(net.until(10_000, |n| n.a.state(a) == Some(State::Established)));
}

#[test]
fn par_morto_acaba_em_tempo_esgotado() {
    let mut net = Net::new();
    let (a, _b) = net.open();
    net.cut = true;
    net.a.write(a, b"alguem ai?", net.now).unwrap();
    assert!(net.until(600_000, |n| n.a.state(a) == Some(State::Closed)));
    let mut buf = [0u8; 4];
    assert_eq!(net.a.read(a, &mut buf), Err(Error::TimedOut));
    assert_eq!(net.a.write(a, b"x", net.now), Err(Error::TimedOut));
}

#[test]
fn syn_sem_resposta_tambem_esgota() {
    let mut net = Net::new();
    net.cut = true;
    let a = net.a.connect(B, 80, net.now, 9).unwrap();
    assert!(net.until(600_000, |n| n.a.state(a) == Some(State::Closed)));
    assert_eq!(net.a.error(a), Some(Error::TimedOut));
}

#[test]
fn porta_fechada_responde_rst_e_a_abertura_e_recusada() {
    let mut net = Net::new();
    let a = net.a.connect(B, 81, net.now, 3).unwrap();
    assert!(net.until(5_000, |n| n.a.state(a) == Some(State::Closed)));
    assert_eq!(net.a.error(a), Some(Error::Refused));
}

#[test]
fn fechamento_ordenado_passa_por_time_wait() {
    let mut net = Net::new();
    let (a, b) = net.open();
    net.a.write(a, b"fim", net.now).unwrap();
    net.a.close(a, net.now);
    net.run_ms(100);
    let mut buf = [0u8; 8];
    assert_eq!(net.b.read(b, &mut buf), Ok(Read::Data(3)));
    assert_eq!(net.b.read(b, &mut buf), Ok(Read::Eof));
    assert_eq!(net.b.state(b), Some(State::CloseWait));
    assert_eq!(net.a.state(a), Some(State::FinWait2));
    // B ainda pode mandar dados depois do FIN de A.
    net.b.write(b, b"resposta", net.now).unwrap();
    net.run_ms(50);
    assert_eq!(net.a.read(a, &mut buf), Ok(Read::Data(8)));
    net.b.close(b, net.now);
    net.run_ms(100);
    assert_eq!(net.a.state(a), Some(State::TimeWait));
    assert_eq!(net.b.state(b), None);
    // Passados 2 MSL, A sai da tabela e a porta volta.
    net.run_ms(61_000);
    assert_eq!(net.a.state(a), None);
}

#[test]
fn fechamento_simultaneo() {
    let mut net = Net::new();
    let (a, b) = net.open();
    net.a.close(a, net.now);
    net.b.close(b, net.now);
    net.run_ms(100);
    assert!(matches!(
        net.a.state(a),
        Some(State::TimeWait | State::Closing) | None
    ));
    net.run_ms(61_000);
    assert_eq!(net.a.state(a), None);
    assert_eq!(net.b.state(b), None);
}

#[test]
fn janela_fecha_e_reabre_com_a_leitura() {
    let mut net = Net::new();
    let (a, b) = net.open();
    let data = pattern(200_000);
    let mut sent = 0;
    // O receptor não lê: o remetente trava no tamanho da janela.
    for _ in 0..5_000 {
        sent += net.a.write(a, &data[sent..], net.now).unwrap();
        net.tick();
    }
    assert_eq!(net.b.recv_ready(b), super::BUF_BYTES);
    assert!(sent < data.len());
    // Ler abre a janela e o resto chega.
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    for _ in 0..200_000 {
        if sent < data.len() {
            sent += net.a.write(a, &data[sent..], net.now).unwrap();
        }
        while let Ok(Read::Data(n)) = net.b.read(b, &mut buf) {
            got.extend_from_slice(&buf[..n]);
        }
        if got.len() == data.len() {
            break;
        }
        net.tick();
    }
    assert_eq!(got, data);
}

#[test]
fn rst_com_sequencia_errada_nao_derruba() {
    let mut net = Net::new();
    let (a, b) = net.open();
    let local = net.b.conns[b].as_ref().unwrap();
    let (rcv_nxt, lport, rport) = (local.rcv_nxt, local.lport, local.rport);
    let mk = |seq: u32| {
        let h = wire::Header {
            sport: rport,
            dport: lport,
            seq,
            ack: 0,
            flags: RST,
            window: 0,
            mss: None,
        };
        let mut out = [0u8; 20];
        let n = wire::build(A, B, &h, &[], &mut out).unwrap();
        out[..n].to_vec()
    };
    // Fora da janela: ignorado. Dentro da janela mas não exato: ACK de desafio.
    net.b
        .input(A, B, &mk(rcv_nxt.wrapping_add(1 << 30)), net.now);
    assert_eq!(net.b.state(b), Some(State::Established));
    net.b.input(A, B, &mk(rcv_nxt.wrapping_add(100)), net.now);
    assert_eq!(net.b.state(b), Some(State::Established));
    assert!(net.b.pop_out().is_some(), "ACK de desafio");
    // Exato: derruba.
    net.b.input(A, B, &mk(rcv_nxt), net.now);
    assert_eq!(net.b.state(b), Some(State::Closed));
    assert_eq!(net.b.error(b), Some(Error::Reset));
    let _ = a;
}

#[test]
fn syn_numa_conexao_aberta_gera_ack_de_desafio() {
    let mut net = Net::new();
    let (_a, b) = net.open();
    let c = net.b.conns[b].as_ref().unwrap();
    let h = wire::Header {
        sport: c.rport,
        dport: c.lport,
        seq: c.rcv_nxt,
        ack: 0,
        flags: SYN,
        window: 1000,
        mss: Some(1460),
    };
    let mut out = [0u8; 24];
    let n = wire::build(A, B, &h, &[], &mut out).unwrap();
    net.b.input(A, B, &out[..n], net.now);
    assert_eq!(net.b.state(b), Some(State::Established));
    let o = net.b.pop_out().unwrap();
    let seg = wire::parse(B, A, &o.data).unwrap();
    assert_eq!(seg.flags, ACK);
}

#[test]
fn numeros_de_sequencia_que_dao_a_volta() {
    let mut net = Net::new();
    // O ISN fica a poucos KiB do fim do espaço de 32 bits.
    let bias = 0u32.wrapping_sub(net.a.isn(B, 80, 49152, net.now) / 2);
    net.a.isn_bias = bias;
    net.b.isn_bias = bias.wrapping_add(777);
    let (a, b) = net.open();
    let data = pattern(150_000);
    let got = transfer(&mut net, a, b, &data, 100_000);
    assert_eq!(got, data);
    net.a.close(a, net.now);
    net.run_ms(100);
    assert_eq!(net.b.read(b, &mut [0u8; 4]), Ok(Read::Eof));
}

#[test]
fn isn_depende_do_segredo_da_tupla_e_do_tempo() {
    let a = Tcp::new([1; 16]);
    let b = Tcp::new([2; 16]);
    let i = a.isn(B, 80, 5000, 0);
    assert_ne!(i, b.isn(B, 80, 5000, 0));
    assert_ne!(i, a.isn(B, 81, 5000, 0));
    assert_ne!(i, a.isn(B, 80, 5001, 0));
    assert_eq!(a.isn(B, 80, 5000, 4_000), i.wrapping_add(1));
}

#[test]
fn escuta_respeita_backlog_e_unlisten() {
    let mut net = Net::new();
    let l = net.b.listen(80, 2).unwrap();
    assert_eq!(net.b.listen(80, 2), Err(Error::InUse));
    let a1 = net.a.connect(B, 80, net.now, 11).unwrap();
    let a2 = net.a.connect(B, 80, net.now, 22).unwrap();
    let a3 = net.a.connect(B, 80, net.now, 33).unwrap();
    net.run_ms(100);
    let estab = [a1, a2, a3]
        .iter()
        .filter(|c| net.a.state(**c) == Some(State::Established))
        .count();
    assert_eq!(estab, 2, "o terceiro fica sem vaga na fila");
    assert!(net.b.accept(l).is_some());
    // Fechar a escuta reinicia o que ninguém aceitou.
    net.b.unlisten(l);
    net.run_ms(100);
    let mortos = [a1, a2, a3]
        .iter()
        .filter(|c| net.a.state(**c) == Some(State::Closed))
        .count();
    assert!(mortos >= 1);
}

#[test]
fn conexoes_ao_mesmo_tempo_tem_portas_distintas() {
    let mut net = Net::new();
    net.b.listen(80, 8).unwrap();
    let ids: Vec<_> = (0..6)
        .map(|i| net.a.connect(B, 80, net.now, i * 1000).unwrap())
        .collect();
    net.run_ms(100);
    let mut ports: Vec<u16> = ids
        .iter()
        .map(|i| net.a.conns[*i].as_ref().unwrap().lport)
        .collect();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), 6);
    for i in ids {
        net.a.abort(i);
    }
    net.run_ms(100);
    // A porta volta depois do abort.
    assert!(!net.a.ports.in_use(ports[0]));
}

#[test]
fn tabela_cheia_recusa_a_conexao() {
    let mut net = Net::new();
    for i in 0..super::MAX_CONNS {
        assert!(
            net.a
                .connect(B, 80, net.now, u32::try_from(i).unwrap())
                .is_ok()
        );
    }
    assert_eq!(net.a.connect(B, 80, net.now, 99), Err(Error::NoSpace));
}

#[test]
fn rtt_e_rto_seguem_a_rfc_6298() {
    let mut net = Net::new();
    net.delay = 20 * MS;
    let (a, b) = net.open();
    let data = pattern(50_000);
    let got = transfer(&mut net, a, b, &data, 50_000);
    assert_eq!(got, data);
    let c = net.a.conns[a].as_ref().unwrap();
    // RTT de ~40 ms: o RTO não pode ficar abaixo do mínimo de 200 ms nem
    // passar de um segundo.
    assert!(c.srtt >= 35 * MS && c.srtt <= 80 * MS, "srtt {}", c.srtt);
    assert!(c.rto >= 200 * MS && c.rto <= 1_000 * MS, "rto {}", c.rto);
}

#[test]
fn segmentos_malformados_nao_entram_em_panico() {
    let mut t = Tcp::new([3; 16]);
    t.set_ip(B);
    t.listen(80, 2).unwrap();
    let h = wire::Header {
        sport: 1000,
        dport: 80,
        seq: 5,
        ack: 0,
        flags: SYN,
        window: 100,
        mss: Some(1460),
    };
    let mut seg = [0u8; 64];
    let n = wire::build(A, B, &h, b"lixo", &mut seg).unwrap();
    // Todo prefixo e toda troca de um byte têm de sobreviver.
    for len in 0..=n {
        t.input(A, B, &seg[..len], 0);
    }
    for i in 0..n {
        for v in [0u8, 0xff, seg[i] ^ 0x55] {
            let mut x = seg;
            x[i] = v;
            t.input(A, B, &x[..n], 1);
        }
    }
    // Opções com comprimento impossível.
    for bad in [[2u8, 0, 0, 0], [2, 5, 0, 0], [3, 1, 0, 0], [2, 4, 5, 0xb4]] {
        let mut x = [0u8; 24];
        x[12] = 6 << 4;
        x[13] = SYN;
        x[20..24].copy_from_slice(&bad);
        let c = crate::ip4::fold(crate::ip4::sum(
            &x,
            crate::udp::pseudo_sum(A, B, crate::ip4::PROTO_TCP, 24),
        ));
        x[16..18].copy_from_slice(&c.to_be_bytes());
        t.input(A, B, &x, 2);
    }
}

#[test]
fn segmento_fin_ack_e_sequencias_curtas() {
    let h = wire::Header {
        sport: 1,
        dport: 2,
        seq: 10,
        ack: 20,
        flags: FIN | ACK,
        window: 300,
        mss: None,
    };
    let mut out = [0u8; 32];
    let n = wire::build(A, B, &h, b"ab", &mut out).unwrap();
    let s = wire::parse(A, B, &out[..n]).unwrap();
    assert_eq!((s.seq, s.ack, s.window, s.seq_len()), (10, 20, 300, 3));
    assert!(wire::parse(A, [10, 0, 2, 99], &out[..n]).is_none());
    let mut pequeno = [0u8; 21];
    assert!(wire::build(A, B, &h, b"ab", &mut pequeno).is_none());
}

#[test]
fn buffer_em_anel() {
    use super::buf::Buf;
    let mut b = Buf::new(8);
    assert_eq!(b.push(b"abcdef"), 6);
    assert_eq!(b.push(b"ghijkl"), 2);
    assert_eq!(b.free(), 0);
    let mut out = [0u8; 4];
    assert_eq!(b.pop(&mut out), 4);
    assert_eq!(&out, b"abcd");
    // Dá a volta no fim do vetor.
    assert_eq!(b.push(b"WXYZ"), 4);
    let mut all = [0u8; 8];
    assert_eq!(b.peek(0, &mut all), 8);
    assert_eq!(&all, b"efghWXYZ");
    assert_eq!(b.peek(6, &mut all[..4]), 2);
    assert_eq!(b.peek(9, &mut all), 0);
    b.consume(100);
    assert!(b.is_empty());
}
