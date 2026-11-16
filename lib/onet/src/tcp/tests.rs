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
    /// Atraso extra máximo dos segmentos reordenados, em ms.
    reorder_ms: u64,
    delay: u64,
    /// Quantos segmentos cada lado mandou e quantos se perderam.
    sent: usize,
    lost: usize,
    /// Descarta tudo (peer morto).
    cut: bool,
    /// Números (de 1) dos segmentos de dados de A para B a descartar.
    drop_data: Vec<usize>,
    data_seen: usize,
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
            reorder_ms: 20,
            delay: 5 * MS,
            sent: 0,
            lost: 0,
            cut: false,
            drop_data: Vec::new(),
            data_seen: 0,
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
        if to_b
            && let Some(seg) = wire::parse(A, B, &data)
            && !seg.data.is_empty()
        {
            self.data_seen += 1;
            if self.drop_data.contains(&self.data_seen) {
                self.lost += 1;
                return;
            }
        }
        if self.cut || self.rng.pct(self.loss) {
            self.lost += 1;
            return;
        }
        let mut at = self.now + self.delay;
        if self.rng.pct(self.reorder) {
            at += u64::from(self.rng.next()) % self.reorder_ms * MS;
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
    let data = pattern(600_000);
    let mut sent = 0;
    // O receptor não lê: o remetente trava no tamanho da janela.
    for _ in 0..5_000 {
        sent += net.a.write(a, &data[sent..], net.now).unwrap();
        net.tick();
    }
    // A janela escalada anda de 8 em 8 bytes (escala 3).
    assert!(net.b.recv_ready(b) + 8 > net.b.conns[b].as_ref().unwrap().limit);
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
            opts: wire::Opts::NONE,
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
        opts: wire::Opts {
            mss: Some(1460),
            ..wire::Opts::NONE
        },
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
    net.a.set_budget(1 << 30);
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
        opts: wire::Opts {
            mss: Some(1460),
            ..wire::Opts::NONE
        },
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
        opts: wire::Opts::NONE,
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

#[test]
fn memoria_dos_buffers_tem_teto() {
    let mut net = Net::new();
    net.a.set_budget(200 * 1024);
    // Cada conexão leva o que cabe; quando nem o mínimo cabe, recusa.
    let mut n = 0;
    while net.a.connect(B, 80, net.now, n).is_ok() {
        n += 1;
        assert!(n < 100, "sem teto");
    }
    assert!(n >= 3);
    // Fechar devolve a reserva.
    net.a.abort(0);
    net.a.poll(net.now);
    assert!(net.a.connect(B, 80, net.now, 999).is_ok());
}

#[test]
fn janela_escalada_e_negociada() {
    let mut net = Net::new();
    let (a, b) = net.open();
    let ca = net.a.conns[a].as_ref().unwrap();
    let cb = net.b.conns[b].as_ref().unwrap();
    assert!(ca.wscale_ok && cb.wscale_ok && ca.ts_ok && cb.ts_ok);
    // 256 KiB cabem na janela de 16 bits com escala 3.
    assert_eq!(ca.rcv_shift, 3);
    assert_eq!(cb.snd_shift, 3);
    // Sem as opções do outro lado, tudo volta ao básico.
    let mut c = super::conn::Conn::new(
        State::SynRcvd,
        (A, 1, B, 2),
        0,
        0,
        100,
        false,
        1 << 18,
        super::Features::ALL,
    );
    c.negotiate(&wire::Opts::NONE);
    assert!(!c.wscale_ok && !c.ts_ok);
    assert_eq!(c.rcv_shift, 0);
}

#[test]
fn opcoes_ida_e_volta() {
    let o = wire::Opts {
        mss: Some(1460),
        wscale: Some(7),
        sack_ok: true,
        ts: Some((0xdead_beef, 0x1234_5678)),
        ..wire::Opts::NONE
    };
    let h = wire::Header {
        sport: 1,
        dport: 2,
        seq: 3,
        ack: 4,
        flags: SYN,
        window: 5,
        opts: o,
    };
    let mut out = [0u8; 64];
    let n = wire::build(A, B, &h, &[], &mut out).unwrap();
    assert_eq!(n, 40);
    assert_eq!(wire::parse(A, B, &out[..n]).unwrap().opts, o);
    // ACK com timestamps e três blocos SACK: 12 + 28 bytes de opções.
    let mut o = wire::Opts {
        ts: Some((1, 2)),
        nsack: 3,
        ..wire::Opts::NONE
    };
    o.sack[..3].copy_from_slice(&[(10, 20), (30, 40), (50, 60)]);
    let h = wire::Header {
        flags: ACK,
        opts: o,
        ..h
    };
    let n = wire::build(A, B, &h, b"xy", &mut out).unwrap();
    assert_eq!(n, 20 + 40 + 2);
    let s = wire::parse(A, B, &out[..n]).unwrap();
    assert_eq!(s.opts.blocks(), &[(10, 20), (30, 40), (50, 60)]);
    assert_eq!(s.opts.ts, Some((1, 2)));
    assert_eq!(s.data, b"xy");
    // A escala acima de 14 vale 14.
    let mut raw = out;
    let h2 = wire::Header {
        opts: wire::Opts {
            wscale: Some(9),
            ..wire::Opts::NONE
        },
        ..h
    };
    let n = wire::build(A, B, &h2, &[], &mut raw).unwrap();
    raw[20 + 3] = 30;
    let c = {
        raw[16..18].fill(0);
        crate::ip4::fold(crate::ip4::sum(
            &raw[..n],
            crate::udp::pseudo_sum(A, B, crate::ip4::PROTO_TCP, n),
        ))
    };
    raw[16..18].copy_from_slice(&c.to_be_bytes());
    assert_eq!(wire::parse(A, B, &raw[..n]).unwrap().opts.wscale, Some(14));
}

#[test]
fn opcao_malformada_derruba_o_segmento() {
    let sum = |x: &mut [u8; 28]| {
        x[16..18].fill(0);
        let c = crate::ip4::fold(crate::ip4::sum(
            &x[..],
            crate::udp::pseudo_sum(A, B, crate::ip4::PROTO_TCP, 28),
        ));
        x[16..18].copy_from_slice(&c.to_be_bytes());
    };
    for bad in [
        [3u8, 4, 1, 1, 0, 0, 0, 0],
        [4, 3, 0, 0, 0, 0, 0, 0],
        [8, 6, 0, 0, 0, 0, 0, 0],
        [5, 9, 0, 0, 0, 0, 0, 0],
        [5, 2, 0, 0, 0, 0, 0, 0],
        [2, 3, 0, 0, 0, 0, 0, 0],
    ] {
        let mut x = [0u8; 28];
        x[12] = 7 << 4;
        x[13] = ACK;
        x[20..28].copy_from_slice(&bad);
        sum(&mut x);
        assert!(wire::parse(A, B, &x).is_none(), "aceitou {bad:?}");
    }
    // Opção desconhecida se pula.
    let mut x = [0u8; 28];
    x[12] = 7 << 4;
    x[13] = ACK;
    x[20..28].copy_from_slice(&[99, 4, 0, 0, 1, 1, 1, 1]);
    sum(&mut x);
    assert!(wire::parse(A, B, &x).is_some());
}

#[test]
fn placar_sack_junta_e_apara() {
    use super::sack::Scoreboard;
    let mut sb = Scoreboard::new();
    // una = 1000, max = 2000.
    sb.insert(1000, 2000, 1200, 1300);
    sb.insert(1000, 2000, 1500, 1600);
    sb.insert(1000, 2000, 1300, 1400); // encosta na primeira
    assert_eq!(sb.ranges(), &[(1200, 1400), (1500, 1600)]);
    sb.insert(1000, 2000, 1390, 1510); // junta as duas
    assert_eq!(sb.ranges(), &[(1200, 1600)]);
    assert_eq!(sb.bytes(), 400);
    assert_eq!(sb.above(1000), 400);
    assert_eq!(sb.above(1300), 300);
    assert_eq!(sb.holes(1000).collect::<Vec<_>>(), [(1000, 1200)]);
    // Fora de (una, max]: ignorado.
    sb.insert(1000, 2000, 900, 1100);
    sb.insert(1000, 2000, 1900, 2100);
    sb.insert(1000, 2000, 1700, 1700);
    sb.insert(1000, 2000, 1800, 1700);
    assert_eq!(sb.ranges(), &[(1200, 1600)]);
    // `una` anda: apara.
    sb.advance(1400);
    assert_eq!(sb.ranges(), &[(1400, 1600)]);
    sb.advance(1600);
    assert!(sb.ranges().is_empty());
}

#[test]
fn placar_sack_na_volta_do_espaco_de_sequencia() {
    use super::sack::Scoreboard;
    let una = u32::MAX - 100;
    let mut sb = Scoreboard::new();
    sb.insert(una, 500, 50, 200);
    sb.insert(una, 500, u32::MAX - 20, 10);
    assert_eq!(sb.ranges(), &[(u32::MAX - 20, 10), (50, 200)]);
    assert_eq!(sb.bytes(), 31 + 150);
    assert_eq!(
        sb.holes(una).collect::<Vec<_>>(),
        [(una, u32::MAX - 20), (10, 50)]
    );
    sb.advance(100);
    assert_eq!(sb.ranges(), &[(100, 200)]);
}

#[test]
fn cubic_reduz_cresce_e_volta_ao_maximo() {
    use super::cubic::Cubic;
    let mss = 1460;
    let mut c = Cubic::new();
    let w = 100 * mss;
    // Reduz a 70 %.
    let ss = c.on_loss(w, mss);
    assert_eq!(ss, 70 * mss);
    // Cresce de 70 até perto de 100 segmentos e passa de 100 depois de K.
    let mut cwnd = ss;
    let mut t = 0u64;
    let rtt = 50_000_000;
    let mut at_max = None;
    for _ in 0..20_000 {
        t += rtt / 40;
        cwnd = c.on_ack(cwnd, mss, mss, t, rtt);
        if at_max.is_none() && cwnd >= w {
            at_max = Some(t);
        }
        if t > 30_000_000_000 {
            break;
        }
    }
    let at = at_max.expect("não voltou ao máximo");
    // K = cbrt(30 / 0,4) ≈ 4,2 s.
    assert!(
        at > 2_500_000_000 && at < 6_500_000_000,
        "voltou em {at} ns"
    );
    assert!(cwnd > w, "não passou do máximo: {cwnd}");
    // Convergência rápida: a segunda perda abaixo do último máximo reduz mais.
    let before = c.on_loss(cwnd, mss);
    let mut d = Cubic::new();
    d.on_loss(w, mss);
    let second = d.on_loss(w / 2, mss);
    assert!(second < w / 2 * 7 / 10 + 1);
    assert!(before > 0);
}

/// Manda `n` bytes de A para B e confere o que chega; devolve os contadores de A.
fn bulk(net: &mut Net, n: usize, max_ms: u64) -> (super::Stats, u64) {
    let (a, b) = net.open();
    let data = pattern(n);
    let mut sent = 0;
    let mut got = 0usize;
    let mut sum_got = 0u64;
    let mut buf = [0u8; 8192];
    let start = net.now;
    for _ in 0..max_ms {
        if sent < data.len() {
            sent += net.a.write(a, &data[sent..], net.now).unwrap();
        }
        while let Ok(Read::Data(k)) = net.b.read(b, &mut buf) {
            for (i, x) in buf[..k].iter().enumerate() {
                assert_eq!(*x, data[got + i], "byte {} trocado", got + i);
            }
            got += k;
            sum_got += k as u64;
        }
        if got == n {
            break;
        }
        net.tick();
    }
    assert_eq!(got, n, "chegaram {got} de {n}");
    assert_eq!(sum_got, n as u64);
    // O buffer de envio nunca passa do limite do orçamento.
    assert!(net.a.conns[a].as_ref().unwrap().send_pending() <= BUF_LIMIT);
    (net.a.stats(a).unwrap(), (net.now - start) / MS)
}

const BUF_LIMIT: usize = super::BUF_BYTES;

#[test]
fn uma_perda_custa_uma_retransmissao() {
    let mut net = Net::new();
    net.drop_data = vec![20];
    let (st, _) = bulk(&mut net, 200_000, 60_000);
    assert_eq!(
        st,
        super::Stats {
            retx_segments: 1,
            fast_recoveries: 1,
            timeouts: 0,
            probes: 0,
            keepalives: 0
        }
    );
}

#[test]
fn varias_perdas_na_mesma_janela_saem_por_sack_sem_rto() {
    let mut net = Net::new();
    net.drop_data = vec![30, 33, 36, 40];
    let (st, _) = bulk(&mut net, 300_000, 60_000);
    assert_eq!(st.timeouts, 0, "{st:?}");
    assert_eq!(st.fast_recoveries, 1, "{st:?}");
    assert_eq!(st.retx_segments, 4, "{st:?}");
}

#[test]
fn par_sem_extensoes_recupera_por_newreno() {
    let mut net = Net::new();
    let f = super::Features {
        wscale: false,
        sack: false,
        timestamps: false,
    };
    net.a.set_features(f);
    net.b.set_features(f);
    net.drop_data = vec![25, 26];
    let (a, b) = net.open();
    let c = net.a.conns[a].as_ref().unwrap();
    assert!(!c.sack_ok && !c.ts_ok && !c.wscale_ok);
    assert_eq!(net.b.conns[b].as_ref().unwrap().rcv_shift, 0);
    let data = pattern(150_000);
    let got = transfer(&mut net, a, b, &data, 120_000);
    assert_eq!(got, data);
    let st = net.a.stats(a).unwrap();
    assert!(st.fast_recoveries >= 1);
}

#[test]
fn um_lado_sem_sack_nao_o_liga() {
    let mut net = Net::new();
    net.b.set_features(super::Features {
        sack: false,
        ..super::Features::ALL
    });
    let (a, b) = net.open();
    assert!(!net.a.conns[a].as_ref().unwrap().sack_ok);
    assert!(!net.b.conns[b].as_ref().unwrap().sack_ok);
    assert!(net.a.conns[a].as_ref().unwrap().ts_ok);
}

#[test]
fn transferencia_de_64_mib_com_2_por_cento_de_perda() {
    let mut net = Net::new();
    net.loss = 2;
    net.reorder = 5;
    // Reordenação de poucos ms, dentro da janela do RACK; a de 20 ms fica nos
    // testes de correção.
    net.reorder_ms = 2;
    let (st, ms) = bulk(&mut net, 64 << 20, 4_000_000);
    // Memória: nenhum dos lados passou do orçamento de buffers.
    assert!(net.a.budget_left() <= super::MEM_BUDGET);
    // Contagens fixas para o gate da T-674 (a semente da rede simulada é
    // fixa): 2 % de perda em ~45 mil segmentos dão ~920 retransmissões, quase
    // todas por recuperação rápida (SACK e RACK), nenhuma por RTO.
    assert_eq!(
        st,
        super::Stats {
            retx_segments: 924,
            fast_recoveries: 779,
            timeouts: 0,
            probes: 0,
            keepalives: 0,
        },
        "contagens mudaram (64 MiB em {ms} ms simulados)"
    );
}

#[test]
fn keepalive_mantem_a_conexao_viva_e_derruba_a_morta() {
    let k = super::Keepalive {
        idle: 10_000 * MS,
        interval: 1_000 * MS,
        count: 3,
    };
    // Par vivo: as sondas são respondidas e a conexão fica.
    let mut net = Net::new();
    let (a, b) = net.open();
    net.a.set_keepalive(a, Some(k));
    net.run_ms(60_000);
    assert_eq!(net.a.state(a), Some(State::Established));
    assert_eq!(net.b.state(b), Some(State::Established));
    let st = net.a.stats(a).unwrap();
    assert!(st.keepalives >= 5 && st.keepalives <= 6, "{st:?}");
    // Par morto: 10 s de silêncio e 3 sondas a 1 s caem a conexão.
    let mut net = Net::new();
    let (a, _b) = net.open();
    net.a.set_keepalive(a, Some(k));
    net.cut = true;
    assert!(net.until(20_000, |n| n.a.state(a) == Some(State::Closed)));
    assert_eq!(net.a.error(a), Some(Error::TimedOut));
    assert_eq!(net.a.stats(a).unwrap().keepalives, 3);
    // Sem `keepalive`, a conexão ociosa nunca manda nada.
    let mut net = Net::new();
    let (a, _) = net.open();
    net.run_ms(60_000);
    assert_eq!(net.a.stats(a).unwrap().keepalives, 0);
    assert_eq!(net.a.state(a), Some(State::Established));
}

#[test]
fn sonda_de_cauda_recupera_o_fim_perdido_sem_rto() {
    let mut net = Net::new();
    let (a, b) = net.open();
    // Aquece o RTT e depois perde o último segmento de um envio curto.
    let warm = pattern(20_000);
    assert_eq!(transfer(&mut net, a, b, &warm, 20_000), warm);
    net.run_ms(100);
    let before = net.data_seen;
    net.drop_data = vec![before + 3];
    let tail = pattern(3 * 1460);
    net.a.write(a, &tail, net.now).unwrap();
    net.run_ms(2_000);
    let mut buf = vec![0u8; tail.len()];
    let mut got = 0;
    while let Ok(Read::Data(n)) = net.b.read(b, &mut buf[got..]) {
        got += n;
    }
    assert_eq!(got, tail.len());
    let st = net.a.stats(a).unwrap();
    assert_eq!(st.timeouts, 0, "{st:?}");
    assert_eq!(st.probes, 1, "{st:?}");
}
