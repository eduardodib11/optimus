//! Uma conexão TCP: estado, envio, recepção, temporizador de retransmissão e
//! controle de congestionamento Reno (o CUBIC entra na T-636).

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use super::buf::Buf;
use super::cubic::Cubic;
use super::sack::Scoreboard;
use super::wire::{self, ACK, FIN, Header, MAX_SACK, Opts, PSH, RST, SYN, Segment};
use super::{Error, ListenId, MAX_OOO, MSS, Out};
use crate::arp::Ip4;

/// Estados (RFC 9293, 3.3.2). O `LISTEN` fica na tabela de escutas.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Sem conexão (fechada, reiniciada ou expirada).
    Closed,
    /// SYN enviado.
    SynSent,
    /// SYN recebido, SYN-ACK enviado.
    SynRcvd,
    /// Aberta.
    Established,
    /// FIN enviado, esperando o ACK dele.
    FinWait1,
    /// FIN confirmado, esperando o FIN do outro lado.
    FinWait2,
    /// O outro lado fechou; falta fecharmos.
    CloseWait,
    /// Os dois fecharam ao mesmo tempo.
    Closing,
    /// Fechamos depois do outro lado, esperando o ACK.
    LastAck,
    /// Espera de 2 MSL.
    TimeWait,
}

/// Limite de cada buffer de uma conexão (envio e recepção). A janela de 16
/// bits só chega a 64 KiB; acima disso a escala (RFC 7323) entra.
pub const BUF_BYTES: usize = 262_144;
/// RTO inicial, mínimo e máximo (RFC 6298; mínimo de 200 ms como no Linux).
const INIT_RTO: u64 = 1_000_000_000;
const MIN_RTO: u64 = 200_000_000;
const MAX_RTO: u64 = 60_000_000_000;
/// Retransmissões antes de desistir (SYN e dados).
const MAX_SYN_RETRIES: u8 = 5;
const MAX_RETRIES: u8 = 8;
/// 2 MSL (MSL de 30 s).
const TIME_WAIT_NS: u64 = 60_000_000_000;
/// Janela inicial de congestionamento, em segmentos (RFC 6928).
const INIT_CWND_SEGS: usize = 10;

pub(super) fn lt(a: u32, b: u32) -> bool {
    #[allow(
        clippy::cast_possible_wrap,
        reason = "aritmética de sequência (RFC 9293)"
    )]
    {
        (a.wrapping_sub(b) as i32) < 0
    }
}

pub(super) fn le(a: u32, b: u32) -> bool {
    a == b || lt(a, b)
}

/// O que a chegada de um segmento mudou para quem está acima.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// Nada que o dono precise saber agora.
    None,
    /// A conexão ficou aberta.
    Established,
}

/// Uma conexão.
#[derive(Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "marcas independentes do automato"
)]
pub struct Conn {
    pub(super) state: State,
    pub(super) user_closed: bool,
    pub(super) err: Option<Error>,
    pub(super) listener: Option<ListenId>,
    pub(super) ephemeral: bool,
    pub(super) lip: Ip4,
    pub(super) lport: u16,
    pub(super) rip: Ip4,
    pub(super) rport: u16,
    // Envio.
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    snd_max: u32,
    snd_wnd: u32,
    snd_wl1: u32,
    snd_wl2: u32,
    /// Sequência do primeiro byte de `sndbuf`.
    buf_seq: u32,
    sndbuf: Buf,
    fin_queued: bool,
    fin_seq: Option<u32>,
    mss: usize,
    cwnd: usize,
    ssthresh: usize,
    dupacks: u8,
    pub(super) srtt: u64,
    rttvar: u64,
    pub(super) rto: u64,
    rtt_probe: Option<(u32, u64)>,
    rtx_at: Option<u64>,
    rtx_count: u8,
    // Recepção.
    irs: u32,
    pub(super) rcv_nxt: u32,
    rcvbuf: Buf,
    ooo: Vec<(u32, Vec<u8>)>,
    fin_at: Option<u32>,
    fin_rcvd: bool,
    time_wait_at: u64,
    // Opções negociadas (RFC 7323 e RFC 2018).
    pub(super) wscale_ok: bool,
    /// Escala da janela do outro lado e a nossa.
    pub(super) snd_shift: u8,
    pub(super) rcv_shift: u8,
    pub(super) ts_ok: bool,
    /// Último `TSval` aceito do outro lado, devolvido em `TSecr`.
    ts_recent: u32,
    /// Relógio da última chamada, para o `TSval` dos segmentos.
    now: u64,
    /// Limite dos dois buffers, para o `Tcp` devolver a cota.
    pub(super) limit: usize,
    // Recuperação de perdas (RFC 6675) e CUBIC (RFC 9438).
    pub(super) sack_ok: bool,
    sb: Scoreboard,
    cubic: Cubic,
    in_recovery: bool,
    recovery_point: u32,
    /// Faixas retransmitidas na recuperação atual: (início, fim, instante).
    retx: Vec<(u32, u32, u64)>,
    /// Quando cada segmento novo saiu: (sequência inicial, instante), em ordem
    /// de sequência. É o relógio do RACK (RFC 8985).
    sent_log: VecDeque<(u32, u64)>,
    /// Início do último segmento fora de ordem recebido (vai primeiro no SACK).
    last_ooo: Option<u32>,
    /// Contagens para o gate da T-674.
    pub(super) stats: Stats,
    /// O que oferecemos no SYN.
    offer: Features,
    /// Sem Nagle: segmentos curtos saem na hora.
    pub(super) nodelay: bool,
    /// Último avanço da conexão (envio de dados novos ou ACK novo), para o
    /// temporizador de sonda de cauda.
    activity: u64,
    /// Já se mandou a sonda de cauda desde o último avanço.
    tlp_sent: bool,
    /// Quando reavaliar a primeira lacuna (RACK): o tempo dela ainda não passou.
    rack_at: Option<u64>,
    pub(super) keepalive: Option<Keepalive>,
    /// Última vez que se ouviu o outro lado.
    last_rx: u64,
    /// Sondas de `keepalive` sem resposta e quando sai a próxima.
    ka_sent: u8,
    ka_at: u64,
}

/// Quais extensões o `Tcp` oferece e aceita. Tudo ligado por padrão; os
/// testes desligam para exercitar o TCP básico (par antigo).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    /// Escala de janela (RFC 7323).
    pub wscale: bool,
    /// SACK (RFC 2018).
    pub sack: bool,
    /// Timestamps (RFC 7323).
    pub timestamps: bool,
}

impl Features {
    /// Todas as extensões.
    pub const ALL: Self = Self {
        wscale: true,
        sack: true,
        timestamps: true,
    };
}

/// Contadores de retransmissão de uma conexão.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Segmentos de dados retransmitidos.
    pub retx_segments: u32,
    /// Entradas em recuperação rápida.
    pub fast_recoveries: u32,
    /// Estouros do RTO.
    pub timeouts: u32,
    /// Sondas de cauda (TLP) enviadas.
    pub probes: u32,
    /// Sondas de `keepalive` enviadas.
    pub keepalives: u32,
}

/// `keepalive` (RFC 9293, 3.8.4): depois de `idle` ns sem ouvir o outro lado,
/// manda uma sonda a cada `interval` ns; sem resposta a `count` sondas, a
/// conexão cai com [`Error::TimedOut`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keepalive {
    /// Silêncio até a primeira sonda (ns).
    pub idle: u64,
    /// Intervalo entre as sondas (ns).
    pub interval: u64,
    /// Sondas sem resposta até desistir.
    pub count: u8,
}

impl Conn {
    #[allow(
        clippy::too_many_arguments,
        reason = "a tupla e as sequências iniciais"
    )]
    pub(super) fn new(
        state: State,
        tuple: (Ip4, u16, Ip4, u16),
        iss: u32,
        irs: u32,
        peer_wnd: u16,
        ephemeral: bool,
        limit: usize,
        offer: Features,
    ) -> Self {
        let mss = 536;
        // Menor escala que deixa o buffer de recepção inteiro na janela.
        let mut rcv_shift = 0u8;
        while (limit >> rcv_shift) > usize::from(u16::MAX) && rcv_shift < 14 {
            rcv_shift += 1;
        }
        Self {
            state,
            user_closed: false,
            err: None,
            listener: None,
            ephemeral,
            lip: tuple.0,
            lport: tuple.1,
            rip: tuple.2,
            rport: tuple.3,
            iss,
            snd_una: iss,
            snd_nxt: iss.wrapping_add(1),
            snd_max: iss.wrapping_add(1),
            snd_wnd: u32::from(peer_wnd),
            snd_wl1: irs,
            snd_wl2: iss,
            buf_seq: iss.wrapping_add(1),
            sndbuf: Buf::new(limit),
            fin_queued: false,
            fin_seq: None,
            mss,
            cwnd: INIT_CWND_SEGS * mss,
            ssthresh: usize::MAX / 2,
            dupacks: 0,
            srtt: 0,
            rttvar: 0,
            rto: INIT_RTO,
            rtt_probe: None,
            rtx_at: None,
            rtx_count: 0,
            irs,
            rcv_nxt: irs.wrapping_add(1),
            rcvbuf: Buf::new(limit),
            ooo: Vec::new(),
            fin_at: None,
            fin_rcvd: false,
            time_wait_at: 0,
            wscale_ok: false,
            snd_shift: 0,
            rcv_shift,
            ts_ok: false,
            ts_recent: 0,
            now: 0,
            limit,
            sack_ok: false,
            sb: Scoreboard::new(),
            cubic: Cubic::new(),
            in_recovery: false,
            recovery_point: 0,
            retx: Vec::new(),
            sent_log: VecDeque::new(),
            last_ooo: None,
            stats: Stats {
                retx_segments: 0,
                fast_recoveries: 0,
                timeouts: 0,
                probes: 0,
                keepalives: 0,
            },
            offer,
            nodelay: false,
            activity: 0,
            tlp_sent: false,
            rack_at: None,
            keepalive: None,
            last_rx: 0,
            ka_sent: 0,
            ka_at: 0,
        }
    }

    /// Aplica as opções do SYN do outro lado: MSS, escala, SACK e timestamps.
    /// Sem a opção na outra ponta, o recurso fica desligado (a escala nossa
    /// também: sem ela a janela anunciada é a de 16 bits).
    pub(super) fn negotiate(&mut self, o: &Opts) {
        self.mss = usize::from(o.mss.unwrap_or(536)).clamp(536, MSS);
        self.cwnd = INIT_CWND_SEGS * self.mss;
        if let (Some(w), true) = (o.wscale, self.offer.wscale) {
            self.wscale_ok = true;
            self.snd_shift = w;
        } else {
            self.wscale_ok = false;
            self.snd_shift = 0;
            self.rcv_shift = 0;
        }
        if let (Some((v, _)), true) = (o.ts, self.offer.timestamps) {
            self.ts_ok = true;
            self.ts_recent = v;
        }
        self.sack_ok = o.sack_ok && self.offer.sack;
        // Os timestamps gastam 12 bytes de cada segmento: sem descontá-los do
        // MSS, um segmento cheio passa do MTU e a pilha o descarta (RFC 7323).
        if self.ts_ok {
            self.mss -= 12;
            self.cwnd = INIT_CWND_SEGS * self.mss;
        }
    }

    /// `TSval`: o relógio em milissegundos.
    fn tsval(&self) -> u32 {
        u32::try_from((self.now / 1_000_000) & 0xffff_ffff).unwrap_or(0)
    }

    /// Opções de um segmento comum (sem SYN): timestamps.
    fn data_opts(&self) -> Opts {
        let mut o = Opts::NONE;
        if self.ts_ok {
            o.ts = Some((self.tsval(), self.ts_recent));
        }
        if self.sack_ok && !self.ooo.is_empty() {
            let max = if self.ts_ok { MAX_SACK - 1 } else { MAX_SACK };
            o.nsack = self.sack_blocks(&mut o.sack[..max]);
        }
        o
    }

    /// Blocos SACK a anunciar: as faixas fora de ordem já unidas, com a do
    /// segmento mais recente primeiro (RFC 2018, 4).
    fn sack_blocks(&self, out: &mut [(u32, u32)]) -> usize {
        let base = self.rcv_nxt;
        let mut v: Vec<(u32, u32)> = self
            .ooo
            .iter()
            .map(|(s, d)| (*s, s.wrapping_add(u32::try_from(d.len()).unwrap_or(0))))
            .collect();
        v.sort_by_key(|r| r.0.wrapping_sub(base));
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (a, b) in v {
            match merged.last_mut() {
                Some(l) if le(a, l.1) => {
                    if lt(l.1, b) {
                        l.1 = b;
                    }
                }
                _ => merged.push((a, b)),
            }
        }
        if let Some(first) = self.last_ooo
            && let Some(i) = merged
                .iter()
                .position(|&(a, b)| le(a, first) && lt(first, b))
        {
            let r = merged.remove(i);
            merged.insert(0, r);
        }
        let n = merged.len().min(out.len());
        out[..n].copy_from_slice(&merged[..n]);
        n
    }

    /// Estado atual.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Janela de recepção anunciada (já deslocada pela escala).
    fn window(&self) -> u16 {
        u16::try_from(self.rcvbuf.free() >> self.rcv_shift).unwrap_or(u16::MAX)
    }

    fn header(&self, flags: u8, seq: u32) -> Header {
        Header {
            sport: self.lport,
            dport: self.rport,
            seq,
            ack: self.rcv_nxt,
            flags,
            window: self.window(),
            opts: self.data_opts(),
        }
    }

    fn emit(&self, ob: &mut VecDeque<Out>, h: &Header, data: &[u8]) {
        let mut seg = alloc::vec![0u8; wire::HEADER_LEN + 40 + data.len()];
        if let Some(n) = wire::build(self.lip, self.rip, h, data, &mut seg) {
            seg.truncate(n);
            ob.push_back(Out {
                dst: self.rip,
                data: seg,
            });
        }
    }

    pub(super) fn send_ack(&self, ob: &mut VecDeque<Out>) {
        self.emit(ob, &self.header(ACK, self.snd_nxt), &[]);
    }

    fn send_syn(&self, ob: &mut VecDeque<Out>) {
        let mut h = self.header(
            SYN | if self.state == State::SynSent { 0 } else { ACK },
            self.iss,
        );
        // A janela do SYN nunca é escalada (RFC 7323, 2.2).
        h.window = u16::try_from(self.rcvbuf.free()).unwrap_or(u16::MAX);
        let active = self.state == State::SynSent;
        let mut o = Opts::NONE;
        o.mss = Some(u16::try_from(MSS).unwrap_or(1460));
        // O ativo oferece tudo; o passivo só responde o que o outro ofereceu.
        if self.offer.wscale && (active || self.wscale_ok) {
            o.wscale = Some(self.rcv_shift);
        }
        o.sack_ok = self.offer.sack;
        if self.offer.timestamps && (active || self.ts_ok) {
            o.ts = Some((self.tsval(), if active { 0 } else { self.ts_recent }));
        }
        h.opts = o;
        if active {
            h.ack = 0;
        }
        self.emit(ob, &h, &[]);
    }

    pub(super) fn start(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        self.send_syn(ob);
        self.rtx_at = Some(now.saturating_add(self.rto));
    }

    fn unsent_from(&self, seq: u32) -> usize {
        let off = seq.wrapping_sub(self.buf_seq) as usize;
        self.sndbuf.len().saturating_sub(off)
    }

    fn arm(&mut self, now: u64) {
        self.rtx_at = Some(now.saturating_add(self.rto));
    }

    /// Envia o que a janela e o congestionamento deixam.
    pub(super) fn output(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        self.now = now;
        if !matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::Closing
                | State::LastAck
        ) {
            return;
        }
        loop {
            let flight = self.pipe();
            let wnd = (self.snd_wnd as usize).min(self.cwnd);
            // Recuperação: primeiro as lacunas que se dão por perdidas.
            if self.in_recovery
                && flight < wnd
                && let Some((seq, n)) = self.next_lost()
            {
                self.send_retx(ob, seq, n, now);
                continue;
            }
            let unsent = self.unsent_from(self.snd_nxt);
            let fresh = self.snd_nxt == self.snd_max;
            if unsent > 0 && flight < wnd {
                let n = unsent.min(self.mss).min(wnd - flight);
                // Segmento curto só se for o fim do que há para mandar e não
                // houver dados em voo (Nagle, RFC 1122 4.2.3.4), ou se nada
                // estiver em voo (a janela estreita não pode travar a
                // conexão). Do contrário espera o ACK a abrir a janela.
                let tail = n == unsent;
                if n < self.mss && !(flight == 0 || (tail && (self.nodelay || self.fin_queued))) {
                    break;
                }
                let mut data = alloc::vec![0u8; n];
                let off = self.snd_nxt.wrapping_sub(self.buf_seq) as usize;
                self.sndbuf.peek(off, &mut data);
                let last = n == unsent;
                let h = self.header(ACK | if last { PSH } else { 0 }, self.snd_nxt);
                self.emit(ob, &h, &data);
                if !fresh {
                    self.stats.retx_segments += 1;
                }
                self.sent_log.push_back((self.snd_nxt, now));
                self.activity = now;
                self.tlp_sent = false;
                if fresh && self.rtt_probe.is_none() {
                    let end = self.snd_nxt.wrapping_add(u32::try_from(n).unwrap_or(0));
                    self.rtt_probe = Some((end, now));
                }
                self.snd_nxt = self.snd_nxt.wrapping_add(u32::try_from(n).unwrap_or(0));
                if lt(self.snd_max, self.snd_nxt) {
                    self.snd_max = self.snd_nxt;
                }
                if self.rtx_at.is_none() {
                    self.arm(now);
                }
            } else if self.fin_queued
                && unsent == 0
                && (self.fin_seq.is_none() || self.fin_seq == Some(self.snd_nxt))
                && flight <= wnd
            {
                let h = self.header(FIN | ACK, self.snd_nxt);
                self.emit(ob, &h, &[]);
                self.fin_seq = Some(self.snd_nxt);
                self.snd_nxt = self.snd_nxt.wrapping_add(1);
                if lt(self.snd_max, self.snd_nxt) {
                    self.snd_max = self.snd_nxt;
                }
                match self.state {
                    State::Established => self.state = State::FinWait1,
                    State::CloseWait => self.state = State::LastAck,
                    _ => {}
                }
                if self.rtx_at.is_none() {
                    self.arm(now);
                }
            } else {
                break;
            }
        }
        // Janela zero com dados esperando: o temporizador vira sonda.
        if self.rtx_at.is_none() && self.unsent_from(self.snd_nxt) > 0 {
            self.arm(now);
        }
    }

    /// Bytes que se supõe estarem na rede (RFC 6675, `SetPipe`): o que foi
    /// enviado menos o confirmado por SACK e o dado por perdido, mais as
    /// retransmissões em voo. Fora da recuperação é `snd_nxt − snd_una`.
    fn pipe(&self) -> usize {
        let nxt = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        if !self.in_recovery {
            return nxt;
        }
        let flight = self.snd_max.wrapping_sub(self.snd_una) as usize;
        if !self.sack_ok {
            // NewReno: cada ACK duplicado diz que um segmento saiu da rede.
            return flight.saturating_sub(usize::from(self.dupacks) * self.mss);
        }
        let lost: usize = self
            .sb
            .holes(self.snd_una)
            .filter(|&(a, b)| self.hole_lost(a, b))
            .map(|(a, b)| b.wrapping_sub(a) as usize)
            .sum();
        (flight + self.retx_out()).saturating_sub(self.sb.bytes() + lost)
    }

    /// RACK simplificado (RFC 8985): a lacuna `[a, b)` está perdida quando
    /// algo enviado depois dela já foi confirmado por SACK e passou o tempo de
    /// uma ida e volta mais a janela de reordenação (um quarto dela). Reordenar
    /// por menos que isso não dispara retransmissão.
    fn hole_lost(&self, a: u32, b: u32) -> bool {
        if self.sb.above(b) == 0 {
            return false;
        }
        let Some(sent) = self.send_time(a) else {
            return true;
        };
        let rtt = if self.srtt == 0 { self.rto } else { self.srtt };
        self.now >= sent.saturating_add(rtt + rtt / 4)
    }

    /// Quando o byte `seq` saiu pela última vez (novo envio).
    fn send_time(&self, seq: u32) -> Option<u64> {
        self.sent_log
            .iter()
            .rev()
            .find(|&&(s, _)| le(s, seq))
            .map(|&(_, t)| t)
    }

    /// Quando a primeira lacuna (com algo confirmado acima dela) passa a ser
    /// dada por perdida, se ainda não é. É o temporizador do RACK.
    fn next_rack(&self) -> Option<u64> {
        if !self.sack_ok {
            return None;
        }
        let (a, b) = self.sb.holes(self.snd_una).next()?;
        if self.sb.above(b) == 0 || self.hole_lost(a, b) {
            return None;
        }
        let rtt = if self.srtt == 0 { self.rto } else { self.srtt };
        Some(self.send_time(a)?.saturating_add(rtt + rtt / 4))
    }

    /// A primeira lacuna se dá por perdida.
    fn first_hole_lost(&self) -> bool {
        self.sb
            .holes(self.snd_una)
            .next()
            .is_some_and(|(a, b)| self.hole_lost(a, b))
    }

    /// Bytes retransmitidos nesta recuperação que ainda não foram
    /// confirmados nem por SACK.
    fn retx_out(&self) -> usize {
        let mut total = 0usize;
        for &(a, b, _) in &self.retx {
            if le(b, self.snd_una) {
                continue;
            }
            let a = if lt(a, self.snd_una) { self.snd_una } else { a };
            let mut len = b.wrapping_sub(a) as usize;
            for &(x, y) in self.sb.ranges() {
                // Parte de [a, b) dentro de [x, y).
                let lo = if lt(a, x) { x } else { a };
                let hi = if lt(b, y) { b } else { y };
                if lt(lo, hi) {
                    len = len.saturating_sub(hi.wrapping_sub(lo) as usize);
                }
            }
            total += len;
        }
        total
    }

    /// Próxima faixa perdida ainda não retransmitida: (início, bytes).
    fn next_lost(&self) -> Option<(u32, usize)> {
        if !self.sack_ok {
            return None;
        }
        for (a, b) in self.sb.holes(self.snd_una) {
            if !self.hole_lost(a, b) {
                continue;
            }
            let mut c = a;
            while let Some(&(_, e, _)) = self.retx.iter().find(|&&(x, y, _)| le(x, c) && lt(c, y)) {
                c = e;
            }
            if lt(c, b) {
                let n = (b.wrapping_sub(c) as usize).min(self.mss);
                return Some((c, n));
            }
        }
        None
    }

    /// Retransmite `n` bytes a partir de `seq` e anota a faixa.
    fn send_retx(&mut self, ob: &mut VecDeque<Out>, seq: u32, n: usize, now: u64) {
        let mut data = alloc::vec![0u8; n];
        let off = seq.wrapping_sub(self.buf_seq) as usize;
        let got = self.sndbuf.peek(off, &mut data);
        data.truncate(got);
        if data.is_empty() {
            return;
        }
        self.emit(ob, &self.header(ACK, seq), &data);
        let end = seq.wrapping_add(u32::try_from(data.len()).unwrap_or(0));
        self.retx.push((seq, end, now));
        self.stats.retx_segments += 1;
    }

    /// Liga ou desliga o `keepalive`.
    pub(super) fn set_keepalive(&mut self, k: Option<Keepalive>, now: u64) {
        self.keepalive = k;
        self.last_rx = now;
        self.ka_sent = 0;
    }

    /// Sonda uma conexão parada: um segmento com a sequência anterior à
    /// próxima, que o outro lado responde com um ACK.
    fn keepalive_step(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        let Some(k) = self.keepalive else { return };
        if !matches!(self.state, State::Established | State::CloseWait)
            || self.snd_una != self.snd_max
        {
            return;
        }
        let due = if self.ka_sent == 0 {
            now >= self.last_rx.saturating_add(k.idle)
        } else {
            now >= self.ka_at
        };
        if !due {
            return;
        }
        if self.ka_sent >= k.count {
            self.fail(Error::TimedOut);
            return;
        }
        self.ka_sent += 1;
        self.ka_at = now.saturating_add(k.interval);
        self.emit(ob, &self.header(ACK, self.snd_nxt.wrapping_sub(1)), &[]);
        self.stats.keepalives += 1;
    }

    /// Sonda de cauda (TLP, RFC 8985): se nada avançou em `2·SRTT` e há dados
    /// em voo, reenvia o último segmento. Se ele chegar, o SACK de volta revela
    /// as perdas da cauda sem esperar o RTO.
    fn probe_tail(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        if self.tlp_sent
            || self.in_recovery
            || self.srtt == 0
            || self.snd_una == self.snd_max
            || !matches!(self.state, State::Established | State::CloseWait)
        {
            return;
        }
        let pto = (2 * self.srtt).max(10_000_000);
        if now < self.activity.saturating_add(pto) {
            return;
        }
        let Some(&(start, _)) = self.sent_log.back() else {
            return;
        };
        let n = (self.snd_max.wrapping_sub(start) as usize).min(self.mss);
        if n == 0 || lt(start, self.snd_una) {
            return;
        }
        self.tlp_sent = true;
        self.activity = now;
        let mut data = alloc::vec![0u8; n];
        let off = start.wrapping_sub(self.buf_seq) as usize;
        let got = self.sndbuf.peek(off, &mut data);
        data.truncate(got);
        if !data.is_empty() {
            self.emit(ob, &self.header(ACK, start), &data);
            self.stats.probes += 1;
            self.stats.retx_segments += 1;
        }
    }

    /// Entra em recuperação rápida: reduz a janela (CUBIC) e marca o ponto
    /// em que ela termina.
    fn enter_recovery(&mut self, ob: &mut VecDeque<Out>) {
        self.in_recovery = true;
        self.recovery_point = self.snd_max;
        self.ssthresh = self.cubic.on_loss(self.cwnd, self.mss);
        self.cwnd = self.ssthresh;
        self.retx.clear();
        self.stats.fast_recoveries += 1;
        if !self.sack_ok {
            self.retransmit_one(ob);
            self.stats.retx_segments += 1;
        }
    }

    /// Reenvia o que está em `snd_una` (um segmento).
    fn retransmit_one(&mut self, ob: &mut VecDeque<Out>) {
        match self.state {
            State::SynSent | State::SynRcvd => self.send_syn(ob),
            _ => {
                let avail = self.unsent_from(self.snd_una);
                if avail > 0 {
                    let n = avail.min(self.mss);
                    let mut data = alloc::vec![0u8; n];
                    let off = self.snd_una.wrapping_sub(self.buf_seq) as usize;
                    self.sndbuf.peek(off, &mut data);
                    self.emit(ob, &self.header(ACK, self.snd_una), &data);
                } else if self.fin_seq == Some(self.snd_una) {
                    self.emit(ob, &self.header(FIN | ACK, self.snd_una), &[]);
                }
            }
        }
        self.rtt_probe = None;
    }

    /// Relógio: retransmissão, sonda de janela zero e fim do `TIME_WAIT`.
    pub(super) fn poll(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        self.now = now;
        if self.state == State::TimeWait && now >= self.time_wait_at {
            self.state = State::Closed;
            return;
        }
        if let Some(t) = self.rack_at
            && now >= t
        {
            self.rack_at = None;
            if !self.in_recovery && self.first_hole_lost() {
                self.enter_recovery(ob);
            }
            self.output(ob, now);
            self.rack_at = self.next_rack();
        }
        self.probe_tail(ob, now);
        self.keepalive_step(ob, now);
        let Some(at) = self.rtx_at else { return };
        if now < at {
            return;
        }
        let limit = if matches!(self.state, State::SynSent | State::SynRcvd) {
            MAX_SYN_RETRIES
        } else {
            MAX_RETRIES
        };
        self.rtx_count += 1;
        if self.rtx_count > limit {
            self.fail(Error::TimedOut);
            return;
        }
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.arm(now);
        if self.snd_una == self.snd_max && self.unsent_from(self.snd_nxt) > 0 {
            // Sonda de janela zero: um byte além da janela.
            let mut b = [0u8; 1];
            let off = self.snd_nxt.wrapping_sub(self.buf_seq) as usize;
            self.sndbuf.peek(off, &mut b);
            self.emit(ob, &self.header(ACK, self.snd_nxt), &b);
            self.snd_nxt = self.snd_nxt.wrapping_add(1);
            self.snd_max = self.snd_nxt;
            return;
        }
        // Perda por tempo: janela de um segmento e recomeça de `snd_una`. O
        // receptor pode ter desistido do que confirmou por SACK (RFC 2018),
        // então o placar se perde.
        self.ssthresh = self.cubic.on_timeout(self.cwnd, self.mss);
        self.cwnd = self.mss;
        self.dupacks = 0;
        self.in_recovery = false;
        self.retx.clear();
        self.sb.clear();
        self.sent_log.clear();
        self.stats.timeouts += 1;
        if matches!(self.state, State::SynSent | State::SynRcvd) {
            self.retransmit_one(ob);
        } else {
            self.snd_nxt = self.snd_una;
            self.rtt_probe = None;
            let before = self.snd_nxt;
            self.output(ob, now);
            if self.snd_nxt == before {
                // Nada de dados (só o FIN, ou janela fechada): reenvia à mão.
                self.retransmit_one(ob);
                if let Some(f) = self.fin_seq {
                    self.snd_nxt = f.wrapping_add(1);
                }
            }
        }
    }

    fn fail(&mut self, e: Error) {
        self.err = Some(e);
        self.state = State::Closed;
        self.rtx_at = None;
    }

    /// RFC 6298: atualiza SRTT, RTTVAR e RTO com uma amostra.
    fn rtt_sample(&mut self, r: u64) {
        if self.srtt == 0 {
            self.srtt = r;
            self.rttvar = r / 2;
        } else {
            let delta = self.srtt.abs_diff(r);
            self.rttvar = (3 * self.rttvar + delta) / 4;
            self.srtt = (7 * self.srtt + r) / 8;
        }
        self.rto = (self.srtt + (4 * self.rttvar).max(1_000_000)).clamp(MIN_RTO, MAX_RTO);
    }

    /// Cresce a janela: partida lenta até `ssthresh` e CUBIC depois. Só
    /// cresce se a conexão usou a janela (RFC 7661).
    fn grow_cwnd(&mut self, acked: usize, flight_before: usize, now: u64) {
        if self.in_recovery || flight_before < self.cwnd / 2 {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = (self.cwnd + acked.min(2 * self.mss)).min(self.ssthresh.max(self.mss));
        } else {
            self.cwnd = self
                .cubic
                .on_ack(self.cwnd, acked, self.mss, now, self.srtt);
        }
    }

    /// O ACK do segmento; `false` se é inaceitável (já respondido).
    fn on_ack(&mut self, seg: &Segment<'_>, ob: &mut VecDeque<Out>, now: u64) -> bool {
        let ack = seg.ack;
        if lt(self.snd_max, ack) {
            self.send_ack(ob);
            return false;
        }
        if self.sack_ok {
            for &(a, b) in seg.opts.blocks() {
                self.sb.insert(self.snd_una, self.snd_max, a, b);
            }
        }
        // Retransmissão que não foi confirmada em duas idas e voltas se perdeu:
        // sai da lista para a lacuna poder ser retransmitida de novo.
        let rtt = if self.srtt == 0 { self.rto } else { self.srtt };
        self.retx
            .retain(|&(_, _, t)| now < t.saturating_add(2 * rtt + rtt / 4));
        let flight_before = self.snd_nxt.wrapping_sub(self.snd_una) as usize;
        if lt(self.snd_una, ack) {
            let advanced = ack.wrapping_sub(self.snd_una) as usize;
            // O SYN e o FIN ocupam sequência mas não ocupam `sndbuf`.
            let data_acked = if lt(ack, self.buf_seq) {
                0
            } else {
                (ack.wrapping_sub(self.buf_seq) as usize).min(self.sndbuf.len())
            };
            self.sndbuf.consume(data_acked);
            self.buf_seq = self
                .buf_seq
                .wrapping_add(u32::try_from(data_acked).unwrap_or(0));
            self.snd_una = ack;
            if lt(self.snd_nxt, ack) {
                self.snd_nxt = ack;
            }
            self.dupacks = 0;
            if self.ts_ok
                && let Some((_, ecr)) = seg.opts.ts
                && ecr != 0
            {
                // RTTM (RFC 7323): amostra em toda confirmação nova.
                let ms = self.tsval().wrapping_sub(ecr);
                if ms < 60_000 {
                    self.rtt_sample(u64::from(ms.max(1)) * 1_000_000);
                }
                self.rtt_probe = None;
            } else if let Some((end, at)) = self.rtt_probe
                && le(end, ack)
            {
                self.rtt_sample(now.saturating_sub(at).max(1));
                self.rtt_probe = None;
            }
            self.activity = now;
            self.tlp_sent = false;
            self.sb.advance(ack);
            self.retx.retain(|&(_, e, _)| lt(ack, e));
            while self.sent_log.len() > 1 && le(self.sent_log[1].0, ack) {
                self.sent_log.pop_front();
            }
            if self.in_recovery {
                if le(self.recovery_point, ack) {
                    // Tudo o que estava em voo na perda foi confirmado.
                    self.in_recovery = false;
                    self.retx.clear();
                    self.cwnd = self.ssthresh;
                } else if !self.sack_ok {
                    // ACK parcial (NewReno): a próxima lacuna.
                    self.retransmit_one(ob);
                    self.stats.retx_segments += 1;
                }
            } else {
                self.grow_cwnd(advanced, flight_before, now);
            }
            self.rtx_count = 0;
            if self.snd_una == self.snd_max {
                self.rtx_at = None;
            } else {
                self.arm(now);
            }
        } else if ack == self.snd_una
            && seg.data.is_empty()
            && seg.flags & (SYN | FIN) == 0
            && self.snd_una != self.snd_max
            && u32::from(seg.window) << self.snd_shift == self.snd_wnd
        {
            self.dupacks = self.dupacks.saturating_add(1);
        }
        if !self.in_recovery
            && self.snd_una != self.snd_max
            && ((!self.sack_ok && self.dupacks >= 3) || (self.sack_ok && self.first_hole_lost()))
        {
            self.enter_recovery(ob);
        }
        self.rack_at = self.next_rack();
        if lt(self.snd_wl1, seg.seq) || (self.snd_wl1 == seg.seq && le(self.snd_wl2, ack)) {
            self.snd_wnd = if seg.flags & SYN != 0 {
                u32::from(seg.window)
            } else {
                u32::from(seg.window) << self.snd_shift
            };
            self.snd_wl1 = seg.seq;
            self.snd_wl2 = ack;
        }
        true
    }

    fn fin_acked(&self) -> bool {
        self.fin_seq
            .is_some_and(|f| le(f.wrapping_add(1), self.snd_una))
    }

    /// Janela de recepção em bytes (para a checagem de aceitação).
    fn rcv_wnd(&self) -> u32 {
        u32::from(self.window()) << self.rcv_shift
    }

    fn acceptable(&self, seg: &Segment<'_>) -> bool {
        let len = seg.seq_len();
        let wnd = self.rcv_wnd();
        let in_win = |s: u32| le(self.rcv_nxt, s) && lt(s, self.rcv_nxt.wrapping_add(wnd));
        match (len, wnd) {
            (0, 0) => seg.seq == self.rcv_nxt,
            (0, _) => in_win(seg.seq),
            (_, 0) => false,
            _ => in_win(seg.seq) || in_win(seg.seq.wrapping_add(len - 1)),
        }
    }

    /// Trata um segmento destinado a esta conexão.
    pub(super) fn segment(&mut self, seg: &Segment<'_>, ob: &mut VecDeque<Out>, now: u64) -> Event {
        self.now = now;
        self.last_rx = now;
        self.ka_sent = 0;
        if self.state == State::SynSent {
            return self.segment_syn_sent(seg, ob, now);
        }
        if !self.acceptable(seg) {
            if seg.flags & RST == 0 {
                self.send_ack(ob);
            }
            return Event::None;
        }
        // Timestamps (RFC 7323): sem a opção, o segmento não vale; com TSval
        // velho (PAWS), responde ACK e descarta.
        if self.ts_ok && seg.flags & (RST | SYN) == 0 {
            let Some((tsval, _)) = seg.opts.ts else {
                return Event::None;
            };
            if lt(tsval, self.ts_recent) {
                self.send_ack(ob);
                return Event::None;
            }
            // Só avança com segmento que não está à frente do que já recebemos.
            if le(seg.seq, self.rcv_nxt) {
                self.ts_recent = tsval;
            }
        }
        if seg.flags & RST != 0 {
            // RFC 5961: só um RST exatamente em `rcv_nxt` derruba a conexão;
            // dentro da janela, responde com um ACK de desafio.
            if seg.seq == self.rcv_nxt {
                self.fail(Error::Reset);
            } else {
                self.send_ack(ob);
            }
            return Event::None;
        }
        if seg.flags & SYN != 0 {
            // SYN numa conexão sincronizada: ACK de desafio (RFC 5961).
            if self.state != State::SynRcvd || seg.seq != self.irs {
                self.send_ack(ob);
            } else {
                // SYN repetido: reenvia o SYN-ACK.
                self.send_syn(ob);
            }
            return Event::None;
        }
        if seg.flags & ACK == 0 {
            return Event::None;
        }
        let mut event = Event::None;
        if self.state == State::SynRcvd {
            if le(self.snd_una.wrapping_add(1), seg.ack) && le(seg.ack, self.snd_max) {
                self.state = State::Established;
                event = Event::Established;
            } else {
                self.emit(
                    ob,
                    &Header {
                        sport: self.lport,
                        dport: self.rport,
                        seq: seg.ack,
                        ack: 0,
                        flags: RST,
                        window: 0,
                        opts: Opts::NONE,
                    },
                    &[],
                );
                return Event::None;
            }
        }
        if !self.on_ack(seg, ob, now) {
            return event;
        }
        if self.fin_acked() {
            match self.state {
                State::FinWait1 => self.state = State::FinWait2,
                State::Closing => self.enter_time_wait(now),
                State::LastAck => {
                    self.state = State::Closed;
                    return event;
                }
                _ => {}
            }
        }
        self.receive(seg, ob, now);
        self.output(ob, now);
        event
    }

    fn enter_time_wait(&mut self, now: u64) {
        self.state = State::TimeWait;
        self.time_wait_at = now.saturating_add(TIME_WAIT_NS);
        self.rtx_at = None;
    }

    fn segment_syn_sent(&mut self, seg: &Segment<'_>, ob: &mut VecDeque<Out>, now: u64) -> Event {
        let ack_ok = seg.flags & ACK != 0 && lt(self.iss, seg.ack) && le(seg.ack, self.snd_max);
        if seg.flags & ACK != 0 && !ack_ok {
            if seg.flags & RST == 0 {
                self.emit(
                    ob,
                    &Header {
                        sport: self.lport,
                        dport: self.rport,
                        seq: seg.ack,
                        ack: 0,
                        flags: RST,
                        window: 0,
                        opts: Opts::NONE,
                    },
                    &[],
                );
            }
            return Event::None;
        }
        if seg.flags & RST != 0 {
            if ack_ok {
                self.fail(Error::Refused);
            }
            return Event::None;
        }
        if seg.flags & SYN == 0 {
            return Event::None;
        }
        self.irs = seg.seq;
        self.rcv_nxt = seg.seq.wrapping_add(1);
        self.negotiate(&seg.opts);
        // A janela do SYN não é escalada.
        self.snd_wnd = u32::from(seg.window);
        self.snd_wl1 = seg.seq;
        self.snd_wl2 = seg.ack;
        if ack_ok {
            self.snd_una = seg.ack;
            self.rtx_at = None;
            self.rtx_count = 0;
            self.state = State::Established;
            self.send_ack(ob);
            self.output(ob, now);
            Event::Established
        } else {
            // Abertura simultânea.
            self.state = State::SynRcvd;
            self.send_syn(ob);
            Event::None
        }
    }

    /// Dados e FIN do segmento (já aceito).
    fn receive(&mut self, seg: &Segment<'_>, ob: &mut VecDeque<Out>, now: u64) {
        if !matches!(
            self.state,
            State::Established | State::FinWait1 | State::FinWait2
        ) {
            return;
        }
        let mut start = seg.seq;
        let mut data = seg.data;
        let fin_pos = seg.seq.wrapping_add(u32::try_from(data.len()).unwrap_or(0));
        if lt(start, self.rcv_nxt) {
            let cut = (self.rcv_nxt.wrapping_sub(start) as usize).min(data.len());
            data = &data[cut..];
            start = start.wrapping_add(u32::try_from(cut).unwrap_or(0));
        }
        let room = self
            .rcv_nxt
            .wrapping_add(self.rcv_wnd())
            .wrapping_sub(start) as usize;
        let mut fin = seg.flags & FIN != 0;
        if data.len() > room {
            data = &data[..room];
            fin = false;
        }
        if start == self.rcv_nxt {
            let n = self.rcvbuf.push(data);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(u32::try_from(n).unwrap_or(0));
            self.drain_ooo();
        } else if !data.is_empty() {
            let dup = self.ooo.iter().any(|(s, d)| {
                le(*s, start)
                    && le(
                        start.wrapping_add(u32::try_from(data.len()).unwrap_or(0)),
                        s.wrapping_add(u32::try_from(d.len()).unwrap_or(0)),
                    )
            });
            if !dup && self.ooo.len() < MAX_OOO {
                self.ooo.push((start, data.to_vec()));
            }
            self.last_ooo = Some(start);
        }
        if fin {
            self.fin_at = Some(fin_pos);
        }
        if self.fin_at == Some(self.rcv_nxt) && !self.fin_rcvd {
            self.fin_rcvd = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
            match self.state {
                State::Established => self.state = State::CloseWait,
                State::FinWait1 => self.state = State::Closing,
                State::FinWait2 => self.enter_time_wait(now),
                _ => {}
            }
            if self.state == State::Closing && self.fin_acked() {
                self.enter_time_wait(now);
            }
        }
        if !seg.data.is_empty() || seg.flags & FIN != 0 {
            self.send_ack(ob);
        }
    }

    /// Junta os segmentos fora de ordem que agora são contíguos.
    fn drain_ooo(&mut self) {
        while let Some(i) = self.ooo.iter().position(|(s, _)| le(*s, self.rcv_nxt)) {
            let (s, d) = self.ooo.swap_remove(i);
            let cut = (self.rcv_nxt.wrapping_sub(s) as usize).min(d.len());
            let n = self.rcvbuf.push(&d[cut..]);
            self.rcv_nxt = self.rcv_nxt.wrapping_add(u32::try_from(n).unwrap_or(0));
        }
    }

    // --- Operações do dono ---

    pub(super) fn write(
        &mut self,
        data: &[u8],
        ob: &mut VecDeque<Out>,
        now: u64,
    ) -> Result<usize, Error> {
        if let Some(e) = self.err {
            return Err(e);
        }
        match self.state {
            State::SynSent | State::SynRcvd | State::Established | State::CloseWait => {}
            _ => return Err(Error::Closed),
        }
        if self.fin_queued {
            return Err(Error::Closed);
        }
        let n = self.sndbuf.push(data);
        self.output(ob, now);
        Ok(n)
    }

    pub(super) fn read(
        &mut self,
        out: &mut [u8],
        ob: &mut VecDeque<Out>,
        now: u64,
    ) -> Result<Option<usize>, Error> {
        self.now = now;
        if self.rcvbuf.is_empty() {
            if let Some(e) = self.err {
                return Err(e);
            }
            return Ok(if self.fin_rcvd || self.state == State::Closed {
                Some(0)
            } else {
                None
            });
        }
        let before = self.rcv_wnd();
        let n = self.rcvbuf.pop(out);
        // Aviso de janela quando a leitura abre espaço relevante.
        let opened = self.rcv_wnd() - before;
        if opened as usize >= self.mss.min(self.limit / 2) && self.state != State::Closed {
            self.send_ack(ob);
        }
        Ok(Some(n))
    }

    pub(super) fn close(&mut self, ob: &mut VecDeque<Out>, now: u64) {
        self.user_closed = true;
        match self.state {
            State::SynSent => self.state = State::Closed,
            State::SynRcvd | State::Established | State::CloseWait => {
                self.fin_queued = true;
                self.output(ob, now);
            }
            _ => {}
        }
    }

    pub(super) fn abort(&mut self, ob: &mut VecDeque<Out>) {
        if matches!(
            self.state,
            State::SynRcvd
                | State::Established
                | State::FinWait1
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
        ) {
            self.emit(ob, &self.header(RST | ACK, self.snd_nxt), &[]);
        }
        self.state = State::Closed;
    }

    /// Espaço livre para escrita.
    pub(super) fn send_space(&self) -> usize {
        self.sndbuf.free()
    }

    /// Bytes prontos para ler.
    pub(super) fn recv_ready(&self) -> usize {
        self.rcvbuf.len()
    }

    /// Bytes escritos que o outro lado ainda não confirmou.
    pub(super) fn send_pending(&self) -> usize {
        self.sndbuf.len()
    }
}
