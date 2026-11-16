//! TCP (RFC 9293): tabela de conexões e escutas, abertura e fechamento,
//! retransmissão por RTO, janela de recepção, ISN pela RFC 6528 e MSS. A
//! pilha não faz E/S: os segmentos a mandar ficam numa fila de saída
//! ([`Tcp::pop_out`]) e o chamador os leva ao IP. Tudo recebe o tempo como
//! parâmetro, então os testes simulam perda e reordenação no host.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::arp::Ip4;
use crate::ports::Ephemeral;

pub mod buf;
mod conn;
pub mod wire;

#[cfg(test)]
mod tests;

pub use conn::{BUF_BYTES, State};
use conn::{Conn, Event};
use wire::{ACK, RST, SYN};

/// MSS que anunciamos (MTU 1500 menos os cabeçalhos de IP e TCP).
pub const MSS: usize = 1460;
/// Conexões ao mesmo tempo.
pub const MAX_CONNS: usize = 32;
/// Escutas ao mesmo tempo.
pub const MAX_LISTENERS: usize = 8;
/// Segmentos fora de ordem guardados por conexão.
pub const MAX_OOO: usize = 8;
/// Memória que os buffers de todas as conexões podem reservar (a cota do
/// `netd` paga o heap; passar disso derrubaria o processo).
pub const MEM_BUDGET: usize = 2_560 * 1024;
/// Menor buffer que vale a pena dar a uma conexão.
const MIN_BUF: usize = 16 * 1024;
/// Intervalo mínimo entre RST por segmento sem dono (ns).
const RST_NS: u64 = 5_000_000;

/// Identificador de conexão.
pub type ConnId = usize;
/// Identificador de escuta.
pub type ListenId = usize;

/// Erros das operações e da conexão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Sem vaga na tabela ou sem porta livre.
    NoSpace,
    /// A porta já tem escuta.
    InUse,
    /// Identificador que não existe.
    NoSuchId,
    /// A conexão não aceita mais esta operação.
    Closed,
    /// O outro lado reiniciou a conexão.
    Reset,
    /// O outro lado recusou a abertura.
    Refused,
    /// Sem resposta depois das retransmissões.
    TimedOut,
}

/// Um segmento a levar ao IP.
#[derive(Debug)]
pub struct Out {
    /// Destino.
    pub dst: Ip4,
    /// O segmento TCP inteiro.
    pub data: Vec<u8>,
}

/// Resultado de uma leitura.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// Bytes lidos.
    Data(usize),
    /// O outro lado fechou e tudo foi lido.
    Eof,
    /// Nada agora.
    WouldBlock,
}

struct Listener {
    port: u16,
    backlog: usize,
    queue: VecDeque<ConnId>,
}

/// A tabela de conexões.
pub struct Tcp {
    ip: Ip4,
    conns: Vec<Option<Conn>>,
    listeners: Vec<Option<Listener>>,
    outbox: VecDeque<Out>,
    secret: [u8; 16],
    ports: Ephemeral,
    rst_at: u64,
    /// Reserva de memória que ainda cabe em buffers.
    budget: usize,
    /// Último relógio visto, para o que não recebe `now` (a leitura).
    now: u64,
    /// Soma ao ISN nos testes, para exercitar a volta do número de sequência.
    #[cfg(test)]
    isn_bias: u32,
}

impl core::fmt::Debug for Tcp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tcp")
            .field("conexoes", &self.conns.iter().flatten().count())
            .finish_non_exhaustive()
    }
}

impl Tcp {
    /// Tabela vazia. `secret` (do DRBG do kernel) mistura o ISN (RFC 6528).
    #[must_use]
    pub const fn new(secret: [u8; 16]) -> Self {
        Self {
            ip: [0; 4],
            conns: Vec::new(),
            listeners: Vec::new(),
            outbox: VecDeque::new(),
            secret,
            ports: Ephemeral::new(),
            rst_at: 0,
            budget: MEM_BUDGET,
            now: 0,
            #[cfg(test)]
            isn_bias: 0,
        }
    }

    /// Troca o segredo do ISN (o `netd` o tira do DRBG do kernel ao subir).
    pub const fn set_secret(&mut self, secret: [u8; 16]) {
        self.secret = secret;
    }

    /// O IP local (zero antes do DHCP).
    pub fn set_ip(&mut self, ip: Ip4) {
        self.ip = ip;
    }

    /// ISN = relógio de 4 µs + F(tupla, segredo) (RFC 6528).
    fn isn(&self, rip: Ip4, rport: u16, lport: u16, now: u64) -> u32 {
        let mut m = [0u8; 16 + 4 + 4 + 2 + 2];
        m[..16].copy_from_slice(&self.secret);
        m[16..20].copy_from_slice(&self.ip);
        m[20..24].copy_from_slice(&rip);
        m[24..26].copy_from_slice(&lport.to_be_bytes());
        m[26..28].copy_from_slice(&rport.to_be_bytes());
        let h = optcrypt::blake3::hash(&m);
        let clock = u32::try_from((now / 4_000) & 0xffff_ffff).unwrap_or(0);
        #[cfg(test)]
        let clock = clock.wrapping_add(self.isn_bias);
        u32::from_le_bytes([h[0], h[1], h[2], h[3]]).wrapping_add(clock)
    }

    /// Reserva a memória dos dois buffers de uma conexão nova e devolve o
    /// limite de cada um: o máximo enquanto a cota folga, menos com muitas
    /// conexões; `None` quando nem o mínimo cabe.
    fn reserve(&mut self) -> Option<usize> {
        let limit = (self.budget / 4).clamp(MIN_BUF, BUF_BYTES);
        if self.budget < 2 * limit {
            return None;
        }
        self.budget -= 2 * limit;
        Some(limit)
    }

    /// Troca o orçamento de memória dos buffers (o `netd` o ajusta à cota).
    pub const fn set_budget(&mut self, bytes: usize) {
        self.budget = bytes;
    }

    fn slot(&mut self) -> Option<usize> {
        if let Some(i) = self.conns.iter().position(Option::is_none) {
            return Some(i);
        }
        if self.conns.len() < MAX_CONNS {
            self.conns.push(None);
            return Some(self.conns.len() - 1);
        }
        None
    }

    // --- Abertura ---

    /// Abre uma conexão para `dst:dport` (`random` escolhe a porta efêmera).
    ///
    /// # Errors
    ///
    /// [`Error::NoSpace`].
    pub fn connect(
        &mut self,
        dst: Ip4,
        dport: u16,
        now: u64,
        random: u32,
    ) -> Result<ConnId, Error> {
        self.now = now;
        let id = self.slot().ok_or(Error::NoSpace)?;
        let lport = self.ports.alloc(random).ok_or(Error::NoSpace)?;
        let iss = self.isn(dst, dport, lport, now);
        let Some(limit) = self.reserve() else {
            self.ports.release(lport);
            return Err(Error::NoSpace);
        };
        let mut c = Conn::new(
            State::SynSent,
            (self.ip, lport, dst, dport),
            iss,
            0,
            0,
            true,
            limit,
        );
        c.start(&mut self.outbox, now);
        self.conns[id] = Some(c);
        Ok(id)
    }

    /// Escuta em `port`, com até `backlog` conexões esperando `accept`.
    ///
    /// # Errors
    ///
    /// [`Error::InUse`] ou [`Error::NoSpace`].
    pub fn listen(&mut self, port: u16, backlog: usize) -> Result<ListenId, Error> {
        if self.listeners.iter().flatten().any(|l| l.port == port) {
            return Err(Error::InUse);
        }
        let l = Listener {
            port,
            backlog: backlog.max(1),
            queue: VecDeque::new(),
        };
        if let Some(i) = self.listeners.iter().position(Option::is_none) {
            self.listeners[i] = Some(l);
            return Ok(i);
        }
        if self.listeners.len() >= MAX_LISTENERS {
            return Err(Error::NoSpace);
        }
        self.listeners.push(Some(l));
        Ok(self.listeners.len() - 1)
    }

    /// Para de escutar e reinicia as conexões que ninguém aceitou.
    pub fn unlisten(&mut self, id: ListenId) {
        if self.listeners.get(id).is_some_and(Option::is_some) {
            self.listeners[id] = None;
            for i in 0..self.conns.len() {
                let orphan = self.conns[i]
                    .as_ref()
                    .is_some_and(|c| c.listener == Some(id));
                if orphan {
                    self.abort(i);
                }
            }
        }
    }

    /// Próxima conexão aberta de uma escuta.
    pub fn accept(&mut self, id: ListenId) -> Option<ConnId> {
        self.listeners.get_mut(id)?.as_mut()?.queue.pop_front()
    }

    // --- Operações da conexão ---

    /// Estado da conexão.
    #[must_use]
    pub fn state(&self, id: ConnId) -> Option<State> {
        self.conns.get(id)?.as_ref().map(Conn::state)
    }

    /// Por que a conexão acabou, se acabou por erro.
    #[must_use]
    pub fn error(&self, id: ConnId) -> Option<Error> {
        self.conns.get(id)?.as_ref()?.err
    }

    /// Escreve até o que couber no buffer de envio e devolve quantos bytes
    /// entraram.
    ///
    /// # Errors
    ///
    /// O erro da conexão, [`Error::Closed`] ou [`Error::NoSuchId`].
    pub fn write(&mut self, id: ConnId, data: &[u8], now: u64) -> Result<usize, Error> {
        let (conns, ob) = (&mut self.conns, &mut self.outbox);
        conns
            .get_mut(id)
            .and_then(Option::as_mut)
            .ok_or(Error::NoSuchId)?
            .write(data, ob, now)
    }

    /// Lê bytes recebidos em ordem.
    ///
    /// # Errors
    ///
    /// O erro da conexão (depois de lidos os bytes que sobraram) ou
    /// [`Error::NoSuchId`].
    pub fn read(&mut self, id: ConnId, out: &mut [u8]) -> Result<Read, Error> {
        let now = self.now;
        let (conns, ob) = (&mut self.conns, &mut self.outbox);
        let c = conns
            .get_mut(id)
            .and_then(Option::as_mut)
            .ok_or(Error::NoSuchId)?;
        Ok(match c.read(out, ob, now)? {
            Some(0) if !out.is_empty() => Read::Eof,
            Some(n) => Read::Data(n),
            None => Read::WouldBlock,
        })
    }

    /// Espaço livre no buffer de envio.
    #[must_use]
    pub fn send_space(&self, id: ConnId) -> usize {
        self.conns
            .get(id)
            .and_then(Option::as_ref)
            .map_or(0, Conn::send_space)
    }

    /// Bytes recebidos esperando leitura.
    #[must_use]
    pub fn recv_ready(&self, id: ConnId) -> usize {
        self.conns
            .get(id)
            .and_then(Option::as_ref)
            .map_or(0, Conn::recv_ready)
    }

    /// Bytes escritos ainda sem confirmação do outro lado.
    #[must_use]
    pub fn send_pending(&self, id: ConnId) -> usize {
        self.conns
            .get(id)
            .and_then(Option::as_ref)
            .map_or(0, Conn::send_pending)
    }

    /// Fecha o lado de envio (FIN depois dos dados). A conexão sai da tabela
    /// quando termina; até lá os dados do outro lado ainda podem ser lidos.
    pub fn close(&mut self, id: ConnId, now: u64) {
        let (conns, ob) = (&mut self.conns, &mut self.outbox);
        if let Some(c) = conns.get_mut(id).and_then(Option::as_mut) {
            c.close(ob, now);
        }
        self.reap(id);
    }

    /// Reinicia a conexão (RST) e a tira da tabela.
    pub fn abort(&mut self, id: ConnId) {
        let (conns, ob) = (&mut self.conns, &mut self.outbox);
        if let Some(c) = conns.get_mut(id).and_then(Option::as_mut) {
            c.abort(ob);
            c.user_closed = true;
        }
        self.reap(id);
    }

    /// Tira da tabela a conexão que acabou e que o dono já fechou.
    fn reap(&mut self, id: ConnId) {
        let done = self
            .conns
            .get(id)
            .and_then(Option::as_ref)
            .is_some_and(|c| c.state == State::Closed && c.user_closed);
        if done && let Some(c) = self.conns[id].take() {
            self.budget += 2 * c.limit;
            if c.ephemeral {
                self.ports.release(c.lport);
            }
            if let Some(l) = c.listener
                && let Some(Some(l)) = self.listeners.get_mut(l)
            {
                l.queue.retain(|q| *q != id);
            }
        }
    }

    // --- Entrada e relógio ---

    /// Tira o próximo segmento a mandar.
    pub fn pop_out(&mut self) -> Option<Out> {
        self.outbox.pop_front()
    }

    /// Devolve à frente da fila um segmento que o IP não pôde mandar agora.
    pub fn push_front_out(&mut self, o: Out) {
        self.outbox.push_front(o);
    }

    /// Relógio: retransmissões, sondas e `TIME_WAIT`.
    pub fn poll(&mut self, now: u64) {
        self.now = now;
        for id in 0..self.conns.len() {
            if let Some(c) = self.conns[id].as_mut() {
                c.poll(&mut self.outbox, now);
            }
            self.reap(id);
        }
    }

    /// Trata um segmento recebido de `src` para `dst`.
    pub fn input(&mut self, src: Ip4, dst: Ip4, bytes: &[u8], now: u64) {
        self.now = now;
        let Some(seg) = wire::parse(src, dst, bytes) else {
            return;
        };
        let found = self.conns.iter().position(|c| {
            c.as_ref().is_some_and(|c| {
                c.state != State::Closed
                    && c.lip == dst
                    && c.lport == seg.dport
                    && c.rip == src
                    && c.rport == seg.sport
            })
        });
        if let Some(id) = found {
            let ev = self.conns[id]
                .as_mut()
                .map_or(Event::None, |c| c.segment(&seg, &mut self.outbox, now));
            if ev == Event::Established {
                let owner = self.conns[id].as_ref().and_then(|c| c.listener);
                if let Some(Some(l)) = owner.and_then(|l| self.listeners.get_mut(l)) {
                    l.queue.push_back(id);
                }
            }
            self.reap(id);
            return;
        }
        if seg.flags & RST != 0 {
            return;
        }
        let listener = self
            .listeners
            .iter()
            .position(|l| l.as_ref().is_some_and(|l| l.port == seg.dport));
        if let Some(l) = listener
            && seg.flags & (SYN | ACK) == SYN
            && self.accept_syn(l, src, dst, &seg, now)
        {
            return;
        }
        self.reset_for(src, dst, &seg, now);
    }

    /// SYN para uma escuta: cria a conexão em `SYN_RCVD`. `false` se a fila
    /// (conexões abertas esperando mais as meio abertas) estourou.
    fn accept_syn(
        &mut self,
        l: ListenId,
        src: Ip4,
        dst: Ip4,
        seg: &wire::Segment<'_>,
        now: u64,
    ) -> bool {
        let Some(lis) = self.listeners[l].as_ref() else {
            return false;
        };
        let half = self
            .conns
            .iter()
            .flatten()
            .filter(|c| c.listener == Some(l) && c.state == State::SynRcvd)
            .count();
        if lis.queue.len() + half >= lis.backlog {
            return true;
        }
        let Some(id) = self.slot() else { return true };
        let iss = self.isn(src, seg.sport, seg.dport, now);
        let Some(limit) = self.reserve() else {
            return true;
        };
        let mut c = Conn::new(
            State::SynRcvd,
            (dst, seg.dport, src, seg.sport),
            iss,
            seg.seq,
            seg.window,
            false,
            limit,
        );
        c.negotiate(&seg.opts);
        c.listener = Some(l);
        c.start(&mut self.outbox, now);
        self.conns[id] = Some(c);
        true
    }

    /// RST para um segmento que não tem dono (RFC 9293, 3.10.7.1), com limite
    /// de taxa para não virar amplificador.
    fn reset_for(&mut self, src: Ip4, dst: Ip4, seg: &wire::Segment<'_>, now: u64) {
        if now < self.rst_at {
            return;
        }
        self.rst_at = now.saturating_add(RST_NS);
        let h = if seg.flags & ACK != 0 {
            wire::Header {
                sport: seg.dport,
                dport: seg.sport,
                seq: seg.ack,
                ack: 0,
                flags: RST,
                window: 0,
                opts: wire::Opts::NONE,
            }
        } else {
            wire::Header {
                sport: seg.dport,
                dport: seg.sport,
                seq: 0,
                ack: seg.seq.wrapping_add(seg.seq_len()),
                flags: RST | ACK,
                window: 0,
                opts: wire::Opts::NONE,
            }
        };
        let mut out = [0u8; wire::HEADER_LEN];
        if let Some(n) = wire::build(dst, src, &h, &[], &mut out) {
            self.outbox.push_back(Out {
                dst: src,
                data: out[..n].to_vec(),
            });
        }
    }
}
