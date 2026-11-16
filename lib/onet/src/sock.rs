//! Sockets do `netd` (ADR 0068, itens 2 a 4 e 8): a tabela que liga os
//! anéis de cada cliente ao UDP e ao TCP da pilha, com a política de rede
//! (`NetAccess`, [`crate::policy`]) checada em cada `connect`.
//!
//! Tudo é puro, como o resto do `onet`: os anéis entram pelo trait [`Rings`]
//! (o `netd` os liga aos anéis SPSC do `ostd`, os testes usam anéis de
//! mentira) e o tempo entra como parâmetro.
//!
//! **Formato dos registros dos anéis.** `tx` (cliente → `netd`): registros
//! de tipo [`KIND_DATA`], um por datagrama UDP ou um pedaço do fluxo TCP.
//! `rx` (`netd` → cliente): [`KIND_DATA`] (idem) e [`KIND_EVENT`], com dois
//! bytes: o código (`EV_*`) e um argumento. O anel não é acoplado à janela do
//! TCP: o `netd` só lê do TCP o que cabe no `rx`, então a janela anunciada é
//! o espaço que sobra (item 4).

use alloc::vec::Vec;

use crate::arp::Ip4;
use crate::policy::{Policy, Proto};
use crate::ports::Ephemeral;
use crate::stack::{Link, SendError, Stack, Upper};
use crate::tcp::{ConnId, Error as TcpError, Read, State};

/// Sockets abertos ao mesmo tempo, de todos os clientes.
pub const MAX_SOCKETS: usize = 16;
/// Maior carga de um registro (a do anel SPSC, 4096 menos o cabeçalho).
pub const MAX_RECORD: usize = 4088;
/// Maior registro de dados que o `netd` grava no `rx` (um MSS): registros
/// pequenos cabem melhor num anel quase cheio.
pub const MAX_RX_RECORD: usize = 1460;
/// Maior datagrama UDP (MTU menos IPv4 e UDP).
pub const MAX_DATAGRAM: usize = 1472;

/// Registro de dados.
pub const KIND_DATA: u16 = 1;
/// Registro de evento no `rx`.
pub const KIND_EVENT: u16 = 2;
/// Evento: a conexão TCP abriu.
pub const EV_CONNECTED: u8 = 1;
/// Evento: o outro lado fechou e tudo foi lido (fim do fluxo).
pub const EV_PEER_CLOSED: u8 = 2;
/// Evento: a conexão acabou por erro; o argumento é um `EV_ERR_*`.
pub const EV_ERROR: u8 = 3;
/// Argumento de [`EV_ERROR`]: o outro lado recusou.
pub const EV_ERR_REFUSED: u8 = 1;
/// Argumento de [`EV_ERROR`]: o outro lado reiniciou a conexão.
pub const EV_ERR_RESET: u8 = 2;
/// Argumento de [`EV_ERROR`]: sem resposta.
pub const EV_ERR_TIMEOUT: u8 = 3;
/// Argumento de [`EV_ERROR`]: o anel de transmissão está corrompido.
pub const EV_ERR_RING: u8 = 4;

/// Por que uma operação de socket não vale (o `SocketError` do contrato).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A política do cliente não permite (ou não há política).
    Denied,
    /// Sockets demais abertos (do cliente ou da máquina).
    Limit,
    /// Sem memória para o socket.
    Quota,
    /// Pedido fora do formato, socket que não existe ou de outro cliente.
    BadRequest,
    /// Sem rota ou sem porta efêmera livre.
    NoRoute,
    /// Operação fora de hora (`connect` num socket já conectado).
    Busy,
}

/// O anel de transmissão corrompeu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingError;

/// Os dois anéis de um socket.
pub trait Rings {
    /// Próximo registro do `tx`: copia a carga para `buf` e devolve
    /// `(tipo, bytes)`; `None` se está vazio.
    ///
    /// # Errors
    ///
    /// [`RingError`] se o anel está corrompido.
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, RingError>;
    /// Cabe agora um registro de `len` bytes no `rx`.
    fn fits(&mut self, len: usize) -> bool;
    /// Grava um registro no `rx`; `false` se não coube.
    fn push(&mut self, kind: u16, data: &[u8]) -> bool;
}

/// Para onde vão as decisões de política (o `logd`, pelo log do kernel;
/// ADR 0068, item 8): cliente, destino e motivo, nunca os dados.
pub trait Audit {
    /// Uma decisão sobre `connect` a `ip:port`.
    fn decision(&mut self, client: u32, proto: Proto, ip: Ip4, port: u16, ok: bool, why: &str);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    /// Aberto, sem destino.
    Idle,
    /// SYN enviado.
    Connecting,
    /// TCP aberto ou UDP com destino.
    Connected,
    /// Acabou (erro ou fechado pelo outro lado e avisado): só `close`.
    Dead,
}

struct Sock<R> {
    owner: u32,
    proto: Proto,
    rings: R,
    st: St,
    conn: Option<ConnId>,
    lport: u16,
    peer: (Ip4, u16),
    /// Já avisou o fim do fluxo.
    eof_sent: bool,
    /// Datagrama que não saiu por falta de MAC ou de vaga: tenta de novo.
    held: Option<Vec<u8>>,
}

struct Client {
    id: u32,
    generation: u32,
    policy: Policy,
    open: u16,
}

/// A tabela de sockets.
pub struct Table<R: Rings> {
    socks: Vec<Option<Sock<R>>>,
    clients: Vec<Client>,
    udp_ports: Ephemeral,
}

const fn split(badge: u64) -> (u32, u32) {
    ((badge & 0xFFFF_FFFF) as u32, (badge >> 32) as u32)
}

impl<R: Rings> Default for Table<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Rings> Table<R> {
    /// Tabela vazia.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            socks: Vec::new(),
            clients: Vec::new(),
            udp_ports: Ephemeral::new(),
        }
    }

    /// O cliente do `badge` (serviço e geração) tem política registrada.
    #[must_use]
    pub fn knows(&self, badge: u64) -> bool {
        let (id, generation) = split(badge);
        self.clients
            .iter()
            .any(|c| c.id == id && c.generation == generation)
    }

    /// Registra a política do cliente do `badge`. Uma geração nova do mesmo
    /// serviço (o cliente reiniciou) fecha o que a anterior deixou aberto
    /// (ADR 0068, item 6). A política vazia ([`Policy::DENY`]) é "sem
    /// `NetAccess`".
    pub fn set_policy(&mut self, stack: &mut Stack, badge: u64, policy: Policy, now: u64) {
        let (id, generation) = split(badge);
        self.close_owner(stack, id, now);
        self.clients.retain(|c| c.id != id);
        self.clients.push(Client {
            id,
            generation,
            policy,
            open: 0,
        });
    }

    fn client_mut(&mut self, badge: u64) -> Option<&mut Client> {
        let (id, generation) = split(badge);
        self.clients
            .iter_mut()
            .find(|c| c.id == id && c.generation == generation)
    }

    fn sock_mut(&mut self, badge: u64, sock: u32) -> Result<&mut Sock<R>, Error> {
        let (id, _) = split(badge);
        self.socks
            .get_mut(usize::try_from(sock).map_err(|_| Error::BadRequest)?)
            .and_then(Option::as_mut)
            .filter(|s| s.owner == id)
            .ok_or(Error::BadRequest)
    }

    /// Abre um socket de `proto`. `make` cria os anéis dado o índice da vaga
    /// (o `netd` deriva dele onde mapeá-los) e roda só depois das conferências
    /// de política e de limite. Devolve o número do socket (o índice).
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] sem política (ou sem `conns`), [`Error::Limit`] e o
    /// erro de `make`.
    pub fn open<F: FnOnce(usize) -> Result<R, Error>>(
        &mut self,
        badge: u64,
        proto: Proto,
        make: F,
    ) -> Result<u32, Error> {
        let (id, _) = split(badge);
        let c = self.client_mut(badge).ok_or(Error::Denied)?;
        if c.policy.max_sockets() == 0 {
            return Err(Error::Denied);
        }
        if c.open >= c.policy.max_sockets() {
            return Err(Error::Limit);
        }
        let slot = match self.socks.iter().position(Option::is_none) {
            Some(i) => i,
            None if self.socks.len() < MAX_SOCKETS => {
                self.socks.push(None);
                self.socks.len() - 1
            }
            None => return Err(Error::Limit),
        };
        let rings = make(slot)?;
        if let Some(c) = self.client_mut(badge) {
            c.open += 1;
        }
        self.socks[slot] = Some(Sock {
            owner: id,
            proto,
            rings,
            st: St::Idle,
            conn: None,
            lport: 0,
            peer: ([0; 4], 0),
            eof_sent: false,
            held: None,
        });
        u32::try_from(slot).map_err(|_| Error::Limit)
    }

    /// Os anéis do socket `sock` do cliente `badge`.
    ///
    /// # Errors
    ///
    /// [`Error::BadRequest`].
    pub fn rings_mut(&mut self, badge: u64, sock: u32) -> Result<&mut R, Error> {
        self.sock_mut(badge, sock).map(|s| &mut s.rings)
    }

    /// Há socket aberto (o `netd` olha os anéis com mais frequência).
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.socks.iter().any(Option::is_some)
    }

    /// Define o destino: UDP guarda o par, TCP começa a conexão (o evento
    /// [`EV_CONNECTED`] avisa a abertura). A política decide por endereço e
    /// porta; cada decisão vai para a auditoria.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`], [`Error::BadRequest`], [`Error::Busy`] e
    /// [`Error::NoRoute`].
    #[allow(clippy::too_many_arguments, reason = "o que um connect precisa")]
    pub fn connect<A: Audit>(
        &mut self,
        stack: &mut Stack,
        audit: &mut A,
        badge: u64,
        sock: u32,
        ip: Ip4,
        port: u16,
        now: u64,
        random: u32,
    ) -> Result<(), Error> {
        let (id, _) = split(badge);
        let policy = self
            .client_mut(badge)
            .map(|c| c.policy)
            .ok_or(Error::Denied)?;
        let s = self.sock_mut(badge, sock)?;
        let proto = s.proto;
        if s.st != St::Idle {
            return Err(Error::Busy);
        }
        // Grupo, difusão e "este endereço" nunca são destino de um cliente.
        if port == 0 || ip == [0; 4] || ip[0] >= 224 {
            audit.decision(id, proto, ip, port, false, "destino inválido");
            return Err(Error::BadRequest);
        }
        if !policy.allows_ip(proto, ip, port) {
            audit.decision(id, proto, ip, port, false, "fora da política");
            return Err(Error::Denied);
        }
        audit.decision(id, proto, ip, port, true, "política");
        match proto {
            Proto::Tcp => {
                let conn = stack
                    .tcp
                    .connect(ip, port, now, random)
                    .map_err(|_| Error::NoRoute)?;
                let s = self.sock_mut(badge, sock)?;
                s.conn = Some(conn);
                s.st = St::Connecting;
            }
            Proto::Udp => {
                let lport = self.udp_ports.alloc(random).ok_or(Error::NoRoute)?;
                let s = self.sock_mut(badge, sock)?;
                s.lport = lport;
                s.st = St::Connected;
            }
        }
        let s = self.sock_mut(badge, sock)?;
        s.peer = (ip, port);
        Ok(())
    }

    /// Fecha o socket e devolve os anéis (que o chamador solta).
    ///
    /// # Errors
    ///
    /// [`Error::BadRequest`].
    pub fn close(
        &mut self,
        stack: &mut Stack,
        badge: u64,
        sock: u32,
        now: u64,
    ) -> Result<R, Error> {
        self.sock_mut(badge, sock)?;
        let slot = usize::try_from(sock).map_err(|_| Error::BadRequest)?;
        let s = self.socks[slot].take().ok_or(Error::BadRequest)?;
        Ok(self.release(stack, s, now))
    }

    /// Solta o que o socket prende na pilha e no cliente.
    fn release(&mut self, stack: &mut Stack, s: Sock<R>, now: u64) -> R {
        if let Some(c) = self.clients.iter_mut().find(|c| c.id == s.owner) {
            c.open = c.open.saturating_sub(1);
        }
        match (s.proto, s.conn) {
            (Proto::Tcp, Some(conn)) => match stack.tcp.state(conn) {
                // Dados que o cliente não leu ficam perdidos: RST.
                Some(State::Established | State::CloseWait) if stack.tcp.recv_ready(conn) > 0 => {
                    stack.tcp.abort(conn);
                }
                Some(_) => stack.tcp.close(conn, now),
                None => {}
            },
            (Proto::Udp, _) if s.lport != 0 => self.udp_ports.release(s.lport),
            _ => {}
        }
        s.rings
    }

    /// Fecha tudo o que o serviço `id` deixou aberto.
    fn close_owner(&mut self, stack: &mut Stack, id: u32, now: u64) {
        for i in 0..self.socks.len() {
            if self.socks[i].as_ref().is_some_and(|s| s.owner == id)
                && let Some(s) = self.socks[i].take()
            {
                drop(self.release(stack, s, now));
            }
        }
    }

    /// Um passo dos sockets: leva os registros do `tx` ao UDP e ao TCP e o
    /// que chegou ao `rx`. Chamado a cada volta do laço do `netd`.
    pub fn pump<L: Link>(&mut self, stack: &mut Stack, link: &mut L, now: u64) {
        for i in 0..self.socks.len() {
            let Some(mut s) = self.socks[i].take() else {
                continue;
            };
            match s.proto {
                Proto::Tcp => pump_tcp(&mut s, stack, now),
                Proto::Udp => pump_udp(&mut s, stack, link, now),
            }
            self.socks[i] = Some(s);
        }
    }
}

fn event<R: Rings>(s: &mut Sock<R>, code: u8, arg: u8) {
    let _ = s.rings.push(KIND_EVENT, &[code, arg]);
}

const fn tcp_error(e: Option<TcpError>) -> u8 {
    match e {
        Some(TcpError::Refused) => EV_ERR_REFUSED,
        Some(TcpError::TimedOut) => EV_ERR_TIMEOUT,
        _ => EV_ERR_RESET,
    }
}

fn pump_tcp<R: Rings>(s: &mut Sock<R>, stack: &mut Stack, now: u64) {
    let Some(conn) = s.conn else { return };
    match s.st {
        St::Connecting => match stack.tcp.state(conn) {
            Some(State::Established | State::CloseWait) => {
                s.st = St::Connected;
                event(s, EV_CONNECTED, 0);
            }
            Some(State::SynSent | State::SynRcvd) => {}
            _ => {
                let why = tcp_error(stack.tcp.error(conn));
                stack.tcp.abort(conn);
                s.conn = None;
                s.st = St::Dead;
                event(s, EV_ERROR, why);
            }
        },
        St::Connected => {
            let mut buf = [0u8; MAX_RECORD];
            // Cliente → rede: só tira do anel o que cabe de uma vez no
            // buffer de envio; o resto espera no anel (contrapressão).
            while stack.tcp.send_space(conn) >= MAX_RECORD {
                match s.rings.pop(&mut buf) {
                    Ok(Some((KIND_DATA, n))) => {
                        let _ = stack.tcp.write(conn, &buf[..n], now);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(RingError) => {
                        stack.tcp.abort(conn);
                        s.conn = None;
                        s.st = St::Dead;
                        event(s, EV_ERROR, EV_ERR_RING);
                        return;
                    }
                }
            }
            // Rede → cliente: só lê do TCP o que cabe no `rx`.
            loop {
                let ready = stack.tcp.recv_ready(conn);
                if ready == 0 {
                    break;
                }
                let want = ready.min(MAX_RX_RECORD);
                if !s.rings.fits(want) {
                    break;
                }
                match stack.tcp.read(conn, &mut buf[..want]) {
                    Ok(Read::Data(n)) => {
                        let _ = s.rings.push(KIND_DATA, &buf[..n]);
                    }
                    _ => break,
                }
            }
            if stack.tcp.recv_ready(conn) == 0 && !s.eof_sent {
                let mut one = [0u8; 1];
                match stack.tcp.read(conn, &mut one) {
                    Ok(Read::Eof) => {
                        s.eof_sent = true;
                        event(s, EV_PEER_CLOSED, 0);
                    }
                    Ok(Read::Data(_) | Read::WouldBlock) => {}
                    Err(e) => {
                        stack.tcp.abort(conn);
                        s.conn = None;
                        s.st = St::Dead;
                        event(s, EV_ERROR, tcp_error(Some(e)));
                    }
                }
            }
        }
        St::Idle | St::Dead => {}
    }
}

fn pump_udp<R: Rings, L: Link>(s: &mut Sock<R>, stack: &mut Stack, link: &mut L, now: u64) {
    if s.st != St::Connected {
        return;
    }
    let mut buf = [0u8; MAX_RECORD];
    loop {
        let (ip, port) = s.peer;
        // Um datagrama que esperava MAC ou vaga vai antes dos novos.
        let len = if let Some(h) = s.held.take() {
            buf[..h.len()].copy_from_slice(&h);
            h.len()
        } else {
            match s.rings.pop(&mut buf) {
                Ok(Some((KIND_DATA, n))) => n,
                Ok(Some(_)) => continue,
                Ok(None) | Err(RingError) => return,
            }
        };
        match stack.send_udp(link, s.lport, ip, port, &buf[..len], now) {
            Err(SendError::Pending | SendError::Busy) => {
                s.held = Some(buf[..len].to_vec());
                return;
            }
            // Sem rota ou grande demais: o datagrama se perde, como no UDP.
            Ok(()) | Err(SendError::NoRoute | SendError::TooBig) => {}
        }
    }
}

impl<R: Rings> Upper for Table<R> {
    fn udp(&mut self, src: Ip4, sport: u16, dport: u16, data: &[u8]) -> bool {
        let found = self.socks.iter_mut().flatten().find(|s| {
            s.proto == Proto::Udp
                && s.st == St::Connected
                && s.lport == dport
                && s.peer == (src, sport)
        });
        match found {
            Some(s) => {
                if s.rings.fits(data.len()) {
                    let _ = s.rings.push(KIND_DATA, data);
                }
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests;
