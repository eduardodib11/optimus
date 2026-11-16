//! O motor de sessão do `tlsd` (`otls::session`) contra o `rustls` do host,
//! com a rede e o cliente simulados por anéis pequenos: prova a
//! contrapressão, o fim de cada lado e os códigos de falha (T-654).

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use otls::client::OcspPolicy;
use otls::session::{
    App, Broken, DATA, EVENT, MAX_DATA, Net, Params, Phase, Session, code, event, net_event,
};
use ox509::Certificate;
use ox509::verify::{Anchors, ServerName};
use tlshost::{CA, NAME, Opts, P256, Server};

const MSS: usize = 1448;

/// O socket do `netd`: o fluxo de um TCP de verdade, em registros de até um
/// MSS, com o anel de transmissão que enche.
struct Wire {
    sock: TcpStream,
    first: Option<(u8, u8)>,
    eof_sent: bool,
    /// Bytes que o anel de transmissão ainda aceita antes de o teste
    /// "esvaziá-lo".
    tx_room: usize,
    tx_total: usize,
}

impl Wire {
    fn new(addr: SocketAddr, connected: bool) -> Self {
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_nonblocking(true).unwrap();
        Self {
            sock,
            first: connected.then_some((net_event::CONNECTED, 0)),
            eof_sent: false,
            tx_room: 6000,
            tx_total: 0,
        }
    }
}

impl Net for Wire {
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, Broken> {
        if let Some((a, b)) = self.first.take() {
            buf[..2].copy_from_slice(&[a, b]);
            return Ok(Some((EVENT, 2)));
        }
        if self.eof_sent {
            return Ok(None);
        }
        let n = buf.len().min(MSS);
        match self.sock.read(&mut buf[..n]) {
            Ok(0) => {
                self.eof_sent = true;
                buf[..2].copy_from_slice(&[net_event::CLOSED, 0]);
                Ok(Some((EVENT, 2)))
            }
            Ok(n) => Ok(Some((DATA, n))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => {
                self.eof_sent = true;
                buf[..2].copy_from_slice(&[net_event::ERROR, 2]);
                Ok(Some((EVENT, 2)))
            }
        }
    }

    fn push(&mut self, data: &[u8]) -> bool {
        if data.len() > self.tx_room {
            return false;
        }
        self.tx_room -= data.len();
        self.tx_total += data.len();
        // Soquete bloqueante só para escrever: o servidor lê sempre.
        self.sock.set_nonblocking(false).unwrap();
        self.sock.write_all(data).unwrap();
        self.sock.set_nonblocking(true).unwrap();
        true
    }
}

/// O cliente do `tlsd`: o anel de recepção de 8 KiB que o teste esvazia aos
/// poucos.
#[derive(Default)]
struct Client {
    to_server: VecDeque<Vec<u8>>,
    got: Vec<u8>,
    events: Vec<[u8; 2]>,
    room: usize,
}

impl App for Client {
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, Broken> {
        Ok(self.to_server.pop_front().map(|r| {
            buf[..r.len()].copy_from_slice(&r);
            (DATA, r.len())
        }))
    }

    fn fits(&mut self, len: usize) -> bool {
        len <= self.room
    }

    fn push(&mut self, kind: u16, data: &[u8]) -> bool {
        if data.len() > self.room {
            return false;
        }
        self.room -= data.len();
        if kind == EVENT {
            self.events.push([data[0], data[1]]);
        } else {
            self.got.extend_from_slice(data);
        }
        true
    }
}

fn urandom() -> impl FnMut(&mut [u8]) {
    let mut f = File::open("/dev/urandom").unwrap();
    move |b| f.read_exact(b).unwrap()
}

fn params(name: &'static str, pin: Option<[u8; 32]>) -> Params<'static> {
    Params {
        name: ServerName::Dns(name),
        anchors: Anchors::parse(CA).unwrap(),
        now: Certificate::parse(P256).unwrap().not_before + 86_400,
        pin,
        ocsp: OcspPolicy::Opportunistic,
    }
}

fn server(o: Opts) -> Server {
    Server::start("127.0.0.1:0".parse().unwrap(), &o).unwrap()
}

struct Run {
    s: Session,
    wire: Wire,
    app: Client,
    t0: Instant,
}

impl Run {
    fn new(addr: SocketAddr, name: &'static str, connected: bool) -> Self {
        let p = params(name, None);
        let t0 = Instant::now();
        Self {
            s: Session::new(&p, 0, &mut urandom()),
            wire: Wire::new(addr, connected),
            app: Client::default(),
            t0,
        }
    }

    fn now(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_nanos()).unwrap()
    }

    /// Uma rodada: o cliente esvazia o anel de recepção (até `drain` bytes) e
    /// a rede esvazia o de transmissão.
    fn round(&mut self, drain: usize) -> bool {
        self.app.room = (self.app.room + drain).min(8192);
        self.wire.tx_room = 6000;
        let now = self.now();
        let busy = self.s.step(now, &mut self.wire, &mut self.app);
        busy
    }

    fn run_until(&mut self, drain: usize, done: impl Fn(&Self) -> bool) {
        let limit = Instant::now() + Duration::from_secs(20);
        while !done(self) {
            assert!(
                Instant::now() < limit,
                "tempo esgotado: {:?}",
                self.s.phase()
            );
            if !self.round(drain) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

fn http_body(raw: &[u8]) -> &[u8] {
    let at = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    &raw[at + 4..]
}

fn complete(raw: &[u8]) -> bool {
    let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&raw[..at]);
    let want: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("Content-Length: "))
        .and_then(|v| v.parse().ok())
        .unwrap();
    raw.len() - at - 4 >= want
}

fn get(r: &mut Run, path: &str, drain: usize) {
    let request = format!("GET {path} HTTP/1.1\r\nHost: {NAME}\r\n\r\n");
    r.run_until(drain, |r| r.s.phase() == Phase::Open || r.s.is_done());
    assert_eq!(r.s.phase(), Phase::Open, "eventos: {:?}", r.app.events);
    for c in request.as_bytes().chunks(MAX_DATA) {
        r.app.to_server.push_back(c.to_vec());
    }
    r.run_until(drain, |r| complete(&r.app.got));
}

#[test]
fn get_com_o_anel_pequeno_e_contrapressao() {
    let s = server(Opts::default());
    let mut r = Run::new(s.addr, NAME, true);
    // O cliente só esvazia 700 bytes por rodada: a sessão tem de segurar o
    // resto sem perder nem reordenar nada.
    get(&mut r, "/big", 700);
    let body = http_body(&r.app.got);
    assert_eq!(body.len(), 1 << 20);
    assert!(
        body.iter()
            .enumerate()
            .all(|(i, &b)| b == (i as u32 % 251) as u8)
    );
    assert_eq!(r.app.events[0], [event::CONNECTED, 0]);
    assert!(r.wire.tx_total > 0);
}

#[test]
fn rekey_e_fim_com_close_notify() {
    let s = server(Opts::default());
    let mut r = Run::new(s.addr, NAME, true);
    get(&mut r, "/rekey", 4096);
    assert!(String::from_utf8_lossy(&r.app.got).contains("optimus tlshost ok"));
    // O servidor responde `Connection: close`: o `close_notify` chega.
    r.run_until(4096, |r| r.s.is_done());
    assert!(
        r.app.events.contains(&[event::CLOSED, 0]),
        "{:?}",
        r.app.events
    );
}

#[test]
fn cliente_fecha_e_a_sessao_manda_close_notify() {
    let s = server(Opts::default());
    let mut r = Run::new(s.addr, NAME, true);
    r.run_until(4096, |r| r.s.phase() == Phase::Open);
    r.round(4096);
    r.s.close(&mut r.wire);
    assert!(r.s.is_done());
    assert_eq!(r.app.events, vec![[event::CONNECTED, 0]]);
}

#[test]
fn falhas_tem_codigo_grosso() {
    let cases: [(Opts, &'static str, u8); 3] = [
        (
            Opts {
                tls12_only: true,
                ..Opts::default()
            },
            NAME,
            code::TLS12_ONLY,
        ),
        (
            Opts {
                hybrid: false,
                ..Opts::default()
            },
            NAME,
            code::NO_COMMON,
        ),
        (Opts::default(), "outro.optimus.test", code::CERTIFICATE),
    ];
    for (o, name, want) in cases {
        let s = server(o);
        let mut r = Run::new(s.addr, name, true);
        r.run_until(4096, |r| r.s.is_done());
        assert_eq!(r.app.events, vec![[event::ERROR, want]], "{name}");
        assert_eq!(r.s.phase(), Phase::Done);
    }
}

#[test]
fn tcp_que_nao_abre_estoura_o_prazo() {
    let s = server(Opts::default());
    // O `netd` nunca diz `connected`.
    let mut r = Run::new(s.addr, NAME, false);
    r.round(4096);
    assert_eq!(r.s.phase(), Phase::Connecting);
    let now = otls::session::HANDSHAKE_NS + 1;
    r.app.room = 64;
    r.s.step(now, &mut r.wire, &mut r.app);
    assert!(r.s.is_done());
    assert_eq!(r.app.events, vec![[event::ERROR, code::NET]]);
}

#[test]
fn servidor_que_fecha_sem_close_notify_e_erro_de_rede() {
    let s = server(Opts {
        tls12_only: false,
        ..Opts::default()
    });
    let mut r = Run::new(s.addr, NAME, true);
    r.run_until(4096, |r| r.s.phase() == Phase::Open);
    // Mata o servidor no meio: o soquete fecha sem `close_notify`.
    r.wire.sock.shutdown(std::net::Shutdown::Both).unwrap();
    r.run_until(4096, |r| r.s.is_done());
    assert!(
        r.app.events.contains(&[event::ERROR, code::NET]),
        "{:?}",
        r.app.events
    );
}
