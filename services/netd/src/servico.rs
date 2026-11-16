//! O serviço de sockets do `netd` (T-637; ADR 0068): serve `Socket` e
//! `Config` num endpoint só, entre as voltas da pilha. Cada chamada vem com o
//! badge do cliente (serviço e geração); a política dele (`NetAccess`) o
//! `netd` pede ao `svcmgr` na primeira chamada. Sem política, nada abre.
//!
//! O laço é um só (ADR 0060, como o `storaged`): a cada volta esvazia o anel
//! de recepção da placa, leva os dados dos sockets, dá a vez ao relógio da
//! pilha e bloqueia em `recv` com prazo curto, que é o que dorme.

use onet::policy::{Policy, Proto};
use onet::sock::{self, Audit, Table};
use onet::stack::{Stack, Upper};
use ostd::boxed::Box;
use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType, Rights};
use ostd::svc::Session;

use crate::netconfig_servidor::{
    self as cfg, Config, ConfigError, ID_CONFIG, NetStatus, despacha_config,
};
use crate::probe::Probes;
use crate::rings::SockRings;
use crate::socket_servidor::{ID_SOCKET, Socket, SocketError, despacha_socket};
use crate::{FRAME_KIND, Nic, TxLink};

/// Prazo de cada volta: curto com socket aberto, longo sem.
const BUSY_NS: u64 = 1_000_000;
const IDLE_NS: u64 = 10_000_000;

/// As decisões de política vão para o log do kernel, que o `logd` guarda
/// (ADR 0068, item 8): cliente, destino e motivo, nunca os dados.
struct Printer;

impl Audit for Printer {
    fn decision(&mut self, client: u32, proto: Proto, ip: [u8; 4], port: u16, ok: bool, why: &str) {
        let p = match proto {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        };
        let v = if ok { "permitido" } else { "negado" };
        ostd::debug::print_fmt(format_args!(
            "netd: política: cliente {client} {p} {}.{}.{}.{}:{port} {v} ({why})",
            ip[0], ip[1], ip[2], ip[3]
        ));
    }
}

/// Probes da imagem de teste e a tabela de sockets, juntas como quem recebe
/// UDP.
struct Both<'a> {
    probes: &'a mut Probes,
    table: &'a mut Table<SockRings>,
}

impl Upper for Both<'_> {
    fn udp(&mut self, src: [u8; 4], sport: u16, dport: u16, data: &[u8]) -> bool {
        self.probes.udp(src, sport, dport, data) || self.table.udp(src, sport, dport, data)
    }
}

/// A pilha, a placa e os sockets.
pub struct Net<'a> {
    s: &'a mut Session,
    nic: Nic,
    /// Na heap: a pilha tem uns 11 KiB e a pilha de 64 KiB do processo não
    /// aguenta as cópias de um valor desses entre as funções de partida.
    stack: Box<Stack>,
    table: Table<SockRings>,
    probes: Probes,
    quota: Handle,
    ntfy: Handle,
    ep: Handle,
    reply: Handle,
}

const fn wire(e: sock::Error) -> SocketError {
    match e {
        sock::Error::Denied => SocketError::Denied,
        sock::Error::Limit => SocketError::Limit,
        sock::Error::Quota => SocketError::Quota,
        sock::Error::BadRequest => SocketError::BadRequest,
        sock::Error::NoRoute => SocketError::NoRoute,
        sock::Error::Busy => SocketError::Busy,
    }
}

fn random() -> u32 {
    let mut r = [0u8; 4];
    let _ = ostd::rand::secure_fill(&mut r);
    u32::from_le_bytes(r)
}

fn grant(h: Handle, rights: Rights) -> Result<u64, SocketError> {
    ostd::cap::mint(h, rights, 0, None)
        .map(|c| u64::from(c.raw()))
        .map_err(|_| SocketError::Quota)
}

impl<'a> Net<'a> {
    /// Junta as partes. `ep` é o endpoint provido (`Socket@1`).
    pub fn new(
        s: &'a mut Session,
        nic: Nic,
        quota: Handle,
        ntfy: Handle,
        ep: Handle,
    ) -> Result<Self, Error> {
        let reply = ostd::cap::create(quota, ObjectType::Reply, 0)?;
        let mut stack = Box::new(Stack::new(nic.mac));
        // O segredo do ISN do TCP e os `xid` do DHCP vêm do DRBG do kernel; o
        // endereço, a rota e o DNS, do servidor DHCP (T-633).
        let mut seed = [0u8; 16];
        let _ = ostd::rand::secure_fill(&mut seed);
        stack.seed(seed);
        stack.start_dhcp();
        stack.start_ipv6();
        Ok(Self {
            s,
            nic,
            stack,
            table: Table::new(),
            probes: Probes::new(),
            quota,
            ntfy,
            ep,
            reply,
        })
    }

    /// Uma volta: quadros recebidos, dados dos sockets e relógio.
    fn turn(&mut self, now: u64) -> Result<(), &'static str> {
        let mut frame = [0u8; onet::eth::MAX_FRAME];
        loop {
            match self.nic.rx.pop(&mut frame) {
                Ok(Some((FRAME_KIND, n))) => {
                    let mut up = Both {
                        probes: &mut self.probes,
                        table: &mut self.table,
                    };
                    let link = &mut TxLink(&mut self.nic.tx);
                    let ev = self.stack.input(link, &mut up, &frame[..n], now);
                    self.probes.event(ev);
                }
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(_) => return Err("anel de recepção corrompido"),
            }
        }
        self.table
            .pump(&mut self.stack, &mut TxLink(&mut self.nic.tx), now);
        self.stack.tick(&mut TxLink(&mut self.nic.tx), now);
        if crate::TESTE {
            self.probes
                .step(&mut self.stack, &mut TxLink(&mut self.nic.tx), now);
        }
        Ok(())
    }

    /// Roda até um erro do kernel ou do anel da placa.
    pub fn run(&mut self) -> Result<(), &'static str> {
        loop {
            self.turn(ostd::time::now_ns())?;
            let wait = if self.table.is_active() {
                BUSY_NS
            } else {
                IDLE_NS
            };
            let deadline = ostd::time::now_ns().saturating_add(wait);
            match ipc::recv(self.ep, self.reply, deadline) {
                Ok(rec) => self.serve(&rec),
                Err(Error::TimedOut | Error::PeerClosed) => {}
                Err(_) => return Err("recepção de chamadas"),
            }
        }
    }

    /// Atende uma chamada e responde pelo `reply`.
    fn serve(&mut self, rec: &ipc::Received) {
        let mut caps = [0u64; 4];
        let ncaps = usize::from(rec.msg.info.caps).min(caps.len());
        for (dst, src) in caps
            .iter_mut()
            .zip(self.s.buffer.get().caps.iter())
            .take(ncaps)
        {
            *dst = u64::from(*src);
        }
        let mut corpo = [0u8; 64];
        let mut saida = [0u8; 64];
        let mut caps_out = [0u64; 1];
        let built = match ipc::copia(&mut self.s.buffer, &rec.msg, &mut corpo) {
            Ok(n) => {
                let label = rec.msg.label;
                let id = (label >> 32) as u32;
                let despacho = if id == ID_SOCKET {
                    let e = crate::socket_servidor::Entrada {
                        rotulo: label,
                        badge: rec.badge,
                        corpo: &corpo[..n],
                        caps: &caps[..ncaps],
                    };
                    despacha_socket(self, 0, &e, &mut saida, &mut caps_out)
                        .map(|d| (d.rotulo, d.corpo, d.caps))
                } else if id == ID_CONFIG {
                    let e = cfg::Entrada {
                        rotulo: label,
                        badge: rec.badge,
                        corpo: &corpo[..n],
                        caps: &caps[..ncaps],
                    };
                    despacha_config(self, 0, &e, &mut saida, &mut caps_out)
                        .map(|d| (d.rotulo, d.corpo, d.caps))
                } else {
                    None
                };
                match despacho {
                    Some((rotulo, len, ncap)) => {
                        ipc::monta(&mut self.s.buffer, rotulo, &saida[..len]).map(|mut m| {
                            if ncap == 1 {
                                self.s.buffer.get().caps[0] =
                                    u32::try_from(caps_out[0]).unwrap_or(0);
                                m.info.caps = 1;
                            }
                            m
                        })
                    }
                    None => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
                }
            }
            Err(_) => Ok(Message::new(osvc::REPLY_BAD_MESSAGE, &[])),
        };
        if let Ok(m) = built {
            let _ = ipc::send(self.reply, &m, 0);
            if m.info.caps == 1 {
                // A cópia que foi na resposta já é do cliente; a daqui sai.
                let _ =
                    ostd::cap::delete(Handle::from_raw(u32::try_from(caps_out[0]).unwrap_or(0)));
            }
        }
    }

    /// A política do cliente do `badge`: a registrada, ou a que o `svcmgr`
    /// tem no manifesto dele (texto vazio: sem `NetAccess`, nega tudo).
    fn ensure_policy(&mut self, badge: u64) -> Result<(), SocketError> {
        if self.table.knows(badge) {
            return Ok(());
        }
        let id = u32::try_from(badge & 0xFFFF_FFFF).map_err(|_| SocketError::BadRequest)?;
        let mut buf = [0u8; osvc::MAX_POLICY];
        let policy = match self.s.net_policy(id, &mut buf) {
            Ok(n) if n > 0 => core::str::from_utf8(&buf[..n])
                .ok()
                .and_then(|t| Policy::parse(t).ok())
                .unwrap_or_else(|| {
                    ostd::debug::print_fmt(format_args!(
                        "netd: política: cliente {id} com texto inválido, negado"
                    ));
                    Policy::DENY
                }),
            // O `svcmgr` recusou: sem política. Outro erro (prazo) não
            // vira negação guardada: o cliente tenta de novo.
            Ok(_) | Err(Error::AccessDenied | Error::InvalidArgument) => Policy::DENY,
            Err(_) => return Err(SocketError::Busy),
        };
        let now = ostd::time::now_ns();
        self.table.set_policy(&mut self.stack, badge, policy, now);
        Ok(())
    }

    fn open_inner(
        &mut self,
        badge: u64,
        proto: u8,
        rx: Handle,
        wake: Handle,
    ) -> Result<u32, SocketError> {
        let proto = match proto {
            0 => Proto::Udp,
            1 => Proto::Tcp,
            _ => return Err(SocketError::BadRequest),
        };
        self.ensure_policy(badge)?;
        let (quota, ntfy) = (self.quota, self.ntfy);
        let r = self.table.open(badge, proto, |slot| {
            SockRings::create(quota, ntfy, slot, rx, wake)
        });
        if r == Err(sock::Error::Denied) {
            ostd::debug::print_fmt(format_args!(
                "netd: política: cliente {} sem NetAccess, socket negado",
                badge & 0xFFFF_FFFF
            ));
        }
        r.map_err(wire)
    }
}

impl Socket for Net<'_> {
    fn open(
        &mut self,
        ctx: &crate::socket_servidor::Contexto,
        proto: u8,
        rx: u64,
        wake: u64,
    ) -> Result<u32, SocketError> {
        let (Ok(rx), Ok(wake)) = (u32::try_from(rx), u32::try_from(wake)) else {
            return Err(SocketError::BadRequest);
        };
        let (rx, wake) = (Handle::from_raw(rx), Handle::from_raw(wake));
        let r = self.open_inner(ctx.badge, proto, rx, wake);
        if r.is_err() {
            // Nada ficou com o socket: as capabilities do cliente saem daqui.
            let _ = ostd::cap::delete(rx);
            let _ = ostd::cap::delete(wake);
        }
        r
    }

    fn tx_ring(
        &mut self,
        ctx: &crate::socket_servidor::Contexto,
        sock: u32,
    ) -> Result<u64, SocketError> {
        let obj = self
            .table
            .rings_mut(ctx.badge, sock)
            .map_err(wire)?
            .tx_object();
        grant(obj, Rights::MAP | Rights::READ | Rights::WRITE)
    }

    fn tx_signal(
        &mut self,
        ctx: &crate::socket_servidor::Contexto,
        sock: u32,
    ) -> Result<u64, SocketError> {
        self.table.rings_mut(ctx.badge, sock).map_err(wire)?;
        grant(self.ntfy, Rights::SIGNAL)
    }

    fn connect(
        &mut self,
        ctx: &crate::socket_servidor::Contexto,
        sock: u32,
        ip: u32,
        port: u16,
    ) -> Result<(), SocketError> {
        let now = ostd::time::now_ns();
        self.table
            .connect(
                &mut self.stack,
                &mut Printer,
                ctx.badge,
                sock,
                ip.to_be_bytes(),
                port,
                now,
                random(),
            )
            .map_err(wire)?;
        // O SYN sai já, sem esperar a próxima volta.
        self.stack.flush_tcp(&mut TxLink(&mut self.nic.tx), now);
        Ok(())
    }

    fn close(
        &mut self,
        ctx: &crate::socket_servidor::Contexto,
        sock: u32,
    ) -> Result<(), SocketError> {
        let now = ostd::time::now_ns();
        let rings = self
            .table
            .close(&mut self.stack, ctx.badge, sock, now)
            .map_err(wire)?;
        drop(rings);
        self.stack.flush_tcp(&mut TxLink(&mut self.nic.tx), now);
        Ok(())
    }
}

impl Config for Net<'_> {
    fn status(&mut self, _: &cfg::Contexto) -> Result<NetStatus, ConfigError> {
        let c = self.stack.config();
        let ip = |a: [u8; 4]| u32::from_be_bytes(a);
        let m = self.stack.mac().0;
        Ok(NetStatus {
            mac: u64::from_le_bytes([m[0], m[1], m[2], m[3], m[4], m[5], 0, 0]),
            ip: ip(c.ip),
            mask: ip(c.mask),
            gateway: ip(c.gateway),
            dns: 0,
        })
    }
}
