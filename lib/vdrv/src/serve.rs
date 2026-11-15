//! Laço de serviço OIDL dos drivers com laço de eventos (ADR 0060, 0063 e 0064):
//! bloqueia em `recv` com prazo curto e, a cada volta (por pedido ou por
//! prazo), chama `pump` para o driver esvaziar as filas do dispositivo.

use ostd::ipc::{self, Message};
use ostd::kabi::{Error, Handle, ObjectType, Rights};

/// Resposta "mensagem inválida" do protocolo dos serviços (`osvc`).
const REPLY_BAD_MESSAGE: u64 = (2 << 62) | 4;

/// Um pedido recebido.
pub struct Req<'a> {
    /// Rótulo de 64 bits (ADR 0033).
    pub rotulo: u64,
    /// Badge de quem chamou.
    pub badge: u64,
    /// Corpo.
    pub corpo: &'a [u8],
    /// Capabilities recebidas (handles do próprio driver).
    pub caps: &'a [u64],
}

/// A resposta que o despacho gerado montou.
pub struct Resp {
    /// Rótulo da resposta.
    pub rotulo: u64,
    /// Bytes escritos em `saida`.
    pub corpo: usize,
    /// Capabilities escritas em `caps_out` (0 ou 1).
    pub caps: usize,
}

/// Cópia de `h` com `rights` e `badge`, para ir numa resposta.
///
/// # Errors
/// Os do kernel.
pub fn grant(h: Handle, rights: Rights, badge: u64) -> Result<u64, Error> {
    ostd::cap::mint(h, rights, badge, None).map(|c| u64::from(c.raw()))
}

/// O despacho gerado: pedido, buffer de saída e capability de saída.
pub type Dispatch<'a> = dyn FnMut(&Req<'_>, &mut [u8], &mut [u64; 1]) -> Option<Resp> + 'a;

/// Atende `ep` até ele ser revogado. `dispatch` é o `despacha_*` gerado.
pub fn serve(
    ep: Handle,
    quota: Handle,
    buf: &mut ipc::Buffer,
    poll_ns: u64,
    pump: &mut dyn FnMut(),
    dispatch: &mut Dispatch<'_>,
) -> Error {
    let reply = match ostd::cap::create(quota, ObjectType::Reply, 0) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let (mut corpo, mut saida) = ([0u8; 64], [0u8; 64]);
    let mut resp: Option<Message> = None;
    loop {
        let deadline = ostd::time::now_ns().saturating_add(poll_ns);
        let got = match resp.take() {
            Some(r) => ipc::reply_recv(ep, reply, &r, deadline),
            None => ipc::recv(ep, reply, deadline),
        };
        let rec = match got {
            Ok(rec) => rec,
            Err(Error::TimedOut | Error::PeerClosed) => {
                pump();
                continue;
            }
            Err(e) => return e,
        };
        pump();
        let mut caps = [0u64; 4];
        let ncaps = usize::from(rec.msg.info.caps).min(caps.len());
        for (dst, src) in caps.iter_mut().zip(buf.get().caps.iter()).take(ncaps) {
            *dst = u64::from(*src);
        }
        let mut caps_out = [0u64; 1];
        let built = match ipc::copia(buf, &rec.msg, &mut corpo) {
            Ok(n) => {
                let req = Req {
                    rotulo: rec.msg.label,
                    badge: rec.badge,
                    corpo: &corpo[..n],
                    caps: &caps[..ncaps],
                };
                match dispatch(&req, &mut saida, &mut caps_out) {
                    Some(d) => ipc::monta(buf, d.rotulo, &saida[..d.corpo]).map(|mut m| {
                        if d.caps == 1 {
                            buf.get().caps[0] = u32::try_from(caps_out[0]).unwrap_or(0);
                            m.info.caps = 1;
                        }
                        m
                    }),
                    None => Ok(Message::new(REPLY_BAD_MESSAGE, &[])),
                }
            }
            Err(_) => Ok(Message::new(REPLY_BAD_MESSAGE, &[])),
        };
        match built {
            Ok(m) => resp = Some(m),
            Err(e) => return e,
        }
    }
}
