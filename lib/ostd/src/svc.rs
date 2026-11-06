//! Cliente de `optimus.svc.Supervisor@1` (ADR 0034, item 6): o que um
//! serviço iniciado pelo `svcmgr` faz na partida.
//!
//! O `svcmgr` passa o canal de controle em `rdi` e a cota do processo em
//! `rsi` (a cota também está no descritor; vem em `rsi` porque o corpo do
//! descritor viaja no buffer de IPC, que precisa dela para existir).
//! [`Session::start`] cria o buffer, chama `bootstrap` e devolve o
//! descritor; [`Session::ready`] avisa o fim da partida.

use kabi::{Error, Handle};

use crate::ipc::{self, Buffer, DEFAULT_BUFFER_VA};
pub use osvc::{Boot, CapDesc, Method, SvcError};

/// Quanto esperar o `svcmgr` em cada chamada, em ns.
const WAIT_NS: u64 = 5_000_000_000;

/// O serviço diante do `svcmgr`.
pub struct Session {
    control: Handle,
    /// O buffer de IPC da thread inicial (fica com o serviço).
    pub buffer: Buffer,
    /// O descritor de partida.
    pub boot: Boot,
}

fn deadline() -> u64 {
    crate::time::now_ns().saturating_add(WAIT_NS)
}

impl Session {
    /// Inicia o `ostd`, cria o buffer de IPC e pede o descritor.
    ///
    /// # Errors
    ///
    /// Os do kernel e `InvalidArgument` para resposta fora do protocolo.
    pub fn start(args: [u64; 3]) -> Result<Self, Error> {
        let control = Handle::from_raw(u32::try_from(args[0]).map_err(|_| Error::InvalidArgument)?);
        let quota = Handle::from_raw(u32::try_from(args[1]).map_err(|_| Error::InvalidArgument)?);
        crate::rt::init(crate::rt::Env { quota });
        let mut buffer = Buffer::new(
            quota,
            crate::vm::SELF,
            Handle::from_raw(0),
            DEFAULT_BUFFER_VA,
        )?;
        let mut body = [0u8; osvc::MAX_BOOT_BYTES];
        let (label, n) = ipc::call_corpo(
            control,
            &mut buffer,
            osvc::label(Method::Bootstrap),
            &[],
            &mut body,
            deadline(),
        )?;
        if label != osvc::REPLY_OK {
            return Err(Error::AccessDenied);
        }
        let boot = osvc::decode_boot(&body[..n]).map_err(|_| Error::InvalidArgument)?;
        Ok(Self {
            control,
            buffer,
            boot,
        })
    }

    /// `ready()`: a partida acabou e o serviço atende.
    ///
    /// # Errors
    ///
    /// Os do kernel e `AccessDenied` se o `svcmgr` recusar.
    pub fn ready(&mut self) -> Result<(), Error> {
        let r = ipc::call(
            self.control,
            &ipc::Message::new(osvc::label(Method::Ready), &[]),
            deadline(),
        )?;
        if r.msg.label == osvc::REPLY_OK {
            Ok(())
        } else {
            Err(Error::AccessDenied)
        }
    }
}
