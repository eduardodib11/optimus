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
pub use osvc::{Boot, CapDesc, DriverInfo, Method, SvcError};

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

    /// `connect(interface, minor)`: a capability `SEND` do provedor de
    /// `interface` (o `interface_id` da ADR 0033), com versão menor de pelo
    /// menos `minor`.
    ///
    /// # Errors
    ///
    /// Os do kernel; `AccessDenied` com o `SvcError` em `Err` do segundo
    /// nível ([`Session::connect_svc`]).
    pub fn connect(&mut self, interface: u32, minor: u16) -> Result<Handle, Error> {
        self.connect_svc(interface, minor)?
            .map_err(|_| Error::AccessDenied)
    }

    /// Como [`Session::connect`], mas devolve o `SvcError` do `svcmgr`.
    ///
    /// # Errors
    ///
    /// Os do kernel e `InvalidArgument` para resposta fora do protocolo.
    pub fn connect_svc(
        &mut self,
        interface: u32,
        minor: u16,
    ) -> Result<Result<Handle, SvcError>, Error> {
        let mut req = [0u8; osvc::MAX_SHORT_BYTES];
        let n =
            osvc::encode_connect(interface, minor, &mut req).map_err(|_| Error::InvalidArgument)?;
        let mut body = [0u8; osvc::MAX_SHORT_BYTES];
        let (label, m) = ipc::call_corpo(
            self.control,
            &mut self.buffer,
            osvc::label(Method::Connect),
            &req[..n],
            &mut body,
            deadline(),
        )?;
        if label == osvc::REPLY_OK {
            let h = self.buffer.get().caps[0];
            return if h == 0 {
                Err(Error::InvalidArgument)
            } else {
                Ok(Ok(Handle::from_raw(h)))
            };
        }
        osvc::decode_error(&body[..m])
            .map(Err)
            .map_err(|_| Error::InvalidArgument)
    }

    /// `name_of(id)`: o nome do serviço `id` (o id é a metade baixa de um
    /// badge de serviço), copiado para `out`; devolve os bytes.
    ///
    /// # Errors
    ///
    /// Os do kernel, `AccessDenied` se o `svcmgr` recusar e
    /// `InvalidArgument` se `out` não couber o nome.
    pub fn name_of(&mut self, id: u32, out: &mut [u8]) -> Result<usize, Error> {
        let mut req = [0u8; osvc::MAX_SHORT_BYTES];
        let n = osvc::encode_name_of(id, &mut req).map_err(|_| Error::InvalidArgument)?;
        let mut body = [0u8; osvc::MAX_SHORT_BYTES];
        let (label, m) = ipc::call_corpo(
            self.control,
            &mut self.buffer,
            osvc::label(Method::NameOf),
            &req[..n],
            &mut body,
            deadline(),
        )?;
        if label != osvc::REPLY_OK {
            return Err(Error::AccessDenied);
        }
        let name = osvc::decode_name(&body[..m]).map_err(|_| Error::InvalidArgument)?;
        let dst = out.get_mut(..name.len()).ok_or(Error::InvalidArgument)?;
        dst.copy_from_slice(name.as_bytes());
        Ok(name.len())
    }

    /// `driver(index)` (1.1): o driver `index` do conjunto compilado, com
    /// as regras de `[match]`, decodificado de `out` (que precisa de
    /// [`osvc::MAX_DRIVER_BYTES`]). Só o `devmgr` recebe resposta.
    ///
    /// # Errors
    ///
    /// Os do kernel, `AccessDenied` se o `svcmgr` recusar (fora da lista
    /// ou quem chama não é o `devmgr`) e `InvalidArgument` para resposta
    /// fora do protocolo.
    pub fn driver<'b>(&mut self, index: u16, out: &'b mut [u8]) -> Result<DriverInfo<'b>, Error> {
        let mut req = [0u8; osvc::MAX_SHORT_BYTES];
        let n = osvc::encode_driver(index, &mut req).map_err(|_| Error::InvalidArgument)?;
        let (label, m) = ipc::call_corpo(
            self.control,
            &mut self.buffer,
            osvc::label(Method::Driver),
            &req[..n],
            out,
            deadline(),
        )?;
        if label != osvc::REPLY_OK {
            return Err(Error::AccessDenied);
        }
        osvc::decode_driver_info(&out[..m]).map_err(|_| Error::InvalidArgument)
    }
}
