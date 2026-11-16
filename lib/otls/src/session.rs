//! A sessão do `tlsd` (T-654; ADR 0070, itens 2, 4 e 8): o cliente TLS
//! ligado a dois pares de anéis, sem E/S própria.
//!
//! De um lado a rede ([`Net`]): o fluxo TCP cifrado, que o `netd` entrega em
//! registros de dados e eventos (`socket.oidl`). Do outro o cliente do
//! `tlsd` ([`App`]): os mesmos anéis, mas em claro, e os eventos da conexão
//! (`tls.oidl`). `step` anda tudo o que dá sem bloquear e devolve quando
//! falta espaço num dos anéis, que é a contrapressão: não se lê mais do que
//! se consegue entregar, e o TCP do `netd` fecha a janela.
//!
//! Eventos para o cliente (registro tipo 2, `código`, `argumento`):
//! 1 conectou; 2 o servidor fechou (`close_notify`); 3 erro, com
//! [`code`] no argumento. Os motivos ficam grossos de propósito (ADR 0070,
//! item 4): quem fala com um servidor hostil não ganha um oráculo.

use alloc::boxed::Box;
use alloc::vec;
use core::ops::Range;

use ox509::verify::ServerName;

use crate::Error;
use crate::client::{Client, Config, OcspPolicy};
use crate::record::{HEADER_LEN, MAX_RECORD};
use crate::verifier::Optcrypt;

/// Tipo de registro de dados, nos dois lados.
pub const DATA: u16 = 1;
/// Tipo de registro de evento, nos dois lados.
pub const EVENT: u16 = 2;
/// Maior registro de dados (`RING_BYTES` de 8192 menos cabeçalhos: o `tx`
/// aceita 4088).
pub const MAX_DATA: usize = 4088;

/// Eventos de `netd` (código; argumento no segundo byte).
pub mod net_event {
    /// A conexão TCP abriu.
    pub const CONNECTED: u8 = 1;
    /// O outro lado fechou e tudo foi lido.
    pub const CLOSED: u8 = 2;
    /// Erro de transporte.
    pub const ERROR: u8 = 3;
}

/// Eventos para o cliente do `tlsd`.
pub mod event {
    /// O handshake terminou.
    pub const CONNECTED: u8 = 1;
    /// O servidor fechou com `close_notify`.
    pub const CLOSED: u8 = 2;
    /// A conexão falhou; o argumento é um [`super::code`].
    pub const ERROR: u8 = 3;
}

/// Os motivos de falha que o cliente vê (argumento do evento 3).
pub mod code {
    /// Rede: recusada, reiniciada, sem resposta, fechada sem `close_notify`
    /// ou tempo esgotado.
    pub const NET: u8 = 1;
    /// Hora de parede: validade sem um relógio confiável.
    pub const CLOCK: u8 = 2;
    /// Certificado recusado (cadeia, nome, validade ou chave fixada).
    pub const CERTIFICATE: u8 = 3;
    /// Certificado revogado, ou resposta OCSP exigida e inválida.
    pub const REVOCATION: u8 = 4;
    /// O servidor só fala TLS 1.2 ou anterior.
    pub const TLS12_ONLY: u8 = 5;
    /// Sem grupo ou suíte em comum.
    pub const NO_COMMON: u8 = 6;
    /// Qualquer outro motivo (nada de detalhe sobre falhas de cifra).
    pub const OTHER: u8 = 7;
}

/// Tempo para o handshake, da abertura ao `Finished`.
pub const HANDSHAKE_NS: u64 = 10_000_000_000;

/// O que o handshake não deve tomar mais que isto da entrada.
const INBUF: usize = MAX_RECORD + MAX_DATA;
const OUTBUF: usize = 2 * MAX_DATA;
/// Eventos pendentes para o cliente (conectou e erro cabem folgados).
const EVENTS: usize = 4;

/// A rede: o socket TCP do `netd` visto da `tlsd`.
pub trait Net {
    /// Próximo registro do anel de recepção, `(tipo, tamanho)`; `Err` se o
    /// anel está corrompido.
    ///
    /// # Errors
    ///
    /// O anel não é mais confiável.
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, Broken>;
    /// Põe `data` no anel de transmissão (registro de dados); `false` se não
    /// cabe agora.
    fn push(&mut self, data: &[u8]) -> bool;
}

/// O cliente do `tlsd`: os anéis em claro e os eventos.
pub trait App {
    /// Próximo registro que o cliente escreveu.
    ///
    /// # Errors
    ///
    /// O anel não é mais confiável.
    fn pop(&mut self, buf: &mut [u8]) -> Result<Option<(u16, usize)>, Broken>;
    /// Cabe um registro de `len` bytes no anel de recepção do cliente?
    fn fits(&mut self, len: usize) -> bool;
    /// Põe um registro no anel de recepção do cliente.
    fn push(&mut self, kind: u16, data: &[u8]) -> bool;
}

/// Anel corrompido.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Broken;

/// Argumentos de uma sessão.
pub struct Params<'a> {
    /// Nome do servidor (DNS ou IP); vai no SNI e na verificação.
    pub name: ServerName<'a>,
    /// Âncoras de confiança.
    pub anchors: ox509::verify::Anchors<'static>,
    /// Hora de parede, segundos Unix.
    pub now: i64,
    /// SHA-256 do SPKI (modo `pin`: sem cadeia, sem relógio).
    pub pin: Option<[u8; 32]>,
    /// Política do OCSP grampeado.
    pub ocsp: OcspPolicy,
}

/// Em que ponto a conexão está.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Esperando o `netd` abrir o TCP.
    Connecting,
    /// Trocando o handshake.
    Handshake,
    /// Dados da aplicação.
    Open,
    /// Fim, por `close_notify` ou por erro (já avisado ao cliente).
    Done,
}

/// Uma conexão TLS.
pub struct Session {
    client: Client<'static, Optcrypt>,
    phase: Phase,
    deadline_ns: u64,
    inb: Box<[u8]>,
    in_len: usize,
    /// Dados da aplicação do registro que está no início de `inb`, ainda
    /// sem entregar; `app_rec` é o tamanho do registro, para descartá-lo.
    app: Range<usize>,
    app_rec: usize,
    out: Box<[u8]>,
    out_len: usize,
    out_pos: usize,
    events: [[u8; 2]; EVENTS],
    n_events: usize,
    /// Fim a caminho: o que falta é esvaziar `out` e os eventos.
    ending: bool,
}

/// Código do erro (ver [`code`]).
#[must_use]
pub fn code_of(e: Error) -> u8 {
    use ox509::verify::VerifyError;
    match e {
        Error::Tls12Only | Error::PeerAlert(70) => code::TLS12_ONLY,
        Error::HandshakeFailure | Error::PeerAlert(40) => code::NO_COMMON,
        Error::Revoked | Error::Ocsp(_) | Error::StapleRequired | Error::PeerAlert(44 | 113) => {
            code::REVOCATION
        }
        Error::Certificate(VerifyError::Expired | VerifyError::NotYetValid) => code::CLOCK,
        Error::Certificate(_)
        | Error::BadCertificate
        | Error::UnsupportedCertificate
        | Error::PeerAlert(42 | 43 | 45 | 46 | 48) => code::CERTIFICATE,
        _ => code::OTHER,
    }
}

impl Session {
    /// Sessão nova, esperando o evento `connected` do `netd`. `now_ns` é o
    /// relógio monotônico, para o prazo do handshake; `rng` vem do `keyd`.
    pub fn new(p: &Params<'_>, now_ns: u64, rng: &mut impl FnMut(&mut [u8])) -> Self {
        let cfg = Config {
            name: p.name,
            anchors: p.anchors,
            now: p.now,
            allow_classic: false,
            pin: p.pin,
            ocsp: p.ocsp,
        };
        Self {
            client: Client::new(cfg, Optcrypt, rng),
            phase: Phase::Connecting,
            deadline_ns: now_ns.saturating_add(HANDSHAKE_NS),
            inb: vec![0; INBUF].into_boxed_slice(),
            in_len: 0,
            app: 0..0,
            app_rec: 0,
            out: vec![0; OUTBUF].into_boxed_slice(),
            out_len: 0,
            out_pos: 0,
            events: [[0; 2]; EVENTS],
            n_events: 0,
            ending: false,
        }
    }

    /// Em que ponto a conexão está.
    #[must_use]
    pub fn phase(&self) -> Phase {
        self.phase
    }

    /// Terminou: nada mais a ler, mandar nem avisar. Quem chama fecha o
    /// socket do `netd` e solta a sessão.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.phase == Phase::Done && self.n_events == 0 && self.out_pos == self.out_len
    }

    /// O cliente pediu o fim: manda `close_notify` e termina.
    pub fn close(&mut self, net: &mut impl Net) {
        if self.phase == Phase::Open && self.out_len == self.out_pos {
            self.out_len = self.client.close(&mut self.out).unwrap_or(0);
            self.out_pos = 0;
        }
        self.finish(None);
        self.flush(net);
    }

    fn event(&mut self, code: u8, arg: u8) {
        if let Some(e) = self.events.get_mut(self.n_events) {
            *e = [code, arg];
            self.n_events += 1;
        }
    }

    fn finish(&mut self, error: Option<u8>) {
        if let Some(c) = error {
            self.event(event::ERROR, c);
        }
        self.phase = Phase::Done;
        self.ending = true;
        self.app = 0..0;
    }

    /// Alerta fatal (quando o erro é nosso) e fim.
    fn fail(&mut self, e: Error, net: &mut impl Net) {
        if self.out_pos == self.out_len {
            self.out_len = self.client.alert(e, &mut self.out);
            self.out_pos = 0;
        }
        self.finish(Some(code_of(e)));
        self.flush(net);
    }

    fn fail_net(&mut self) {
        // Sem transporte não há a quem mandar alerta.
        self.out_len = 0;
        self.out_pos = 0;
        self.finish(Some(code::NET));
    }

    /// Empurra `out` para a rede; `true` se esvaziou.
    fn flush(&mut self, net: &mut impl Net) -> bool {
        while self.out_pos < self.out_len {
            let n = (self.out_len - self.out_pos).min(MAX_DATA);
            if !net.push(&self.out[self.out_pos..self.out_pos + n]) {
                return false;
            }
            self.out_pos += n;
        }
        self.out_len = 0;
        self.out_pos = 0;
        true
    }

    fn flush_events(&mut self, app: &mut impl App) {
        let mut sent = 0;
        while sent < self.n_events && app.push(EVENT, &self.events[sent]) {
            sent += 1;
        }
        self.events.copy_within(sent..self.n_events, 0);
        self.n_events -= sent;
    }

    /// Anda o que der sem bloquear. `now_ns` é o relógio monotônico. Devolve
    /// `true` se fez algo (quem chama volta logo) e `false` se está parado
    /// à espera de um anel, de um evento ou do prazo.
    pub fn step(&mut self, now_ns: u64, net: &mut impl Net, app: &mut impl App) -> bool {
        let mut busy = false;
        // O que falta dizer ao cliente e à rede vem antes de qualquer coisa
        // nova: assim nada cresce sem limite.
        let had = (self.n_events, self.out_len - self.out_pos);
        self.flush_events(app);
        let out_done = self.flush(net);
        busy |= had != (self.n_events, self.out_len - self.out_pos);
        if self.phase == Phase::Done {
            return busy;
        }
        if now_ns >= self.deadline_ns && self.phase != Phase::Open {
            self.fail_net();
            self.flush_events(app);
            return true;
        }
        if !out_done || self.n_events != 0 {
            return busy;
        }
        busy | match self.phase {
            Phase::Connecting => self.connecting(net),
            Phase::Handshake | Phase::Open => self.running(net, app),
            Phase::Done => false,
        }
    }

    /// Antes do TCP abrir: só o evento do `netd` importa.
    fn connecting(&mut self, net: &mut impl Net) -> bool {
        let mut b = [0u8; 8];
        match net.pop(&mut b) {
            Ok(Some((EVENT, 2))) if b[0] == net_event::CONNECTED => {
                match self.client.start(&mut self.out) {
                    Ok(n) => {
                        self.out_len = n;
                        self.out_pos = 0;
                        self.phase = Phase::Handshake;
                        self.flush(net);
                    }
                    Err(e) => self.fail(e, net),
                }
                true
            }
            Ok(Some(_)) | Err(_) => {
                // Erro, recusa ou qualquer coisa fora de ordem.
                self.fail_net();
                true
            }
            Ok(None) => false,
        }
    }

    fn running(&mut self, net: &mut impl Net, app: &mut impl App) -> bool {
        let mut busy = false;
        // 1. Dados da aplicação já decifrados esperando lugar no cliente.
        while self.app.start < self.app.end {
            let n = (self.app.end - self.app.start).min(MAX_DATA);
            if !app.fits(n) {
                return busy;
            }
            if !app.push(DATA, &self.inb[self.app.start..self.app.start + n]) {
                return busy;
            }
            self.app.start += n;
            busy = true;
        }
        if self.app_rec != 0 {
            self.inb.copy_within(self.app_rec..self.in_len, 0);
            self.in_len -= self.app_rec;
            self.app_rec = 0;
            self.app = 0..0;
        }
        // 2. Um registro inteiro no buffer de entrada.
        if self.in_len >= HEADER_LEN {
            let need = HEADER_LEN + usize::from(u16::from_be_bytes([self.inb[3], self.inb[4]]));
            if need > MAX_RECORD {
                self.fail(Error::RecordOverflow, net);
                return true;
            }
            if self.in_len >= need {
                self.record(need, net, app);
                return true;
            }
        }
        // 3. Mais bytes da rede, se cabem.
        if self.in_len + MAX_DATA <= self.inb.len() {
            let mut buf = [0u8; MAX_DATA];
            match net.pop(&mut buf) {
                Ok(Some((DATA, n))) if n <= MAX_DATA => {
                    self.inb[self.in_len..self.in_len + n].copy_from_slice(&buf[..n]);
                    self.in_len += n;
                    return true;
                }
                Ok(Some((EVENT, 2))) => {
                    // O TCP fechou sem `close_notify`: truncamento.
                    self.fail_net();
                    return true;
                }
                Ok(None) => {}
                _ => {
                    self.fail_net();
                    return true;
                }
            }
        }
        // 4. Dados do cliente, depois do handshake.
        if self.phase == Phase::Open {
            let mut buf = [0u8; MAX_DATA];
            match app.pop(&mut buf) {
                Ok(Some((DATA, n))) if n <= MAX_DATA => {
                    match self.client.write_app(&buf[..n], &mut self.out) {
                        Ok(w) => {
                            self.out_len = w;
                            self.out_pos = 0;
                            self.flush(net);
                        }
                        Err(e) => self.fail(e, net),
                    }
                    return true;
                }
                Ok(None) => {}
                _ => {
                    // Anel do cliente corrompido ou registro que não é dado:
                    // o cliente quebrou o contrato.
                    self.fail(Error::Internal, net);
                    return true;
                }
            }
        }
        busy
    }

    /// Entrega o registro de `need` bytes ao cliente TLS.
    fn record(&mut self, need: usize, net: &mut impl Net, _app: &mut impl App) {
        let r = self
            .client
            .read_record(&mut self.inb[..need], &mut self.out);
        let ev = match r {
            Ok(ev) => ev,
            Err(e) => {
                // O alerta, se o erro for nosso, sai pelo `fail`.
                self.out_len = 0;
                self.out_pos = 0;
                self.fail(e, net);
                return;
            }
        };
        self.out_len = ev.send;
        self.out_pos = 0;
        if ev.connected {
            self.phase = Phase::Open;
            self.event(event::CONNECTED, 0);
        }
        if ev.closed {
            self.event(event::CLOSED, 0);
            self.finish(None);
        }
        if ev.app.is_empty() {
            self.inb.copy_within(need..self.in_len, 0);
            self.in_len -= need;
        } else {
            self.app = ev.app;
            self.app_rec = need;
        }
        self.flush(net);
    }
}
