//! Núcleo do `logd` (T-356, ADR 0036): registro de produtores, buffer de
//! linhas em memória e consulta por serviço e nível. Não faz I/O: o serviço
//! lê os anéis dos produtores, chama [`Store::ingest`] e escreve na serial
//! o que [`Store::drain_serial`] devolve.
//!
//! Garantias: a ordem de cada serviço é preservada (todas as linhas têm um
//! `seq` global crescente); quando o buffer enche, a linha mais antiga sai e
//! conta-se em `dropped`; nunca se perde nada sem contar.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

/// Nível de uma linha, do mais grave ao mais detalhado.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Erro.
    Error = 0,
    /// Aviso.
    Warn = 1,
    /// Informação.
    Info = 2,
    /// Depuração.
    Debug = 3,
    /// Rastro.
    Trace = 4,
}

impl Level {
    /// Converte do número do formato; `None` para valor desconhecido.
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Error,
            1 => Self::Warn,
            2 => Self::Info,
            3 => Self::Debug,
            4 => Self::Trace,
            _ => return None,
        })
    }
}

/// Uma linha guardada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Número global, crescente.
    pub seq: u64,
    /// Produtor que escreveu a linha.
    pub service: u16,
    /// Nível.
    pub level: Level,
    /// Texto.
    pub text: String,
}

/// Erros de registro e consulta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Produtor desconhecido (não registrado).
    UnknownService,
    /// Limite de produtores atingido.
    TooManyServices,
    /// Texto acima do limite de uma linha.
    LineTooLong,
}

/// Limite de produtores registrados.
pub const MAX_SERVICES: usize = 64;
/// Limite de bytes de uma linha.
pub const MAX_LINE: usize = 4096 - 8;

struct Producer {
    name: String,
    /// Linhas que este produtor perdeu no anel ou por marca-d'água.
    dropped: u64,
    /// Último `seq` aceito deste produtor (para conferir a ordem).
    last_seq: u64,
}

/// Estado do `logd`.
pub struct Store {
    capacity: usize,
    records: VecDeque<Record>,
    next_seq: u64,
    /// Linhas tiradas do buffer por falta de espaço.
    pub dropped: u64,
    producers: BTreeMap<u16, Producer>,
    next_id: u16,
    /// Quantas linhas do buffer já foram para a serial.
    flushed: usize,
}

impl Store {
    /// Cria um buffer com `capacity` linhas.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            records: VecDeque::new(),
            next_seq: 1,
            dropped: 0,
            producers: BTreeMap::new(),
            next_id: 1,
            flushed: 0,
        }
    }

    /// Registra um produtor e devolve o identificador dele.
    ///
    /// # Errors
    /// [`Error::TooManyServices`] acima de [`MAX_SERVICES`].
    pub fn register(&mut self, name: &str) -> Result<u16, Error> {
        if self.producers.len() >= MAX_SERVICES {
            return Err(Error::TooManyServices);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        self.producers.insert(
            id,
            Producer {
                name: String::from(name),
                dropped: 0,
                last_seq: 0,
            },
        );
        Ok(id)
    }

    /// Nome de um produtor registrado.
    #[must_use]
    pub fn name(&self, service: u16) -> Option<&str> {
        self.producers.get(&service).map(|p| p.name.as_str())
    }

    /// Acrescenta uma linha de `service`. Se o buffer está cheio, a linha
    /// mais antiga sai e conta em `dropped`.
    ///
    /// # Errors
    /// [`Error::UnknownService`] e [`Error::LineTooLong`].
    pub fn ingest(&mut self, service: u16, level: Level, text: &str) -> Result<u64, Error> {
        if text.len() > MAX_LINE {
            return Err(Error::LineTooLong);
        }
        let p = self
            .producers
            .get_mut(&service)
            .ok_or(Error::UnknownService)?;
        let seq = self.next_seq;
        self.next_seq += 1;
        p.last_seq = seq;
        if self.records.len() == self.capacity
            && let Some(old) = self.records.pop_front()
        {
            self.dropped += 1;
            if let Some(q) = self.producers.get_mut(&old.service) {
                q.dropped += 1;
            }
            if self.flushed > 0 {
                self.flushed -= 1;
            }
        }
        self.records.push_back(Record {
            seq,
            service,
            level,
            text: String::from(text),
        });
        Ok(seq)
    }

    /// Conta uma linha que o produtor perdeu antes de chegar (anel cheio).
    ///
    /// # Errors
    /// [`Error::UnknownService`].
    pub fn count_lost(&mut self, service: u16, n: u64) -> Result<(), Error> {
        let p = self
            .producers
            .get_mut(&service)
            .ok_or(Error::UnknownService)?;
        p.dropped += n;
        Ok(())
    }

    /// Linhas perdidas de um produtor (no anel ou no buffer).
    #[must_use]
    pub fn lost(&self, service: u16) -> Option<u64> {
        self.producers.get(&service).map(|p| p.dropped)
    }

    /// Últimas `n` linhas que passam pelo filtro, em ordem crescente.
    /// `service` = `None` aceita todos; `max_level` é o nível mais detalhado
    /// aceito.
    #[must_use]
    pub fn query(&self, service: Option<u16>, max_level: Level, n: usize) -> Vec<&Record> {
        let mut out: Vec<&Record> = self
            .records
            .iter()
            .rev()
            .filter(|r| service.is_none_or(|s| r.service == s) && r.level <= max_level)
            .take(n)
            .collect();
        out.reverse();
        out
    }

    /// Linhas ainda não enviadas à serial, em ordem; marca-as como enviadas.
    pub fn drain_serial(&mut self) -> Vec<&Record> {
        let pending = self.records.len().saturating_sub(self.flushed);
        let start = self.records.len() - pending;
        self.flushed = self.records.len();
        self.records.range(start..).collect()
    }

    /// Último `seq` aceito de um produtor.
    #[must_use]
    pub fn last_seq(&self, service: u16) -> Option<u64> {
        self.producers.get(&service).map(|p| p.last_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordem_por_servico_preservada() {
        let mut s = Store::new(1000);
        let a = s.register("a").unwrap();
        let b = s.register("b").unwrap();
        for i in 0..200 {
            s.ingest(a, Level::Info, &alloc::format!("a{i}")).unwrap();
            s.ingest(b, Level::Info, &alloc::format!("b{i}")).unwrap();
        }
        let linhas_a: Vec<u64> = s
            .query(Some(a), Level::Trace, usize::MAX)
            .iter()
            .map(|r| r.seq)
            .collect();
        assert_eq!(linhas_a.len(), 200);
        assert!(linhas_a.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(s.dropped, 0);
    }

    #[test]
    fn buffer_cheio_conta_o_que_sai() {
        let mut s = Store::new(10);
        let a = s.register("a").unwrap();
        for i in 0..25 {
            s.ingest(a, Level::Info, &alloc::format!("{i}")).unwrap();
        }
        assert_eq!(s.dropped, 15);
        assert_eq!(s.lost(a), Some(15));
        let ultimas = s.query(None, Level::Trace, 3);
        assert_eq!(
            ultimas.iter().map(|r| r.text.as_str()).collect::<Vec<_>>(),
            ["22", "23", "24"]
        );
    }

    #[test]
    fn filtra_por_nivel_e_servico() {
        let mut s = Store::new(100);
        let a = s.register("a").unwrap();
        let b = s.register("b").unwrap();
        s.ingest(a, Level::Error, "erro-a").unwrap();
        s.ingest(a, Level::Trace, "trace-a").unwrap();
        s.ingest(b, Level::Info, "info-b").unwrap();
        let so_erros = s.query(None, Level::Error, 10);
        assert_eq!(so_erros.len(), 1);
        assert_eq!(so_erros[0].text, "erro-a");
        assert_eq!(s.query(Some(b), Level::Trace, 10)[0].text, "info-b");
    }

    #[test]
    fn descoberta_e_erros() {
        let mut s = Store::new(4);
        assert_eq!(s.ingest(9, Level::Info, "x"), Err(Error::UnknownService));
        let a = s.register("a").unwrap();
        let grande = "x".repeat(MAX_LINE + 1);
        assert_eq!(s.ingest(a, Level::Info, &grande), Err(Error::LineTooLong));
        assert_eq!(s.name(a), Some("a"));
        assert_eq!(Level::from_u8(7), None);
    }

    #[test]
    fn envio_a_serial_nao_repete() {
        let mut s = Store::new(100);
        let a = s.register("a").unwrap();
        s.ingest(a, Level::Info, "1").unwrap();
        s.ingest(a, Level::Info, "2").unwrap();
        assert_eq!(s.drain_serial().len(), 2);
        assert_eq!(s.drain_serial().len(), 0);
        s.ingest(a, Level::Info, "3").unwrap();
        let t: Vec<&str> = s.drain_serial().iter().map(|r| r.text.as_str()).collect();
        assert_eq!(t, ["3"]);
    }
}
