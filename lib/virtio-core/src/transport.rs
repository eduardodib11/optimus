//! Configuração comum: reset, negociação de features e ativação de filas.

use crate::{DmaBuf, Error, Mmio, Queue};

/// Bits do `device_status`.
pub mod status {
    /// O SO reconheceu o dispositivo.
    pub const ACKNOWLEDGE: u8 = 1;
    /// O SO sabe dirigi-lo.
    pub const DRIVER: u8 = 2;
    /// O driver está pronto.
    pub const DRIVER_OK: u8 = 4;
    /// A negociação de features terminou.
    pub const FEATURES_OK: u8 = 8;
    /// O dispositivo precisa de reset.
    pub const NEEDS_RESET: u8 = 64;
    /// O driver desistiu.
    pub const FAILED: u8 = 128;
}

/// Bit 32: dispositivo moderno (1.0+).
pub const F_VERSION_1: u64 = 1 << 32;
/// Bit 33: o dispositivo respeita a tradução da IOMMU.
pub const F_ACCESS_PLATFORM: u64 = 1 << 33;

const DEVICE_FEATURE_SELECT: usize = 0;
const DEVICE_FEATURE: usize = 4;
const DRIVER_FEATURE_SELECT: usize = 8;
const DRIVER_FEATURE: usize = 12;
const MSIX_CONFIG: usize = 16;
const NUM_QUEUES: usize = 18;
const DEVICE_STATUS: usize = 20;
const QUEUE_SELECT: usize = 22;
const QUEUE_SIZE: usize = 24;
const QUEUE_MSIX_VECTOR: usize = 26;
const QUEUE_ENABLE: usize = 28;
const QUEUE_NOTIFY_OFF: usize = 30;
const QUEUE_DESC: usize = 32;
const QUEUE_DRIVER: usize = 40;
const QUEUE_DEVICE: usize = 48;

/// Sem vetor MSI-X.
pub const NO_VECTOR: u16 = 0xFFFF;
const RESET_POLLS: u32 = 1000;

/// A configuração comum de um dispositivo.
pub struct Transport<M: Mmio> {
    common: M,
    features: u64,
}

impl<M: Mmio> Transport<M> {
    /// `common` é a região de configuração comum já mapeada.
    pub const fn new(common: M) -> Self {
        Self {
            common,
            features: 0,
        }
    }

    /// Features aceitas na última [`negotiate`](Self::negotiate).
    pub const fn features(&self) -> u64 {
        self.features
    }

    /// Número de filas que o dispositivo declara.
    pub fn num_queues(&self) -> u16 {
        self.common.read16(NUM_QUEUES)
    }

    /// Status atual.
    pub fn status(&self) -> u8 {
        self.common.read8(DEVICE_STATUS)
    }

    fn device_features(&self) -> u64 {
        self.common.write32(DEVICE_FEATURE_SELECT, 0);
        let lo = u64::from(self.common.read32(DEVICE_FEATURE));
        self.common.write32(DEVICE_FEATURE_SELECT, 1);
        let hi = u64::from(self.common.read32(DEVICE_FEATURE));
        lo | hi << 32
    }

    /// Reset, `ACKNOWLEDGE`, `DRIVER` e negociação. Aceita só `VERSION_1` e o
    /// que estiver em `wanted` e o dispositivo oferecer; `required` é o que
    /// não pode faltar (ex.: `F_ACCESS_PLATFORM` com IOMMU).
    ///
    /// # Errors
    /// [`Error::ResetTimeout`], [`Error::NoVersion1`] ou
    /// [`Error::FeaturesRejected`]; nos dois últimos o status vira `FAILED`.
    pub fn negotiate(&mut self, wanted: u64, required: u64) -> Result<u64, Error> {
        self.common.write8(DEVICE_STATUS, 0);
        let mut polls = 0;
        while self.status() != 0 {
            polls += 1;
            if polls > RESET_POLLS {
                return Err(Error::ResetTimeout);
            }
        }
        self.common.write8(DEVICE_STATUS, status::ACKNOWLEDGE);
        self.common
            .write8(DEVICE_STATUS, status::ACKNOWLEDGE | status::DRIVER);
        let offered = self.device_features();
        let want = (wanted | F_VERSION_1 | required) & offered;
        let fail = |t: &Self, e| {
            t.common.write8(DEVICE_STATUS, status::FAILED);
            Err(e)
        };
        if offered & F_VERSION_1 == 0 {
            return fail(self, Error::NoVersion1);
        }
        if want & required != required {
            return fail(self, Error::FeaturesRejected);
        }
        self.common.write32(DRIVER_FEATURE_SELECT, 0);
        self.common.write32(DRIVER_FEATURE, want as u32);
        self.common.write32(DRIVER_FEATURE_SELECT, 1);
        self.common.write32(DRIVER_FEATURE, (want >> 32) as u32);
        let s = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK;
        self.common.write8(DEVICE_STATUS, s);
        if self.status() & status::FEATURES_OK == 0 {
            return fail(self, Error::FeaturesRejected);
        }
        self.features = want;
        Ok(want)
    }

    /// Escolhe o vetor MSI-X da configuração (`NO_VECTOR` desliga).
    ///
    /// # Errors
    /// [`Error::NoVector`] se o dispositivo não guardou o vetor.
    pub fn set_config_vector(&self, v: u16) -> Result<(), Error> {
        self.common.write16(MSIX_CONFIG, v);
        if self.common.read16(MSIX_CONFIG) == v {
            Ok(())
        } else {
            Err(Error::NoVector)
        }
    }

    /// Configura e habilita a fila `index` sobre `dma`. Devolve a fila e o
    /// deslocamento de notificação (`queue_notify_off`).
    ///
    /// # Errors
    /// [`Error::BadQueue`], [`Error::DmaTooSmall`] ou [`Error::NoVector`].
    pub fn setup_queue<D: DmaBuf, const N: usize>(
        &self,
        index: u16,
        dma: D,
        vector: u16,
    ) -> Result<(Queue<D, N>, u16), Error> {
        self.common.write16(QUEUE_SELECT, index);
        let max = usize::from(self.common.read16(QUEUE_SIZE));
        if max == 0 || N > max {
            return Err(Error::BadQueue);
        }
        let q = Queue::<D, N>::new(dma)?;
        self.common.write16(QUEUE_SIZE, N as u16);
        let (d, a, u) = q.addrs();
        for (off, v) in [(QUEUE_DESC, d), (QUEUE_DRIVER, a), (QUEUE_DEVICE, u)] {
            self.common.write32(off, v as u32);
            self.common.write32(off + 4, (v >> 32) as u32);
        }
        self.common.write16(QUEUE_MSIX_VECTOR, vector);
        if self.common.read16(QUEUE_MSIX_VECTOR) != vector {
            return Err(Error::NoVector);
        }
        let notify_off = self.common.read16(QUEUE_NOTIFY_OFF);
        self.common.write16(QUEUE_ENABLE, 1);
        Ok((q, notify_off))
    }

    /// Marca `DRIVER_OK`: o dispositivo pode começar a operar.
    pub fn driver_ok(&self) {
        let s = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK;
        self.common.write8(DEVICE_STATUS, s);
    }
}
