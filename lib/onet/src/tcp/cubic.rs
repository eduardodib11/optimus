//! CUBIC (RFC 9438) em aritmética inteira (sem ponto flutuante nem `cbrt`):
//! o tempo em milissegundos, a janela em milésimos de segmento.
//!
//! `W(t) = C·(t − K)³ + W_max`, com `C = 0,4` e `β = 0,7`; `K` é o tempo até
//! voltar a `W_max` partindo da janela depois da redução.

/// `β` (redução) e `C`, em milésimos.
const BETA_MILLI: usize = 700;
const C_MILLI: i128 = 400;
/// Ganho da região amigável ao Reno (RFC 9438, 4.3): `3(1−β)/(1+β)`.
const ALPHA_MILLI: usize = 529;

/// Raiz cúbica inteira (piso).
fn icbrt(n: u128) -> u128 {
    let mut x = 0u128;
    let mut bit = 1u128 << 42;
    while bit > 0 {
        let t = x | bit;
        if t * t * t <= n {
            x = t;
        }
        bit >>= 1;
    }
    x
}

/// Estado do CUBIC de uma conexão.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cubic {
    /// `W_max` em bytes.
    w_max: usize,
    /// `W_max` da redução anterior, para a convergência rápida.
    w_last_max: usize,
    /// Início da época (ns); `None` até o primeiro ACK depois de uma perda.
    epoch: Option<u64>,
    /// `K` em ms.
    k_ms: u64,
    /// Janela no início da época, em bytes.
    cwnd_epoch: usize,
    /// Estimativa de um Reno equivalente, em bytes.
    w_est: usize,
}

impl Cubic {
    /// Estado zerado.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            w_max: 0,
            w_last_max: 0,
            epoch: None,
            k_ms: 0,
            cwnd_epoch: 0,
            w_est: 0,
        }
    }

    /// Perda detectada com janela `cwnd`: devolve o novo `ssthresh` (que
    /// também vira a janela). Aplica a convergência rápida.
    pub fn on_loss(&mut self, cwnd: usize, mss: usize) -> usize {
        self.epoch = None;
        self.w_max = if cwnd < self.w_last_max {
            cwnd * (1000 + BETA_MILLI) / 2000
        } else {
            cwnd
        };
        self.w_last_max = cwnd;
        (cwnd * BETA_MILLI / 1000).max(2 * mss)
    }

    /// Volta ao início depois de um RTO: sem memória da curva.
    pub fn on_timeout(&mut self, cwnd: usize, mss: usize) -> usize {
        self.on_loss(cwnd, mss)
    }

    /// `acked` bytes novos confirmados em `now` (ns) com RTT `srtt` (ns):
    /// devolve a janela nova.
    pub fn on_ack(&mut self, cwnd: usize, acked: usize, mss: usize, now: u64, srtt: u64) -> usize {
        let epoch = if let Some(e) = self.epoch {
            e
        } else {
            self.epoch = Some(now);
            self.cwnd_epoch = cwnd;
            self.w_est = cwnd;
            if self.w_max <= cwnd {
                // Sem perda anterior a que voltar: a curva parte daqui.
                self.w_max = cwnd;
                self.k_ms = 0;
            } else {
                let diff_seg_milli = ((self.w_max - cwnd) * 1000 / mss) as u128;
                // K³ = (W_max − cwnd) / C em s³ = diff · 2,5 · 10⁹ ms³.
                self.k_ms =
                    u64::try_from(icbrt(diff_seg_milli * 2_500_000)).unwrap_or(u64::MAX / 2);
            }
            now
        };
        let t_ms = (now - epoch) / 1_000_000 + srtt / 1_000_000;
        let dt = i128::from(t_ms) - i128::from(self.k_ms);
        // W(t) em bytes: 0,4·dt³/10⁹ segmentos, em ms.
        let delta =
            C_MILLI * dt * dt * dt * i128::try_from(mss).unwrap_or(1460) / 1_000 / 1_000_000_000;
        let target = (i128::try_from(self.w_max).unwrap_or(i128::MAX) + delta).max(0);
        let mut target = usize::try_from(target).unwrap_or(usize::MAX);
        // Região amigável ao Reno: nunca cresce menos que ele.
        self.w_est += ALPHA_MILLI * mss / 1000 * acked / cwnd.max(1);
        if self.w_est > target {
            target = self.w_est;
        }
        if target > cwnd {
            // Sobe (alvo − cwnd)/cwnd por segmento confirmado, no máximo
            // 1,5× por RTT (RFC 9438, 4.4).
            let inc = (target - cwnd) * acked / cwnd.max(1);
            cwnd + inc.min(acked / 2 + 1)
        } else {
            // Perto do platô: crescimento mínimo.
            cwnd + mss * acked / (100 * cwnd.max(1))
        }
    }
}
