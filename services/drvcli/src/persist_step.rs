//! Cenário de integração do armazenamento (T-540): o `drvcli`, no papel do
//! `optfs`, monta um volume cifrado numa partição `cifra`. No primeiro boot
//! o `keyd` cria o volume (a senha vai pelo console), o cliente grava o
//! cabeçalho com os keyslots no bloco 0 e um arquivo cifrado. No segundo boot
//! (o `xtask` reaproveita o disco) o `keyd` desbloqueia o mesmo cabeçalho, o
//! volume monta numa época nova e o conteúdo da época anterior volta igual.
//!
//! O contrato do `keyd` devolve `K_cab ‖ K_meta ‖ K_nome`; a chave dos dados
//! do dataset sai de `K_meta` por HKDF (o contrato não devolve `K_ds` ainda).

use super::keyd_cliente::KeyringCliente;
use super::optfs_step::{QueueIo, Sha};
use super::{Fila, PAGE};
use optcrypt::chacha20::KEY_LEN;
use optcrypt::keyring::{header_mac, header_verify, to_hex};
use optcrypt::secret::Secret;
use optfs::{Allocator, BlockIo, Fs, Tx, VolumeCipher, mount};
use optfs_format::{BlockPtr, Integrity, SUPERBLOCKS, Superblock};
use ostd::vec::Vec;

const MAGIC: &[u8; 8] = b"OPTFSVH1";
const UUID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const UUID_HEX: &str = "0102030405060708090a0b0c0d0e0f10";
const SLOTS_LEN: usize = 202;
const SALT: usize = 32;
/// Épocas que o cabeçalho comporta (o teste usa duas).
const MAX_EPOCHS: usize = 8;
/// Texto que não pode aparecer em claro no disco (o `xtask` procura).
pub const SEGREDO: &[u8] = b"segredo-do-usuario-optfs-cifrado-T540";
const FILE_LEN: usize = 5000;

fn corpo(seed: u8) -> Vec<u8> {
    let mut v: Vec<u8> = (0..FILE_LEN)
        .map(|i| (i as u8).wrapping_mul(5).wrapping_add(seed))
        .collect();
    v[..SEGREDO.len()].copy_from_slice(SEGREDO);
    v
}

/// Cabeçalho do volume no bloco 0 (ADR 0053, item 3, versão do teste).
struct Header {
    slots: [u8; SLOTS_LEN],
    epochs: Vec<(u32, [u8; SALT])>,
}

impl Header {
    /// Tudo menos o MAC: magic, UUID, slots, nº de épocas e épocas.
    fn body(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(MAGIC);
        b.extend_from_slice(&UUID);
        b.extend_from_slice(&self.slots);
        b.extend_from_slice(&(self.epochs.len() as u32).to_le_bytes());
        for (e, s) in &self.epochs {
            b.extend_from_slice(&e.to_le_bytes());
            b.extend_from_slice(s);
        }
        b
    }

    #[allow(
        clippy::many_single_char_names,
        reason = "deslocamentos curtos do formato"
    )]
    fn parse(b: &[u8; PAGE]) -> Option<(Self, [u8; 32])> {
        if &b[..8] != MAGIC || b[8..24] != UUID {
            return None;
        }
        let mut slots = [0u8; SLOTS_LEN];
        slots.copy_from_slice(&b[24..24 + SLOTS_LEN]);
        let at = 24 + SLOTS_LEN;
        let n = u32::from_le_bytes(b[at..at + 4].try_into().ok()?) as usize;
        if n > MAX_EPOCHS {
            return None;
        }
        let mut epochs = Vec::new();
        let mut p = at + 4;
        for _ in 0..n {
            let e = u32::from_le_bytes(b[p..p + 4].try_into().ok()?);
            let mut s = [0u8; SALT];
            s.copy_from_slice(&b[p + 4..p + 4 + SALT]);
            epochs.push((e, s));
            p += 4 + SALT;
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&b[p..p + 32]);
        Some((Self { slots, epochs }, mac))
    }

    fn encode(&self, cab: &Secret<KEY_LEN>) -> [u8; PAGE] {
        let body = self.body();
        let mut b = [0u8; PAGE];
        b[..body.len()].copy_from_slice(&body);
        b[body.len()..body.len() + 32].copy_from_slice(&header_mac(cab, &body));
        b
    }
}

fn secret(b: &[u8]) -> Option<Secret<KEY_LEN>> {
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(b.get(..KEY_LEN)?);
    Some(Secret::take(&mut k))
}

/// Chave dos dados: HKDF de `K_meta` com o UUID (o contrato do `keyd` ainda
/// não devolve `K_ds`).
fn data_key(meta: &[u8]) -> Option<Secret<KEY_LEN>> {
    let prk = optcrypt::hkdf::extract(&UUID, meta);
    optcrypt::hkdf::expand_secret::<KEY_LEN>(&prk, b"optimus/optfs/v1/ds").ok()
}

/// Gravação do primeiro boot ou conferência do segundo. `None` em qualquer
/// divergência.
#[inline(never)]
#[allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    reason = "cenário linear de teste: um passo por linha"
)]
pub fn run(
    f: &mut Fila,
    blocks: u64,
    keyring: &KeyringCliente,
    buf: &mut ostd::ipc::Buffer,
) -> Option<()> {
    let h = Sha;
    let mut io = QueueIo::new(f, blocks);
    let mut raw = [0u8; PAGE];
    io.read(0, &mut raw).ok()?;
    let parsed = Header::parse(&raw);
    let first = parsed.is_none();
    let (mut header, old_mac) = if let Some((hd, m)) = parsed {
        (hd, Some(m))
    } else {
        {
            let slots = keyring.create_volume(buf, UUID_HEX).ok()?.ok()?;
            let mut s = [0u8; SLOTS_LEN];
            s.copy_from_slice(slots.as_slice().get(..SLOTS_LEN)?);
            (
                Header {
                    slots: s,
                    epochs: Vec::new(),
                },
                None,
            )
        }
    };
    let mut hex = [0u8; SLOTS_LEN * 2];
    let n = to_hex(&header.slots, &mut hex);
    let keys = keyring
        .unlock(buf, UUID_HEX, core::str::from_utf8(&hex[..n]).ok()?)
        .ok()?
        .ok()?;
    let k = keys.as_slice();
    let cab = secret(&k[..32])?;
    let meta_key = &k[32..64];
    let nome = k.get(64..96)?;
    let mut name_key = [0u8; 32];
    name_key.copy_from_slice(nome);
    if let Some(mac) = old_mac {
        // Cabeçalho adulterado: o volume não monta.
        let body_len = header.body().len();
        header_verify(&cab, &raw[..body_len], &mac).ok()?;
    }
    // Época nova a cada boot: sal aleatório gravado antes de qualquer bloco
    // dela (ADR 0053, item 2).
    let epoch = header.epochs.last().map_or(1, |(e, _)| e + 1);
    let mut salt = [0u8; SALT];
    ostd::rand::secure_fill(&mut salt).ok()?;
    if header.epochs.len() >= MAX_EPOCHS {
        return None;
    }
    header.epochs.push((epoch, salt));
    io.write(0, &header.encode(&cab)).ok()?;
    io.flush().ok()?;
    let make_cipher = || {
        let mut c = VolumeCipher::new(
            UUID,
            0,
            secret(meta_key)?,
            data_key(meta_key)?,
            epoch,
            &salt,
        );
        for (e, s) in &header.epochs {
            c.add_epoch(*e, s);
        }
        Some(c)
    };
    let mut cipher = make_cipher()?;
    if first {
        let s1 = Superblock {
            uuid: UUID,
            txg: 1,
            integrity: Integrity::Aead,
            root: BlockPtr::null(),
            volume_blocks: blocks,
            epochs: 1,
            free_blocks: blocks,
        };
        io.write(SUPERBLOCKS[1], &s1.encode(&h)).ok()?;
        io.flush().ok()?;
        let mut al = Allocator::new(blocks);
        let mut tx = Tx::new(&mut io, &h, &mut al, 2, 1).with_cipher(&mut cipher);
        let mut fs = Fs::create(&mut tx, name_key).ok()?;
        let file = fs.create_file(&mut tx, 1, "segredo.txt").ok()?;
        fs.write(&mut tx, file, 0, &corpo(1)).ok()?;
        let mut new = s1;
        new.root = fs.root;
        new.free_blocks = tx.free_blocks();
        tx.commit(&s1, new).ok()?;
        ostd::debug::print("drvcli: optfs cifrado: gravado");
        return Some(());
    }
    // Segundo boot: monta, confere o arquivo da época 1 e grava outro na
    // época nova.
    let m = mount(&mut io, &h).ok()?;
    if m.sb.integrity != Integrity::Aead {
        return None;
    }
    let mut al = Allocator::new(blocks);
    let mut tx = Tx::new(&mut io, &h, &mut al, m.sb.txg + 1, 1).with_cipher(&mut cipher);
    tx.mark_reachable(&[m.sb.root]).ok()?;
    let mut fs = Fs::from_root(m.sb.root, name_key);
    let (file, _) = fs.lookup(&mut tx, 1, "segredo.txt").ok()??;
    if fs.read(&mut tx, file, 0, FILE_LEN).ok()? != corpo(1) {
        return None;
    }
    ostd::debug::print("drvcli: optfs cifrado: relido igual");
    let novo = fs.create_file(&mut tx, 1, "depois.txt").ok()?;
    fs.write(&mut tx, novo, 0, &corpo(2)).ok()?;
    let mut new = m.sb;
    new.root = fs.root;
    new.epochs = epoch;
    new.free_blocks = tx.free_blocks();
    let sb = tx.commit(&m.sb, new).ok()?;
    // Remonta: os dois arquivos (épocas 1 e 2) voltam do disco.
    let m = mount(&mut io, &h).ok()?;
    let mut cipher = make_cipher()?;
    let mut al = Allocator::new(blocks);
    let mut tx = Tx::new(&mut io, &h, &mut al, sb.txg + 1, 1).with_cipher(&mut cipher);
    let fs = Fs::from_root(m.sb.root, name_key);
    let (a, _) = fs.lookup(&mut tx, 1, "segredo.txt").ok()??;
    let (b, _) = fs.lookup(&mut tx, 1, "depois.txt").ok()??;
    if m.sb.txg != sb.txg
        || fs.read(&mut tx, a, 0, FILE_LEN).ok()? != corpo(1)
        || fs.read(&mut tx, b, 0, FILE_LEN).ok()? != corpo(2)
    {
        return None;
    }
    ostd::debug::print("drvcli: optfs cifrado: duas épocas lidas");
    Some(())
}
