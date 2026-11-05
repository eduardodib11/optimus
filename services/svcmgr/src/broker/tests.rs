use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// Registro das operações: cada `mint` guarda `(src, rights, badge, dest)`.
#[derive(Default)]
struct Fake {
    next: u32,
    endpoints: Vec<Handle>,
    mints: Vec<(Handle, Rights, Badge, Option<Handle>)>,
    deleted: Vec<Handle>,
    /// Falha o `mint` de número `fail_at` (a partir de 0).
    fail_at: Option<usize>,
}

impl Fake {
    fn fresh(&mut self) -> Handle {
        self.next += 1;
        Handle::from_raw(1000 + self.next)
    }

    fn sent_to(&self, child: Handle) -> Vec<(Handle, Rights, Badge)> {
        self.mints
            .iter()
            .filter(|m| m.3 == Some(child))
            .map(|m| (m.0, m.1, m.2))
            .collect()
    }
}

impl Caps for Fake {
    fn create_endpoint(&mut self, _quota: Handle) -> Result<Handle, KError> {
        let h = self.fresh();
        self.endpoints.push(h);
        Ok(h)
    }

    fn mint(
        &mut self,
        src: Handle,
        rights: Rights,
        badge: Badge,
        dest: Option<Handle>,
    ) -> Result<Handle, KError> {
        if self.fail_at == Some(self.mints.len()) {
            return Err(KError::QuotaExceeded);
        }
        self.mints.push((src, rights, badge, dest));
        Ok(self.fresh())
    }

    fn delete(&mut self, h: Handle) -> Result<(), KError> {
        self.deleted.push(h);
        Ok(())
    }
}

const CONTROL: Handle = Handle::from_raw(7);
const QUOTA: Handle = Handle::from_raw(8);
const DEBUG: Handle = Handle::from_raw(9);
const PRESSURE: Handle = Handle::from_raw(10);

fn child(id: u32) -> Handle {
    Handle::from_raw(500 + id)
}

fn manifest(name: &str, needs: &[&str], provides: &[&str]) -> Oman {
    let quote = |v: &[&str]| {
        v.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<String>>()
            .join(",")
    };
    let mut all: Vec<&str> = needs.to_vec();
    all.push("mem:quota:4MiB");
    let src = format!(
        "[service]\nname = \"{name}\"\nbinary = \"svc/{name}\"\npriority = 130\nrestart = \"never\"\n\
         [capabilities]\nneeds = [{}]\nprovides = [{}]\n[limits]\nmax_threads = 2\n",
        quote(&all),
        quote(provides)
    );
    let m = mkmanifest::parse(&src).expect("manifesto de teste");
    oman::parse(&mkmanifest::encode(&m, b"elf").expect("codifica")).expect("lê")
}

/// `timed` (0) provê o relógio, `logd` (1) precisa dele e o `hello` (2)
/// precisa do log e, opcionalmente, do `memd`, que não existe.
fn sistema() -> Broker {
    Broker::new(vec![
        manifest("timed", &["kernel:debug"], &["optimus.time.Clock@1.2"]),
        manifest(
            "logd",
            &["svc:optimus.time.Clock@1.1"],
            &["optimus.log.Log@1.0"],
        ),
        manifest(
            "hello",
            &["svc:optimus.log.Log@1", "svc:optimus.mem.Mem@1?"],
            &[],
        ),
    ])
    .expect("corretor")
}

fn sobe(b: &mut Broker, id: u32, caps: &mut Fake) -> Boot {
    let pool = [("debug", DEBUG), ("mem-pressure", PRESSURE)];
    let boot = b
        .deliver(id, child(id), CONTROL, QUOTA, &pool, caps)
        .expect("entrega");
    b.set_running(id, true);
    boot
}

#[test]
fn interface_id_da_adr_0033() {
    assert_eq!(interface_id("optimus.fs.Directory", 1), 0xA17C_D8BB);
    assert_ne!(
        interface_id("optimus.fs.Directory", 1),
        interface_id("optimus.fs.Directory", 2)
    );
}

#[test]
fn servico_so_recebe_o_que_o_manifesto_lista() {
    let mut b = sistema();
    let mut caps = Fake::default();
    let boot = sobe(&mut b, 0, &mut caps);
    // timed: controle, cota, kernel:debug e o provide. Sem mem-pressure.
    let got = caps.sent_to(child(0));
    let clock_root = caps.endpoints[0];
    assert_eq!(
        got,
        vec![
            (CONTROL, Rights::SEND, badge(0, 1)),
            (QUOTA, QUOTA_RIGHTS, 0),
            (DEBUG, Rights::ALL, 0),
            (clock_root, PROVIDER_RIGHTS, 0),
        ]
    );
    let kinds: Vec<(u8, u16)> = boot.caps.iter().map(|c| (c.kind, c.index)).collect();
    assert_eq!(kinds, vec![(0, 0), (2, QUOTA_INDEX), (5, 0), (6, 0)]);
    assert_eq!(boot.caps[2].name_hash, name_hash("debug"));
    assert_eq!(
        boot.caps[3].name_hash,
        interface_id("optimus.time.Clock", 1)
    );
    assert_eq!(boot.generation, 1);
}

#[test]
fn clientes_recebem_send_com_o_proprio_badge() {
    let mut b = sistema();
    let mut caps = Fake::default();
    sobe(&mut b, 0, &mut caps);
    sobe(&mut b, 1, &mut caps);
    let boot = sobe(&mut b, 2, &mut caps);
    let clock_root = caps.endpoints[0];
    let log_root = caps.endpoints[1];
    assert!(
        caps.sent_to(child(1))
            .contains(&(clock_root, CLIENT_RIGHTS, badge(1, 1)))
    );
    // hello: o log (obrigatório); o memd opcional não existe, fica sem cap.
    let got = caps.sent_to(child(2));
    assert_eq!(
        got,
        vec![
            (CONTROL, Rights::SEND, badge(2, 1)),
            (QUOTA, QUOTA_RIGHTS, 0),
            (log_root, CLIENT_RIGHTS, badge(2, 1)),
        ]
    );
    assert_eq!(boot.caps.len(), 3);
    // Nenhum endpoint vai a um filho sem badge, salvo a cópia do provedor.
    for (src, rights, badge, _) in &caps.mints {
        if *rights != PROVIDER_RIGHTS && *src != QUOTA && *src != DEBUG {
            assert_ne!(*badge, 0);
        }
    }
}

#[test]
fn pedido_fora_do_manifesto_e_access_denied() {
    let mut b = sistema();
    let mut caps = Fake::default();
    sobe(&mut b, 0, &mut caps);
    sobe(&mut b, 1, &mut caps);
    sobe(&mut b, 2, &mut caps);
    let clock = interface_id("optimus.time.Clock", 1);
    let log = interface_id("optimus.log.Log", 1);
    // hello não lista o relógio.
    assert_eq!(
        b.connect(badge(2, 1), clock, 0, &mut caps),
        Err(SvcError::NotInManifest)
    );
    // Badge que não é de serviço.
    assert_eq!(
        b.connect(badge(99, 1), clock, 0, &mut caps),
        Err(SvcError::NotInManifest)
    );
    // Reconexão ao que está listado: SEND com o badge do cliente, no svcmgr.
    let before = caps.mints.len();
    assert!(b.connect(badge(2, 1), log, 0, &mut caps).is_ok());
    assert_eq!(
        caps.mints[before],
        (caps.endpoints[1], CLIENT_RIGHTS, badge(2, 1), None)
    );
    // Versão menor acima da do provedor.
    assert_eq!(
        b.connect(badge(1, 1), clock, 3, &mut caps),
        Err(SvcError::VersionTooOld)
    );
    assert!(b.connect(badge(1, 1), clock, 2, &mut caps).is_ok());
    // Opcional listado, mas sem provedor.
    let mem = interface_id("optimus.mem.Mem", 1);
    assert_eq!(
        b.connect(badge(2, 1), mem, 0, &mut caps),
        Err(SvcError::NotRunning)
    );
}

#[test]
fn reinicio_troca_a_geracao_e_recusa_o_badge_velho() {
    let mut b = sistema();
    let mut caps = Fake::default();
    sobe(&mut b, 0, &mut caps);
    sobe(&mut b, 1, &mut caps);
    let clock = interface_id("optimus.time.Clock", 1);
    // O provedor morre: raízes para revogar, e o cliente vê NotRunning.
    assert_eq!(b.retire(0), vec![caps.endpoints[0]]);
    assert_eq!(
        b.connect(badge(1, 1), clock, 0, &mut caps),
        Err(SvcError::NotRunning)
    );
    let boot = sobe(&mut b, 0, &mut caps);
    assert_eq!(boot.generation, 2);
    assert!(b.connect(badge(1, 1), clock, 0, &mut caps).is_ok());
    // O cliente reinicia: o badge da instância anterior deixa de valer.
    b.retire(1);
    assert_eq!(b.badge_of(1), Some(badge(1, 2)));
    assert_eq!(
        b.connect(badge(1, 1), clock, 0, &mut caps),
        Err(SvcError::NotRunning)
    );
    // A geração dá a volta sem passar por zero.
    for _ in 0..u32::from(u16::MAX) {
        b.retire(2);
    }
    assert_eq!(b.badge_of(2), Some(badge(2, 1)));
}

#[test]
fn recusas_antes_de_qualquer_syscall() {
    let mut b = Broker::new(vec![
        manifest("a", &["svc:optimus.b.B@1"], &[]),
        manifest("b", &["kernel:mem-pressure"], &["optimus.b.B@1.0"]),
        manifest("c", &["dev:net/*"], &[]),
    ])
    .expect("corretor");
    let mut caps = Fake::default();
    let pool = [("debug", DEBUG)];
    let mut tenta = |b: &mut Broker, id| b.deliver(id, child(id), CONTROL, QUOTA, &pool, &mut caps);
    assert_eq!(tenta(&mut b, 0), Err(DeliverError::NotRunning));
    assert_eq!(tenta(&mut b, 1), Err(DeliverError::MissingKernelCap));
    assert_eq!(tenta(&mut b, 2), Err(DeliverError::NotSupported));
    assert_eq!(tenta(&mut b, 3), Err(DeliverError::NoSuchService));
    assert!(caps.mints.is_empty() && caps.endpoints.is_empty());
}

#[test]
fn falha_no_meio_apaga_as_raizes() {
    let mut b = Broker::new(vec![manifest(
        "a",
        &[],
        &["optimus.a.A@1.0", "optimus.a.B@1.0"],
    )])
    .expect("corretor");
    // Mints: controle, cota, provide A; o do provide B falha.
    let mut caps = Fake {
        fail_at: Some(3),
        ..Fake::default()
    };
    assert_eq!(
        b.deliver(0, child(0), CONTROL, QUOTA, &[], &mut caps),
        Err(DeliverError::Kernel(KError::QuotaExceeded))
    );
    assert_eq!(caps.deleted, caps.endpoints);
    assert_eq!(caps.deleted.len(), 2);
    // Pode tentar de novo: nada ficou preso no corretor.
    caps.fail_at = None;
    assert!(
        b.deliver(0, child(0), CONTROL, QUOTA, &[], &mut caps)
            .is_ok()
    );
    assert_eq!(
        b.deliver(0, child(0), CONTROL, QUOTA, &[], &mut caps),
        Err(DeliverError::Busy)
    );
}

#[test]
fn provedor_duplicado_e_recusado() {
    let r = Broker::new(vec![
        manifest("a", &[], &["optimus.x.X@1.0"]),
        manifest("b", &[], &["optimus.x.X@1.1"]),
    ]);
    assert!(matches!(r, Err(DeliverError::DuplicateProvider)));
}
