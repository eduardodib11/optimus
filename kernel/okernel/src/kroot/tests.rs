//! Testes de kernel do bootfs e do `root` (T-211).

use super::{ROOT_NAME, bootfs, load, run_until_exit};
use crate::kcap::root_quota;
use crate::ktest::{Outcome, Test};
use crate::kthread::take_debug_log;

/// Testes de kernel do bootfs.
pub const TESTS: &[Test] = &[
    Test {
        name: "bootfs.entregue_e_verificado",
        run: entregue,
    },
    Test {
        name: "bootfs.root_inicia_a_partir_do_bootfs",
        run: root_inicia,
    },
];

fn entregue() -> Outcome {
    let image = bootfs().ok_or("sem bootfs na BootInfo")?;
    let fs = obfs::Image::parse(image).map_err(|_| "bootfs inválido")?;
    ensure!(fs.verify().is_ok());
    let root = fs.find(ROOT_NAME).ok_or("sem root")?;
    ensure!(oelf::Elf::parse_user(root.data).is_ok());
    ensure!(oelf::Elf::parse(root.data).is_err());
    info!(
        "ktest: · bootfs de {} KiB com {} entradas; root com {} bytes",
        image.len() >> 10,
        fs.len(),
        root.data.len()
    );
    Ok(())
}

/// Aceite do T-211: o `root` do bootfs roda no anel 3 e se anuncia.
fn root_inicia() -> Outcome {
    let quota = root_quota().ok_or("sem cota raiz")?;
    let used0 = quota.used();
    {
        let image = bootfs().ok_or("sem bootfs")?;
        let _ = take_debug_log();
        let p = load(image)?;
        ensure!(run_until_exit(&p.thread, 5_000_000_000));
        let (log, len) = take_debug_log();
        let text = core::str::from_utf8(&log[..len]).unwrap_or("?");
        info!("ktest: · o root imprimiu \"{text}\"");
        ensure!(text == "root: iniciado");
        // Quebra o ciclo thread ↔ CapSpace e devolve tudo à cota.
        let [_, _, thread] = p.handles;
        drop(p.cspace.lock().delete(thread));
    }
    ensure!(quota.used() == used0);
    Ok(())
}
