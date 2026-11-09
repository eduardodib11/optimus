use super::*;
use alloc::string::ToString;
use alloc::vec;

fn blk_node() -> Node {
    Node {
        id: 1,
        bus: Bus::Pci,
        pci_id: Some((0x1af4, 0x1042)),
        class: Some(Class {
            class: 1,
            subclass: 0,
            prog_if: 0,
        }),
        compatible: vec![],
    }
}

fn drv(name: &str, rules: Vec<Rule>) -> Driver {
    Driver {
        name: name.to_string(),
        rules,
    }
}

#[test]
fn casa_o_driver_certo_e_nao_o_errado() {
    let drivers = [
        drv("virtio-net", vec![Rule::Pci(0x1af4, 0x1041)]),
        drv("virtio-blk", vec![Rule::Pci(0x1af4, 0x1042)]),
    ];
    match best_match(&drivers, &blk_node()) {
        Outcome::Driver(d) => assert_eq!(d.name, "virtio-blk"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn id_exato_vence_classe() {
    let drivers = [
        drv("generico", vec![Rule::Class(1, 0, None)]),
        drv("especifico", vec![Rule::Pci(0x1af4, 0x1042)]),
    ];
    match best_match(&drivers, &blk_node()) {
        Outcome::Driver(d) => assert_eq!(d.name, "especifico"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn prog_if_pesa_mais_que_classe_sozinha() {
    let drivers = [
        drv("a", vec![Rule::Class(1, 0, None)]),
        drv("b", vec![Rule::Class(1, 0, Some(0))]),
    ];
    match best_match(&drivers, &blk_node()) {
        Outcome::Driver(d) => assert_eq!(d.name, "b"),
        o => panic!("{o:?}"),
    }
}

#[test]
fn prog_if_diferente_nao_casa() {
    let drivers = [drv("a", vec![Rule::Class(1, 0, Some(5))])];
    assert_eq!(best_match(&drivers, &blk_node()), Outcome::None);
}

#[test]
fn empate_e_erro_e_nenhum_carrega() {
    let drivers = [
        drv("a", vec![Rule::Pci(0x1af4, 0x1042)]),
        drv("b", vec![Rule::Pci(0x1af4, 0x1042)]),
    ];
    assert!(matches!(
        best_match(&drivers, &blk_node()),
        Outcome::Tie(..)
    ));
}

#[test]
fn compatible_casa_no_acpi() {
    let node = Node {
        id: 2,
        bus: Bus::Acpi,
        pci_id: None,
        class: None,
        compatible: vec!["PNP0B00".to_string()],
    };
    let drivers = [drv("rtc", vec![Rule::Compatible("PNP0B00".to_string())])];
    assert!(matches!(best_match(&drivers, &node), Outcome::Driver(_)));
    assert_eq!(best_match(&drivers, &blk_node()), Outcome::None);
}

#[test]
fn sem_drivers_nao_casa() {
    assert_eq!(best_match(&[], &blk_node()), Outcome::None);
}
