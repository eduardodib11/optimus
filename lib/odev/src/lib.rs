//! `odev`: nós de dispositivo e casamento com drivers (ADR 0042, itens 2 e
//! 3; T-401). Núcleo do `devmgr`, sem syscalls.
//!
//! O casamento pontua cada regra do manifesto do driver contra o nó:
//! id `vendor:device` exato vale 3, classe com subclasse e `prog_if` vale 2,
//! classe com subclasse (sem `prog_if`) vale 1 e `compatible` vale 1. O
//! driver de maior pontuação vence; empate entre drivers distintos é erro e
//! nenhum é carregado.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Barramento de origem do nó.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    /// PCI Express.
    Pci,
    /// Descrito pelo ACPI.
    Acpi,
}

/// Classe PCI de um nó.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Class {
    /// Código de classe.
    pub class: u8,
    /// Subclasse.
    pub subclass: u8,
    /// Interface de programação.
    pub prog_if: u8,
}

/// Nó de dispositivo publicado ao `devmgr`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Id estável do nó.
    pub id: u32,
    /// Barramento.
    pub bus: Bus,
    /// Vendor e device PCI, quando houver.
    pub pci_id: Option<(u16, u16)>,
    /// Classe, quando houver.
    pub class: Option<Class>,
    /// Strings `compatible` (por exemplo `_HID` do ACPI).
    pub compatible: Vec<String>,
}

/// Regra de casamento de um manifesto de driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// `vendor:device` exato.
    Pci(u16, u16),
    /// Classe e subclasse; `prog_if` opcional.
    Class(u8, u8, Option<u8>),
    /// String `compatible`.
    Compatible(String),
}

/// Driver candidato: nome e regras.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Driver {
    /// Nome do driver (serviço no bootfs).
    pub name: String,
    /// Regras `[match]`.
    pub rules: Vec<Rule>,
}

/// Resultado do casamento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// Nenhum driver casa.
    None,
    /// Este driver vence.
    Driver(&'a Driver),
    /// Dois drivers distintos empatam na maior pontuação: erro do manifesto.
    Tie(&'a Driver, &'a Driver),
}

/// Pontuação de uma regra contra o nó (0 = não casa).
#[must_use]
pub fn score_rule(rule: &Rule, node: &Node) -> u8 {
    match rule {
        Rule::Pci(v, d) => {
            if node.pci_id == Some((*v, *d)) {
                3
            } else {
                0
            }
        }
        Rule::Class(c, s, pi) => match node.class {
            Some(k) if k.class == *c && k.subclass == *s => match pi {
                Some(p) if *p == k.prog_if => 2,
                Some(_) => 0,
                None => 1,
            },
            _ => 0,
        },
        Rule::Compatible(name) => u8::from(node.compatible.iter().any(|c| c == name)),
    }
}

/// Maior pontuação de um driver contra o nó (0 = não casa).
#[must_use]
pub fn score(driver: &Driver, node: &Node) -> u8 {
    driver
        .rules
        .iter()
        .map(|r| score_rule(r, node))
        .max()
        .unwrap_or(0)
}

/// Escolhe o driver mais específico para o nó.
#[must_use]
pub fn best_match<'a>(drivers: &'a [Driver], node: &Node) -> Outcome<'a> {
    let mut best: Option<(&Driver, u8)> = None;
    let mut tie: Option<&Driver> = None;
    for d in drivers {
        let s = score(d, node);
        if s == 0 {
            continue;
        }
        match best {
            None => best = Some((d, s)),
            Some((_, b)) if s > b => {
                best = Some((d, s));
                tie = None;
            }
            Some((_, b)) if s == b => tie = Some(d),
            Some(_) => {}
        }
    }
    match (best, tie) {
        (None, _) => Outcome::None,
        (Some((d, _)), None) => Outcome::Driver(d),
        (Some((d, _)), Some(t)) => Outcome::Tie(d, t),
    }
}

#[cfg(test)]
mod tests;
