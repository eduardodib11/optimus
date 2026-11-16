//! Cache de vizinhos do IPv6 (RFC 4861, 5.1): a mesma tabela do ARP, com
//! endereços de 16 bytes. Simplificação consciente: uma entrada resolvida vale
//! por [`crate::arp::TTL_NS`] e depois se pergunta de novo (sem os estados
//! `STALE`, `DELAY` e `PROBE`); a pergunta é a solicitação de vizinho para o
//! endereço de nó solicitado.

use crate::arp::Table;

/// Cache de vizinhos IPv6.
pub type Cache = Table<16>;
