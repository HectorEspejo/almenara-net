//! Descubrimiento mDNS/DNS-SD (Fase 2).
//!
//! Incluye el parser de respuestas DNS, el listener pasivo del grupo multicast
//! 224.0.0.251:5353 y el browse activo de _services._dns-sd._udp.local.

pub mod listener;
pub mod parser;
pub mod query;

pub use listener::MdnsListener;
pub use parser::MdnsRecord;
// La integración del escáner todavía no nombra este tipo, pero forma parte de
// la API pública acordada; en un crate binario hay que silenciar el aviso de
// importación sin usar (solo lo usan los tests).
#[allow(unused_imports)]
pub use parser::MdnsService;
pub use query::MdnsQuery;
