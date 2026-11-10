//! Descubrimiento SSDP/UPnP (Fase 2).
//!
//! Incluye el parser de mensajes HTTPU, el listener pasivo del grupo multicast
//! 239.255.255.250:1900, el M-SEARCH activo y la descarga del XML de descripción.

pub mod listener;
pub mod parser;
pub mod query;

pub use listener::SsdpListener;
pub use parser::{SsdpRecord, UpnpDescription};
// Tipo público del contrato que la integración actual aún no nombra; en un
// crate binario hay que silenciar el aviso de importación sin usar.
#[allow(unused_imports)]
pub use parser::SsdpMessageType;
pub use query::SsdpQuery;
