//! Eventos nuevos de la reconciliación de F5 (§7.7): presencia, servicios e
//! identidad.
//!
//! Este módulo contiene solo tipos y funciones puras: no abren SQLite ni leen el
//! reloj, salvo el instante que reciben por parámetro. La persistencia la hace
//! `scanner::reconcile` con `Repo::append_event` y las consultas de apoyo
//! (servicios conocidos y último evento de cada puerto) las resuelve el DAO, de
//! modo que las reglas de aquí se pueden probar sin base de datos.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use serde_json::{json, Value};

use crate::classify::DeviceType;
use crate::discovery::DetectedService;
use crate::repo::events::EventType;
use crate::repo::{rfc3339_a_instante, Device, DeviceService, Protocol};

/// Evento nuevo listo para persistirse en DEVICE_EVENTS (tabla de F1).
///
/// El tipo se guarda como TEXT sin CHECK (ADR-61) y se valida en código; los
/// detalles siguen el formato JSON de §7.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewEvent {
    /// Tipo de evento.
    pub tipo: EventType,
    /// Detalles JSON de §7.7.
    pub details: Value,
}

/// Cálculo de los eventos nuevos que añade la reconciliación de F5 (§7.7).
///
/// Se agrupan en tres funciones puras que el reconciliador llama en este orden:
/// [`Changes::presence`], [`Changes::services`] y [`Changes::identity`].
pub struct Changes;

impl Changes {
    /// Evento `reappeared` si un equipo que estaba OFFLINE vuelve a verse.
    ///
    /// `antes` es el equipo tal como estaba persistido antes del ciclo (su
    /// `last_seen` es la última vez que se le vio) y `visto` indica si ha
    /// aparecido en el ciclo actual. La transición OFFLINE → ONLINE ya la decide
    /// F1 con `ChangeSet::became_online`; esta función solo construye el evento
    /// y calcula la ausencia.
    ///
    /// Detalles: `away_since` (el `last_seen` anterior) y `away_s` (segundos
    /// transcurridos hasta `ahora`). Si `last_seen` estuviera corrupto o en el
    /// futuro, `away_s` vale 0 y el evento se emite igual: la transición es lo
    /// importante para la presencia.
    pub fn presence(antes: &Device, visto: bool, ahora: SystemTime) -> Option<NewEvent> {
        if !visto || antes.is_online {
            return None;
        }
        let away_s = rfc3339_a_instante(&antes.last_seen)
            .and_then(|ultima_vez| ahora.duration_since(ultima_vez).ok())
            .map(|ausencia| ausencia.as_secs())
            .unwrap_or(0);
        Some(NewEvent {
            tipo: EventType::Reappeared,
            details: json!({
                "away_since": &antes.last_seen,
                "away_s": away_s,
            }),
        })
    }

    /// Eventos de servicios de un escaneo de puertos real (§7.7).
    ///
    /// Reglas:
    ///
    /// - Sin eventos en el primer escaneo del equipo (`ya_escaneado = false`:
    ///   es su línea base) ni con `passive_only` (no hay escaneo).
    /// - `service_new` al ver abierto un puerto que no estaba en
    ///   DEVICE_SERVICES (`reopened = false`) o que estaba CERRADO
    ///   (`reopened = true`).
    /// - `service_gone` al ver cerrado un puerto que estaba abierto.
    /// - Un puerto que solo está STALE por tiempo no está en
    ///   `puertos_escaneados` (no se ha escaneado en este ciclo) y, por tanto,
    ///   nunca genera evento.
    ///
    /// El estado CERRADO es el último evento de servicio del puerto: tras un
    /// `service_gone` el puerto sigue cerrado hasta un `service_new`.
    /// `ultimos_eventos` trae el tipo del último evento de cada puerto TCP (el
    /// DAO lo consulta antes de escribir los servicios del ciclo) y así no se
    /// duplica `service_gone` en escaneos sucesivos.
    ///
    /// `puertos_escaneados` son los puertos TCP que ha intentado el escaneo y
    /// `abiertos` solo los que han respondido; la diferencia son los cerrados.
    pub fn services(
        ya_escaneado: bool,
        passive_only: bool,
        puertos_escaneados: &[u16],
        abiertos: &[DetectedService],
        conocidos: &[DeviceService],
        ultimos_eventos: &HashMap<u16, EventType>,
    ) -> Vec<NewEvent> {
        if passive_only || !ya_escaneado {
            return Vec::new();
        }

        let escaneados: HashSet<u16> = puertos_escaneados.iter().copied().collect();
        let mut eventos = Vec::new();

        // Puertos abiertos: nuevos (no estaban) o reabiertos (estaban cerrados).
        let mut abiertos_ordenados: Vec<&DetectedService> = abiertos.iter().collect();
        abiertos_ordenados.sort_by_key(|servicio| servicio.port);
        abiertos_ordenados.dedup_by_key(|servicio| servicio.port);
        for abierto in abiertos_ordenados {
            let conocido = conocidos.iter().any(|servicio| {
                servicio.port == abierto.port && servicio.protocol == Protocol::Tcp
            });
            let estaba_cerrado =
                ultimos_eventos.get(&abierto.port) == Some(&EventType::ServiceGone);
            if !conocido {
                eventos.push(evento_service_new(abierto, false));
            } else if estaba_cerrado {
                eventos.push(evento_service_new(abierto, true));
            }
        }

        // Puertos cerrados: estaban abiertos y el escaneo no los ve abiertos.
        let mut cerrados: Vec<&DeviceService> = conocidos
            .iter()
            .filter(|servicio| {
                servicio.protocol == Protocol::Tcp
                    && escaneados.contains(&servicio.port)
                    && !abiertos.iter().any(|abierto| abierto.port == servicio.port)
            })
            .collect();
        cerrados.sort_by_key(|servicio| servicio.port);
        cerrados.dedup_by_key(|servicio| servicio.port);
        for servicio in cerrados {
            if ultimos_eventos.get(&servicio.port) == Some(&EventType::ServiceGone) {
                // Ya se avisó del cierre: el puerto sigue cerrado.
                continue;
            }
            eventos.push(NewEvent {
                tipo: EventType::ServiceGone,
                details: json!({
                    "port": servicio.port,
                    "protocol": servicio.protocol.as_str(),
                    "service": &servicio.service,
                }),
            });
        }

        eventos
    }

    /// Eventos de identidad entre el equipo anterior y el recién persistido.
    ///
    /// - `os_changed` solo si `os_family` cambia entre dos valores no nulos.
    ///   Los detalles llevan `before`, `after` y el `os_source` del equipo
    ///   después del cambio.
    /// - `type_changed` solo si el `device_type` automático cambia entre dos
    ///   valores conocidos (no `unknown`) y no hay override manual en ninguno
    ///   de los dos lados: el `t` de F2 es una acción de la persona y no genera
    ///   evento.
    pub fn identity(antes: &Device, despues: &Device) -> Vec<NewEvent> {
        let mut eventos = Vec::new();

        let os_antes = familia_no_nula(antes.os_family.as_deref());
        let os_despues = familia_no_nula(despues.os_family.as_deref());
        if let (Some(antes_os), Some(despues_os)) = (os_antes, os_despues) {
            if antes_os != despues_os {
                eventos.push(NewEvent {
                    tipo: EventType::OsChanged,
                    details: json!({
                        "before": antes_os,
                        "after": despues_os,
                        "os_source": &despues.os_source,
                    }),
                });
            }
        }

        if !tiene_override_manual(antes) && !tiene_override_manual(despues) {
            let tipo_antes = DeviceType::from_str(&antes.device_type);
            let tipo_despues = DeviceType::from_str(&despues.device_type);
            if let (Some(antes_tipo), Some(despues_tipo)) = (tipo_antes, tipo_despues) {
                if antes_tipo != DeviceType::Unknown
                    && despues_tipo != DeviceType::Unknown
                    && antes_tipo != despues_tipo
                {
                    eventos.push(NewEvent {
                        tipo: EventType::TypeChanged,
                        details: json!({
                            "before": &antes.device_type,
                            "after": &despues.device_type,
                        }),
                    });
                }
            }
        }

        eventos
    }
}

/// Construye el evento `service_new` de un puerto abierto.
fn evento_service_new(abierto: &DetectedService, reopened: bool) -> NewEvent {
    NewEvent {
        tipo: EventType::ServiceNew,
        details: json!({
            "port": abierto.port,
            "protocol": abierto.protocol.as_str(),
            "service": abierto.service.map(|clase| clase.as_str()),
            "reopened": reopened,
        }),
    }
}

/// Familia de SO persistida, descartando cadenas vacías.
fn familia_no_nula(valor: Option<&str>) -> Option<&str> {
    valor.filter(|texto| !texto.trim().is_empty())
}

/// Indica si el equipo tiene un override manual de tipo activo.
fn tiene_override_manual(device: &Device) -> bool {
    device
        .device_type_manual
        .as_deref()
        .filter(|tipo| !tipo.trim().is_empty())
        .is_some()
}
