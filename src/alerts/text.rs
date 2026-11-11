//! Títulos y notificaciones saneados (§7.13 / ADR-77).
//!
//! Todo texto que viene de la red (nombres DHCP, mDNS, NetBIOS o UPnP,
//! fabricantes, organizaciones) se sanea al crear la alerta: fuera secuencias
//! ANSI y caracteres de control, y longitud acotada. En la notificación se
//! escapan además `&`, `<` y `>`, porque muchos servidores interpretan marcado
//! en el cuerpo.

use std::time::{Duration, SystemTime};

use chrono::{DateTime, Datelike, Local, Timelike, Utc};
use serde_json::Value;

use super::{RuleId, Subject, BODY_MAX, LABEL_MAX, TITLE_MAX};

/// Longitud máxima de la frase del porqué que consume la TUI.
pub const PORQUE_MAX: usize = 240;

/// Sujeto de una alerta con su etiqueta ya saneada.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectInfo {
    /// Sujeto.
    pub subject: Subject,
    /// Etiqueta visible.
    pub label: String,
}

/// Textos compuestos de una alerta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertTexts {
    /// Título corto (≤ 120 caracteres).
    pub title: String,
    /// Etiqueta del sujeto (≤ 64 caracteres).
    pub subject_label: String,
    /// Cuerpo de la notificación (sin escapar todavía).
    pub body: String,
}

/// Composición del texto de cada regla (§7.1).
#[derive(Debug, Clone, Copy, Default)]
pub struct AlertText;

impl AlertText {
    /// Compone título, etiqueta y cuerpo de una alerta.
    pub fn compose(rule: RuleId, subject: &SubjectInfo, key: &str, details: &Value) -> AlertTexts {
        let etiqueta = Self::sanitize(&subject.label, LABEL_MAX);
        let clave = Self::sanitize(key, TITLE_MAX);
        let title = match rule {
            RuleId::DeviceNew => {
                if detalle_bool(details, "mac_random").unwrap_or(false) {
                    "Equipo nuevo · MAC privada".to_string()
                } else {
                    "Equipo nuevo · MAC fija".to_string()
                }
            }
            RuleId::PortNew => {
                let servicio = detalle_texto(details, "service");
                let sufijo = servicio
                    .map(|nombre| format!(" ({nombre})"))
                    .unwrap_or_default();
                let estado = if detalle_bool(details, "reopened").unwrap_or(false) {
                    "Puerto reabierto"
                } else {
                    "Puerto nuevo"
                };
                format!("{estado}: {clave}{sufijo}")
            }
            RuleId::MacChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("Cambio de MAC: {antes} → {despues}")
            }
            RuleId::NameChanged => {
                let antes =
                    detalle_texto(details, "before").unwrap_or_else(|| "sin nombre".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("Cambio de nombre: {antes} → {despues}")
            }
            RuleId::OsChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("Cambio de SO: {antes} → {despues}")
            }
            RuleId::TypeChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("Cambio de tipo: {antes} → {despues}")
            }
            RuleId::NewApp => format!("App nueva: {}", etiqueta_de(details, &clave)),
            RuleId::NewCategory => {
                format!("Categoría nueva: {}", etiqueta_de(details, &clave))
            }
            RuleId::NewCountry => format!("País nuevo: {}", etiqueta_de(details, &clave)),
            RuleId::NewOrg => format!("Organización nueva: {}", etiqueta_de(details, &clave)),
            RuleId::NewJa4 => format!("Huella TLS nueva (JA4): {clave}"),
            RuleId::TrafficHigh => {
                let flecha = if clave == "up" { "↑" } else { "↓" };
                let factor = detalle_f64(details, "factor");
                match factor {
                    Some(valor) if valor.is_finite() => {
                        format!("Más tráfico de lo habitual {flecha} ×{}", decimal(valor, 1))
                    }
                    _ => format!("Más tráfico de lo habitual {flecha}"),
                }
            }
            RuleId::WatchedPresence => {
                if clave == "gone" {
                    "Vigilado ausente".to_string()
                } else {
                    match detalle_numero(details, "away_s") {
                        Some(segundos) => {
                            format!("Vigilado de vuelta tras {}", formato_duracion(segundos))
                        }
                        None => "Vigilado de vuelta".to_string(),
                    }
                }
            }
            RuleId::CaptureStopped => "Captura parada".to_string(),
            RuleId::CaptureDrops => match detalle_f64(details, "percent") {
                Some(porcentaje) => format!("Pérdidas de captura · {} %", decimal(porcentaje, 1)),
                None => "Pérdidas de captura".to_string(),
            },
            RuleId::DbSize => match detalle_numero(details, "db_bytes") {
                Some(bytes) => format!(
                    "Base de datos grande · {}",
                    formato_bytes(bytes + detalle_numero(details, "wal_bytes").unwrap_or(0))
                ),
                None => "Base de datos grande".to_string(),
            },
        };
        let body = cuerpo(rule, &etiqueta, &clave, details);
        AlertTexts {
            title: Self::sanitize(&title, TITLE_MAX),
            subject_label: etiqueta,
            body: Self::sanitize(&body, BODY_MAX),
        }
    }

    /// Quita caracteres de control y secuencias ANSI y recorta a `max`.
    pub fn sanitize(text: &str, max: usize) -> String {
        let sin_ansi = quitar_ansi(text);
        let limpio: String = sin_ansi.chars().filter(|c| !c.is_control()).collect();
        recortar(&limpio, max)
    }

    /// Escapa `&`, `<` y `>` para el cuerpo de una notificación.
    pub fn escape_markup(text: &str) -> String {
        text.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }
}

impl AlertText {
    /// Explica el porqué de una alerta en una o dos líneas (§7.1 y §7.13).
    ///
    /// La consume el panel de detalle de la TUI; se guarda en
    /// `details["porque"]` al crear la alerta y va saneada a `PORQUE_MAX`
    /// caracteres.
    pub fn porque(
        rule: RuleId,
        subject: &SubjectInfo,
        key: &str,
        details: &Value,
        now: SystemTime,
    ) -> String {
        let etiqueta = Self::sanitize(&subject.label, LABEL_MAX);
        let clave = Self::sanitize(key, TITLE_MAX);
        let frase = match rule {
            RuleId::DeviceNew => {
                let origen = match detalle_texto(details, "source").as_deref() {
                    Some("capture") => "captura de tráfico",
                    _ => "escaneo ARP",
                };
                let nombre = match detalle_texto(details, "hostname") {
                    Some(nombre) => format!(" · nombre: {nombre}"),
                    None => " · sin nombre DHCP ni mDNS".to_string(),
                };
                format!(
                    "Primera vez en la red: {} ({origen}){nombre}",
                    momento(now, now)
                )
            }
            RuleId::PortNew => {
                let servicio = detalle_texto(details, "service")
                    .map(|nombre| format!(" · servicio {nombre}"))
                    .unwrap_or_default();
                if detalle_bool(details, "reopened").unwrap_or(false) {
                    format!(
                        "El escaneo de puertos vio que {clave} vuelve a estar abierto{servicio}"
                    )
                } else {
                    format!("El escaneo de puertos vio abierto {clave}{servicio}")
                }
            }
            RuleId::MacChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                let motivo = match detalle_texto(details, "reason").as_deref() {
                    Some("rotation") => "rotación de MAC privada",
                    Some("ip_takeover") => "toma de IP por otro equipo",
                    _ => "cambio de identidad",
                };
                format!("La MAC cambió de {antes} a {despues} ({motivo})")
            }
            RuleId::NameChanged => {
                let antes =
                    detalle_texto(details, "before").unwrap_or_else(|| "sin nombre".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("El nombre del equipo cambió de {antes} a {despues}")
            }
            RuleId::OsChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("El SO del equipo cambió de {antes} a {despues}")
            }
            RuleId::TypeChanged => {
                let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
                let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.clone());
                format!("El tipo del equipo cambió de {antes} a {despues}")
            }
            RuleId::NewApp
            | RuleId::NewCategory
            | RuleId::NewCountry
            | RuleId::NewOrg
            | RuleId::NewJa4 => {
                let que = match rule {
                    RuleId::NewApp => "la app",
                    RuleId::NewCategory => "la categoría",
                    RuleId::NewCountry => "el país",
                    RuleId::NewOrg => "la organización",
                    _ => "la huella TLS",
                };
                let nombre = etiqueta_de(details, &clave);
                let sujeto = if etiqueta.is_empty() {
                    String::new()
                } else {
                    format!(" en {etiqueta}")
                };
                let aprendido = details
                    .get("learned_at")
                    .and_then(Value::as_str)
                    .and_then(instante_rfc3339)
                    .map(|aprendido| format!(" · aprendido {}", fecha_corta(aprendido, now)))
                    .unwrap_or_default();
                format!("Primera vez que se ve {que} «{nombre}»{sujeto}{aprendido}")
            }
            RuleId::TrafficHigh => {
                let sentido = if clave == "up" { "Subida" } else { "Bajada" };
                let valor = detalle_numero(details, "value").unwrap_or(0);
                let mediana = detalle_numero(details, "median").unwrap_or(0);
                let muestras = detalle_numero(details, "samples").unwrap_or(0);
                let hora = details
                    .get("hour")
                    .and_then(Value::as_i64)
                    .and_then(|segundos| u64::try_from(segundos).ok())
                    .and_then(|segundos| {
                        SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(segundos))
                    })
                    .map(hora_local)
                    .unwrap_or_else(|| "esa hora".to_string());
                let factor = detalle_f64(details, "factor");
                let base = if mediana == 0 {
                    format!("sin tráfico en esa hora en {muestras} días con datos")
                } else {
                    format!(
                        "mediana de {} en {muestras} días con datos",
                        formato_bytes(mediana)
                    )
                };
                match factor {
                    Some(factor) if factor.is_finite() => format!(
                        "{sentido} de {} a las {hora} · {base} (×{})",
                        formato_bytes(valor),
                        decimal(factor, 1)
                    ),
                    _ => format!(
                        "{sentido} de {} a las {hora} · {base}",
                        formato_bytes(valor)
                    ),
                }
            }
            RuleId::WatchedPresence => {
                if clave == "gone" {
                    let desde = details
                        .get("last_seen")
                        .and_then(Value::as_str)
                        .and_then(instante_rfc3339)
                        .map(|visto| format!(" desde {}", momento(visto, now)))
                        .unwrap_or_default();
                    let cerrada = if detalle_bool(details, "while_closed").unwrap_or(false) {
                        " · se fue mientras Almenara estaba cerrada"
                    } else {
                        ""
                    };
                    format!("{etiqueta} no responde{desde}{cerrada}")
                } else {
                    match detalle_numero(details, "away_s") {
                        Some(segundos) => {
                            format!("{etiqueta} volvió tras {}", formato_duracion(segundos))
                        }
                        None => format!("{etiqueta} volvió"),
                    }
                }
            }
            RuleId::CaptureStopped => {
                let interfaz = detalle_texto(details, "interface")
                    .map(|nombre| format!(" en {nombre}"))
                    .unwrap_or_default();
                let motivo = detalle_texto(details, "reason")
                    .map(|motivo| format!(" · {motivo}"))
                    .unwrap_or_default();
                format!("La captura no está activa{interfaz}{motivo}")
            }
            RuleId::CaptureDrops => {
                let porcentaje = detalle_f64(details, "percent").unwrap_or(0.0);
                let minutos = detalle_numero(details, "minutes").unwrap_or(0);
                format!(
                    "Pérdidas del {} % durante {minutos} min seguidos",
                    decimal(porcentaje, 1)
                )
            }
            RuleId::DbSize => {
                let bytes = detalle_numero(details, "db_bytes").unwrap_or(0)
                    + detalle_numero(details, "wal_bytes").unwrap_or(0);
                let limite = detalle_numero(details, "max_db_mb").unwrap_or(0);
                format!(
                    "La base de datos ocupa {} (límite {limite} MB)",
                    formato_bytes(bytes)
                )
            }
        };
        Self::sanitize(&frase, PORQUE_MAX)
    }
}

/// Hora local «HH:00» de un instante (inicio de la hora).
fn hora_local(instante: SystemTime) -> String {
    let local: DateTime<Local> = instante.into();
    format!("{:02}:00", local.hour())
}

/// Nombres de los meses en castellano, para las fechas cortas.
const MESES: [&str; 12] = [
    "ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic",
];

/// Instante en formato «hoy 10:44», «ayer 22:17» o «el 9 nov».
fn momento(instante: SystemTime, ahora: SystemTime) -> String {
    let local: DateTime<Local> = instante.into();
    let hoy: DateTime<Local> = ahora.into();
    let hora = format!("{:02}:{:02}", local.hour(), local.minute());
    let dia = local.date_naive();
    let dia_hoy = hoy.date_naive();
    if dia == dia_hoy {
        format!("hoy {hora}")
    } else if Some(dia) == dia_hoy.pred_opt() {
        format!("ayer {hora}")
    } else {
        format!(
            "el {} {}",
            local.day(),
            MESES[(local.month() as usize).saturating_sub(1)]
        )
    }
}

/// Fecha corta sin hora: «hoy», «ayer» o «el 9 nov».
fn fecha_corta(instante: SystemTime, ahora: SystemTime) -> String {
    let local: DateTime<Local> = instante.into();
    let hoy: DateTime<Local> = ahora.into();
    let dia = local.date_naive();
    let dia_hoy = hoy.date_naive();
    if dia == dia_hoy {
        "hoy".to_string()
    } else if Some(dia) == dia_hoy.pred_opt() {
        "ayer".to_string()
    } else {
        format!(
            "el {} {}",
            local.day(),
            MESES[(local.month() as usize).saturating_sub(1)]
        )
    }
}

/// Parsea una fecha RFC 3339 UTC de `details`.
fn instante_rfc3339(texto: &str) -> Option<SystemTime> {
    DateTime::parse_from_rfc3339(texto)
        .ok()
        .map(|fecha| fecha.with_timezone(&Utc).into())
}

/// Cuerpo de la notificación: el sujeto y lo esencial de la regla (§7.13).
fn cuerpo(rule: RuleId, etiqueta: &str, clave: &str, details: &Value) -> String {
    match rule {
        RuleId::DeviceNew => {
            let mac = if detalle_bool(details, "mac_random").unwrap_or(false) {
                "MAC privada"
            } else {
                "MAC fija"
            };
            let fabricante = detalle_texto(details, "vendor");
            match fabricante {
                Some(vendor) => format!("{etiqueta} ({vendor}) · {mac}"),
                None => format!("{etiqueta} · {mac}"),
            }
        }
        RuleId::PortNew => {
            let estado = if detalle_bool(details, "reopened").unwrap_or(false) {
                "reabierto"
            } else {
                "nuevo"
            };
            format!("{etiqueta} · {clave} · {estado}")
        }
        RuleId::MacChanged => {
            let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
            let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.to_string());
            let motivo = match detalle_texto(details, "reason").as_deref() {
                Some("rotation") => " · rotación de privacidad",
                Some("ip_takeover") => " · toma de IP",
                _ => "",
            };
            format!("{etiqueta} · {antes} → {despues}{motivo}")
        }
        RuleId::NameChanged => {
            let antes =
                detalle_texto(details, "before").unwrap_or_else(|| "sin nombre".to_string());
            let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.to_string());
            format!("{etiqueta} · {antes} → {despues}")
        }
        RuleId::OsChanged => {
            let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
            let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.to_string());
            format!("{etiqueta} · SO {antes} → {despues}")
        }
        RuleId::TypeChanged => {
            let antes = detalle_texto(details, "before").unwrap_or_else(|| "?".to_string());
            let despues = detalle_texto(details, "after").unwrap_or_else(|| clave.to_string());
            format!("{etiqueta} · tipo {antes} → {despues}")
        }
        RuleId::NewApp | RuleId::NewCategory | RuleId::NewCountry | RuleId::NewOrg => {
            format!("{etiqueta} · {}", etiqueta_de(details, clave))
        }
        RuleId::NewJa4 => format!("{etiqueta} · huella {clave}"),
        RuleId::TrafficHigh => {
            let sentido = if clave == "up" { "Subida" } else { "Bajada" };
            let valor = detalle_numero(details, "value").unwrap_or(0);
            let mediana = detalle_numero(details, "median").unwrap_or(0);
            let factor = detalle_f64(details, "factor");
            match factor {
                Some(factor) if factor.is_finite() => format!(
                    "{etiqueta} · {sentido} de {} en la hora (×{} la mediana de {})",
                    formato_bytes(valor),
                    decimal(factor, 1),
                    formato_bytes(mediana)
                ),
                _ => format!(
                    "{etiqueta} · {sentido} de {} en la hora (sin base, {} muestras)",
                    formato_bytes(valor),
                    detalle_numero(details, "samples").unwrap_or(0)
                ),
            }
        }
        RuleId::WatchedPresence => {
            if clave == "gone" {
                format!("{etiqueta} · vigilado ausente")
            } else {
                match detalle_numero(details, "away_s") {
                    Some(segundos) => {
                        format!("{etiqueta} · de vuelta tras {}", formato_duracion(segundos))
                    }
                    None => format!("{etiqueta} · de vuelta"),
                }
            }
        }
        RuleId::CaptureStopped => {
            let interfaz = detalle_texto(details, "interface");
            let motivo = detalle_texto(details, "reason");
            match (interfaz, motivo) {
                (Some(interfaz), Some(motivo)) => format!("{etiqueta} · {interfaz} · {motivo}"),
                (Some(interfaz), None) => format!("{etiqueta} · {interfaz}"),
                (None, Some(motivo)) => format!("{etiqueta} · {motivo}"),
                (None, None) => etiqueta.to_string(),
            }
        }
        RuleId::CaptureDrops => {
            let porcentaje = detalle_f64(details, "percent");
            let minutos = detalle_numero(details, "minutes").unwrap_or(0);
            match porcentaje {
                Some(valor) => format!(
                    "{etiqueta} · {} % de pérdidas durante {minutos} min seguidos",
                    decimal(valor, 1)
                ),
                None => format!("{etiqueta} · {minutos} min con pérdidas"),
            }
        }
        RuleId::DbSize => {
            let bytes = detalle_numero(details, "db_bytes").unwrap_or(0)
                + detalle_numero(details, "wal_bytes").unwrap_or(0);
            let limite = detalle_numero(details, "max_db_mb").unwrap_or(0);
            format!(
                "{etiqueta} · {} en la base de datos (límite {limite} MB)",
                formato_bytes(bytes)
            )
        }
    }
}

/// Etiqueta de una entrada nueva del inventario, con la clave como respaldo.
fn etiqueta_de(details: &Value, clave: &str) -> String {
    detalle_texto(details, "label").unwrap_or_else(|| clave.to_string())
}

/// Cadena saneada de `details`.
fn detalle_texto(details: &Value, clave: &str) -> Option<String> {
    details
        .get(clave)
        .and_then(Value::as_str)
        .map(|texto| AlertText::sanitize(texto, TITLE_MAX))
        .filter(|texto| !texto.is_empty())
}

/// Número entero de `details`.
fn detalle_numero(details: &Value, clave: &str) -> Option<u64> {
    details.get(clave).and_then(|valor| {
        valor
            .as_u64()
            .or_else(|| valor.as_i64().and_then(|n| u64::try_from(n).ok()))
    })
}

/// Número real de `details`.
fn detalle_f64(details: &Value, clave: &str) -> Option<f64> {
    details.get(clave).and_then(Value::as_f64)
}

/// Booleano de `details`.
fn detalle_bool(details: &Value, clave: &str) -> Option<bool> {
    details.get(clave).and_then(Value::as_bool)
}

/// Formatea un número con coma decimal (castellano).
fn decimal(valor: f64, decimales: usize) -> String {
    if !valor.is_finite() {
        return "?".to_string();
    }
    let texto = if (valor - valor.round()).abs() < 0.05 {
        format!("{valor:.0}")
    } else {
        format!("{valor:.decimales$}")
    };
    texto.replace('.', ",")
}

/// Formato de bytes con unidades de 1 000 (como F3): `2,4 GB`.
pub fn formato_bytes(bytes: u64) -> String {
    const UNIDADES: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    if bytes < 1_000 {
        return format!("{bytes} B");
    }
    let mut valor = bytes as f64;
    let mut unidad = 0;
    while valor >= 1_000.0 && unidad < UNIDADES.len() - 1 {
        valor /= 1_000.0;
        unidad += 1;
    }
    format!("{} {}", decimal(valor, 1), UNIDADES[unidad])
}

/// Formato breve de una duración: `41 min`, `2 h 5 min`, `3 d`.
pub fn formato_duracion(segundos: u64) -> String {
    if segundos < 60 {
        return format!("{segundos} s");
    }
    let minutos = segundos / 60;
    if minutos < 60 {
        return format!("{minutos} min");
    }
    let horas = minutos / 60;
    if horas < 24 {
        let resto = minutos % 60;
        if resto == 0 {
            return format!("{horas} h");
        }
        return format!("{horas} h {resto} min");
    }
    let dias = horas / 24;
    let resto = horas % 24;
    if resto == 0 {
        format!("{dias} d")
    } else {
        format!("{dias} d {resto} h")
    }
}

/// Quita las secuencias ANSI (CSI, OSC y de dos bytes) de un texto.
fn quitar_ansi(texto: &str) -> String {
    let mut salida = String::with_capacity(texto.len());
    let mut caracteres = texto.chars().peekable();
    while let Some(caracter) = caracteres.next() {
        if caracter != '\u{1b}' {
            salida.push(caracter);
            continue;
        }
        match caracteres.peek().copied() {
            // CSI: ESC [ … byte final 0x40-0x7E.
            Some('[') => {
                caracteres.next();
                for siguiente in caracteres.by_ref() {
                    if ('@'..='~').contains(&siguiente) {
                        break;
                    }
                }
            }
            // OSC: ESC ] … BEL o ESC .
            Some(']') => {
                caracteres.next();
                let mut terminado = false;
                while !terminado {
                    match caracteres.next() {
                        Some('\u{7}') | None => terminado = true,
                        Some('\u{1b}') => {
                            if caracteres.peek() == Some(&'\\') {
                                caracteres.next();
                            }
                            terminado = true;
                        }
                        Some(_) => {}
                    }
                }
            }
            // Secuencia de dos bytes: ESC seguido de un carácter de control.
            Some(_) => {
                caracteres.next();
            }
            None => {}
        }
    }
    salida
}

/// Recorta a `max` caracteres añadiendo «…».
fn recortar(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut salida: String = text.chars().take(max.saturating_sub(1)).collect();
        salida.push('…');
        salida
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sujeto(label: &str) -> SubjectInfo {
        SubjectInfo {
            subject: Subject::Host,
            label: label.to_string(),
        }
    }

    #[test]
    fn ac_elimina_secuencias_ansi_y_caracteres_de_control() {
        let crudo = "\u{1b}[31m<b>x</b>\u{1b}[0m\u{7}\u{0}";
        let saneado = AlertText::sanitize(crudo, 120);
        assert_eq!(saneado, "<b>x</b>");
    }

    #[test]
    fn quita_tambien_osc_y_secuencias_de_dos_bytes() {
        assert_eq!(AlertText::sanitize("\u{1b}]0;título\u{7}hola", 120), "hola");
        assert_eq!(AlertText::sanitize("\u{1b}Mtexto", 120), "texto");
        assert_eq!(
            AlertText::sanitize("\u{1b}]8;;http://x\u{1b}\\enlace", 120),
            "enlace"
        );
    }

    #[test]
    fn ac_el_cuerpo_de_la_notificacion_escapa_el_marcado() {
        let crudo = AlertText::sanitize("\u{1b}[1m<b>x</b> & y\u{1b}[0m", 200);
        assert_eq!(
            AlertText::escape_markup(&crudo),
            "&lt;b&gt;x&lt;/b&gt; &amp; y"
        );
    }

    #[test]
    fn recorta_titulo_etiqueta_y_cuerpo() {
        let largo = "a".repeat(300);
        let textos = AlertText::compose(
            RuleId::NewApp,
            &sujeto(&largo),
            "clave",
            &json!({"label": largo}),
        );
        assert_eq!(textos.title.chars().count(), TITLE_MAX);
        assert_eq!(textos.subject_label.chars().count(), LABEL_MAX);
        assert!(textos.body.chars().count() <= BODY_MAX);
        assert!(textos.title.ends_with('…'));
    }

    #[test]
    fn device_new_con_mac_privada_y_fija() {
        let textos = AlertText::compose(
            RuleId::DeviceNew,
            &sujeto("192.168.1.201"),
            "",
            &json!({"mac_random": true, "vendor": "Xiaomi"}),
        );
        assert_eq!(textos.title, "Equipo nuevo · MAC privada");
        assert!(textos.body.contains("192.168.1.201 (Xiaomi) · MAC privada"));

        let textos = AlertText::compose(
            RuleId::DeviceNew,
            &sujeto("192.168.1.201"),
            "",
            &json!({"mac_random": false}),
        );
        assert_eq!(textos.title, "Equipo nuevo · MAC fija");
        assert_eq!(textos.body, "192.168.1.201 · MAC fija");
    }

    #[test]
    fn port_new_con_servicio_y_reabierto() {
        let textos = AlertText::compose(
            RuleId::PortNew,
            &sujeto("nas"),
            "22/tcp",
            &json!({"port": 22, "protocol": "tcp", "service": "ssh", "reopened": false}),
        );
        assert_eq!(textos.title, "Puerto nuevo: 22/tcp (ssh)");
        assert_eq!(textos.body, "nas · 22/tcp · nuevo");

        let textos = AlertText::compose(
            RuleId::PortNew,
            &sujeto("nas"),
            "22/tcp",
            &json!({"service": "ssh", "reopened": true}),
        );
        assert_eq!(textos.title, "Puerto reabierto: 22/tcp (ssh)");
    }

    #[test]
    fn cambios_de_identidad() {
        let mac = AlertText::compose(
            RuleId::MacChanged,
            &sujeto("nas"),
            "",
            &json!({"before": "aa:bb:cc:dd:ee:ff", "after": "11:22:33:44:55:66", "reason": "rotation"}),
        );
        assert_eq!(
            mac.title,
            "Cambio de MAC: aa:bb:cc:dd:ee:ff → 11:22:33:44:55:66"
        );
        assert!(mac.body.contains("rotación de privacidad"));

        let nombre = AlertText::compose(
            RuleId::NameChanged,
            &sujeto("nas"),
            "nas",
            &json!({"before": "diskstation", "after": "nas"}),
        );
        assert_eq!(nombre.title, "Cambio de nombre: diskstation → nas");

        let so = AlertText::compose(
            RuleId::OsChanged,
            &sujeto("tv-sala"),
            "windows",
            &json!({"before": "linux", "after": "windows", "os_source": "dhcp"}),
        );
        assert_eq!(so.title, "Cambio de SO: linux → windows");

        let tipo = AlertText::compose(
            RuleId::TypeChanged,
            &sujeto("tv-sala"),
            "tv",
            &json!({"before": "iot", "after": "tv"}),
        );
        assert_eq!(tipo.title, "Cambio de tipo: iot → tv");
    }

    #[test]
    fn ac_app_nueva_con_el_nombre_del_catalogo() {
        let textos = AlertText::compose(
            RuleId::NewApp,
            &sujeto("[host]"),
            "steam",
            &json!({"kind": "app", "key": "steam", "label": "Steam"}),
        );
        assert_eq!(textos.title, "App nueva: Steam");
        assert_eq!(textos.body, "[host] · Steam");
    }

    #[test]
    fn paises_categorias_organizaciones_y_ja4() {
        let pais = AlertText::compose(
            RuleId::NewCountry,
            &sujeto("[host]"),
            "IE",
            &json!({"label": "Irlanda (IE)"}),
        );
        assert_eq!(pais.title, "País nuevo: Irlanda (IE)");
        let categoria = AlertText::compose(
            RuleId::NewCategory,
            &sujeto("[host]"),
            "video",
            &json!({"label": "Vídeo"}),
        );
        assert_eq!(categoria.title, "Categoría nueva: Vídeo");
        let org = AlertText::compose(
            RuleId::NewOrg,
            &sujeto("[host]"),
            "cloudflare",
            &json!({"label": "Cloudflare"}),
        );
        assert_eq!(org.title, "Organización nueva: Cloudflare");
        let ja4 = AlertText::compose(
            RuleId::NewJa4,
            &sujeto("[host]"),
            "t13d1516h2_8daaf6152771_02713d6af862",
            &json!({}),
        );
        assert!(ja4.title.starts_with("Huella TLS nueva (JA4): t13d1516"));
    }

    #[test]
    fn ac_trafico_alto_muestra_la_mediana_y_el_factor() {
        let textos = AlertText::compose(
            RuleId::TrafficHigh,
            &sujeto("[host]"),
            "down",
            &json!({
                "direction": "down",
                "hour": 1_790_000_000_i64,
                "value": 2_400_000_000_u64,
                "median": 400_000_000_u64,
                "factor": 6.0,
                "samples": 8,
            }),
        );
        assert_eq!(textos.title, "Más tráfico de lo habitual ↓ ×6");
        assert!(
            textos.body.contains("Bajada de 2,4 GB"),
            "cuerpo: {}",
            textos.body
        );
        assert!(
            textos.body.contains("×6 la mediana"),
            "cuerpo: {}",
            textos.body
        );

        let subida = AlertText::compose(
            RuleId::TrafficHigh,
            &sujeto("nas"),
            "up",
            &json!({"value": 100_000_000_u64, "median": 0_u64, "samples": 5}),
        );
        assert_eq!(subida.title, "Más tráfico de lo habitual ↑");
        assert!(subida.body.contains("sin base"));
    }

    #[test]
    fn vigilancias_ausente_y_de_vuelta() {
        let ausente = AlertText::compose(
            RuleId::WatchedPresence,
            &sujeto("nas"),
            "gone",
            &json!({"state": "gone", "away_s": 0, "while_closed": false}),
        );
        assert_eq!(ausente.title, "Vigilado ausente");

        let vuelta = AlertText::compose(
            RuleId::WatchedPresence,
            &sujeto("nas"),
            "back",
            &json!({"state": "back", "away_s": 2460, "while_closed": false}),
        );
        assert_eq!(vuelta.title, "Vigilado de vuelta tras 41 min");
    }

    #[test]
    fn salud_de_captura_y_base_de_datos() {
        let parada = AlertText::compose(
            RuleId::CaptureStopped,
            &sujeto("Almenara"),
            "capture",
            &json!({"interface": "eth0", "reason": null}),
        );
        assert_eq!(parada.title, "Captura parada");
        assert_eq!(parada.body, "Almenara · eth0");

        let perdidas = AlertText::compose(
            RuleId::CaptureDrops,
            &sujeto("Almenara"),
            "drops",
            &json!({"percent": 2.5, "minutes": 5}),
        );
        assert_eq!(perdidas.title, "Pérdidas de captura · 2,5 %");
        assert!(perdidas.body.contains("5 min seguidos"));

        let bd = AlertText::compose(
            RuleId::DbSize,
            &sujeto("Almenara"),
            "db",
            &json!({"db_bytes": 900_000_000_u64, "wal_bytes": 100_000_000_u64, "max_db_mb": 1024}),
        );
        assert_eq!(bd.title, "Base de datos grande · 1 GB");
        assert!(bd.body.contains("límite 1024 MB"));
    }

    #[test]
    fn formato_de_bytes_y_duraciones() {
        assert_eq!(formato_bytes(0), "0 B");
        assert_eq!(formato_bytes(999), "999 B");
        assert_eq!(formato_bytes(1_000), "1 kB");
        assert_eq!(formato_bytes(2_400_000_000), "2,4 GB");
        assert_eq!(formato_bytes(400_000_000), "400 MB");

        assert_eq!(formato_duracion(0), "0 s");
        assert_eq!(formato_duracion(59), "59 s");
        assert_eq!(formato_duracion(2_460), "41 min");
        assert_eq!(formato_duracion(3_600), "1 h");
        assert_eq!(formato_duracion(7_500), "2 h 5 min");
        assert_eq!(formato_duracion(86_400), "1 d");
        assert_eq!(formato_duracion(93_600), "1 d 2 h");
    }

    #[test]
    fn el_sujeto_visible_se_sanea() {
        let textos = AlertText::compose(
            RuleId::DeviceNew,
            &sujeto("\u{1b}[31mrouter\u{1b}[0m\u{7}"),
            "",
            &json!({"mac_random": false, "vendor": "\u{1b}[32mACME\u{1b}[0m"}),
        );
        assert_eq!(textos.subject_label, "router");
        assert!(textos.body.contains("ACME"));
        assert!(!textos.body.contains('\u{1b}'));
    }

    fn ahora() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000)
    }

    #[test]
    fn porque_de_equipo_nuevo() {
        let frase = AlertText::porque(
            RuleId::DeviceNew,
            &sujeto("192.168.1.201"),
            "",
            &json!({"source": "scan", "hostname": null, "vendor": "Xiaomi"}),
            ahora(),
        );
        assert!(
            frase.starts_with("Primera vez en la red: hoy "),
            "frase: {frase}"
        );
        assert!(frase.contains("(escaneo ARP)"));
        assert!(frase.contains("sin nombre DHCP ni mDNS"));
        assert!(frase.chars().count() <= PORQUE_MAX);
    }

    #[test]
    fn porque_de_puerto_reabierto() {
        let frase = AlertText::porque(
            RuleId::PortNew,
            &sujeto("nas"),
            "22/tcp",
            &json!({"service": "ssh", "reopened": true}),
            ahora(),
        );
        assert!(frase.contains("22/tcp vuelve a estar abierto"));
        assert!(frase.contains("servicio ssh"));
    }

    #[test]
    fn porque_del_cambio_de_mac() {
        let frase = AlertText::porque(
            RuleId::MacChanged,
            &sujeto("nas"),
            "11:22:33:44:55:66",
            &json!({"before": "aa:bb:cc:dd:ee:ff", "after": "11:22:33:44:55:66", "reason": "rotation"}),
            ahora(),
        );
        assert_eq!(
            frase,
            "La MAC cambió de aa:bb:cc:dd:ee:ff a 11:22:33:44:55:66 (rotación de MAC privada)"
        );
    }

    #[test]
    fn porque_de_lo_nuevo_con_aprendizaje() {
        let frase = AlertText::porque(
            RuleId::NewApp,
            &sujeto("[host]"),
            "steam",
            &json!({"label": "Steam", "learned_at": "2026-11-09T00:00:00Z"}),
            ahora(),
        );
        assert!(frase.contains("Primera vez que se ve la app «Steam» en [host]"));
        assert!(frase.contains("aprendido"));
    }

    #[test]
    fn porque_de_trafico_alto() {
        let frase = AlertText::porque(
            RuleId::TrafficHigh,
            &sujeto("[host]"),
            "down",
            &json!({
                "direction": "down",
                "hour": 1_790_000_000_i64,
                "value": 2_400_000_000_u64,
                "median": 400_000_000_u64,
                "factor": 6.0,
                "samples": 8,
            }),
            ahora(),
        );
        assert!(frase.contains("Bajada de 2,4 GB a las "), "frase: {frase}");
        assert!(frase.contains("mediana de 400 MB en 8 días con datos"));
        assert!(frase.contains("(×6)"));
    }

    #[test]
    fn porque_de_vigilado_ausente_cerrada() {
        let frase = AlertText::porque(
            RuleId::WatchedPresence,
            &sujeto("nas"),
            "gone",
            &json!({
                "state": "gone",
                "last_seen": "2026-11-11T10:00:00Z",
                "away_s": 0,
                "while_closed": true,
            }),
            ahora(),
        );
        assert!(frase.contains("nas no responde"));
        assert!(frase.contains("mientras Almenara estaba cerrada"));

        let vuelta = AlertText::porque(
            RuleId::WatchedPresence,
            &sujeto("nas"),
            "back",
            &json!({"state": "back", "away_s": 2_460, "while_closed": false}),
            ahora(),
        );
        assert_eq!(vuelta, "nas volvió tras 41 min");
    }

    #[test]
    fn porque_de_salud() {
        let parada = AlertText::porque(
            RuleId::CaptureStopped,
            &sujeto("Almenara"),
            "capture",
            &json!({"interface": "eth0", "reason": null}),
            ahora(),
        );
        assert_eq!(parada, "La captura no está activa en eth0");

        let bd = AlertText::porque(
            RuleId::DbSize,
            &sujeto("Almenara"),
            "db",
            &json!({"db_bytes": 900_000_000_u64, "wal_bytes": 100_000_000_u64, "max_db_mb": 1024}),
            ahora(),
        );
        assert!(bd.contains("La base de datos ocupa 1 GB (límite 1024 MB)"));
    }

    #[test]
    fn el_porque_se_sanea_y_se_recorta() {
        let nombre = format!("\u{1b}[31m{}\u{1b}[0m", "x".repeat(300));
        let frase = AlertText::porque(
            RuleId::NameChanged,
            &sujeto("nas"),
            "largo",
            &json!({"before": "antes", "after": nombre}),
            ahora(),
        );
        assert!(frase.chars().count() <= PORQUE_MAX);
        assert!(!frase.contains('\u{1b}'));
    }
}
