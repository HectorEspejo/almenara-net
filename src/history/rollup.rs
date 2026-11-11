//! Acumuladores del minuto del histórico (§7.2).
//!
//! El agregador de F3/F4 ([crate::rankings::Rankings]) llama a [MinuteRollup]
//! con el mismo volcado por flujo y segundo: no se toca la base de datos hasta
//! que cambia el minuto. Al cerrarse el minuto, [MinuteRollup::flush] aplica los
//! topes de claves, genera ~otros y anota el inventario visto antes de los topes.
//! El lote resultante lo escribe el hilo de la TUI (único escritor, ADR-35).
//!
//! Claves y sujetos siguen §7.1: el total cuenta para todos los equipos que
//! participan en el flujo (los dos en un flujo LAN↔LAN), mientras que el resto de
//! dimensiones cuentan una sola vez, para el sujeto de la columna «Equipo» de F4.

// Varias operaciones de esta API son parte del checklist de F5 y solo las usan
// las pruebas o la integración de la TUI; se permite dead_code como en los DAO
// de fases anteriores.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::history::build::aplicar_topes;
use crate::history::{
    clave_especial, Counter, Dimension, FlowDims, RollupBatch, RollupRow, SeenItem, SeenKind,
    Subject, KEY_OTHERS,
};
use crate::inference::{AppProtocol, FlowLabel};
use crate::rankings::{Dir, FlowCtx};
use crate::traffic::DEVICE_ID_HOST;

/// Tope de entradas de los acumuladores del minuto (§7.2).
pub const MAX_ENTRADAS: usize = 20_000;

/// Instantánea de un flujo nuevo del minuto, para contar sus conexiones y
/// refrescar su etiqueta hasta el cierre.
#[derive(Debug, Clone, PartialEq)]
struct FlujoNuevo {
    subjects: Vec<Subject>,
    dims: FlowDims,
}

/// Acumuladores del minuto en curso.
#[derive(Debug)]
pub struct MinuteRollup {
    enabled: bool,
    top_keys: usize,
    max_entradas: usize,
    minute: i64,
    /// Contadores agrupados por sujeto y dimensión: la clave se busca por &str
    /// para no asignar memoria en cada volcado por flujo y segundo.
    acc: HashMap<(Subject, Dimension), HashMap<String, Counter>>,
    /// Número total de entradas de los acumuladores (tope de memoria).
    entradas: usize,
    flujos: HashMap<u64, FlujoNuevo>,
    ja4: HashSet<(i64, String)>,
    overflow: u64,
}

impl Default for MinuteRollup {
    fn default() -> Self {
        Self::new(false)
    }
}

impl MinuteRollup {
    /// Crea los acumuladores (desactivados si el histórico está apagado).
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            top_keys: 20,
            max_entradas: MAX_ENTRADAS,
            minute: 0,
            acc: HashMap::new(),
            entradas: 0,
            flujos: HashMap::new(),
            ja4: HashSet::new(),
            overflow: 0,
        }
    }

    /// Activa o desactiva la acumulación.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            self.limpiar();
        }
    }

    /// Indica si el histórico está activo.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Fija el tope de claves por sujeto, dimensión y cubo.
    pub fn set_top_keys(&mut self, top_keys: usize) {
        self.top_keys = top_keys.max(1);
    }

    /// Tope de claves configurado.
    pub fn top_keys(&self) -> usize {
        self.top_keys
    }

    /// Minuto en curso (segundos Unix UTC); 0 si todavía no se ha fijado.
    pub fn minute(&self) -> i64 {
        self.minute
    }

    /// Fija el minuto en curso.
    pub fn set_minute(&mut self, minute: i64) {
        self.minute = minute;
    }

    /// Número de entradas de los acumuladores (diagnóstico y pruebas).
    pub fn entries(&self) -> usize {
        self.entradas
    }

    /// Contador de entradas que no cabían (rollup_overflow).
    pub fn overflow(&self) -> u64 {
        self.overflow
    }

    /// Ajusta el tope de entradas (solo pruebas de memoria).
    pub fn set_max_entradas(&mut self, max: usize) {
        self.max_entradas = max.max(1);
    }

    /// Vacía los acumuladores y los flujos sin generar lote.
    pub fn limpiar(&mut self) {
        self.acc.clear();
        self.entradas = 0;
        self.flujos.clear();
        self.ja4.clear();
    }

    /// Indica si un flujo ya está contado en el minuto en curso.
    pub fn conoce_flujo(&self, flujo: u64) -> bool {
        self.flujos.contains_key(&flujo)
    }

    /// Suma los bytes de un flujo a sus sujetos, dimensiones y claves (§7.1).
    pub fn add(&mut self, subjects: &[Subject], dims: &FlowDims, bytes: u64, dir: Dir) {
        if !self.enabled || bytes == 0 {
            return;
        }
        for subject in subjects {
            // El otro equipo de un flujo LAN↔LAN ve los bytes al revés: lo que
            // el cliente recibe, el servidor de la LAN lo envía.
            let direccion = if dims.peer == Some(*subject) {
                direccion_inversa(dir)
            } else {
                dir
            };
            self.sumar(*subject, Dimension::Total, "", bytes, direccion);
        }
        let Some(subject) = dims.subject else {
            return;
        };
        if subject == Subject::Network {
            return;
        }
        for dimension in Dimension::ALL {
            if dimension == Dimension::Total {
                continue;
            }
            if let Some(clave) = dims.clave(dimension) {
                self.sumar(subject, dimension, clave.as_ref(), bytes, dir);
            }
        }
        if let Subject::Device(device_id) = subject {
            if let Some(ja4) = dims.ja4.as_ref().filter(|huella| !huella.is_empty()) {
                self.ja4.insert((device_id, ja4.clone()));
            }
        }
    }

    /// Registra un flujo nuevo del minuto (conexión contada en su cubo).
    ///
    /// La instantánea se actualiza después con [MinuteRollup::actualizar_flujo]
    /// para contar el flujo con la etiqueta que tiene al cierre del minuto.
    pub fn add_flow(&mut self, flujo: u64, subjects: &[Subject], dims: &FlowDims) {
        if !self.enabled {
            return;
        }
        if self.flujos.len() >= self.max_entradas && !self.flujos.contains_key(&flujo) {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        self.flujos.insert(
            flujo,
            FlujoNuevo {
                subjects: subjects.to_vec(),
                dims: dims.clone(),
            },
        );
    }

    /// Refresca la etiqueta de un flujo nuevo ya conocido del minuto.
    pub fn actualizar_flujo(&mut self, flujo: u64, subjects: &[Subject], dims: &FlowDims) {
        if !self.enabled {
            return;
        }
        if let Some(entrada) = self.flujos.get_mut(&flujo) {
            entrada.subjects = subjects.to_vec();
            entrada.dims = dims.clone();
        }
    }

    /// Cierra el minuto: cuenta flujos, aplica topes y anota el inventario.
    pub fn flush(&mut self, minute: i64) -> RollupBatch {
        if !self.enabled {
            return RollupBatch {
                minute,
                ..RollupBatch::default()
            };
        }
        // Las conexiones de los flujos nuevos se cuentan antes de los topes: así
        // cada fila lleva sus conexiones aunque su clave acabe en ~otros.
        let flujos = std::mem::take(&mut self.flujos);
        for flujo in flujos.values() {
            for subject in &flujo.subjects {
                self.acumular_conexion(*subject, Dimension::Total, "");
            }
            let Some(subject) = flujo.dims.subject else {
                continue;
            };
            for dimension in Dimension::ALL {
                if dimension == Dimension::Total {
                    continue;
                }
                if let Some(clave) = flujo.dims.clave(dimension) {
                    self.acumular_conexion(subject, dimension, clave.as_ref());
                }
            }
        }

        // Inventario antes de los topes: todas las claves normales vistas de las
        // dimensiones de inventario para sujetos equipo.
        let mut seen = Vec::new();
        for ((subject, dimension), claves) in self.acc.iter() {
            let Subject::Device(device_id) = subject else {
                continue;
            };
            let Some(kind) = SeenKind::from_dimension(*dimension) else {
                continue;
            };
            for clave in claves.keys() {
                // Las claves especiales (~sin_identificar, ~lan, ~desconocido,
                // ~otros) no entran en el inventario (§7.9).
                if clave_especial(clave) {
                    continue;
                }
                seen.push(SeenItem {
                    device_id: *device_id,
                    kind,
                    key: clave.clone(),
                });
            }
        }
        seen.sort_by(|a, b| {
            a.device_id
                .cmp(&b.device_id)
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.key.cmp(&b.key))
        });
        seen.dedup_by(|a, b| a.device_id == b.device_id && a.kind == b.kind && a.key == b.key);
        for (device_id, huella) in self.ja4.iter() {
            seen.push(SeenItem {
                device_id: *device_id,
                kind: SeenKind::Ja4,
                key: huella.clone(),
            });
        }

        let mut totales = Vec::new();
        let mut resto = Vec::new();
        for ((subject, dimension), claves) in self.acc.drain() {
            for (clave, counter) in claves {
                let fila = RollupRow {
                    subject,
                    dimension,
                    key: clave,
                    counter,
                };
                if dimension == Dimension::Total {
                    totales.push(fila);
                } else {
                    resto.push(fila);
                }
            }
        }
        self.entradas = 0;
        totales.sort_by_key(|fila| (fila.subject, fila.dimension));
        let resto = aplicar_topes(resto, self.top_keys);
        let mut rows = totales;
        rows.extend(resto);

        let overflow = self.overflow;
        self.overflow = 0;
        self.ja4.clear();
        RollupBatch {
            minute,
            rows,
            seen,
            overflow,
        }
    }

    fn acumular_conexion(&mut self, subject: Subject, dimension: Dimension, clave: &str) {
        if let Some(grupo) = self.acc.get_mut(&(subject, dimension)) {
            if let Some(entrada) = grupo.get_mut(clave) {
                entrada.connections = entrada.connections.saturating_add(1);
                return;
            }
        }
        if self.entradas < self.max_entradas || dimension == Dimension::Total {
            self.acc.entry((subject, dimension)).or_default().insert(
                clave.to_string(),
                Counter {
                    down: 0,
                    up: 0,
                    connections: 1,
                },
            );
            self.entradas += 1;
            return;
        }
        self.overflow = self.overflow.saturating_add(1);
        self.acc
            .entry((subject, dimension))
            .or_default()
            .entry(KEY_OTHERS.to_string())
            .or_default()
            .connections += 1;
    }

    fn sumar(&mut self, subject: Subject, dimension: Dimension, clave: &str, bytes: u64, dir: Dir) {
        if let Some(grupo) = self.acc.get_mut(&(subject, dimension)) {
            if let Some(counter) = grupo.get_mut(clave) {
                counter.suma_bytes(bytes, dir);
                return;
            }
        }
        // La dimensión total tiene una sola clave: nunca se desborda.
        if dimension != Dimension::Total && self.entradas >= self.max_entradas {
            self.overflow = self.overflow.saturating_add(1);
            self.acc
                .entry((subject, dimension))
                .or_default()
                .entry(KEY_OTHERS.to_string())
                .or_default()
                .suma_bytes(bytes, dir);
            return;
        }
        let mut counter = Counter::default();
        counter.suma_bytes(bytes, dir);
        self.acc
            .entry((subject, dimension))
            .or_default()
            .insert(clave.to_string(), counter);
        self.entradas += 1;
    }
}

/// Dirección contraria (para el otro equipo de un flujo LAN↔LAN).
pub fn direccion_inversa(dir: Dir) -> Dir {
    match dir {
        Dir::Down => Dir::Up,
        Dir::Up => Dir::Down,
    }
}

/// Construye los sujetos y las dimensiones de un flujo a partir de su etiqueta
/// y su contexto de F4.
///
/// subjects son los sujetos que suman en total (el equipo atribuido, el otro
/// equipo de un flujo LAN↔LAN y la red entera); dims lleva la columna «Equipo»
/// para el resto de dimensiones.
pub fn sujetos_y_dims(label: &FlowLabel, ctx: &FlowCtx) -> (Vec<Subject>, FlowDims) {
    let atribuido = match ctx.device_id {
        Some(DEVICE_ID_HOST) => Subject::Host,
        Some(id) => Subject::Device(id),
        None => Subject::Other,
    };
    let mut subjects = vec![atribuido];
    let mut peer = None;
    if let crate::inference::DestinationKind::Lan = label.destination.kind {
        if let Some(id) = label
            .destination
            .key
            .strip_prefix("lan:")
            .and_then(|clave| clave.parse::<i64>().ok())
        {
            let otro = if id == DEVICE_ID_HOST {
                Subject::Host
            } else {
                Subject::Device(id)
            };
            if !subjects.contains(&otro) {
                subjects.push(otro);
                peer = Some(otro);
            }
        }
    }
    subjects.push(Subject::Network);

    let protocolo = label
        .app_protocol
        .or(ctx.protocol)
        .map(|protocolo| protocolo.as_str().to_string());
    let dims = FlowDims {
        subject: Some(atribuido),
        app: label.app.clone(),
        category: label.category.clone(),
        destination: if label.destination.key.is_empty() {
            None
        } else {
            Some(label.destination.key.clone())
        },
        protocol: protocolo,
        process: ctx
            .process
            .as_ref()
            .map(|(_, nombre)| nombre.clone())
            .filter(|nombre| !nombre.is_empty()),
        org: label.destination.org.clone(),
        country: label.destination.country.clone(),
        destination_lan: matches!(
            label.destination.kind,
            crate::inference::DestinationKind::Lan
        ),
        peer,
        // El inventario JA4 es el de los flujos en los que el equipo es cliente.
        ja4: if ctx.es_cliente {
            label.ja4.clone()
        } else {
            None
        },
    };
    (subjects, dims)
}

/// Protocolo de respaldo de un flujo (transporte cuando no hay firma).
pub fn protocolo_de_respaldo(protocolo: crate::capture::Protocol) -> AppProtocol {
    AppProtocol::transport_fallback(protocolo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::{DestinationInfo, DestinationKind};

    fn etiqueta(app: Option<&str>, destino: &str, kind: DestinationKind) -> FlowLabel {
        FlowLabel {
            app: app.map(str::to_string),
            category: app.map(|_| "streaming".to_string()),
            destination: DestinationInfo {
                key: destino.to_string(),
                label: destino.to_string(),
                org: None,
                country: None,
                kind,
            },
            ..FlowLabel::empty("0.0.0.0".parse().unwrap())
        }
    }

    fn contexto(device_id: Option<i64>) -> FlowCtx {
        FlowCtx {
            device_id,
            process: None,
            l4: None,
            protocol: Some(AppProtocol::Tls),
            es_cliente: true,
        }
    }

    fn suma(batch: &RollupBatch, subject: Subject, dimension: Dimension) -> u64 {
        batch
            .rows
            .iter()
            .filter(|fila| fila.subject == subject && fila.dimension == dimension)
            .map(|fila| fila.counter.total())
            .sum()
    }

    #[test]
    fn el_equipo_y_la_red_suman_y_las_demas_dimensiones_una_vez() {
        let mut rollup = MinuteRollup::new(true);
        let mut label = etiqueta(Some("youtube"), "youtube.com", DestinationKind::Domain);
        label.destination.org = Some("Google LLC".to_string());
        label.destination.country = Some("US".to_string());
        label.ja4 = Some("t13d1516h2".to_string());
        let (subjects, dims) = sujetos_y_dims(&label, &contexto(Some(3)));
        rollup.add(&subjects, &dims, 100, Dir::Down);
        rollup.add(&subjects, &dims, 10, Dir::Up);
        let batch = rollup.flush(1_800_000_000);
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::Total), 110);
        assert_eq!(suma(&batch, Subject::Network, Dimension::Total), 110);
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::App), 110);
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::Org), 110);
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::Country), 110);
        assert!(batch
            .seen
            .iter()
            .any(|item| item.kind == SeenKind::App && item.key == "youtube"));
        assert!(batch
            .seen
            .iter()
            .any(|item| item.kind == SeenKind::Org && item.key == "Google LLC"));
        assert!(batch
            .seen
            .iter()
            .any(|item| item.kind == SeenKind::Ja4 && item.key == "t13d1516h2"));
        // La red nunca lleva dimensiones distintas de total.
        assert!(!batch
            .rows
            .iter()
            .any(|fila| fila.subject == Subject::Network && fila.dimension != Dimension::Total));
    }

    #[test]
    fn un_flujo_lan_entre_dos_equipos_suma_en_los_dos_totales() {
        let mut rollup = MinuteRollup::new(true);
        let label = etiqueta(None, "lan:7", DestinationKind::Lan);
        let (subjects, dims) = sujetos_y_dims(&label, &contexto(Some(3)));
        rollup.add(&subjects, &dims, 50, Dir::Down);
        let batch = rollup.flush(1_800_000_000);
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::Total), 50);
        assert_eq!(suma(&batch, Subject::Device(7), Dimension::Total), 50);
        assert_eq!(suma(&batch, Subject::Network, Dimension::Total), 50);
        // Solo el equipo atribuido lleva las demás dimensiones.
        assert_eq!(suma(&batch, Subject::Device(3), Dimension::Destination), 50);
        assert_eq!(suma(&batch, Subject::Device(7), Dimension::Destination), 0);
    }

    #[test]
    fn el_host_es_el_unico_que_lleva_procesos() {
        let mut rollup = MinuteRollup::new(true);
        let label = etiqueta(None, "1.1.1.1", DestinationKind::Ip);
        let mut ctx = contexto(Some(DEVICE_ID_HOST));
        ctx.process = Some((10, "firefox".to_string()));
        let (subjects, dims) = sujetos_y_dims(&label, &ctx);
        rollup.add(&subjects, &dims, 40, Dir::Up);
        let batch = rollup.flush(1_800_000_000);
        let proceso = batch
            .rows
            .iter()
            .find(|fila| fila.dimension == Dimension::Process)
            .expect("debe haber proceso del host");
        assert_eq!(proceso.key, "firefox");
        assert_eq!(proceso.subject, Subject::Host);
    }

    #[test]
    fn las_claves_especiales_cuadran_con_el_total() {
        let mut rollup = MinuteRollup::new(true);
        let sin_app = etiqueta(None, "10.0.0.1", DestinationKind::Ip);
        let (sujetos, dims) = sujetos_y_dims(&sin_app, &contexto(Some(1)));
        rollup.add(&sujetos, &dims, 30, Dir::Down);
        let batch = rollup.flush(1_800_000_000);
        assert_eq!(suma(&batch, Subject::Device(1), Dimension::App), 30);
        assert!(batch.rows.iter().any(|fila| {
            fila.dimension == Dimension::App && fila.key == crate::history::KEY_UNIDENTIFIED
        }));
        assert!(batch.rows.iter().any(|fila| {
            fila.dimension == Dimension::Org && fila.key == crate::history::KEY_UNKNOWN
        }));
    }

    #[test]
    fn los_topes_separan_las_claves_especiales_y_crean_otros() {
        let mut rollup = MinuteRollup::new(true);
        rollup.set_top_keys(2);
        let ctx = contexto(Some(2));
        for indice in 0..5u64 {
            let label = etiqueta(
                Some(&format!("app{indice}")),
                &format!("destino{indice}.com"),
                DestinationKind::Domain,
            );
            let (sujetos, dims) = sujetos_y_dims(&label, &ctx);
            rollup.add(&sujetos, &dims, 10 + indice, Dir::Down);
        }
        let batch = rollup.flush(1_800_000_000);
        let apps: Vec<&RollupRow> = batch
            .rows
            .iter()
            .filter(|fila| fila.dimension == Dimension::App && !clave_especial(&fila.key))
            .collect();
        assert_eq!(apps.len(), 2);
        assert!(batch
            .rows
            .iter()
            .any(|fila| { fila.dimension == Dimension::App && fila.key == KEY_OTHERS }));
        // La suma de la dimensión sigue cuadrando con el total.
        assert_eq!(suma(&batch, Subject::Device(2), Dimension::App), 60);
    }

    #[test]
    fn los_flujos_nuevos_cuentan_una_conexion_por_dimension() {
        let mut rollup = MinuteRollup::new(true);
        let label = etiqueta(Some("youtube"), "youtube.com", DestinationKind::Domain);
        let (sujetos, dims) = sujetos_y_dims(&label, &contexto(Some(4)));
        rollup.add(&sujetos, &dims, 100, Dir::Down);
        rollup.add_flow(7, &sujetos, &dims);
        rollup.actualizar_flujo(7, &sujetos, &dims);
        // Repetir el flujo no cuenta otra conexión.
        rollup.add_flow(7, &sujetos, &dims);
        let batch = rollup.flush(1_800_000_000);
        let total = batch
            .rows
            .iter()
            .find(|fila| fila.subject == Subject::Device(4) && fila.dimension == Dimension::Total)
            .unwrap();
        assert_eq!(total.counter.connections, 1);
        let app = batch
            .rows
            .iter()
            .find(|fila| fila.dimension == Dimension::App)
            .unwrap();
        assert_eq!(app.counter.connections, 1);
    }

    #[test]
    fn el_desbordamiento_suma_en_otros_sin_perder_el_total() {
        let mut rollup = MinuteRollup::new(true);
        rollup.set_max_entradas(3);
        let ctx = contexto(Some(5));
        for indice in 0..10u64 {
            let label = etiqueta(
                Some(&format!("app{indice}")),
                &format!("destino{indice}.com"),
                DestinationKind::Domain,
            );
            let (sujetos, dims) = sujetos_y_dims(&label, &ctx);
            rollup.add(&sujetos, &dims, 5, Dir::Down);
        }
        let batch = rollup.flush(1_800_000_000);
        assert!(batch.overflow > 0);
        assert_eq!(suma(&batch, Subject::Device(5), Dimension::App), 50);
        assert_eq!(suma(&batch, Subject::Device(5), Dimension::Total), 50);
    }

    #[test]
    fn desactivado_no_acumula_ni_emite_lote() {
        let mut rollup = MinuteRollup::new(false);
        let label = etiqueta(Some("youtube"), "youtube.com", DestinationKind::Domain);
        let (sujetos, dims) = sujetos_y_dims(&label, &contexto(Some(1)));
        rollup.add(&sujetos, &dims, 100, Dir::Down);
        rollup.add_flow(1, &sujetos, &dims);
        let batch = rollup.flush(1_800_000_000);
        assert!(batch.rows.is_empty());
        assert!(batch.seen.is_empty());
        assert_eq!(batch.minute, 1_800_000_000);
    }

    /// Memoria residente del proceso en KiB (solo Linux).
    fn memoria_kib() -> u64 {
        let Ok(contenido) = std::fs::read_to_string("/proc/self/statm") else {
            return 0;
        };
        let Some(paginas) = contenido.split_whitespace().nth(1) else {
            return 0;
        };
        let Ok(paginas) = paginas.parse::<u64>() else {
            return 0;
        };
        paginas * 4
    }

    #[test]
    #[ignore]
    fn medir_memoria_historial() {
        // §8: memoria añadida ≤ 16 MB con los topes del histórico.
        let base = memoria_kib();
        let mut rollup = MinuteRollup::new(true);
        for indice in 0..MAX_ENTRADAS {
            // Claves distintas para llenar el tope de 20 000 entradas.
            let app = format!("app{}", indice % 5_000);
            let mut label = etiqueta(Some(&app), "youtube.com", DestinationKind::Domain);
            label.ja4 = Some(format!("t13d1516h2{indice}"));
            let (sujetos, dims) = sujetos_y_dims(&label, &contexto(Some(1)));
            rollup.add(&sujetos, &dims, 10, Dir::Down);
        }
        let con_acumuladores = memoria_kib();
        // Un lote representativo de 50 equipos × 8 dimensiones × 20 claves, diez
        // veces (los lotes pendientes máximos de §4.1).
        let mut lote = RollupBatch {
            minute: 1_800_000_000,
            rows: Vec::new(),
            seen: Vec::new(),
            overflow: 0,
        };
        for device_id in 1..=50i64 {
            for dimension in Dimension::ALL {
                for clave in 0..20 {
                    lote.rows.push(RollupRow {
                        subject: Subject::Device(device_id),
                        dimension,
                        key: format!("clave-{dimension:?}-{clave}"),
                        counter: Counter {
                            down: 1_000,
                            up: 100,
                            connections: 1,
                        },
                    });
                }
            }
        }
        let pendientes: Vec<RollupBatch> = (0..10).map(|_| lote.clone()).collect();
        let con_lotes = memoria_kib();
        println!(
            "memoria: acumuladores {:.2} MB, 10 lotes {:.2} MB",
            (con_acumuladores.saturating_sub(base)) as f64 / 1024.0,
            (con_lotes.saturating_sub(con_acumuladores)) as f64 / 1024.0
        );
        let total = con_lotes.saturating_sub(base);
        assert!(
            total <= 16 * 1024,
            "la memoria añadida debe ser ≤ 16 MB (medida {:.2} MB)",
            total as f64 / 1024.0
        );
        drop(pendientes);
    }

    #[test]
    #[ignore]
    fn medir_minute_rollup() {
        // §8: MinuteRollup::add debe superar 1 millón de llamadas por segundo.
        // Se mide con etiquetas precomputadas (el coste de sujetos_y_dims lo paga
        // el agregador antes de llamar a add, en el mismo volcado por flujo).
        let mut rollup = MinuteRollup::new(true);
        let mut flujos = Vec::new();
        for indice in 0..8u64 {
            let app = format!("app{indice}");
            let destino = format!("destino{indice}.com");
            let label = etiqueta(Some(&app), &destino, DestinationKind::Domain);
            flujos.push(sujetos_y_dims(&label, &contexto(Some(1))));
        }
        // Calentamiento para que el mapa tenga sus grupos creados.
        for _ in 0..10_000 {
            for (subjects, dims) in flujos.iter() {
                rollup.add(subjects, dims, 10, Dir::Down);
            }
        }
        let iteraciones: u64 = 1_000_000;
        let inicio = std::time::Instant::now();
        for indice in 0..iteraciones {
            let (subjects, dims) = &flujos[(indice % flujos.len() as u64) as usize];
            rollup.add(subjects, dims, 10, Dir::Down);
        }
        let transcurrido = inicio.elapsed();
        let por_segundo = iteraciones as f64 / transcurrido.as_secs_f64();
        println!(
            "MinuteRollup::add: {por_segundo:.0} llamadas/s ({transcurrido:?} para {iteraciones})"
        );
        assert!(
            por_segundo >= 1_000_000.0,
            "MinuteRollup::add debe superar 1 millón/s (medido {por_segundo:.0})"
        );
    }

    #[test]
    fn el_ja4_solo_entra_en_el_inventario_del_cliente() {
        let mut label = etiqueta(Some("youtube"), "youtube.com", DestinationKind::Domain);
        label.ja4 = Some("t13d1516h2".to_string());
        let mut cliente = contexto(Some(3));
        cliente.es_cliente = true;
        let mut rollup = MinuteRollup::new(true);
        let (subjects, dims) = sujetos_y_dims(&label, &cliente);
        rollup.add(&subjects, &dims, 10, Dir::Down);
        let batch = rollup.flush(1_800_000_000);
        assert!(batch
            .seen
            .iter()
            .any(|item| item.kind == SeenKind::Ja4 && item.key == "t13d1516h2"));

        // Como servidor de la LAN no se le apunta la JA4 del cliente remoto.
        let mut servidor = contexto(Some(3));
        servidor.es_cliente = false;
        let mut rollup = MinuteRollup::new(true);
        let (subjects, dims) = sujetos_y_dims(&label, &servidor);
        rollup.add(&subjects, &dims, 10, Dir::Down);
        let batch = rollup.flush(1_800_000_000);
        assert!(!batch.seen.iter().any(|item| item.kind == SeenKind::Ja4));
    }

    #[test]
    fn el_protocolo_de_respaldo_cubre_icmp() {
        assert_eq!(
            protocolo_de_respaldo(crate::capture::Protocol::Icmp),
            AppProtocol::Icmp
        );
        assert_eq!(
            protocolo_de_respaldo(crate::capture::Protocol::Tcp),
            AppProtocol::Tcp
        );
    }
}
