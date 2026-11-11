//! Catálogo de apps y categorías embebido + apps.toml del usuario (§7.9).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::inference::L4;

/// Catálogo embebido en el binario (data/catalogo.toml).
pub const EMBEDDED: &str = include_str!("../../data/catalogo.toml");

/// Tope de apps propias cargadas desde el apps.toml del usuario (§7.9).
const MAX_USER_APPS: usize = 500;
/// Longitud máxima de una clave de app.
const MAX_KEY_LEN: usize = 32;
/// Longitud máxima del nombre de una app propia.
const MAX_NAME_LEN: usize = 40;
/// Longitud máxima de un sufijo de dominio.
const MAX_DOMAIN_LEN: usize = 253;
/// Longitud máxima de una etiqueta de dominio.
const MAX_LABEL_LEN: usize = 63;

/// Servicios de Fase 2 (y anuncios mDNS asimilables) que se asignan a cada app
/// de la categoría especial lan (§7.9 y §7.8).
///
/// La comparación se hace sobre el servicio normalizado: minúsculas, se toma el
/// primer componente de un tipo mDNS (_airplay._tcp → airplay) y los guiones se
/// convierten en guiones bajos.
const LAN_SERVICES: &[(&str, &str)] = &[
    // Compartición de archivos
    ("smb", "lan_files"),
    ("cifs", "lan_files"),
    ("afp", "lan_files"),
    ("nfs", "lan_files"),
    // Impresión
    ("ipp", "lan_printing"),
    ("lpd", "lan_printing"),
    ("printer", "lan_printing"),
    ("jetdirect", "lan_printing"),
    // AirPlay y Google Cast
    ("airplay", "lan_airplay"),
    ("cast", "lan_cast"),
    ("googlecast", "lan_cast"),
    ("chromecast", "lan_cast"),
    // Escritorio remoto y SSH
    ("rdp", "lan_remote_desktop"),
    ("vnc", "lan_remote_desktop"),
    ("ssh", "lan_ssh"),
    // Domótica
    ("mqtt", "lan_domotica"),
    ("coap", "lan_domotica"),
    ("homeassistant", "lan_domotica"),
    ("home_assistant", "lan_domotica"),
    // Cámaras
    ("rtsp", "lan_cameras"),
    ("onvif", "lan_cameras"),
    ("camera", "lan_cameras"),
    // UPnP/DLNA y servidores multimedia
    ("upnp", "lan_upnp"),
    ("dlna", "lan_upnp"),
    ("plex", "lan_media"),
    ("jellyfin", "lan_media"),
];

/// Categoría del catálogo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// Clave persistida (streaming, music…).
    pub key: String,
    /// Nombre largo.
    pub name: String,
    /// Nombre corto para la TUI.
    pub short: String,
}

/// Regla de puerto de una app.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRule {
    /// Transporte.
    pub l4: L4,
    /// Primer puerto del rango.
    pub start: u16,
    /// Último puerto del rango (igual a start si es un puerto único).
    pub end: u16,
}

impl PortRule {
    /// Indica si el puerto cae en la regla.
    pub fn matches(&self, l4: L4, port: u16) -> bool {
        self.l4 == l4 && (self.start..=self.end).contains(&port)
    }
}

/// App del catálogo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    /// Clave persistida en CONNECTIONS.app.
    pub key: String,
    /// Nombre visible.
    pub name: String,
    /// Clave de la categoría.
    pub category: String,
    /// Sufijos de dominio propios y de sus subdominios.
    pub domains: Vec<String>,
    /// ASN exclusivos de la app.
    pub asn: Vec<u32>,
    /// Reglas por puerto.
    pub ports: Vec<PortRule>,
    /// Comentario de origen (obligatorio en las apps embebidas).
    pub origin: Option<String>,
    /// La app viene del apps.toml del usuario.
    pub user_defined: bool,
}

/// Aviso del catálogo (fichero ausente, entrada inválida…).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogWarning {
    /// Mensaje en castellano.
    pub message: String,
}

impl CatalogWarning {
    /// Construye un aviso a partir de un mensaje.
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Cifras del catálogo para la pestaña Config.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CatalogCounts {
    /// Apps embebidas cargadas.
    pub embedded_apps: usize,
    /// Apps propias cargadas.
    pub user_apps: usize,
    /// Avisos emitidos al cargar.
    pub warnings: usize,
}

/// Catálogo cargado en memoria.
#[derive(Debug, Default)]
pub struct Catalog {
    apps: Vec<App>,
    categories: Vec<Category>,
    counts: CatalogCounts,
    /// Índice sufijo de dominio → posición en apps (gana la primera regla).
    by_domain: HashMap<String, usize>,
    /// Índice ASN → posición en apps (gana la primera regla).
    by_asn: HashMap<u32, usize>,
    /// Reglas de puerto con su app, en orden de aparición.
    by_port: Vec<(L4, u16, u16, usize)>,
    /// Servicio normalizado de F2 → posición de la app lan correspondiente.
    lan: HashMap<String, usize>,
}

impl Catalog {
    /// Carga el catálogo embebido y, si existe, el apps.toml del usuario.
    pub fn load(embedded: &str, user_file: Option<&Path>) -> (Self, Vec<CatalogWarning>) {
        let mut avisos = Vec::new();
        let mut categorias: Vec<Category> = Vec::new();
        let mut apps: Vec<App> = Vec::new();
        let mut embedded_apps = 0usize;

        // Catálogo embebido: es un dato de compilación, pero se valida igual y
        // cualquier anomalía se avisa en vez de provocar un pánico.
        if let Some(documento) = parse_document(embedded, &mut avisos) {
            for def in documento.categories {
                upsert_category(&mut categorias, def, &mut avisos);
            }
            for def in documento.apps {
                let origen = documento.origins.get(&def.key).cloned();
                match validate_app(&def, &categorias, false) {
                    Ok(mut app) => {
                        match origen {
                            Some(comentario) => app.origin = Some(comentario),
                            None => avisos.push(CatalogWarning::new(format!(
                                "la app embebida «{}» no lleva comentario «# origen:»; se carga igualmente",
                                app.key
                            ))),
                        }
                        apps.push(app);
                        embedded_apps += 1;
                    }
                    Err(motivo) => avisos.push(CatalogWarning::new(format!(
                        "la app embebida «{}» no es válida ({motivo}); se ignora",
                        def.key
                    ))),
                }
            }
        } else {
            avisos.push(CatalogWarning::new(
                "el catálogo embebido no se pudo cargar; no habrá apps identificadas",
            ));
        }

        // apps.toml del usuario.
        let mut user_apps = 0usize;
        if let Some(ruta) = user_file {
            match std::fs::read_to_string(ruta) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    avisos.push(CatalogWarning::new(format!(
                        "no existe el fichero de apps propias «{}»; se usan solo las apps embebidas",
                        ruta.display()
                    )));
                }
                Err(error) => avisos.push(CatalogWarning::new(format!(
                    "no se pudo leer el fichero de apps propias «{}» ({error}); se usan solo las apps embebidas",
                    ruta.display()
                ))),
                Ok(texto) => {
                    if let Some(documento) = parse_document(&texto, &mut avisos) {
                        // Las categorías del propio fichero se admiten (§7.16) y
                        // deben estar disponibles antes de validar sus apps.
                        for def in documento.categories {
                            upsert_category(&mut categorias, def, &mut avisos);
                        }
                        let mut vistas: std::collections::HashSet<String> =
                            std::collections::HashSet::new();
                        for def in documento.apps {
                            if user_apps >= MAX_USER_APPS {
                                avisos.push(CatalogWarning::new(format!(
                                    "el fichero de apps propias supera el máximo de {MAX_USER_APPS} apps; se ignoran las restantes"
                                )));
                                break;
                            }
                            if !vistas.insert(def.key.clone()) {
                                avisos.push(CatalogWarning::new(format!(
                                    "clave de app duplicada en el fichero de apps propias («{}»); se ignora la segunda",
                                    def.key
                                )));
                                continue;
                            }
                            match validate_app(&def, &categorias, true) {
                                Ok(mut app) => {
                                    app.origin = documento.origins.get(&def.key).cloned();
                                    app.user_defined = true;
                                    match apps.iter().position(|existente| existente.key == app.key) {
                                        Some(posicion) => apps[posicion] = app,
                                        None => apps.push(app),
                                    }
                                    user_apps += 1;
                                }
                                Err(motivo) => avisos.push(CatalogWarning::new(format!(
                                    "la app propia «{}» no es válida ({motivo}); se ignora esa entrada",
                                    def.key
                                ))),
                            }
                        }
                    }
                }
            }
        }

        let mut catalogo = Catalog {
            apps,
            categories: categorias,
            counts: CatalogCounts {
                embedded_apps,
                user_apps,
                warnings: avisos.len(),
            },
            ..Catalog::default()
        };
        catalogo.rebuild_indices();
        (catalogo, avisos)
    }

    /// Carga solo el catálogo embebido.
    pub fn embedded_only(embedded: &str) -> (Self, Vec<CatalogWarning>) {
        Self::load(embedded, None)
    }

    /// Reconstruye los índices de búsqueda tras aplicar el apps.toml.
    fn rebuild_indices(&mut self) {
        self.by_domain.clear();
        self.by_asn.clear();
        self.by_port.clear();
        self.lan.clear();
        for (indice, app) in self.apps.iter().enumerate() {
            for dominio in &app.domains {
                self.by_domain.entry(dominio.clone()).or_insert(indice);
            }
            for asn in &app.asn {
                self.by_asn.entry(*asn).or_insert(indice);
            }
            for regla in &app.ports {
                self.by_port
                    .push((regla.l4, regla.start, regla.end, indice));
            }
        }
        for (servicio, clave) in LAN_SERVICES {
            if let Some(indice) = self.apps.iter().position(|app| app.key == *clave) {
                self.lan.entry((*servicio).to_string()).or_insert(indice);
            }
        }
    }

    /// App que casa con un nombre por el sufijo más largo.
    pub fn match_name(&self, name: &str) -> Option<&App> {
        let mut normalizado = name.trim().to_ascii_lowercase();
        while normalizado.ends_with('.') {
            normalizado.pop();
        }
        if normalizado.is_empty()
            || normalizado.contains("://")
            || normalizado.contains('/')
            || normalizado.contains(':')
        {
            return None;
        }
        let etiquetas: Vec<&str> = normalizado.split('.').collect();
        if etiquetas.len() < 2 {
            return None;
        }
        // Del sufijo más largo al más corto: music.youtube.com → YouTube Music
        // antes que youtube.com → YouTube.
        for inicio in 0..etiquetas.len() - 1 {
            let candidato = etiquetas[inicio..].join(".");
            if let Some(indice) = self.by_domain.get(candidato.as_str()) {
                return self.apps.get(*indice);
            }
        }
        None
    }

    /// App que casa con un ASN.
    pub fn match_asn(&self, asn: u32) -> Option<&App> {
        self.by_asn
            .get(&asn)
            .and_then(|indice| self.apps.get(*indice))
    }

    /// App que casa con un puerto.
    pub fn match_port(&self, l4: L4, port: u16) -> Option<&App> {
        self.by_port
            .iter()
            .find(|(transporte, inicio, fin, _)| {
                *transporte == l4 && (*inicio..=*fin).contains(&port)
            })
            .and_then(|(_, _, _, indice)| self.apps.get(*indice))
    }

    /// App de red local para un servicio de F2 ("smb", "rdp"…).
    pub fn lan_app(&self, service: &str) -> Option<&App> {
        let normalizado = normalize_service(service)?;
        self.lan
            .get(normalizado.as_str())
            .and_then(|indice| self.apps.get(*indice))
    }

    /// App por clave.
    pub fn app(&self, key: &str) -> Option<&App> {
        self.apps.iter().find(|app| app.key == key)
    }

    /// Categoría por clave.
    pub fn category(&self, key: &str) -> Option<&Category> {
        self.categories
            .iter()
            .find(|categoria| categoria.key == key)
    }

    /// Todas las apps.
    pub fn apps(&self) -> &[App] {
        &self.apps
    }

    /// Todas las categorías.
    pub fn categories(&self) -> &[Category] {
        &self.categories
    }

    /// Nombre visible de una app por clave.
    pub fn app_name(&self, key: &str) -> Option<&str> {
        self.app(key).map(|app| app.name.as_str())
    }

    /// Nombre corto de una categoría por clave.
    pub fn category_short(&self, key: &str) -> Option<&str> {
        self.category(key).map(|categoria| categoria.short.as_str())
    }

    /// Cifras para la pestaña Config.
    pub fn counts(&self) -> CatalogCounts {
        self.counts
    }
}

/// Documento TOML del catálogo o del apps.toml del usuario.
struct Document {
    categories: Vec<CategoryDef>,
    apps: Vec<AppDef>,
    /// Comentario "# origen:" de cada app, indexado por clave.
    origins: HashMap<String, String>,
}

/// Categoría tal y como se escribe en el TOML.
#[derive(Debug, Deserialize)]
struct CategoryDef {
    key: String,
    name: String,
    short: String,
}

/// App tal y como se escribe en el TOML.
#[derive(Debug, Deserialize)]
struct AppDef {
    key: String,
    name: String,
    category: String,
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    asn: Vec<u32>,
    #[serde(default)]
    ports: Vec<String>,
}

/// Interpreta un documento TOML y devuelve sus entradas válidas por tipo.
///
/// Los errores de sintaxis descartan el documento entero (lo decide el llamador);
/// los errores de una entrada concreta solo descartan esa entrada.
fn parse_document(texto: &str, avisos: &mut Vec<CatalogWarning>) -> Option<Document> {
    let valor: toml::Value = match toml::from_str(texto) {
        Ok(valor) => valor,
        Err(error) => {
            avisos.push(CatalogWarning::new(format!(
                "el fichero de catálogo no es TOML válido ({error}); se ignora entero"
            )));
            return None;
        }
    };
    let Some(tabla) = valor.as_table() else {
        avisos.push(CatalogWarning::new(
            "el fichero de catálogo no es una tabla TOML; se ignora entero",
        ));
        return None;
    };
    Some(Document {
        categories: parse_entries(tabla.get("category"), "category", avisos),
        apps: parse_entries(tabla.get("app"), "app", avisos),
        origins: extract_origins(texto),
    })
}

/// Convierte una lista de tablas TOML en entradas de tipo T, avisando de las
/// que no se pueden interpretar sin descartar el resto.
fn parse_entries<T>(
    valor: Option<&toml::Value>,
    nombre: &str,
    avisos: &mut Vec<CatalogWarning>,
) -> Vec<T>
where
    T: for<'de> Deserialize<'de>,
{
    let Some(valor) = valor else {
        return Vec::new();
    };
    let Some(lista) = valor.as_array() else {
        avisos.push(CatalogWarning::new(format!(
            "«{nombre}» debe ser una lista de tablas; se ignora"
        )));
        return Vec::new();
    };
    let mut salida = Vec::new();
    for (indice, entrada) in lista.iter().enumerate() {
        match entrada.clone().try_into::<T>() {
            Ok(convertida) => salida.push(convertida),
            Err(error) => avisos.push(CatalogWarning::new(format!(
                "la entrada {} de «{nombre}» no es válida ({error}); se ignora",
                indice + 1
            ))),
        }
    }
    salida
}

/// Extrae los comentarios "# origen: ..." de cada bloque [[app]].
///
/// Va línea a línea porque serde no conserva los comentarios; así el catálogo
/// embebido puede documentar la procedencia de cada regla.
fn extract_origins(texto: &str) -> HashMap<String, String> {
    let mut origenes = HashMap::new();
    let mut bloque: Option<(Option<String>, Option<String>)> = None;
    for linea in texto.lines() {
        let recortada = linea.trim();
        if recortada.starts_with("[[") {
            if let Some((Some(clave), Some(origen))) = bloque.take() {
                origenes.entry(clave).or_insert(origen);
            }
            // Solo se recogen los orígenes de las apps; las categorías no los llevan.
            bloque = if recortada == "[[app]]" {
                Some((None, None))
            } else {
                None
            };
            continue;
        }
        let Some((clave, origen)) = bloque.as_mut() else {
            continue;
        };
        if clave.is_none() {
            if let Some(resto) = recortada.strip_prefix("key") {
                if let Some(resto) = resto.trim_start().strip_prefix('=') {
                    if let Some(valor) = resto
                        .trim()
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                    {
                        *clave = Some(valor.to_string());
                    }
                }
            }
        }
        if origen.is_none() {
            if let Some(resto) = recortada.strip_prefix("# origen:") {
                let comentario = resto.trim();
                if !comentario.is_empty() {
                    *origen = Some(comentario.to_string());
                }
            }
        }
    }
    if let Some((Some(clave), Some(origen))) = bloque {
        origenes.entry(clave).or_insert(origen);
    }
    origenes
}

/// Normaliza el nombre de un servicio de F2 o de un tipo mDNS.
fn normalize_service(service: &str) -> Option<String> {
    let minusculas = service.trim().to_ascii_lowercase();
    if minusculas.is_empty() {
        return None;
    }
    // "_airplay._tcp" → "airplay"; un nombre simple se queda igual.
    let primero = minusculas.split('.').next().unwrap_or(minusculas.as_str());
    let normalizado = primero.replace('-', "_");
    let recortado = normalizado.trim_matches('_');
    if recortado.is_empty() {
        None
    } else {
        Some(recortado.to_string())
    }
}

/// Añade o sustituye una categoría por clave.
fn upsert_category(
    categorias: &mut Vec<Category>,
    def: CategoryDef,
    avisos: &mut Vec<CatalogWarning>,
) {
    let clave = def.key.trim();
    if !es_clave_valida(clave) {
        avisos.push(CatalogWarning::new(format!(
            "la categoría «{}» tiene una clave inválida (^[a-z0-9_]{{1,32}}$); se ignora",
            def.key
        )));
        return;
    }
    if def.name.trim().is_empty() || def.short.trim().is_empty() {
        avisos.push(CatalogWarning::new(format!(
            "la categoría «{clave}» necesita nombre y nombre corto; se ignora"
        )));
        return;
    }
    let categoria = Category {
        key: clave.to_string(),
        name: def.name.trim().to_string(),
        short: def.short.trim().to_string(),
    };
    match categorias
        .iter_mut()
        .find(|existente| existente.key == categoria.key)
    {
        Some(existente) => *existente = categoria,
        None => categorias.push(categoria),
    }
}

/// Valida y convierte una app del TOML. El mensaje de error va en castellano.
fn validate_app(def: &AppDef, categorias: &[Category], propia: bool) -> Result<App, String> {
    let clave = def.key.trim();
    if !es_clave_valida(clave) {
        return Err(format!(
            "clave «{}» inválida: debe casar con ^[a-z0-9_]{{1,32}}$",
            def.key
        ));
    }
    let nombre = def.name.trim();
    if nombre.is_empty() {
        return Err("el nombre está vacío".to_string());
    }
    if propia && nombre.chars().count() > MAX_NAME_LEN {
        return Err(format!(
            "el nombre «{nombre}» supera el máximo de {MAX_NAME_LEN} caracteres"
        ));
    }
    if !categorias
        .iter()
        .any(|categoria| categoria.key == def.category.trim())
    {
        return Err(format!("la categoría «{}» no existe", def.category));
    }
    let mut dominios = Vec::with_capacity(def.domains.len());
    for dominio in &def.domains {
        validate_domain(dominio)?;
        let normalizado = dominio.trim().trim_end_matches('.').to_ascii_lowercase();
        if !dominios.contains(&normalizado) {
            dominios.push(normalizado);
        }
    }
    let mut puertos = Vec::with_capacity(def.ports.len());
    for regla in &def.ports {
        puertos.push(parse_port_rule(regla)?);
    }
    Ok(App {
        key: clave.to_string(),
        name: nombre.to_string(),
        category: def.category.trim().to_string(),
        domains: dominios,
        asn: def.asn.clone(),
        ports: puertos,
        origin: None,
        user_defined: propia,
    })
}

/// Indica si una clave cumple ^[a-z0-9_]{1,32}$.
fn es_clave_valida(clave: &str) -> bool {
    !clave.is_empty()
        && clave.len() <= MAX_KEY_LEN
        && clave.chars().all(|caracter| {
            caracter.is_ascii_lowercase() || caracter.is_ascii_digit() || caracter == '_'
        })
}

/// Valida un sufijo de dominio del catálogo: minúsculas, sin esquema ni comodines
/// y con al menos dos etiquetas.
fn validate_domain(dominio: &str) -> Result<(), String> {
    let texto = dominio.trim();
    if texto.is_empty() {
        return Err("hay un dominio vacío".to_string());
    }
    if texto.len() > MAX_DOMAIN_LEN {
        return Err(format!(
            "el dominio «{texto}» supera los {MAX_DOMAIN_LEN} caracteres"
        ));
    }
    if texto.contains("://") {
        return Err(format!("el dominio «{texto}» no puede llevar esquema"));
    }
    if texto.contains('*') {
        return Err(format!("el dominio «{texto}» no puede llevar comodines"));
    }
    if texto != texto.to_ascii_lowercase() {
        return Err(format!("el dominio «{texto}» debe estar en minúsculas"));
    }
    if texto.starts_with('.') || texto.ends_with('.') {
        return Err(format!(
            "el dominio «{texto}» no puede empezar ni acabar en punto"
        ));
    }
    let etiquetas: Vec<&str> = texto.split('.').collect();
    if etiquetas.len() < 2 {
        return Err(format!(
            "el dominio «{texto}» necesita al menos dos etiquetas (no se aceptan TLD sueltos)"
        ));
    }
    for etiqueta in etiquetas {
        if etiqueta.is_empty() {
            return Err(format!("el dominio «{texto}» tiene una etiqueta vacía"));
        }
        if etiqueta.len() > MAX_LABEL_LEN {
            return Err(format!(
                "el dominio «{texto}» tiene una etiqueta de más de {MAX_LABEL_LEN} caracteres"
            ));
        }
        if !etiqueta.chars().all(|caracter| {
            caracter.is_ascii_lowercase() || caracter.is_ascii_digit() || caracter == '-'
        }) {
            return Err(format!(
                "el dominio «{texto}» solo admite letras, dígitos, guiones y puntos"
            ));
        }
        if etiqueta.starts_with('-') || etiqueta.ends_with('-') {
            return Err(format!(
                "el dominio «{texto}» tiene una etiqueta que empieza o acaba en guion"
            ));
        }
    }
    Ok(())
}

/// Interpreta una regla de puerto "tcp/443" o "udp/27015-27050".
fn parse_port_rule(texto: &str) -> Result<PortRule, String> {
    let recortado = texto.trim();
    let Some((transporte, puertos)) = recortado.split_once('/') else {
        return Err(format!(
            "el puerto «{recortado}» no es válido: se esperaba tcp/443 o udp/27015-27050"
        ));
    };
    let Some(l4) = L4::from_str(transporte) else {
        return Err(format!(
            "el transporte «{transporte}» de «{recortado}» no es válido: solo tcp o udp"
        ));
    };
    let (inicio_texto, fin_texto) = match puertos.split_once('-') {
        Some((inicio, fin)) => (inicio, fin),
        None => (puertos, puertos),
    };
    let inicio = parse_port_number(inicio_texto, recortado)?;
    let fin = parse_port_number(fin_texto, recortado)?;
    if inicio == 0 || fin == 0 {
        return Err(format!("el puerto «{recortado}» no puede ser 0"));
    }
    if inicio > fin {
        return Err(format!(
            "el rango «{recortado}» está al revés: el primer puerto debe ser menor o igual que el último"
        ));
    }
    Ok(PortRule {
        l4,
        start: inicio,
        end: fin,
    })
}

/// Convierte un número de puerto con un mensaje de error en castellano.
fn parse_port_number(texto: &str, regla: &str) -> Result<u16, String> {
    texto
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("el puerto «{texto}» de «{regla}» no es un número entre 1 y 65535"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cartografía de categorías esperada del §7.9: clave, nombre, nombre corto
    /// y número de apps de la lista mínima.
    const CATEGORIAS: &[(&str, &str, &str, usize)] = &[
        ("streaming", "Vídeo y streaming", "Vídeo", 14),
        ("music", "Música y audio", "Música", 8),
        ("social", "Redes sociales", "Social", 10),
        ("messaging", "Mensajería", "Mensajería", 7),
        ("calls", "Videollamadas", "Llamadas", 6),
        ("games", "Juegos", "Juegos", 11),
        ("system", "Sistema y actualizaciones", "Sistema", 12),
        ("cloud", "Nube y copias", "Nube", 10),
        ("work", "Trabajo y desarrollo", "Trabajo", 17),
        ("web", "Navegación, compras y banca", "Web", 21),
        (
            "tracking",
            "Publicidad, rastreo y telemetría",
            "Rastreo",
            18,
        ),
        ("infrastructure", "Infraestructura", "Infraestr.", 18),
        (
            "lan",
            "Red local (especial: servicios de F2)",
            "Red local",
            10,
        ),
    ];

    fn catalogo_embebido() -> Catalog {
        let (catalogo, avisos) = Catalog::embedded_only(EMBEDDED);
        assert!(
            avisos.is_empty(),
            "avisos embebidos inesperados: {avisos:?}"
        );
        catalogo
    }

    #[test]
    fn catalogo_embebido_con_162_apps_y_13_categorias() {
        let catalogo = catalogo_embebido();
        let counts = catalogo.counts();
        assert_eq!(counts.embedded_apps, 162);
        assert_eq!(counts.user_apps, 0);
        assert_eq!(counts.warnings, 0);
        assert_eq!(catalogo.apps().len(), 162);
        assert_eq!(catalogo.categories().len(), 13);

        for (clave, nombre, corto, total) in CATEGORIAS {
            let categoria = catalogo
                .category(clave)
                .unwrap_or_else(|| panic!("falta la categoría {clave}"));
            assert_eq!(&categoria.name, nombre);
            assert_eq!(&categoria.short, corto);
            assert_eq!(catalogo.category_short(clave), Some(*corto));
            let cargadas = catalogo
                .apps()
                .iter()
                .filter(|app| app.category == *clave)
                .count();
            assert_eq!(cargadas, *total, "categoría {clave}");
        }

        // Cada app embebida lleva su comentario de origen.
        for app in catalogo.apps() {
            assert!(
                app.origin
                    .as_deref()
                    .is_some_and(|origen| !origen.is_empty()),
                "la app {} no tiene comentario «# origen:»",
                app.key
            );
            assert!(!app.user_defined, "{} debería ser embebida", app.key);
        }
    }

    #[test]
    fn sufijo_mas_largo_y_musica_de_youtube() {
        let catalogo = catalogo_embebido();
        assert_eq!(
            catalogo
                .match_name("music.youtube.com")
                .map(|app| app.key.as_str()),
            Some("youtube_music")
        );
        assert_eq!(
            catalogo
                .match_name("www.youtube.com")
                .map(|app| app.key.as_str()),
            Some("youtube")
        );
        assert_eq!(
            catalogo
                .match_name("rr3---sn-x.googlevideo.com")
                .map(|app| app.key.as_str()),
            Some("youtube")
        );
        // Normalización: mayúsculas y punto final.
        assert_eq!(
            catalogo
                .match_name("MUSIC.YouTube.COM.")
                .map(|app| app.key.as_str()),
            Some("youtube_music")
        );
        // Los dominios de proveedor compartidos van a apps genéricas.
        assert_eq!(
            catalogo
                .match_name("fonts.gstatic.com")
                .map(|app| app.key.as_str()),
            Some("google_services")
        );
        assert_eq!(
            catalogo
                .match_name("cdn.example.akamaized.net")
                .map(|app| app.key.as_str()),
            Some("cdn_akamai")
        );
        assert_eq!(
            catalogo
                .match_name("d123.cloudfront.net")
                .map(|app| app.key.as_str()),
            Some("aws")
        );
        // Sin coincidencia.
        assert_eq!(catalogo.match_name("no-existe.example"), None);
        assert_eq!(catalogo.match_name(""), None);
        assert_eq!(catalogo.match_name("localhost"), None);
        assert_eq!(catalogo.match_name("https://youtube.com"), None);
    }

    #[test]
    fn reglas_por_asn_y_por_puerto() {
        let catalogo = catalogo_embebido();
        assert_eq!(
            catalogo.match_asn(2906).map(|app| app.key.as_str()),
            Some("netflix")
        );
        assert_eq!(
            catalogo.match_asn(13335).map(|app| app.key.as_str()),
            Some("cdn_cloudflare")
        );
        assert_eq!(catalogo.match_asn(64512), None);

        assert_eq!(
            catalogo
                .match_port(L4::Udp, 123)
                .map(|app| app.key.as_str()),
            Some("ntp")
        );
        assert_eq!(
            catalogo
                .match_port(L4::Tcp, 27015)
                .map(|app| app.key.as_str()),
            Some("steam")
        );
        assert_eq!(
            catalogo
                .match_port(L4::Udp, 27050)
                .map(|app| app.key.as_str()),
            Some("steam")
        );
        assert_eq!(catalogo.match_port(L4::Tcp, 27051), None);
        assert_eq!(
            catalogo.match_port(L4::Tcp, 53).map(|app| app.key.as_str()),
            Some("dns")
        );
        // Los servicios de la LAN no se usan como regla global de puerto.
        assert_eq!(catalogo.match_port(L4::Tcp, 445), None);
    }

    #[test]
    fn apps_toml_temporal_sustituye_anade_y_avisa() {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let ruta = dir.path().join("apps.toml");
        let contenido = r#"
[[category]]
key = "mi_categoria"
name = "Mi categoría"
short = "Mía"

[[app]]
key = "youtube"
name = "YouTube propio"
category = "streaming"

[[app]]
key = "mi_app"
name = "Mi app"
category = "mi_categoria"
domains = ["mi-app.example"]
asn = [64512]
ports = ["udp/9999"]
# origen: prueba de apps propias

[[app]]
key = "Clave Invalida!"
name = "Inválida"
category = "streaming"

[[app]]
key = "categoria_ajena"
name = "Categoría ajena"
category = "no_existe"
"#;
        std::fs::write(&ruta, contenido).expect("escribir apps.toml");

        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&ruta));
        assert_eq!(catalogo.counts().embedded_apps, 162);
        assert_eq!(catalogo.counts().user_apps, 2);
        assert_eq!(catalogo.counts().warnings, avisos.len());
        assert_eq!(avisos.len(), 2, "avisos: {avisos:?}");

        // La app con la misma clave sustituye entera a la embebida (ya no casa).
        assert_eq!(catalogo.app_name("youtube"), Some("YouTube propio"));
        assert_eq!(catalogo.match_name("youtube.com"), None);
        assert!(catalogo.app("youtube").is_some_and(|app| app.user_defined));

        // La app nueva se añade con su categoría propia y sus reglas.
        let nueva = catalogo.app("mi_app").expect("app propia");
        assert_eq!(nueva.name, "Mi app");
        assert_eq!(nueva.category, "mi_categoria");
        assert_eq!(nueva.origin.as_deref(), Some("prueba de apps propias"));
        assert_eq!(
            catalogo
                .match_name("sub.mi-app.example")
                .map(|app| app.key.as_str()),
            Some("mi_app")
        );
        assert_eq!(
            catalogo.match_asn(64512).map(|app| app.key.as_str()),
            Some("mi_app")
        );
        assert_eq!(
            catalogo
                .match_port(L4::Udp, 9999)
                .map(|app| app.key.as_str()),
            Some("mi_app")
        );
        assert_eq!(catalogo.category_short("mi_categoria"), Some("Mía"));

        // Las entradas inválidas se avisan y se ignoran sin descartar el resto.
        assert!(avisos
            .iter()
            .any(|aviso| aviso.message.contains("Clave Invalida!")));
        assert!(avisos
            .iter()
            .any(|aviso| aviso.message.contains("categoria_ajena")));
    }

    #[test]
    fn apps_toml_ausente_ilegible_o_invalido_conserva_el_embebido() {
        let dir = tempfile::tempdir().expect("directorio temporal");

        // Fichero ausente: aviso informativo y catálogo embebido intacto.
        let inexistente = dir.path().join("no-existe.toml");
        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&inexistente));
        assert_eq!(avisos.len(), 1);
        assert!(avisos[0].message.contains("no existe"));
        assert_eq!(catalogo.counts().embedded_apps, 162);

        // Fichero con TOML roto: se ignora entero.
        let roto = dir.path().join("roto.toml");
        std::fs::write(&roto, "esto no es toml [[[").expect("escribir roto");
        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&roto));
        assert_eq!(catalogo.counts().embedded_apps, 162);
        assert_eq!(catalogo.counts().user_apps, 0);
        assert!(avisos.iter().any(|aviso| aviso.message.contains("TOML")));

        // Fichero vacío: no hay apps propias ni avisos de entradas.
        let vacio = dir.path().join("vacio.toml");
        std::fs::write(&vacio, "").expect("escribir vacío");
        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&vacio));
        assert_eq!(catalogo.counts().embedded_apps, 162);
        assert_eq!(catalogo.counts().user_apps, 0);
        assert!(avisos.is_empty(), "avisos: {avisos:?}");

        // Fichero con bytes no UTF-8: se avisa y se ignora.
        let binario = dir.path().join("binario.toml");
        std::fs::write(&binario, [0xff, 0xfe, 0x00, 0x80]).expect("escribir binario");
        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&binario));
        assert_eq!(catalogo.counts().embedded_apps, 162);
        assert!(avisos
            .iter()
            .any(|aviso| aviso.message.contains("no se pudo leer")));
    }

    #[test]
    fn apps_toml_limita_a_500_apps_propias() {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let ruta = dir.path().join("apps.toml");
        let mut contenido = String::new();
        for indice in 0..MAX_USER_APPS + 1 {
            contenido.push_str(&format!(
                "[[app]]\nkey = \"propia_{indice}\"\nname = \"Propia {indice}\"\ncategory = \"web\"\ndomains = [\"propia{indice}.example\"]\n\n"
            ));
        }
        std::fs::write(&ruta, contenido).expect("escribir apps.toml");

        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&ruta));
        assert_eq!(catalogo.counts().user_apps, MAX_USER_APPS);
        assert_eq!(catalogo.apps().len(), 162 + MAX_USER_APPS);
        assert!(
            avisos
                .iter()
                .any(|aviso| aviso.message.contains("máximo de 500")),
            "avisos: {avisos:?}"
        );
    }

    #[test]
    fn validacion_de_entradas_propias() {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let ruta = dir.path().join("apps.toml");
        let invalidas = [
            // clave que no casa con ^[a-z0-9_]{1,32}$
            "[[app]]\nkey = \"AppMayus\"\nname = \"Mayúsculas\"\ncategory = \"web\"\n",
            // nombre vacío
            "[[app]]\nkey = \"sin_nombre\"\nname = \"   \"\ncategory = \"web\"\n",
            // nombre de más de 40 caracteres
            "[[app]]\nkey = \"nombre_largo\"\nname = \"Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\ncategory = \"web\"\n",
            // categoría inexistente
            "[[app]]\nkey = \"sin_categoria\"\nname = \"Sin categoría\"\ncategory = \"inexistente\"\n",
            // dominio con mayúsculas
            "[[app]]\nkey = \"dominio_mayus\"\nname = \"Dominio mayúsculas\"\ncategory = \"web\"\ndomains = [\"Ejemplo.COM\"]\n",
            // dominio con esquema
            "[[app]]\nkey = \"dominio_esquema\"\nname = \"Dominio esquema\"\ncategory = \"web\"\ndomains = [\"https://ejemplo.com\"]\n",
            // dominio con comodín
            "[[app]]\nkey = \"dominio_comodin\"\nname = \"Dominio comodín\"\ncategory = \"web\"\ndomains = [\"*.ejemplo.com\"]\n",
            // dominio de una sola etiqueta
            "[[app]]\nkey = \"dominio_tld\"\nname = \"Dominio TLD\"\ncategory = \"web\"\ndomains = [\"com\"]\n",
            // asn con un tipo que no es u32
            "[[app]]\nkey = \"asn_texto\"\nname = \"ASN texto\"\ncategory = \"web\"\nasn = [\"15169\"]\n",
            // puerto sin transporte
            "[[app]]\nkey = \"puerto_sin_l4\"\nname = \"Puerto sin L4\"\ncategory = \"web\"\nports = [\"443\"]\n",
            // puerto con transporte desconocido
            "[[app]]\nkey = \"puerto_icmp\"\nname = \"Puerto ICMP\"\ncategory = \"web\"\nports = [\"icmp/5\"]\n",
            // rango al revés
            "[[app]]\nkey = \"rango_al_reves\"\nname = \"Rango al revés\"\ncategory = \"web\"\nports = [\"tcp/900-800\"]\n",
            // puerto 0
            "[[app]]\nkey = \"puerto_cero\"\nname = \"Puerto cero\"\ncategory = \"web\"\nports = [\"udp/0\"]\n",
        ];
        let mut contenido = String::new();
        for entrada in invalidas {
            contenido.push_str(entrada);
            contenido.push('\n');
        }
        // App válida de control con las dos formas admitidas de regla de puerto.
        contenido.push_str(
            "[[app]]\nkey = \"control\"\nname = \"Control\"\ncategory = \"web\"\ndomains = [\"control.example\"]\nports = [\"tcp/443\", \"udp/27051-27060\"]\n",
        );
        std::fs::write(&ruta, contenido).expect("escribir apps.toml");

        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&ruta));
        assert_eq!(
            catalogo.counts().user_apps,
            1,
            "solo la app de control es válida"
        );
        assert!(catalogo.app("control").is_some());
        assert_eq!(
            catalogo.counts().warnings,
            avisos.len(),
            "los avisos se contabilizan"
        );
        assert_eq!(
            avisos.len(),
            invalidas.len(),
            "una entrada inválida genera un aviso: {avisos:?}"
        );
        assert_eq!(
            catalogo
                .match_port(L4::Tcp, 443)
                .map(|app| app.key.as_str()),
            Some("control")
        );
        assert_eq!(
            catalogo
                .match_port(L4::Udp, 27055)
                .map(|app| app.key.as_str()),
            Some("control")
        );
        // Las reglas embebidas conservan la prioridad sobre las propias.
        assert_eq!(
            catalogo
                .match_port(L4::Udp, 27030)
                .map(|app| app.key.as_str()),
            Some("steam")
        );
    }

    #[test]
    fn lan_app_mapea_los_servicios_de_f2() {
        let catalogo = catalogo_embebido();
        let casos = [
            ("smb", "lan_files"),
            ("cifs", "lan_files"),
            ("afp", "lan_files"),
            ("nfs", "lan_files"),
            ("ipp", "lan_printing"),
            ("lpd", "lan_printing"),
            ("printer", "lan_printing"),
            ("airplay", "lan_airplay"),
            ("_airplay._tcp", "lan_airplay"),
            ("cast", "lan_cast"),
            ("googlecast", "lan_cast"),
            ("_googlecast._tcp", "lan_cast"),
            ("rdp", "lan_remote_desktop"),
            ("vnc", "lan_remote_desktop"),
            ("ssh", "lan_ssh"),
            ("mqtt", "lan_domotica"),
            ("coap", "lan_domotica"),
            ("home-assistant", "lan_domotica"),
            ("rtsp", "lan_cameras"),
            ("onvif", "lan_cameras"),
            ("upnp", "lan_upnp"),
            ("dlna", "lan_upnp"),
            ("plex", "lan_media"),
            ("jellyfin", "lan_media"),
        ];
        for (servicio, clave) in casos {
            assert_eq!(
                catalogo.lan_app(servicio).map(|app| app.key.as_str()),
                Some(clave),
                "servicio {servicio}"
            );
        }
        assert_eq!(catalogo.lan_app("http"), None);
        assert_eq!(catalogo.lan_app(""), None);
        assert_eq!(catalogo.lan_app("servicio-desconocido"), None);

        // Las 10 apps lan existen y están en la categoría lan.
        let lan = catalogo
            .apps()
            .iter()
            .filter(|app| app.category == "lan")
            .count();
        assert_eq!(lan, 10);
    }

    #[test]
    fn claves_duplicadas_en_el_fichero_propio_se_avisan() {
        let dir = tempfile::tempdir().expect("directorio temporal");
        let ruta = dir.path().join("apps.toml");
        let contenido = r#"
[[app]]
key = "repetida"
name = "Primera"
category = "web"
domains = ["primera.example"]

[[app]]
key = "repetida"
name = "Segunda"
category = "web"
domains = ["segunda.example"]
"#;
        std::fs::write(&ruta, contenido).expect("escribir apps.toml");
        let (catalogo, avisos) = Catalog::load(EMBEDDED, Some(&ruta));
        assert_eq!(catalogo.counts().user_apps, 1);
        assert_eq!(catalogo.app_name("repetida"), Some("Primera"));
        assert!(avisos
            .iter()
            .any(|aviso| aviso.message.contains("duplicada")));
    }

    #[test]
    fn catalogo_tolera_entradas_aleatorias_sin_panico() {
        let muestras = [
            "",
            "[[app]]",
            "[[app]]\nkey = 5",
            "[[category]]\nkey = \"x\"",
            "[[category]]\nkey = \"x\"\nname = 1\nshort = 2",
            "no es toml",
            "\u{0}\u{1}\u{2}",
            "[[app]]\nkey = \"a\"\nname = \"b\"\ncategory = \"c\"\ndomains = 7\n",
        ];
        for muestra in muestras {
            let (catalogo, _) = Catalog::load(muestra, None);
            assert_eq!(catalogo.counts().embedded_apps, 0);
            assert!(catalogo.match_name("x.com").is_none());
        }
        // Cadena larga seudaleatoria determinista: ni pánicos ni desbordes.
        let mut estado: u64 = 0x5eed_1234;
        let mut texto = String::new();
        for _ in 0..4000 {
            estado = estado
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let byte = b' ' + ((estado >> 33) % 95) as u8;
            texto.push(byte as char);
        }
        let (catalogo, _) = Catalog::load(&texto, None);
        assert_eq!(catalogo.counts().embedded_apps, 0);

        // Un nombre de servidor enorme tampoco provoca pánicos.
        let enorme = format!("{}.com", "a".repeat(10_000));
        assert!(catalogo_embebido().match_name(&enorme).is_none());
    }

    #[test]
    fn catalogo_vacio_por_defecto() {
        let catalogo = Catalog::default();
        assert!(catalogo.apps().is_empty());
        assert!(catalogo.categories().is_empty());
        assert_eq!(catalogo.counts(), CatalogCounts::default());
        assert!(catalogo.match_name("music.youtube.com").is_none());
        assert!(catalogo.match_asn(15169).is_none());
        assert!(catalogo.match_port(L4::Tcp, 443).is_none());
        assert!(catalogo.lan_app("smb").is_none());
        assert!(catalogo.app_name("youtube").is_none());
        assert!(catalogo.category_short("streaming").is_none());
    }
}
