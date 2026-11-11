//! Caché IP → nombre con caducidad (§7.7).
//!
//! La alimentan las respuestas DNS (A/AAAA/CNAME), el SNI de TLS/QUIC y la
//! cabecera `Host` de HTTP en claro. Varias entradas por IP son normales en
//! CDN: [`NameCache::lookup`] prefiere el nombre consultado por el mismo equipo
//! cliente y, si no, el más reciente. Los nombres caducan entre 1 h y 24 h y
//! cada uso para etiquetar refresca la entrada.

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::inference::{NameObservation, NameSource};

/// Número máximo de entradas de la caché.
pub const MAX_NAMES: usize = 10_000;
/// Caducidad mínima de una entrada (1 h).
pub const MIN_TTL_S: u64 = 3600;
/// Caducidad máxima de una entrada (24 h).
pub const MAX_TTL_S: u64 = 86_400;

/// Entrada de la caché IP → nombre (y de la tabla NAME_CACHE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameEntry {
    /// IP del servidor.
    pub ip: IpAddr,
    /// Nombre observado (minúsculas, sin punto final).
    pub name: String,
    /// Fuente del nombre.
    pub source: NameSource,
    /// Primera observación.
    pub first_seen: SystemTime,
    /// Última observación o uso.
    pub last_seen: SystemTime,
    /// Caducidad.
    pub expires_at: SystemTime,
    /// Equipo que hizo la consulta, si se conoce (solo en memoria).
    pub requester: Option<IpAddr>,
}

impl NameEntry {
    /// Indica si la entrada ha caducado.
    pub fn is_expired(&self, now: SystemTime) -> bool {
        now >= self.expires_at
    }

    /// Años mínimos de la entrada (para la TUI: "hace N s").
    pub fn age(&self, now: SystemTime) -> Duration {
        now.duration_since(self.last_seen).unwrap_or_default()
    }
}

/// Caché IP → nombre en memoria.
#[derive(Debug, Default)]
pub struct NameCache {
    entries: Vec<NameEntry>,
    max: usize,
    dirty: Vec<NameEntry>,
}

impl NameCache {
    /// Crea una caché vacía con el tope indicado.
    pub fn new(max: usize) -> Self {
        Self {
            entries: Vec::new(),
            max: max.max(1),
            dirty: Vec::new(),
        }
    }

    /// Inserta o refresca una observación y devuelve la entrada resultante.
    ///
    /// Los nombres se normalizan (minúsculas, sin punto final y máx. 255); una
    /// observación vacía o inválida se ignora. El TTL se acota a 1 h–24 h (DNS)
    /// o se fija en 1 h (SNI y Host).
    pub fn observe(&mut self, obs: NameObservation, now: SystemTime) -> Option<NameEntry> {
        let nombre = normalizar(&obs.name)?;
        let ttl = ttl_de(obs.source, obs.ttl_seconds);
        if let Some(entrada) = self
            .entries
            .iter_mut()
            .find(|entrada| entrada.ip == obs.ip && entrada.name == nombre)
        {
            entrada.last_seen = now;
            entrada.expires_at = refrescar(entrada.expires_at, now, ttl);
            if obs.requester.is_some() {
                entrada.requester = obs.requester;
            }
            let copia = entrada.clone();
            self.marcar_sucia(&copia);
            return Some(copia);
        }
        let entrada = NameEntry {
            ip: obs.ip,
            name: nombre,
            source: obs.source,
            first_seen: now,
            last_seen: now,
            expires_at: now + Duration::from_secs(ttl),
            requester: obs.requester,
        };
        if self.entries.len() >= self.max {
            self.desalojar();
        }
        self.entries.push(entrada.clone());
        self.marcar_sucia(&entrada);
        Some(entrada)
    }

    /// Mejor nombre vigente para una IP.
    ///
    /// Prefiere la entrada que consultó el mismo equipo (`requester`); si no,
    /// la observada/consultada más recientemente. El uso refresca `last_seen` y
    /// `expires_at` (mínimo 1 h más, sin pasar de 24 h desde la observación).
    pub fn lookup(
        &mut self,
        ip: IpAddr,
        requester: Option<IpAddr>,
        now: SystemTime,
    ) -> Option<NameEntry> {
        let indice = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entrada)| entrada.ip == ip && !entrada.is_expired(now))
            .max_by_key(|(_, entrada)| {
                let mismo_equipo = requester.is_some() && entrada.requester == requester;
                (mismo_equipo, entrada.last_seen)
            })
            .map(|(indice, _)| indice)?;
        let entrada = &mut self.entries[indice];
        entrada.last_seen = now;
        let ttl = ttl_de(entrada.source, Some(MIN_TTL_S));
        entrada.expires_at = refrescar(entrada.expires_at, now, ttl);
        let copia = entrada.clone();
        self.marcar_sucia(&copia);
        Some(copia)
    }

    /// Todas las entradas (incluidas las caducadas hasta la purga).
    pub fn entries(&self) -> &[NameEntry] {
        &self.entries
    }

    /// Entradas nuevas o refrescadas desde la última llamada (para persistir).
    pub fn take_dirty(&mut self) -> Vec<NameEntry> {
        std::mem::take(&mut self.dirty)
    }

    /// Carga entradas al arrancar en caliente (las caducadas se descartan).
    pub fn load(&mut self, entries: Vec<NameEntry>) {
        let ahora = SystemTime::now();
        self.entries = entries
            .into_iter()
            .filter(|entrada| !entrada.is_expired(ahora))
            .collect();
        if self.entries.len() > self.max {
            let exceso = self.entries.len() - self.max;
            self.entries.sort_by_key(|entrada| entrada.last_seen);
            self.entries.drain(0..exceso);
        }
        self.dirty.clear();
    }

    /// Elimina las entradas caducadas y devuelve cuántas se borraron.
    pub fn prune(&mut self, now: SystemTime) -> usize {
        let antes = self.entries.len();
        self.entries.retain(|entrada| !entrada.is_expired(now));
        let despues = self.entries.len();
        self.dirty.retain(|entrada| !entrada.is_expired(now));
        antes - despues
    }

    /// Número de entradas.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Indica si está vacía.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Marca una entrada como pendiente de persistir (sin duplicados).
    fn marcar_sucia(&mut self, entrada: &NameEntry) {
        if let Some(existente) = self
            .dirty
            .iter_mut()
            .find(|sucia| sucia.ip == entrada.ip && sucia.name == entrada.name)
        {
            *existente = entrada.clone();
        } else {
            self.dirty.push(entrada.clone());
        }
    }

    /// Desaloja la entrada con el `last_seen` más antiguo.
    fn desalojar(&mut self) {
        let Some((indice, _)) = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entrada)| entrada.last_seen)
        else {
            return;
        };
        self.entries.swap_remove(indice);
    }
}

/// Normaliza un nombre observado: minúsculas, sin punto final y máx. 255.
fn normalizar(nombre: &str) -> Option<String> {
    let limpio = nombre.trim().trim_end_matches('.').to_ascii_lowercase();
    if limpio.is_empty()
        || limpio.len() > crate::inference::MAX_SERVER_NAME
        || limpio.chars().any(|c| c.is_whitespace() || c == '/')
    {
        return None;
    }
    Some(limpio)
}

/// TTL efectivo de una observación: DNS acotado a 1 h–24 h; SNI y Host 1 h.
fn ttl_de(source: NameSource, sugerido: Option<u64>) -> u64 {
    match source {
        NameSource::Dns => sugerido.unwrap_or(MIN_TTL_S).clamp(MIN_TTL_S, MAX_TTL_S),
        NameSource::Sni | NameSource::Http | NameSource::Cache => MIN_TTL_S,
    }
}

/// Refresca la caducidad: al menos `ahora + ttl`, sin pasar de 24 h desde ahora.
fn refrescar(actual: SystemTime, ahora: SystemTime, ttl: u64) -> SystemTime {
    let minimo = ahora + Duration::from_secs(ttl);
    let tope = ahora + Duration::from_secs(MAX_TTL_S);
    let nuevo = if actual > minimo { actual } else { minimo };
    if nuevo > tope {
        tope
    } else {
        nuevo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ip: &str, nombre: &str, fuente: NameSource, ttl: Option<u64>) -> NameObservation {
        NameObservation {
            ip: ip.parse().unwrap(),
            name: nombre.to_string(),
            source: fuente,
            requester: None,
            ttl_seconds: ttl,
        }
    }

    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn observa_y_recupera_nombres_normalizados() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        assert!(cache
            .observe(
                obs("1.2.3.4", "Example.COM.", NameSource::Dns, Some(3600)),
                ahora
            )
            .is_some());
        let entrada = cache
            .lookup("1.2.3.4".parse().unwrap(), None, ahora)
            .expect("vigente");
        assert_eq!(entrada.name, "example.com");
        assert_eq!(entrada.source, NameSource::Dns);
        assert_eq!(cache.len(), 1);
        assert!(cache
            .observe(obs("1.2.3.4", "  ", NameSource::Dns, None), ahora)
            .is_none());
    }

    #[test]
    fn caducidad_dns_se_acota_entre_una_hora_y_veinticuatro() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        cache.observe(obs("1.2.3.4", "a.test", NameSource::Dns, Some(10)), ahora);
        let corta = cache
            .lookup("1.2.3.4".parse().unwrap(), None, ahora)
            .unwrap();
        assert_eq!(corta.expires_at, ahora + Duration::from_secs(MIN_TTL_S));

        let mut cache = NameCache::new(10);
        cache.observe(
            obs("1.2.3.4", "a.test", NameSource::Dns, Some(999_999)),
            ahora,
        );
        let larga = cache
            .lookup("1.2.3.4".parse().unwrap(), None, ahora)
            .unwrap();
        assert_eq!(larga.expires_at, ahora + Duration::from_secs(MAX_TTL_S));

        let mut cache = NameCache::new(10);
        cache.observe(obs("1.2.3.4", "a.test", NameSource::Sni, None), ahora);
        let sni = cache
            .lookup("1.2.3.4".parse().unwrap(), None, ahora)
            .unwrap();
        assert_eq!(sni.expires_at, ahora + Duration::from_secs(MIN_TTL_S));
    }

    #[test]
    fn prefiere_el_nombre_del_mismo_equipo_y_refresca() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        let mut uno = obs("1.2.3.4", "cdn-a.test", NameSource::Dns, Some(3600));
        uno.requester = Some("192.168.1.10".parse().unwrap());
        let mut dos = obs("1.2.3.4", "cdn-b.test", NameSource::Dns, Some(3600));
        dos.requester = Some("192.168.1.20".parse().unwrap());
        cache.observe(uno, ahora);
        cache.observe(dos, ahora + Duration::from_secs(10));
        let sin_equipo = cache
            .lookup(
                "1.2.3.4".parse().unwrap(),
                None,
                ahora + Duration::from_secs(15),
            )
            .unwrap();
        assert_eq!(
            sin_equipo.name, "cdn-b.test",
            "sin equipo gana el más reciente"
        );
        let otro_equipo = cache
            .lookup(
                "1.2.3.4".parse().unwrap(),
                Some("192.168.1.10".parse().unwrap()),
                ahora + Duration::from_secs(20),
            )
            .unwrap();
        assert_eq!(otro_equipo.name, "cdn-a.test");
        assert_eq!(otro_equipo.last_seen, ahora + Duration::from_secs(20));
    }

    #[test]
    fn purga_las_entradas_caducadas() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        cache.observe(obs("1.2.3.4", "a.test", NameSource::Sni, None), ahora);
        cache.observe(obs("5.6.7.8", "b.test", NameSource::Sni, None), ahora);
        assert_eq!(cache.prune(ahora + Duration::from_secs(MIN_TTL_S + 1)), 2);
        assert!(cache.is_empty());
        assert_eq!(cache.lookup("1.2.3.4".parse().unwrap(), None, ahora), None);
    }

    #[test]
    fn desaloja_la_mas_antigua_al_llenarse() {
        let mut cache = NameCache::new(2);
        let ahora = t0();
        cache.observe(
            obs("1.1.1.1", "uno.test", NameSource::Dns, Some(3600)),
            ahora,
        );
        cache.observe(
            obs("2.2.2.2", "dos.test", NameSource::Dns, Some(3600)),
            ahora + Duration::from_secs(1),
        );
        cache.observe(
            obs("3.3.3.3", "tres.test", NameSource::Dns, Some(3600)),
            ahora + Duration::from_secs(2),
        );
        assert_eq!(cache.len(), 2);
        assert!(cache
            .entries()
            .iter()
            .all(|entrada| entrada.ip != "1.1.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn take_dirty_devuelve_lo_nuevo_y_refrescado() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        cache.observe(obs("1.2.3.4", "a.test", NameSource::Dns, Some(3600)), ahora);
        assert_eq!(cache.take_dirty().len(), 1);
        assert!(cache.take_dirty().is_empty());
        cache.lookup(
            "1.2.3.4".parse().unwrap(),
            None,
            ahora + Duration::from_secs(5),
        );
        assert_eq!(cache.take_dirty().len(), 1, "el uso refresca la entrada");
    }

    #[test]
    fn la_carga_descarta_caducadas_y_limpia_sucias() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        cache.observe(obs("1.2.3.4", "a.test", NameSource::Sni, None), ahora);
        let mut entradas = cache.take_dirty();
        entradas[0].expires_at = ahora - Duration::from_secs(1);
        cache.load(entradas);
        assert!(cache.is_empty());
        assert!(cache.take_dirty().is_empty());
    }

    #[test]
    fn el_refresco_no_pasa_de_veinticuatro_horas() {
        let mut cache = NameCache::new(10);
        let ahora = t0();
        cache.observe(
            obs("1.2.3.4", "a.test", NameSource::Dns, Some(MAX_TTL_S)),
            ahora,
        );
        let entrada = cache
            .lookup(
                "1.2.3.4".parse().unwrap(),
                None,
                ahora + Duration::from_secs(MAX_TTL_S / 2),
            )
            .unwrap();
        assert!(entrada.expires_at <= ahora + Duration::from_secs(MAX_TTL_S + 1));
    }
}
