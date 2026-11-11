//! Identificación de equipos con señales de la captura (Fase 4, §7.12).
//!
//! Combina la huella TCP de F2 con la huella DHCP, el modelo anunciado (mDNS o
//! UPnP) y el User-Agent HTTP para estimar `os_family` con el umbral 4 y
//! registrar la señal que ganó (`os_source`).

// La fase expone la API completa del checklist; se permite código muerto para no
// marcar como muerta esa superficie pública, igual que en fases anteriores.
#![allow(dead_code)]

pub mod dhcp;
pub mod mac;
pub mod models;
pub mod observed;
pub mod useragent;

use std::collections::HashMap;
use std::net::IpAddr;

use crate::classify::OsFamily;
use crate::inference::DhcpObservation;

/// Señal que fijó `os_family` (`DEVICES.os_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsSource {
    /// Fingerprint TCP de F2 (TTL y opciones).
    Tcp,
    /// Huella DHCP capturada.
    Dhcp,
    /// Modelo anunciado por mDNS o UPnP.
    Model,
    /// User-Agent de HTTP en claro.
    UserAgent,
}

impl OsSource {
    /// Valor persistido en `DEVICES.os_source`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Dhcp => "dhcp",
            Self::Model => "model",
            Self::UserAgent => "ua",
        }
    }

    /// Reconstruye la fuente desde su valor persistido.
    pub fn from_str(valor: &str) -> Option<Self> {
        match valor {
            "tcp" => Some(Self::Tcp),
            "dhcp" => Some(Self::Dhcp),
            "model" => Some(Self::Model),
            "ua" => Some(Self::UserAgent),
            _ => None,
        }
    }

    /// Etiqueta visible.
    pub fn label(self) -> &'static str {
        match self {
            Self::Tcp => "huella TCP",
            Self::Dhcp => "DHCP",
            Self::Model => "modelo",
            Self::UserAgent => "User-Agent",
        }
    }
}

/// Señales de identificación disponibles para puntuar el SO.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OsSignals {
    /// Señal de F2: (sistema, puntos).
    pub tcp: Option<(OsFamily, u8)>,
    /// Señales de la huella DHCP.
    pub dhcp: Vec<(OsFamily, u8)>,
    /// Señales del modelo anunciado.
    pub model: Vec<(OsFamily, u8)>,
    /// Señales del User-Agent.
    pub user_agent: Vec<(OsFamily, u8)>,
}

impl OsSignals {
    /// Suma una señal con su origen.
    pub fn push(&mut self, source: OsSource, familia: OsFamily, puntos: u8) {
        match source {
            OsSource::Tcp => self.tcp = Some((familia, puntos)),
            OsSource::Dhcp => self.dhcp.push((familia, puntos)),
            OsSource::Model => self.model.push((familia, puntos)),
            OsSource::UserAgent => self.user_agent.push((familia, puntos)),
        }
    }

    /// Indica si no hay ninguna señal.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_none()
            && self.dhcp.is_empty()
            && self.model.is_empty()
            && self.user_agent.is_empty()
    }
}

/// Umbral de confianza mínimo para fijar `os_family` (§7.12: el mismo que F2).
const UMBRAL_SO: u16 = 4;

/// Puntúa las señales y devuelve el SO ganador (umbral 4, empates → NULL) y la
/// señal que más aportó al ganador.
///
/// Se suman los puntos de todas las señales por familia; gana la que más suma
/// si alcanza el umbral 4. Un empate en el máximo deja `os_family` a NULL
/// (no se desempata por el orden de la taxonomía). Cuando hay un ganador,
/// `os_source` es la fuente que más puntos le aportó, con orden fijo de
/// preferencia ante un empate entre fuentes: huella TCP, DHCP, modelo y
/// User-Agent.
pub fn os_family(signals: &OsSignals) -> (Option<OsFamily>, Option<OsSource>) {
    let mut totales: Vec<(OsFamily, [u16; 4], u16)> = Vec::with_capacity(OsFamily::ALL.len());
    let mut maximo = 0u16;
    for familia in OsFamily::ALL {
        let aportes = aportes_por_fuente(signals, familia);
        let total: u16 = aportes.iter().sum();
        maximo = maximo.max(total);
        totales.push((familia, aportes, total));
    }

    if maximo < UMBRAL_SO {
        return (None, None);
    }
    let mut ganadores = totales.iter().filter(|(_, _, total)| *total == maximo);
    let Some(ganador) = ganadores.next() else {
        return (None, None);
    };
    if ganadores.next().is_some() {
        // Empate entre familias: no hay evidencia suficiente para elegir.
        return (None, None);
    }

    let (familia, aportes, _) = ganador;
    let fuentes = [
        OsSource::Tcp,
        OsSource::Dhcp,
        OsSource::Model,
        OsSource::UserAgent,
    ];
    let mut fuente = fuentes[0];
    let mut max_aporte = 0u16;
    for (indice, puntos) in aportes.iter().enumerate() {
        // Se queda la primera fuente con el máximo (orden fijo de fuentes).
        if *puntos > max_aporte {
            max_aporte = *puntos;
            fuente = fuentes[indice];
        }
    }
    if max_aporte == 0 {
        return (Some(*familia), None);
    }
    (Some(*familia), Some(fuente))
}

/// Puntos que aporta cada fuente a una familia concreta.
///
/// El orden del vector es el de `OsSource`: TCP, DHCP, modelo y User-Agent.
fn aportes_por_fuente(signals: &OsSignals, familia: OsFamily) -> [u16; 4] {
    let tcp = signals
        .tcp
        .filter(|(otra, _)| *otra == familia)
        .map(|(_, puntos)| u16::from(puntos))
        .unwrap_or(0);
    [
        tcp,
        suma_puntos(&signals.dhcp, familia),
        suma_puntos(&signals.model, familia),
        suma_puntos(&signals.user_agent, familia),
    ]
}

/// Suma los puntos de una lista de señales para una familia.
fn suma_puntos(senales: &[(OsFamily, u8)], familia: OsFamily) -> u16 {
    senales
        .iter()
        .filter(|(otra, _)| *otra == familia)
        .map(|(_, puntos)| u16::from(*puntos))
        .sum()
}

/// Señales de identidad de un equipo capturadas en línea.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIdentitySignals {
    /// Última huella DHCP observada.
    pub dhcp: Option<DhcpObservation>,
    /// Último User-Agent HTTP en claro observado.
    pub user_agent: Option<String>,
}

impl DeviceIdentitySignals {
    /// Indica si no hay ninguna señal.
    pub fn is_empty(&self) -> bool {
        self.dhcp.is_none() && self.user_agent.is_none()
    }
}

/// Almacén compartido entre los hilos de captura y el ciclo de escaneo.
#[derive(Debug, Default)]
pub struct CaptureIdentityStore {
    by_mac: HashMap<String, DeviceIdentitySignals>,
    by_ip: HashMap<IpAddr, DeviceIdentitySignals>,
}

impl CaptureIdentityStore {
    /// Crea un almacén vacío.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registra una identidad DHCP capturada.
    ///
    /// La última observación por MAC y por IP es la que vale: si el mismo ciclo
    /// ve un cambio de equipo en la misma IP, la identidad que se drena es la
    /// del equipo actual y no la del anterior.
    pub fn record_dhcp(&mut self, observacion: DhcpObservation) {
        let Some(mac) = observacion.mac.clone() else {
            return;
        };
        self.by_mac.entry(mac).or_default().dhcp = Some(observacion.clone());
        if let Some(ip) = observacion.ip {
            self.by_ip.entry(ip).or_default().dhcp = Some(observacion);
        }
    }

    /// Registra el User-Agent de un equipo por su IP de origen.
    ///
    /// Gana el último User-Agent visto en esa IP dentro del ciclo.
    pub fn record_user_agent(&mut self, ip: IpAddr, user_agent: String) {
        self.by_ip.entry(ip).or_default().user_agent = Some(user_agent);
    }

    /// Vacía el almacén y devuelve las señales acumuladas por MAC e IP.
    pub fn drain(&mut self) -> Vec<(Option<String>, Option<IpAddr>, DeviceIdentitySignals)> {
        let mut resultado: Vec<(Option<String>, Option<IpAddr>, DeviceIdentitySignals)> =
            Vec::with_capacity(self.by_mac.len() + self.by_ip.len());
        for (mac, senales) in self.by_mac.drain() {
            resultado.push((Some(mac), None, senales));
        }
        for (ip, senales) in self.by_ip.drain() {
            resultado.push((None, Some(ip), senales));
        }
        resultado
    }

    /// Indica si el almacén está vacío.
    pub fn is_empty(&self) -> bool {
        self.by_mac.is_empty() && self.by_ip.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construye señales a partir de tuplas (fuente, familia, puntos).
    fn senales(lista: &[(OsSource, OsFamily, u8)]) -> OsSignals {
        let mut signals = OsSignals::default();
        for (fuente, familia, puntos) in lista {
            signals.push(*fuente, *familia, *puntos);
        }
        signals
    }

    #[test]
    fn la_fuente_de_so_va_y_vuelve() {
        for fuente in [
            OsSource::Tcp,
            OsSource::Dhcp,
            OsSource::Model,
            OsSource::UserAgent,
        ] {
            assert_eq!(OsSource::from_str(fuente.as_str()), Some(fuente));
            assert!(!fuente.label().is_empty());
        }
        assert_eq!(OsSource::from_str("otra"), None);
        assert_eq!(OsSource::from_str(""), None);
    }

    #[test]
    fn sin_senales_no_hay_so() {
        assert_eq!(os_family(&OsSignals::default()), (None, None));
        assert!(OsSignals::default().is_empty());
    }

    #[test]
    fn el_umbral_es_cuatro() {
        // Solo TCP con 3 puntos (p. ej. Linux por huella de F2) no llega.
        assert_eq!(
            os_family(&senales(&[(OsSource::Tcp, OsFamily::Linux, 3)])),
            (None, None)
        );
        // Con 4 puntos sí.
        assert_eq!(
            os_family(&senales(&[(OsSource::Tcp, OsFamily::Windows, 4)])),
            (Some(OsFamily::Windows), Some(OsSource::Tcp))
        );
    }

    #[test]
    fn las_senales_de_varias_fuentes_se_suman() {
        // TCP Linux 3 + User-Agent Linux 3 = 6: gana Linux aunque ninguna
        // señal por separado alcance el umbral.
        let signals = senales(&[
            (OsSource::Tcp, OsFamily::Linux, 3),
            (OsSource::UserAgent, OsFamily::Linux, 3),
        ]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::Linux), Some(OsSource::Tcp))
        );
    }

    #[test]
    fn un_empate_en_el_maximo_deja_null() {
        // Windows por User-Agent y macOS por modelo, ambos con 4.
        let signals = senales(&[
            (OsSource::UserAgent, OsFamily::Windows, 4),
            (OsSource::Model, OsFamily::MacOs, 4),
        ]);
        assert_eq!(os_family(&signals), (None, None));

        // Empate a tres bandas.
        let signals = senales(&[
            (OsSource::UserAgent, OsFamily::Windows, 4),
            (OsSource::Model, OsFamily::MacOs, 4),
            (OsSource::Dhcp, OsFamily::Ios, 4),
        ]);
        assert_eq!(os_family(&signals), (None, None));
    }

    #[test]
    fn os_source_es_la_senal_que_mas_aporta_al_ganador() {
        // El modelo MacBook (5) gana a la huella DHCP (2) dentro de macOS.
        let signals = senales(&[
            (OsSource::Dhcp, OsFamily::MacOs, 2),
            (OsSource::Model, OsFamily::MacOs, 5),
        ]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::MacOs), Some(OsSource::Model))
        );

        // Empate entre fuentes del mismo ganador: orden fijo de preferencia
        // (TCP, DHCP, modelo, User-Agent).
        let signals = senales(&[
            (OsSource::Dhcp, OsFamily::Windows, 4),
            (OsSource::UserAgent, OsFamily::Windows, 4),
        ]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::Windows), Some(OsSource::Dhcp))
        );

        let signals = senales(&[
            (OsSource::Tcp, OsFamily::Windows, 1),
            (OsSource::UserAgent, OsFamily::Windows, 4),
        ]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::Windows), Some(OsSource::UserAgent))
        );
    }

    #[test]
    fn un_macbook_anunciado_por_modelo_cumple_el_criterio() {
        // AC del checklist: model=MacBookPro… → os_family = macos,
        // os_source = model.
        let signals = senales(&[(OsSource::Model, OsFamily::MacOs, 5)]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::MacOs), Some(OsSource::Model))
        );

        // Con huella TCP débil de F2 (1 punto) el resultado no cambia.
        let con_tcp = senales(&[
            (OsSource::Tcp, OsFamily::MacOs, 1),
            (OsSource::Model, OsFamily::MacOs, 5),
        ]);
        assert_eq!(
            os_family(&con_tcp),
            (Some(OsFamily::MacOs), Some(OsSource::Model))
        );
    }

    #[test]
    fn un_iphone_con_modelo_y_user_agent_es_ios() {
        let signals = senales(&[
            (OsSource::UserAgent, OsFamily::Ios, 4),
            (OsSource::Model, OsFamily::Ios, 5),
        ]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::Ios), Some(OsSource::Model))
        );
    }

    #[test]
    fn los_puntos_no_se_mezclan_entre_familias() {
        // Dos familias con 2 puntos cada una y una tercera sin señales: no
        // alcanza el umbral aunque haya "cuatro puntos en total".
        let signals = senales(&[
            (OsSource::Model, OsFamily::MacOs, 2),
            (OsSource::UserAgent, OsFamily::Ios, 2),
        ]);
        assert_eq!(os_family(&signals), (None, None));
    }

    #[test]
    fn push_y_estado_de_las_senales() {
        let mut signals = OsSignals::default();
        assert!(signals.is_empty());
        signals.push(OsSource::Tcp, OsFamily::Windows, 4);
        assert!(!signals.is_empty());
        // La señal TCP es única: la última sustituye a la anterior.
        signals.push(OsSource::Tcp, OsFamily::Linux, 3);
        assert_eq!(signals.tcp, Some((OsFamily::Linux, 3)));
        signals.push(OsSource::Dhcp, OsFamily::Linux, 3);
        signals.push(OsSource::Model, OsFamily::Linux, 5);
        signals.push(OsSource::UserAgent, OsFamily::Linux, 3);
        assert_eq!(signals.dhcp, vec![(OsFamily::Linux, 3)]);
        assert_eq!(signals.model, vec![(OsFamily::Linux, 5)]);
        assert_eq!(signals.user_agent, vec![(OsFamily::Linux, 3)]);
        assert_eq!(
            os_family(&signals),
            (Some(OsFamily::Linux), Some(OsSource::Model))
        );
    }

    /// Observación DHCP de prueba con MAC e IP.
    fn observacion(mac: &str, ip: &str) -> DhcpObservation {
        DhcpObservation {
            mac: Some(mac.to_string()),
            ip: Some(ip.parse().expect("IP de prueba válida")),
            message_type: Some(1),
            fingerprint: Some("1,3,6,15,119,252".to_string()),
            vendor: Some("MSFT 5.0".to_string()),
            hostname: Some("equipo".to_string()),
            client_id: None,
        }
    }

    #[test]
    fn el_almacen_drena_las_senales_por_mac_y_por_ip() {
        let ip: IpAddr = "192.168.1.20".parse().expect("IP de prueba válida");
        let mut store = CaptureIdentityStore::new();
        assert!(store.is_empty());

        store.record_dhcp(observacion("02:00:00:00:00:01", "192.168.1.20"));
        store.record_user_agent(ip, "Mozilla/5.0".to_string());
        assert!(!store.is_empty());

        let drenado = store.drain();
        assert!(store.is_empty(), "el vaciado deja el almacén vacío");
        assert_eq!(drenado.len(), 2, "una entrada por MAC y otra por IP");

        let por_mac = drenado
            .iter()
            .find(|(mac, _, _)| mac.as_deref() == Some("02:00:00:00:00:01"))
            .expect("entrada por MAC");
        assert_eq!(por_mac.1, None);
        assert!(por_mac.2.dhcp.is_some());
        assert!(por_mac.2.user_agent.is_none());

        let por_ip = drenado
            .iter()
            .find(|(_, ip_drenada, _)| *ip_drenada == Some(ip))
            .expect("entrada por IP");
        assert!(por_ip.2.dhcp.is_some());
        assert_eq!(por_ip.2.user_agent.as_deref(), Some("Mozilla/5.0"));
    }

    #[test]
    fn gana_la_ultima_senal_de_cada_ip() {
        let ip: IpAddr = "192.168.1.30".parse().expect("IP de prueba válida");
        let mut store = CaptureIdentityStore::new();
        store.record_user_agent(ip, "primero".to_string());
        store.record_user_agent(ip, "segundo".to_string());
        store.record_dhcp(observacion("02:00:00:00:00:01", "192.168.1.30"));
        store.record_dhcp(observacion("02:00:00:00:00:02", "192.168.1.30"));

        let drenado = store.drain();
        let por_ip = drenado
            .iter()
            .find(|(_, ip_drenada, _)| *ip_drenada == Some(ip))
            .expect("entrada por IP");
        assert_eq!(por_ip.2.user_agent.as_deref(), Some("segundo"));
        assert_eq!(
            por_ip.2.dhcp.as_ref().and_then(|dhcp| dhcp.mac.as_deref()),
            Some("02:00:00:00:00:02"),
            "si un equipo toma la IP, no se le atribuye la huella del anterior"
        );
    }

    #[test]
    fn una_observacion_sin_mac_se_ignora_y_sin_ip_solo_va_por_mac() {
        let mut store = CaptureIdentityStore::new();
        let mut sin_mac = observacion("02:00:00:00:00:01", "192.168.1.40");
        sin_mac.mac = None;
        store.record_dhcp(sin_mac);
        assert!(store.is_empty());

        let mut sin_ip = observacion("02:00:00:00:00:03", "192.168.1.41");
        sin_ip.ip = None;
        store.record_dhcp(sin_ip);
        let drenado = store.drain();
        assert_eq!(drenado.len(), 1);
        assert_eq!(drenado[0].0.as_deref(), Some("02:00:00:00:00:03"));
        assert_eq!(drenado[0].1, None);
        assert!(drenado[0].2.dhcp.is_some());
    }
}
