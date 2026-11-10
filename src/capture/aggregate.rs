//! Agregación por dispositivo y global del tráfico capturado.
//!
//! Mantiene, por cada equipo conocido, los contadores de bytes y paquetes de los
//! últimos 60 s, las series de 60 s y 5 min para los sparklines, el pico por
//! segundo (`peak_bps`) y el top de puertos remotos. La atribución se hace por
//! IP con el mapa IP -> device_id que publica la tarea de tráfico.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::Instant;

use super::windows::{Windows, LEN_60S};
use super::{PacketMeta, Protocol};

/// Número máximo de puertos en el top de un dispositivo.
pub const MAX_TOP_PORTS: usize = 5;
/// Número máximo de entradas (protocolo, puerto) acumuladas por dispositivo.
const MAX_PUERTOS: usize = 256;

/// Estadística de un puerto remoto en el top de un dispositivo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortStat {
    /// Puerto remoto.
    pub port: u16,
    /// Protocolo del puerto.
    pub protocol: Protocol,
    /// Bytes acumulados (origen y destino del flujo, según corresponda).
    pub bytes: u64,
}

/// Tráfico agregado de un dispositivo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceTraffic {
    /// Identificador del dispositivo en la base de datos.
    pub device_id: i64,
    /// Bytes recibidos en los últimos 60 s.
    pub bytes_in: u64,
    /// Bytes enviados en los últimos 60 s.
    pub bytes_out: u64,
    /// Paquetes recibidos en los últimos 60 s.
    pub packets_in: u64,
    /// Paquetes enviados en los últimos 60 s.
    pub packets_out: u64,
    /// Bytes por segundo recibidos en el último segundo.
    pub rate_in: u64,
    /// Bytes por segundo enviados en el último segundo.
    pub rate_out: u64,
    /// Máximo de (bytes de entrada + bytes de salida) de un segundo en 60 s.
    pub peak_bps: u64,
    /// Serie de 60 puntos (1/s) de bytes de entrada.
    pub series_60s_in: [u64; LEN_60S],
    /// Serie de 60 puntos (1/s) de bytes de salida.
    pub series_60s_out: [u64; LEN_60S],
    /// Serie de 60 puntos (1/5 s) de bytes de entrada.
    pub series_5min_in: [u64; LEN_60S],
    /// Serie de 60 puntos (1/5 s) de bytes de salida.
    pub series_5min_out: [u64; LEN_60S],
    /// Hasta cinco puertos remotos con más bytes (descendente).
    pub top_ports: Vec<PortStat>,
}

/// Tráfico global del monitor.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GlobalTraffic {
    /// Bytes recibidos por los dispositivos conocidos en los últimos 60 s.
    pub bytes_in: u64,
    /// Bytes enviados por los dispositivos conocidos en los últimos 60 s.
    pub bytes_out: u64,
    /// Bytes de difusión/multidifusión desde el último reset.
    pub broadcast_bytes: u64,
    /// Paquetes procesados desde el último reset.
    pub packets_total: u64,
}

/// Instantánea inmutable de la agregación, ya lista para la TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AggregatorSnapshot {
    /// Tráfico por dispositivo, ordenado por consumo descendente.
    pub devices: Vec<DeviceTraffic>,
    /// Agregados globales.
    pub global: GlobalTraffic,
}

/// Contadores internos de un dispositivo.
#[derive(Debug, Clone)]
struct DeviceAgg {
    bytes_60s_in: Windows,
    bytes_60s_out: Windows,
    bytes_5min_in: Windows,
    bytes_5min_out: Windows,
    packets_60s_in: Windows,
    packets_60s_out: Windows,
    puertos: HashMap<(u8, u16), u64>,
}

impl DeviceAgg {
    /// Crea los contadores vacíos de un dispositivo.
    fn nuevo(origin: Instant) -> Self {
        Self {
            bytes_60s_in: Windows::new_60s(origin),
            bytes_60s_out: Windows::new_60s(origin),
            bytes_5min_in: Windows::new_5min(origin),
            bytes_5min_out: Windows::new_5min(origin),
            packets_60s_in: Windows::new_60s(origin),
            packets_60s_out: Windows::new_60s(origin),
            puertos: HashMap::new(),
        }
    }

    /// Avanza todas las ventanas del dispositivo.
    fn avanzar(&mut self, now: Instant) {
        self.bytes_60s_in.advance(now);
        self.bytes_60s_out.advance(now);
        self.bytes_5min_in.advance(now);
        self.bytes_5min_out.advance(now);
        self.packets_60s_in.advance(now);
        self.packets_60s_out.advance(now);
    }

    /// Acumula bytes en el puerto remoto indicado.
    ///
    /// El mapa está acotado a [MAX_PUERTOS] entradas: si se llena, se descarta
    /// la entrada con menos bytes (con desempate estable por protocolo y puerto).
    fn sumar_puerto(&mut self, codigo: u8, puerto: u16, bytes: u64) {
        let clave = (codigo, puerto);
        if let Some(acumulado) = self.puertos.get_mut(&clave) {
            *acumulado = acumulado.saturating_add(bytes);
            return;
        }
        if self.puertos.len() >= MAX_PUERTOS {
            let clave_minima = self
                .puertos
                .iter()
                .min_by_key(|(clave, valor)| (**valor, clave.0, clave.1))
                .map(|(clave, _)| *clave);
            if let Some(clave_minima) = clave_minima {
                self.puertos.remove(&clave_minima);
            }
        }
        self.puertos.insert(clave, bytes);
    }

    /// Construye la vista inmutable del dispositivo.
    fn snapshot(&self, device_id: i64) -> DeviceTraffic {
        let serie_60s_in = self.bytes_60s_in.series_60s();
        let serie_60s_out = self.bytes_60s_out.series_60s();
        let mut peak_bps = 0u64;
        for (entrada, salida) in serie_60s_in.iter().zip(serie_60s_out.iter()) {
            peak_bps = peak_bps.max(entrada.saturating_add(*salida));
        }
        let mut top_ports: Vec<PortStat> = self
            .puertos
            .iter()
            .map(|((codigo, puerto), bytes)| PortStat {
                port: *puerto,
                protocol: protocolo_desde_codigo(*codigo),
                bytes: *bytes,
            })
            .collect();
        top_ports.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.protocol.as_str().cmp(b.protocol.as_str()))
                .then_with(|| a.port.cmp(&b.port))
        });
        top_ports.truncate(MAX_TOP_PORTS);
        DeviceTraffic {
            device_id,
            bytes_in: self.bytes_60s_in.total(),
            bytes_out: self.bytes_60s_out.total(),
            packets_in: self.packets_60s_in.total(),
            packets_out: self.packets_60s_out.total(),
            rate_in: self.bytes_60s_in.last(),
            rate_out: self.bytes_60s_out.last(),
            peak_bps,
            series_60s_in: serie_60s_in,
            series_60s_out: serie_60s_out,
            series_5min_in: self.bytes_5min_in.series_5min(),
            series_5min_out: self.bytes_5min_out.series_5min(),
            top_ports,
        }
    }
}

/// Acumulador de tráfico por dispositivo y global.
#[derive(Debug)]
pub struct Aggregator {
    /// Instante del bucket 0 de todas las ventanas.
    origin: Instant,
    /// Mapa IP -> device_id publicado por la tarea de tráfico.
    ip_to_device: HashMap<IpAddr, i64>,
    /// Contadores por dispositivo.
    devices: HashMap<i64, DeviceAgg>,
    /// Bytes de difusión/multidifusión desde el último reset.
    broadcast_bytes: u64,
    /// Paquetes procesados desde el último reset.
    packets_total: u64,
}

impl Aggregator {
    /// Crea la agregación vacía con el origen de las ventanas en `now`.
    pub fn new(now: Instant) -> Self {
        Self {
            origin: now,
            ip_to_device: HashMap::new(),
            devices: HashMap::new(),
            broadcast_bytes: 0,
            packets_total: 0,
        }
    }

    /// Sustituye el mapa IP -> device_id y crea los contadores que falten.
    ///
    /// Los contadores de los dispositivos que siguen existiendo se conservan;
    /// los de los que han desaparecido del mapa se descartan.
    pub fn set_devices(&mut self, ip_to_device: &HashMap<IpAddr, i64>) {
        self.ip_to_device = ip_to_device.clone();
        let ids: HashSet<i64> = ip_to_device.values().copied().collect();
        self.devices.retain(|device_id, _| ids.contains(device_id));
        for device_id in ids {
            if !self.devices.contains_key(&device_id) {
                self.devices
                    .insert(device_id, DeviceAgg::nuevo(self.origin));
            }
        }
    }

    /// Agrega un paquete capturado usando su `timestamp` para bucketizar.
    ///
    /// El origen (si es un dispositivo conocido) suma como salida y el destino
    /// (si es un dispositivo conocido) suma como entrada. El tráfico de difusión
    /// se contabiliza además en el agregado global.
    pub fn update(&mut self, meta: &PacketMeta) {
        self.packets_total = self.packets_total.saturating_add(1);
        let bytes = u64::from(meta.len);
        if let Some(device_id) = self.ip_to_device.get(&meta.src_ip).copied() {
            if let Some(dispositivo) = self.devices.get_mut(&device_id) {
                dispositivo.bytes_60s_out.push(meta.timestamp, bytes);
                dispositivo.packets_60s_out.push(meta.timestamp, 1);
                if let Some(puerto) = meta.dst_port {
                    dispositivo.sumar_puerto(codigo_protocolo(meta.protocol), puerto, bytes);
                }
            }
        }
        if let Some(device_id) = self.ip_to_device.get(&meta.dst_ip).copied() {
            if let Some(dispositivo) = self.devices.get_mut(&device_id) {
                dispositivo.bytes_60s_in.push(meta.timestamp, bytes);
                dispositivo.packets_60s_in.push(meta.timestamp, 1);
                if let Some(puerto) = meta.src_port {
                    dispositivo.sumar_puerto(codigo_protocolo(meta.protocol), puerto, bytes);
                }
            }
        }
        if meta.is_broadcast() {
            self.broadcast_bytes = self.broadcast_bytes.saturating_add(bytes);
        }
    }

    /// Avanza las ventanas de todos los dispositivos hasta `now`.
    ///
    /// La tarea de tráfico lo llama una vez por segundo; los huecos se rellenan
    /// con ceros y no se pierde ningún dato que siga dentro de la ventana.
    pub fn tick(&mut self, now: Instant) {
        for dispositivo in self.devices.values_mut() {
            dispositivo.avanzar(now);
        }
    }

    /// Devuelve la instantánea actual (los contadores se calculan al vuelo).
    pub fn snapshot(&self) -> AggregatorSnapshot {
        let mut devices: Vec<DeviceTraffic> = self
            .devices
            .iter()
            .map(|(device_id, dispositivo)| dispositivo.snapshot(*device_id))
            .collect();
        devices.sort_by(|a, b| {
            let total_a = a.bytes_in.saturating_add(a.bytes_out);
            let total_b = b.bytes_in.saturating_add(b.bytes_out);
            total_b
                .cmp(&total_a)
                .then_with(|| a.device_id.cmp(&b.device_id))
        });
        let mut bytes_in = 0u64;
        let mut bytes_out = 0u64;
        for dispositivo in &devices {
            bytes_in = bytes_in.saturating_add(dispositivo.bytes_in);
            bytes_out = bytes_out.saturating_add(dispositivo.bytes_out);
        }
        AggregatorSnapshot {
            devices,
            global: GlobalTraffic {
                bytes_in,
                bytes_out,
                broadcast_bytes: self.broadcast_bytes,
                packets_total: self.packets_total,
            },
        }
    }

    /// Vacía todos los contadores y reinicia el origen de las ventanas en `now`.
    ///
    /// El mapa IP -> device_id y el conjunto de dispositivos se conservan. Es
    /// parte de la API del contrato aunque la tarea de tráfico todavía no lo use.
    #[allow(dead_code)]
    pub fn reset(&mut self, now: Instant) {
        self.origin = now;
        self.broadcast_bytes = 0;
        self.packets_total = 0;
        let ids: HashSet<i64> = self.ip_to_device.values().copied().collect();
        self.devices = ids
            .into_iter()
            .map(|device_id| (device_id, DeviceAgg::nuevo(now)))
            .collect();
    }
}

/// Código numérico estable de protocolo para las claves internas del top de puertos.
fn codigo_protocolo(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmp => 1,
        Protocol::Icmpv6 => 58,
        Protocol::Other => 0,
    }
}

/// Protocolo a partir del código numérico usado en las claves del top de puertos.
fn protocolo_desde_codigo(codigo: u8) -> Protocol {
    match codigo {
        6 => Protocol::Tcp,
        17 => Protocol::Udp,
        1 => Protocol::Icmp,
        58 => Protocol::Icmpv6,
        _ => Protocol::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ip(texto: &str) -> IpAddr {
        texto.parse().expect("IP válida en el test")
    }

    fn mapa_dispositivos(pares: &[(&str, i64)]) -> HashMap<IpAddr, i64> {
        pares
            .iter()
            .map(|(texto, device_id)| (ip(texto), *device_id))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn paquete(
        timestamp: Instant,
        src: &str,
        dst: &str,
        protocol: Protocol,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        len: u32,
    ) -> PacketMeta {
        PacketMeta {
            timestamp,
            src_ip: ip(src),
            dst_ip: ip(dst),
            src_port,
            dst_port,
            protocol,
            len,
            tcp_flags: None,
            headers: None,
            dns_qname: None,
            sni: None,
        }
    }

    fn tcp(ts: Instant, src: &str, dst: &str, sport: u16, dport: u16, len: u32) -> PacketMeta {
        paquete(ts, src, dst, Protocol::Tcp, Some(sport), Some(dport), len)
    }

    fn udp(ts: Instant, src: &str, dst: &str, sport: u16, dport: u16, len: u32) -> PacketMeta {
        paquete(ts, src, dst, Protocol::Udp, Some(sport), Some(dport), len)
    }

    #[test]
    fn el_paquete_suma_salida_al_origen_y_entrada_al_destino() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[
            ("192.168.1.10", 1),
            ("192.168.1.20", 2),
        ]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 41000, 443, 100));

        let instantanea = agregado.snapshot();
        assert_eq!(instantanea.devices.len(), 2);
        let dispositivo_1 = instantanea
            .devices
            .iter()
            .find(|dispositivo| dispositivo.device_id == 1)
            .expect("device 1");
        assert_eq!(dispositivo_1.bytes_out, 100);
        assert_eq!(dispositivo_1.packets_out, 1);
        assert_eq!(dispositivo_1.bytes_in, 0);
        let dispositivo_2 = instantanea
            .devices
            .iter()
            .find(|dispositivo| dispositivo.device_id == 2)
            .expect("device 2");
        assert_eq!(dispositivo_2.bytes_in, 100);
        assert_eq!(dispositivo_2.packets_in, 1);
        assert_eq!(dispositivo_2.bytes_out, 0);
    }

    #[test]
    fn con_un_solo_dispositivo_conocido_solo_cuenta_su_lado() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&udp(ahora, "192.168.1.10", "1.1.1.1", 52000, 53, 80));

        let instantanea = agregado.snapshot();
        let dispositivo = &instantanea.devices[0];
        assert_eq!(dispositivo.bytes_out, 80);
        assert_eq!(dispositivo.bytes_in, 0);
        assert_eq!(instantanea.global.bytes_in, 0);
        assert_eq!(instantanea.global.bytes_out, 80);
        assert_eq!(instantanea.global.packets_total, 1);
    }

    #[test]
    fn el_trafico_de_difusion_va_al_global() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&udp(ahora, "192.168.1.10", "255.255.255.255", 68, 67, 300));

        let instantanea = agregado.snapshot();
        assert_eq!(instantanea.global.broadcast_bytes, 300);
    }

    #[test]
    fn peak_bps_es_el_maximo_de_entrada_mas_salida_por_segundo() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 1000, 443, 100));
        agregado.update(&tcp(
            ahora + Duration::from_secs(1),
            "192.168.1.10",
            "192.168.1.20",
            1000,
            443,
            400,
        ));
        agregado.update(&tcp(
            ahora + Duration::from_secs(1),
            "192.168.1.20",
            "192.168.1.10",
            443,
            1000,
            300,
        ));
        agregado.update(&tcp(
            ahora + Duration::from_secs(2),
            "192.168.1.10",
            "192.168.1.20",
            1000,
            443,
            50,
        ));
        agregado.tick(ahora + Duration::from_secs(3));

        let instantanea = agregado.snapshot();
        let dispositivo = &instantanea.devices[0];
        // En el segundo 1: 400 de salida + 300 de entrada.
        assert_eq!(dispositivo.peak_bps, 700);
        assert_eq!(dispositivo.bytes_out, 550);
        assert_eq!(dispositivo.bytes_in, 300);
    }

    #[test]
    fn rate_es_el_ultimo_bucket_de_la_ventana() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 1000, 443, 100));
        agregado.tick(ahora + Duration::from_secs(2));
        agregado.update(&tcp(
            ahora + Duration::from_secs(2),
            "192.168.1.10",
            "192.168.1.20",
            1000,
            443,
            60,
        ));

        let instantanea = agregado.snapshot();
        let dispositivo = &instantanea.devices[0];
        assert_eq!(dispositivo.rate_out, 60);
        assert_eq!(dispositivo.bytes_out, 160);
    }

    #[test]
    fn al_avanzar_mas_de_60_segundos_los_contadores_de_ventana_se_vacian() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 1000, 443, 500));
        agregado.tick(ahora + Duration::from_secs(61));

        let instantanea = agregado.snapshot();
        let dispositivo = &instantanea.devices[0];
        assert_eq!(dispositivo.bytes_out, 0);
        assert_eq!(dispositivo.series_60s_out, [0u64; LEN_60S]);
        // El top de puertos es acumulativo (no depende de la ventana).
        assert_eq!(dispositivo.top_ports.len(), 1);
        assert_eq!(dispositivo.top_ports[0].port, 443);
    }

    #[test]
    fn las_series_tienen_60_puntos_y_el_bucket_reciente_marca_el_ultimo_segundo() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&udp(ahora, "192.168.1.10", "1.1.1.1", 50000, 53, 70));
        agregado.tick(ahora + Duration::from_secs(1));
        agregado.update(&udp(
            ahora + Duration::from_secs(1),
            "192.168.1.10",
            "1.1.1.1",
            50000,
            53,
            90,
        ));

        let instantanea = agregado.snapshot();
        let dispositivo = &instantanea.devices[0];
        assert_eq!(dispositivo.series_60s_out.len(), LEN_60S);
        assert_eq!(dispositivo.series_5min_out.len(), 60);
        assert_eq!(dispositivo.series_60s_out[LEN_60S - 1], 90);
        assert_eq!(dispositivo.series_60s_out[LEN_60S - 2], 70);
        assert_eq!(dispositivo.rate_out, 90);
    }

    #[test]
    fn top_ports_ordena_descendente_y_limita_a_cinco() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        for (puerto, bytes) in [
            (80u16, 100u32),
            (443, 500),
            (22, 50),
            (8080, 200),
            (53, 400),
            (25, 10),
        ] {
            agregado.update(&tcp(
                ahora,
                "192.168.1.10",
                "192.168.1.20",
                40000,
                puerto,
                bytes,
            ));
        }

        let instantanea = agregado.snapshot();
        let puertos = &instantanea.devices[0].top_ports;
        assert_eq!(puertos.len(), MAX_TOP_PORTS);
        assert_eq!(puertos[0].port, 443);
        assert_eq!(puertos[0].bytes, 500);
        assert_eq!(puertos[0].protocol, Protocol::Tcp);
        assert_eq!(puertos[1].port, 53);
        assert_eq!(puertos[2].port, 8080);
        assert_eq!(puertos[3].port, 80);
        assert_eq!(puertos[4].port, 22);
    }

    #[test]
    fn top_ports_cuenta_el_puerto_remoto_en_cada_direccion() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        // Salida del equipo hacia el 443 remoto.
        agregado.update(&tcp(ahora, "192.168.1.10", "1.1.1.1", 50000, 443, 120));
        // Entrada al equipo desde el 80 remoto.
        agregado.update(&tcp(ahora, "1.1.1.1", "192.168.1.10", 80, 50000, 80));

        let instantanea = agregado.snapshot();
        let puertos = &instantanea.devices[0].top_ports;
        assert_eq!(puertos.len(), 2);
        assert_eq!(puertos[0].port, 443);
        assert_eq!(puertos[0].bytes, 120);
        assert_eq!(puertos[1].port, 80);
        assert_eq!(puertos[1].bytes, 80);
    }

    #[test]
    fn el_top_de_puertos_se_mantiene_acotado_sin_perder_los_mayores() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        // 300 puertos distintos: el mapa interno debe quedarse en 256 entradas,
        // descartando las de menos bytes; los mayores siguen en el top.
        for puerto in 1u16..=300 {
            agregado.update(&tcp(
                ahora,
                "192.168.1.10",
                "192.168.1.20",
                40000,
                puerto,
                u32::from(puerto),
            ));
        }
        let instantanea = agregado.snapshot();
        let puertos = &instantanea.devices[0].top_ports;
        assert_eq!(puertos.len(), MAX_TOP_PORTS);
        assert_eq!(puertos[0].port, 300);
        assert_eq!(puertos[1].port, 299);
        assert_eq!(puertos[4].port, 296);
    }

    #[test]
    fn set_devices_pruna_los_equipos_que_desaparecen_y_conserva_los_demas() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[
            ("192.168.1.10", 1),
            ("192.168.1.20", 2),
        ]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 1000, 443, 100));
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));

        let instantanea = agregado.snapshot();
        assert_eq!(instantanea.devices.len(), 1);
        assert_eq!(instantanea.devices[0].device_id, 1);
        assert_eq!(instantanea.devices[0].bytes_out, 100);
    }

    #[test]
    fn el_snapshot_ordena_los_dispositivos_por_consumo() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[
            ("192.168.1.10", 1),
            ("192.168.1.20", 2),
        ]));
        agregado.update(&tcp(ahora, "192.168.1.10", "1.1.1.1", 1000, 443, 100));
        agregado.update(&tcp(ahora, "192.168.1.20", "1.1.1.1", 1000, 443, 900));

        let instantanea = agregado.snapshot();
        assert_eq!(instantanea.devices[0].device_id, 2);
        assert_eq!(instantanea.devices[1].device_id, 1);
    }

    #[test]
    fn reset_vacia_los_contadores_y_conserva_los_dispositivos() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&udp(ahora, "192.168.1.10", "255.255.255.255", 68, 67, 300));
        agregado.reset(ahora + Duration::from_secs(10));

        let instantanea = agregado.snapshot();
        assert_eq!(instantanea.devices.len(), 1);
        assert_eq!(instantanea.devices[0].bytes_out, 0);
        assert_eq!(instantanea.devices[0].top_ports.len(), 0);
        assert_eq!(instantanea.global.broadcast_bytes, 0);
        assert_eq!(instantanea.global.packets_total, 0);
    }

    #[test]
    fn sin_dispositivos_conocidos_no_se_atribuye_trafico_pero_si_se_cuentan_paquetes() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.update(&udp(ahora, "8.8.8.8", "1.1.1.1", 53, 1234, 90));

        let instantanea = agregado.snapshot();
        assert!(instantanea.devices.is_empty());
        assert_eq!(instantanea.global.packets_total, 1);
        assert_eq!(instantanea.global.bytes_in, 0);
        assert_eq!(instantanea.global.bytes_out, 0);
    }

    #[test]
    fn el_tick_repetido_es_idempotente() {
        let ahora = Instant::now();
        let mut agregado = Aggregator::new(ahora);
        agregado.set_devices(&mapa_dispositivos(&[("192.168.1.10", 1)]));
        agregado.update(&tcp(ahora, "192.168.1.10", "192.168.1.20", 1000, 443, 100));
        agregado.tick(ahora + Duration::from_secs(5));
        let primera = agregado.snapshot();
        agregado.tick(ahora + Duration::from_secs(5));
        let segunda = agregado.snapshot();
        assert_eq!(primera, segunda);
        assert_eq!(segunda.devices[0].bytes_out, 100);
    }
}
