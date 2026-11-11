//! Almenara — monitor de red en TUI para Linux.
//!
//! Punto de entrada: parsea la CLI, carga configuración, inicializa logging,
//! abre SQLite con migraciones y lanza el escáner y la interfaz.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Parser};

mod alerts;
mod capabilities;
mod capture;
mod classify;
mod config;
mod discovery;
mod error;
mod events;
mod history;
mod identify;
mod inference;
mod instance;
mod logging;
mod notifier;
mod notify;
mod oui;
mod rankings;
mod repo;
mod scanner;
mod traffic;
mod tui;

use config::Config;
use error::Result;
use events::{AppEvent, ScanCommand};
use notifier::Level;
use repo::Repo;
use scanner::ScanOptions;
use tui::app::App;
use tui::theme::Theme;

/// Monitor de red en TUI para Linux: descubre los equipos de la red local.
#[derive(Debug, Parser)]
#[command(
    name = "almenara",
    version,
    about = "Monitor de red en TUI para Linux: descubre los equipos de la red local",
    long_about = "Almenara descubre los equipos de la red local (ARP, ICMP, reverse DNS y OUI), \
                  guarda el inventario en SQLite y lo muestra en una TUI. \
                  Fase 4: captura en vivo con AF_PACKET + TPACKET_V3, inferencia de protocolos, \
                  apps y names, rankings por destino/app/categoría/protocolo/proceso y \
                  «¿Quién lo usa?».",
    disable_help_flag = true,
    disable_version_flag = true,
    help_template = "Ayuda de {name} — versión {version}\n\n{about-with-newline}\nUso: {usage}\n\nOpciones:\n{options}"
)]
struct Cli {
    /// Ruta alternativa del fichero de configuración TOML.
    #[arg(short = 'c', long = "config", value_name = "RUTA")]
    config: Option<PathBuf>,

    /// Aumenta el detalle de los logs: -v (debug), -vv (trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,

    /// Desactiva el color de la interfaz (equivale a NO_COLOR=1).
    #[arg(long = "no-color")]
    no_color: bool,

    /// Muestra esta ayuda y sale.
    #[arg(short = 'h', long = "help", action = ArgAction::Help)]
    help: Option<bool>,

    /// Muestra la versión y sale.
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    version: Option<bool>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match ejecutar(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Almenara: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn ejecutar(cli: Cli) -> Result<()> {
    // 1) Logging a fichero (nunca a stdout/stderr para no romper la TUI).
    let log_dir = Config::log_dir().unwrap_or_else(|_| std::env::temp_dir().join("almenara-log"));
    let _log_guard = match logging::init(cli.verbose, &log_dir) {
        Ok(guard) => Some(guard),
        Err(err) => {
            eprintln!("Aviso: {err}. Se continúa sin registro en fichero.");
            None
        }
    };
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        verbose = cli.verbose,
        "Arrancando Almenara"
    );

    // 2) Configuración (si falta se crea una plantilla; si falla se usan defaults).
    let (config_path, aviso_escritura) = Config::ensure_default_file(cli.config.as_deref());
    let (config, avisos_carga) = Config::load_or_default(Some(&config_path));
    let mut avisos: Vec<String> = Vec::new();
    if let Some(aviso) = aviso_escritura {
        avisos.push(aviso);
    }
    avisos.extend(avisos_carga);
    tracing::info!(ruta = %config_path.display(), "Configuración cargada");
    for aviso in &avisos {
        tracing::warn!(%aviso, "aviso de configuración");
    }

    // 3) Rutas y tema.
    let db_path = config.database_path()?;
    let theme = Theme::from_flags(config.ui.no_color, cli.no_color);

    // Instancia única por base de datos (ADR-65): si otra Almenara tiene el
    // bloqueo, se sale sin abrir la BD y con código 1.
    let _instance_lock = match instance::InstanceLock::acquire(&db_path) {
        Ok(bloqueo) => bloqueo,
        Err(err) => {
            tracing::warn!(%err, "ya hay una instancia de Almenara en marcha");
            return Err(error::Error::Config(err.to_string()));
        }
    };

    // 4) Capacidades y base de datos (con modal bloqueante si falla).
    let capabilities = capabilities::Capabilities::detect();
    tracing::info!(modo = capabilities.mode_label(), detalle = %capabilities.detail, "Capacidades detectadas");

    let mut repo = loop {
        match Repo::init(&db_path) {
            Ok(repo) => break repo,
            Err(err) => {
                tracing::error!(%err, "no se pudo abrir la base de datos");
                let reintentar = tui::db_error_modal(&theme, &err, &db_path)?;
                if !reintentar {
                    return Err(err);
                }
            }
        }
    };
    let version_esquema = repo.schema_version().unwrap_or(0);
    let equipos_en_bd = repo.count_devices().unwrap_or(0);
    tracing::info!(
        ruta = %repo.path().display(),
        version_esquema,
        equipos_en_bd,
        "Base de datos abierta y migrada"
    );

    // Semilla de Fase 3: último snapshot de tráfico por dispositivo (para no
    // arrancar con la TUI vacía) y purga de las conexiones caducadas de la
    // ejecución anterior.
    let snapshots_trafico = repo.list_snapshots().unwrap_or_else(|err| {
        tracing::warn!(%err, "no se pudo leer TRAFFIC_SNAPSHOT");
        Vec::new()
    });
    match repo.prune_expired_connections(std::time::SystemTime::now()) {
        Ok(borradas) if borradas > 0 => {
            tracing::info!(borradas, "conexiones caducadas purgadas al arrancar");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "no se pudieron purgar las conexiones caducadas"),
    }
    // Arranque en caliente de la caché IP → nombre de Fase 4.
    let nombres_cache = match repo.list_names(std::time::SystemTime::now()) {
        Ok(entradas) => {
            tracing::info!(entradas = entradas.len(), "caché de nombres cargada");
            entradas
        }
        Err(err) => {
            tracing::warn!(%err, "no se pudo leer NAME_CACHE");
            Vec::new()
        }
    };

    // 5) Detección y persistencia inicial de interfaces, datos persistidos y poda.
    match scanner::persistir_interfaces_iniciales(&mut repo) {
        Ok(cantidad) => tracing::info!(
            interfaces = cantidad,
            "interfaces detectadas y persistidas al arrancar"
        ),
        Err(err) => {
            let aviso = format!("No se pudieron persistir las interfaces detectadas: {err}");
            tracing::warn!(%err, "fallo persistiendo interfaces iniciales");
            avisos.push(aviso);
        }
    }

    let devices = repo.list_devices().unwrap_or_else(|err| {
        tracing::warn!(%err, "no se pudo cargar la lista de equipos");
        Vec::new()
    });
    // Estado inicial del port scan: los equipos ya persistidos no se reescanean
    // en el primer ciclo (solo los nuevos, los que cambian de IP/MAC o con r).
    let equipos_conocidos: Vec<(String, String)> = devices
        .iter()
        .map(|device| (device.mac.clone(), device.ip.clone()))
        .collect();
    let interfaces = repo.list_interfaces().unwrap_or_else(|err| {
        tracing::warn!(%err, "no se pudo cargar la lista de interfaces");
        Vec::new()
    });
    match repo.prune_events(config.storage.events_retention_days) {
        Ok(borrados) if borrados > 0 => {
            tracing::info!(borrados, "eventos antiguos purgados");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "no se pudo podar el histórico"),
    }

    // 6) Canales, estado de la TUI y tarea de escaneo.
    let (event_tx, event_rx) = events::bus();

    // Histórico (F5): las sesiones interrumpidas se cierran en el arranque y se
    // abre la de esta ejecución; el lector de solo lectura se lanza después de
    // las migraciones (la conexión de escritura ya creó el WAL).
    match repo.close_open_sessions() {
        Ok(cerradas) if cerradas > 0 => {
            tracing::info!(cerradas, "sesiones interrumpidas cerradas al arrancar");
        }
        Ok(_) => {}
        Err(err) => tracing::warn!(%err, "no se pudieron cerrar las sesiones abiertas"),
    }
    let session_info = history::SessionInfo {
        // Valores persistidos de APP_SESSIONS.mode (§3): privileged/degraded.
        mode: if capabilities.raw_sockets {
            "privileged"
        } else {
            "degraded"
        }
        .to_string(),
        capture: config.capture.enabled && capabilities.raw_sockets,
        passive_only: config.scan.passive_only,
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    let session_id = match repo.open_session(&session_info) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(%err, "no se pudo abrir la sesión del histórico");
            None
        }
    };
    let history_reader = match history::reader::HistoryReader::spawn(&db_path, event_tx.clone()) {
        Ok(handle) => Some(handle),
        Err(err) => {
            tracing::warn!(%err, "no se pudo lanzar el lector del histórico");
            None
        }
    };
    let (command_tx, command_rx) = events::command_channel();
    let scan_options = ScanOptions::from_config(&config.scan, capabilities.raw_sockets)?;
    let intervalo = Duration::from_secs(config.scan.interval_s);

    let mut app = App::new(
        config.clone(),
        config_path,
        db_path,
        capabilities.clone(),
        Some(command_tx),
    );
    app.theme = theme;
    app.set_data(devices, interfaces);
    app.session_id = session_id;
    app.last_beat = Some(std::time::Instant::now());
    app.history_reader = history_reader;
    for aviso in avisos {
        app.push_notification(Level::Warn, aviso);
    }
    if capabilities.degraded() && !config.scan.passive_only {
        app.push_notification(
            Level::Warn,
            "Modo degradado: sin CAP_NET_RAW. Solo se leerá /proc/net/arp; para descubrimiento activo ejecuta: sudo setcap cap_net_raw+ep target/debug/almenara",
        );
        app.degraded_warned = true;
    }
    if config.scan.passive_only {
        app.push_notification(
            Level::Warn,
            "Modo pasivo: [scan].passive_only = true. Sin ARP scan, ICMP, mDNS browse, M-SEARCH, port scan, banner grabbing, NetBIOS ni DNS inverso; la captura pasiva sigue activa",
        );
    }

    // Interfaces detectadas: multicast mDNS/SSDP, interfaces de captura y IP
    // propias del host (para la atribución [host] de las conexiones).
    let interfaces_detectadas = scanner::interfaces::detect();
    let ips_multicast: Vec<std::net::Ipv4Addr> = interfaces_detectadas
        .iter()
        .filter_map(|iface| iface.ipv4)
        .collect();
    let interfaces_captura: Vec<capture::CaptureInterface> = match &config.scan.interfaces {
        config::InterfacesSetting::Auto => interfaces_detectadas
            .iter()
            .filter(|iface| iface.is_up && iface.ipv4.is_some())
            .map(interfaz_de_captura)
            .collect(),
        config::InterfacesSetting::Names(nombres) => interfaces_detectadas
            .iter()
            .filter(|iface| iface.is_up && iface.ipv4.is_some() && nombres.contains(&iface.name))
            .map(interfaz_de_captura)
            .collect(),
    };
    let mut ips_propias: std::collections::HashSet<std::net::IpAddr> = interfaces_detectadas
        .iter()
        .filter_map(|iface| iface.ipv4.map(std::net::IpAddr::V4))
        .collect();
    ips_propias.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    ips_propias.insert(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
    tracing::debug!(interfaces = ?ips_multicast, "interfaces para multicast mDNS/SSDP");

    // 6b) Monitor de tráfico en vivo (Fase 3). La captura de paquetes requiere
    // CAP_NET_RAW; las conexiones de /proc/net/* y conntrack funcionan igualmente.
    let dispositivos_trafico = dispositivos_para_trafico(&app, &repo);
    let inicio_trafico = traffic::spawn(
        &config,
        interfaces_captura,
        ips_propias,
        dispositivos_trafico.clone(),
        nombres_cache,
        capabilities.raw_sockets,
        event_tx.clone(),
    );
    app.traffic.capture = inicio_trafico.status;
    app.set_traffic_seed(snapshots_trafico);
    app.traffic_command_tx = Some(inicio_trafico.handle.command_tx.clone());
    for (nivel, mensaje) in inicio_trafico.notices {
        app.push_notification(nivel, mensaje);
    }
    let catalog_counts = inicio_trafico.catalog;
    let ipdb_date = inicio_trafico.ipdb_date;
    app.catalog_counts = catalog_counts;
    app.ipdb_date = ipdb_date;
    let observado = inicio_trafico.observed;
    let identidad = inicio_trafico.identity;
    let traffic_command_tx = inicio_trafico.handle.command_tx.clone();
    let mut traffic_join = inicio_trafico.handle.join;
    let scan_tx = event_tx.clone();
    let scan_task = tokio::spawn(async move {
        let mut command_rx = command_rx;
        let mut state = scanner::ScanState::new(&equipos_conocidos);
        let mut discovery_state = discovery::DiscoveryState::start_on(&ips_multicast);
        let mut manual = false;
        loop {
            let _ = scan_tx.send(AppEvent::ScanStarted);
            let informe = scanner::run_scan(
                &scan_options,
                &mut state,
                &mut discovery_state,
                manual,
                &observado,
                &identidad,
            )
            .await;
            manual = false;
            // Los avisos no fatales del ciclo también van al log de fichero para
            // poder diagnosticar problemas de descubrimiento sin la TUI abierta.
            for error in &informe.errors {
                tracing::warn!(aviso = %error, "aviso del escaneo");
            }
            let _ = scan_tx.send(AppEvent::Devices(Box::new(informe)));

            tokio::select! {
                _ = tokio::time::sleep(intervalo) => {}
                comando = command_rx.recv() => {
                    match comando {
                        // Un rescaneo manual fuerza port scan/fingerprint de todos
                        // los equipos, además de adelantar el ciclo.
                        Some(ScanCommand::Rescan) => manual = true,
                        Some(ScanCommand::Stop) | None => break,
                    }
                }
            }
        }
    });

    // 7) Bucle de la TUI (bloquea hasta que el usuario sale).
    let resultado = tui::run(app, repo, event_rx).await;

    let _ = event_tx.send(AppEvent::Quit);
    scan_task.abort();
    let _ = scan_task.await;
    let _ = traffic_command_tx.try_send(events::TrafficCommand::Stop);
    if tokio::time::timeout(Duration::from_secs(2), &mut traffic_join)
        .await
        .is_err()
    {
        traffic_join.abort();
    }
    tracing::info!("Almenara finalizado");
    resultado
}

/// Construye la interfaz de captura con todos sus datos de red.
fn interfaz_de_captura(
    iface: &scanner::interfaces::DetectedInterface,
) -> capture::CaptureInterface {
    capture::CaptureInterface::with_details(
        iface.name.clone(),
        iface.ipv4,
        iface.mac.clone(),
        iface.netmask,
        iface.gateway,
    )
}

/// Referencias de dispositivo con sus servicios de F2 para el agregador de tráfico.
fn dispositivos_para_trafico(app: &App, repo: &Repo) -> Vec<traffic::DeviceRef> {
    app.devices
        .iter()
        .map(|device| {
            let servicios = repo
                .list_services(device.id)
                .unwrap_or_default()
                .into_iter()
                .map(|servicio| traffic::ServiceRef {
                    port: servicio.port,
                    protocol: match servicio.protocol {
                        repo::Protocol::Tcp => capture::Protocol::Tcp,
                        repo::Protocol::Udp => capture::Protocol::Udp,
                    },
                    service: servicio.service.clone(),
                })
                .collect();
            traffic::DeviceRef::with_details(
                device.id,
                device.ip.clone(),
                device.mac.clone(),
                Some(device.display_name().to_string()),
                servicios,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn la_cli_esta_bien_definida() {
        Cli::command().debug_assert();
    }

    #[test]
    fn la_cli_acepta_los_flags_de_la_especificacion() {
        let cli = Cli::try_parse_from(["almenara", "-c", "/tmp/config.toml", "-vv", "--no-color"])
            .expect("flags válidos");
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/config.toml")));
        assert_eq!(cli.verbose, 2);
        assert!(cli.no_color);
    }

    #[test]
    fn la_cli_por_defecto_no_es_verbosa() {
        let cli = Cli::try_parse_from(["almenara"]).unwrap();
        assert!(cli.config.is_none());
        assert_eq!(cli.verbose, 0);
        assert!(!cli.no_color);
    }
}
