//! Almenara — monitor de red en TUI para Linux.
//!
//! Punto de entrada: parsea la CLI, carga configuración, inicializa logging,
//! abre SQLite con migraciones y lanza el escáner y la interfaz.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{ArgAction, Parser};

mod capabilities;
mod classify;
mod config;
mod discovery;
mod error;
mod events;
mod logging;
mod notifier;
mod oui;
mod repo;
mod scanner;
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
                  guarda el inventario en SQLite y los muestra en una TUI. \
                  Fase 1: fundación y descubrimiento básico.",
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
            "Modo pasivo: [scan].passive_only = true. Sin ARP scan, ICMP, mDNS browse, M-SEARCH, port scan ni banner grabbing",
        );
    }

    // Interfaces con IPv4 para unir los grupos multicast de mDNS/SSDP. Unirse
    // con INADDR_ANY puede no seleccionar la interfaz correcta en Wi-Fi.
    let ips_multicast: Vec<std::net::Ipv4Addr> = scanner::interfaces::detect()
        .iter()
        .filter_map(|iface| iface.ipv4)
        .collect();

    tracing::debug!(interfaces = ?ips_multicast, "interfaces para multicast mDNS/SSDP");
    let scan_tx = event_tx.clone();
    let scan_task = tokio::spawn(async move {
        let mut command_rx = command_rx;
        let mut state = scanner::ScanState::new(&equipos_conocidos);
        let mut discovery_state = discovery::DiscoveryState::start_on(&ips_multicast);
        let mut manual = false;
        loop {
            let _ = scan_tx.send(AppEvent::ScanStarted);
            let informe =
                scanner::run_scan(&scan_options, &mut state, &mut discovery_state, manual).await;
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
    tracing::info!("Almenara finalizado");
    resultado
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
