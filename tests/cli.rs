//! Pruebas de la interfaz de línea de comandos del binario.
//!
//! Se ejecutan sin terminal interactiva: clap resuelve --help y --version antes
//! de inicializar la TUI.

use std::process::Command;

fn binario() -> Command {
    Command::new(env!("CARGO_BIN_EXE_almenara"))
}

#[test]
fn la_ayuda_muestra_los_flags_de_la_especificacion() {
    let salida = binario()
        .arg("--help")
        .output()
        .expect("ejecutar almenara --help");
    assert!(
        salida.status.success(),
        "el binario debe salir con éxito en --help"
    );
    let stdout = String::from_utf8_lossy(&salida.stdout);
    for flag in ["--config", "--verbose", "--no-color", "--version", "--help"] {
        assert!(
            stdout.contains(flag),
            "la ayuda no menciona {flag}:\n{stdout}"
        );
    }
    assert!(stdout.contains("Almenara descubre"));
    assert!(stdout.contains("Uso:"));
    assert!(stdout.contains("Opciones:"));
}

#[test]
fn la_ayuda_corta_tambien_esta_en_castellano() {
    let salida = binario().arg("-h").output().expect("ejecutar almenara -h");
    assert!(salida.status.success());
    let stdout = String::from_utf8_lossy(&salida.stdout);
    assert!(stdout.contains("Ayuda de almenara"));
    assert!(stdout.contains("Muestra esta ayuda y sale"));
}

#[test]
fn la_version_coincide_con_el_paquete() {
    let salida = binario()
        .arg("--version")
        .output()
        .expect("ejecutar almenara --version");
    assert!(salida.status.success());
    let stdout = String::from_utf8_lossy(&salida.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "versión inesperada: {stdout}"
    );
    assert!(stdout.contains("almenara"));
}

#[test]
fn un_flag_desconocido_falla() {
    let salida = binario()
        .arg("--no-existe")
        .output()
        .expect("ejecutar almenara --no-existe");
    assert!(!salida.status.success(), "un flag desconocido debe fallar");
}
