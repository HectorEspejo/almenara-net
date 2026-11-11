//! Consolidación de horas y días (§7.3).
//!
//! La agregación SQL vive en el DAO (Repo::build_hour y Repo::build_day); este
//! módulo reúne la lógica pura de topes que comparten el cierre del minuto, la
//! consolidación y la aplicación de claves especiales.

use crate::history::{clave_especial, Counter, Dimension, RollupRow, KEY_OTHERS};

/// Aplica el tope de top_keys claves normales por sujeto y dimensión.
///
/// Las claves especiales (~sin_identificar, ~lan, ~desconocido) no cuentan para
/// el tope y nunca se funden en ~otros. El resto de claves normales se ordena
/// por total de bytes descendente; las que pasan del tope se suman a ~otros,
/// junto con el ~otros que ya viniera de una resolución inferior.
pub fn aplicar_topes(filas: Vec<RollupRow>, top_keys: usize) -> Vec<RollupRow> {
    use std::collections::BTreeMap;

    let mut grupos: BTreeMap<(crate::history::Subject, Dimension), Vec<RollupRow>> =
        BTreeMap::new();
    for fila in filas {
        grupos
            .entry((fila.subject, fila.dimension))
            .or_default()
            .push(fila);
    }

    let mut salida = Vec::new();
    for ((subject, dimension), mut items) in grupos {
        if dimension == Dimension::Total {
            items.sort_by(|a, b| a.key.cmp(&b.key));
            salida.extend(items);
            continue;
        }

        let mut otros = Counter::default();
        let mut normales: Vec<RollupRow> = Vec::new();
        let mut especiales: Vec<RollupRow> = Vec::new();
        for item in items.drain(..) {
            if item.key == KEY_OTHERS {
                otros.suma(item.counter);
            } else if clave_especial(&item.key) {
                especiales.push(item);
            } else {
                normales.push(item);
            }
        }
        normales.sort_by(|a, b| {
            b.counter
                .total()
                .cmp(&a.counter.total())
                .then_with(|| a.counter.down.cmp(&b.counter.down))
                .then_with(|| a.key.cmp(&b.key))
        });
        let tope = top_keys.max(1);
        if normales.len() > tope {
            for item in normales.drain(tope..) {
                otros.suma(item.counter);
            }
        }
        especiales.sort_by(|a, b| a.key.cmp(&b.key));
        salida.extend(especiales);
        salida.extend(normales);
        if otros != Counter::default() {
            salida.push(RollupRow {
                subject,
                dimension,
                key: KEY_OTHERS.to_string(),
                counter: otros,
            });
        }
    }
    salida
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::Subject;

    fn fila(subject: Subject, dimension: Dimension, key: &str, down: u64, up: u64) -> RollupRow {
        RollupRow {
            subject,
            dimension,
            key: key.to_string(),
            counter: Counter {
                down,
                up,
                connections: 0,
            },
        }
    }

    #[test]
    fn el_tope_agrupa_el_resto_en_otros_sin_tocar_especiales() {
        let mut filas = Vec::new();
        for indice in 0..30u64 {
            filas.push(fila(
                Subject::Device(1),
                Dimension::Destination,
                &format!("destino{indice:02}"),
                100 - indice,
                0,
            ));
        }
        filas.push(fila(
            Subject::Device(1),
            Dimension::Destination,
            crate::history::KEY_LAN,
            7,
            1,
        ));
        let resultado = aplicar_topes(filas, 20);

        let destinos: Vec<&RollupRow> = resultado
            .iter()
            .filter(|fila| fila.key.starts_with("destino"))
            .collect();
        assert_eq!(destinos.len(), 20);
        assert!(resultado
            .iter()
            .any(|fila| fila.key == crate::history::KEY_LAN));
        let otros = resultado
            .iter()
            .find(|fila| fila.key == KEY_OTHERS)
            .expect("debe existir ~otros");
        // Las diez claves que no caben suman 80 + 79 + ... + 71 = 755.
        assert_eq!(otros.counter.down, (71..=80).sum::<u64>());
        let total: u64 = resultado.iter().map(|fila| fila.counter.down).sum();
        assert_eq!(total, (71..=100).sum::<u64>() + 7);
    }

    #[test]
    fn el_otros_previo_se_suma_al_nuevo_y_el_total_no_se_toca() {
        let filas = vec![
            fila(Subject::Network, Dimension::Total, "", 10, 5),
            fila(Subject::Device(2), Dimension::App, "youtube", 60, 0),
            fila(Subject::Device(2), Dimension::App, "netflix", 50, 0),
            fila(Subject::Device(2), Dimension::App, "twitch", 40, 0),
            fila(Subject::Device(2), Dimension::App, KEY_OTHERS, 25, 1),
            fila(
                Subject::Device(2),
                Dimension::App,
                crate::history::KEY_UNIDENTIFIED,
                9,
                0,
            ),
        ];
        let resultado = aplicar_topes(filas, 2);
        assert_eq!(
            resultado
                .iter()
                .filter(|fila| fila.dimension == Dimension::Total)
                .count(),
            1
        );
        let otros = resultado
            .iter()
            .find(|fila| fila.key == KEY_OTHERS)
            .unwrap();
        assert_eq!(
            otros.counter,
            Counter {
                down: 65,
                up: 1,
                connections: 0
            }
        );
        let sin_identificar = resultado
            .iter()
            .find(|fila| fila.key == crate::history::KEY_UNIDENTIFIED)
            .unwrap();
        assert_eq!(sin_identificar.counter.down, 9);
    }

    #[test]
    fn sin_exceso_no_se_crea_otros() {
        let filas = vec![
            fila(Subject::Host, Dimension::App, "youtube", 10, 0),
            fila(Subject::Host, Dimension::App, "netflix", 5, 0),
        ];
        let resultado = aplicar_topes(filas, 20);
        assert_eq!(resultado.len(), 2);
        assert!(!resultado.iter().any(|fila| fila.key == KEY_OTHERS));
    }
}
