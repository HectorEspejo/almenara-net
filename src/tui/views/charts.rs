//! Utilidades de dibujo del histórico (F5).
//!
//! Reúne las piezas que comparten la pestaña Histórico y el detalle de equipo:
//! barras con huecos (nunca interpolados) y tiempo futuro en blanco, filas de
//! tráfico y de presencia sobre el mismo eje, rejilla de presencia de 7 días por
//! 24 horas y formateos de bytes, porcentajes y huecos.
//!
//! Nada depende solo del color: los huecos llevan ░, la presencia █, la ausencia
//! · y el futuro se deja en blanco; siempre acompañados de su leyenda.

use ratatui::text::{Line, Span};

use crate::history::{PresenceSpan, PresenceState, Range, Series};
use crate::tui::theme::Theme;

/// Carácter de un hueco de datos.
pub const HUECO: char = '░';
/// Carácter de presencia.
pub const PRESENTE: char = '█';
/// Carácter de ausencia.
pub const AUSENTE: char = '·';
/// Leyenda de los huecos.
pub const LEYENDA_HUECOS: &str = "░ sin datos";
/// Leyenda de la presencia.
pub const LEYENDA_PRESENCIA: &str = "█ presente · · ausente · ░ sin datos";
/// Bloques de ocho niveles, de menor a mayor.
const BLOQUES: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Punto mínimo de una barra de la gráfica.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BarraPunto {
    /// Bytes totales (bajada + subida).
    pub total: u64,
    /// El punto no tiene cobertura de tráfico.
    pub hueco: bool,
    /// El punto cae en el futuro (se dibuja en blanco).
    pub futuro: bool,
}

impl BarraPunto {
    /// Convierte un punto de la serie en un punto de barra.
    pub fn de_serie(punto: &crate::history::SeriesPoint) -> Self {
        Self {
            total: punto.total(),
            hueco: punto.gap,
            futuro: punto.future,
        }
    }
}

/// Convierte una serie en los puntos de sus barras.
pub fn puntos_de_serie(serie: &Series) -> Vec<BarraPunto> {
    serie.points.iter().map(BarraPunto::de_serie).collect()
}

/// Máximo de la serie (sin contar huecos ni futuro); 0 si no hay datos.
pub fn maximo_de_serie(serie: &Series) -> u64 {
    serie
        .points
        .iter()
        .filter(|punto| !punto.gap && !punto.future)
        .map(crate::history::SeriesPoint::total)
        .max()
        .unwrap_or(0)
}

/// Formatea un porcentaje con su espacio y el símbolo («42 %»).
pub fn formatear_pct(pct: f32) -> String {
    format!("{:.0} %", pct)
}

/// Formatea una duración de hueco de forma legible («8 h 21 min»).
pub fn formatear_hueco(segundos: i64) -> String {
    let segundos = segundos.max(0);
    if segundos < 60 {
        return format!("{segundos} s");
    }
    if segundos < 3600 {
        return format!("{} min", segundos / 60);
    }
    if segundos < 86_400 {
        let horas = segundos / 3600;
        let minutos = (segundos % 3600) / 60;
        return if minutos == 0 {
            format!("{horas} h")
        } else {
            format!("{horas} h {minutos} min")
        };
    }
    let dias = segundos / 86_400;
    let horas = (segundos % 86_400) / 3600;
    if horas == 0 {
        format!("{dias} d")
    } else {
        format!("{dias} d {horas} h")
    }
}

/// Etiqueta de la resolución de una gráfica según su rango (§7.11).
pub fn formatear_resolucion(range: Range) -> &'static str {
    match range {
        Range::Hours24 => "puntos de 30 min",
        Range::Days7 => "puntos de 3 h",
        Range::Days30 => "por día",
        Range::Year1 => "por semana",
    }
}

/// Etiqueta de fecha local de un punto («dom 8 nov»).
pub fn etiqueta_dia(unix: i64) -> String {
    crate::history::localtime::format_dia_local(unix)
}

/// Etiqueta de fecha y hora local de un punto («dom 8 nov 21:00»).
pub fn etiqueta_fecha_hora(unix: i64) -> String {
    format!(
        "{} {}",
        etiqueta_dia(unix),
        crate::history::localtime::format_hora_local(unix)
    )
}

/// Etiqueta corta de un punto según el rango de la gráfica.
pub fn etiqueta_punto(at: i64, range: Range) -> String {
    match range {
        Range::Hours24 | Range::Days7 => etiqueta_fecha_hora(at),
        Range::Days30 | Range::Year1 => etiqueta_dia(at),
    }
}

/// Hora local de un instante («HH:MM»).
pub fn hora_local(unix: i64) -> String {
    crate::history::localtime::format_hora_local(unix)
}

/// Índice del punto que corresponde a una columna del ancho disponible.
fn indice_de_columna(columna: usize, ancho: usize, puntos: usize) -> usize {
    if puntos == 0 || ancho == 0 {
        return 0;
    }
    (columna * puntos / ancho).min(puntos - 1)
}

/// Dibuja las barras de la gráfica con la altura indicada.
///
/// Cada punto ocupa una o varias columnas según el ancho; los huecos se dibujan
/// con ░ en la fila inferior y el futuro queda en blanco. La columna del cursor
/// se resalta con el estilo de selección del tema.
pub fn barras(
    puntos: &[BarraPunto],
    maximo: u64,
    ancho: u16,
    alto: u16,
    cursor: Option<usize>,
    theme: &Theme,
) -> Vec<Line<'static>> {
    let ancho = usize::from(ancho);
    let alto = usize::from(alto);
    let mut lineas = Vec::with_capacity(alto);
    let maximo = maximo.max(1);
    for fila in 0..alto {
        let desde_abajo = alto - 1 - fila;
        let mut spans: Vec<Span<'static>> = Vec::with_capacity(ancho);
        for columna in 0..ancho {
            let indice = indice_de_columna(columna, ancho, puntos.len());
            let punto = puntos.get(indice).copied().unwrap_or_default();
            let en_cursor = cursor == Some(indice);
            let (caracter, estilo) = caracter_de_barra(&punto, maximo, desde_abajo, alto);
            let estilo = if en_cursor {
                theme.selected
            } else {
                estilo(theme)
            };
            spans.push(Span::styled(caracter.to_string(), estilo));
        }
        lineas.push(Line::from(spans));
    }
    lineas
}

/// Carácter y estilo de una celda de barras.
fn caracter_de_barra(
    punto: &BarraPunto,
    maximo: u64,
    desde_abajo: usize,
    alto: usize,
) -> (char, fn(&Theme) -> ratatui::style::Style) {
    if punto.futuro {
        return (' ', |theme| theme.normal);
    }
    if punto.hueco {
        return if desde_abajo == 0 {
            (HUECO, |theme| theme.dim)
        } else {
            (' ', |theme| theme.normal)
        };
    }
    if punto.total == 0 {
        return if desde_abajo == 0 {
            ('▁', |theme| theme.dim)
        } else {
            (' ', |theme| theme.normal)
        };
    }
    let niveles = (punto.total as u128 * alto as u128 * 8 / maximo as u128) as usize;
    let completos = niveles / 8;
    let resto = niveles % 8;
    if desde_abajo < completos {
        ('█', |theme| theme.accent)
    } else if desde_abajo == completos && resto > 0 {
        (BLOQUES[resto - 1], |theme| theme.accent)
    } else if niveles == 0 && desde_abajo == 0 {
        ('▁', |theme| theme.accent)
    } else {
        (' ', |theme| theme.normal)
    }
}

/// Fila del eje de fechas bajo la gráfica.
pub fn eje_fechas(serie: &Series, ancho: u16, theme: &Theme) -> Line<'static> {
    let ancho = usize::from(ancho);
    let puntos = serie.points.len();
    if ancho == 0 || puntos == 0 {
        return Line::default();
    }
    let mut celdas = vec![' '; ancho];
    let maximo_etiquetas = (ancho / 12).clamp(2, 6);
    let paso = if maximo_etiquetas > 1 {
        (puntos - 1) / (maximo_etiquetas - 1)
    } else {
        puntos
    };
    let mut ultima_columna: Option<usize> = None;
    let mut indice = 0;
    while indice < puntos {
        let etiqueta = etiqueta_punto(serie.points[indice].at, serie.range);
        let columna = if puntos > 1 {
            indice * (ancho - 1) / (puntos - 1)
        } else {
            0
        };
        let cabe = ultima_columna
            .map(|ultima| columna > ultima + 1)
            .unwrap_or(true);
        if cabe && columna + etiqueta.chars().count() <= ancho {
            for (posicion, caracter) in etiqueta.chars().enumerate() {
                if let Some(celda) = celdas.get_mut(columna + posicion) {
                    *celda = caracter;
                }
            }
            ultima_columna = Some(columna + etiqueta.chars().count());
        }
        indice += paso.max(1);
    }
    Line::from(Span::styled(
        celdas.into_iter().collect::<String>(),
        theme.dim,
    ))
}

/// Fila de tráfico del detalle: una celda por punto sobre el eje del rango.
pub fn fila_trafico(serie: &Series, ancho: u16, theme: &Theme) -> Line<'static> {
    let ancho = usize::from(ancho);
    let maximo = maximo_de_serie(serie);
    let puntos = serie.points.len();
    let mut spans = Vec::with_capacity(ancho);
    for columna in 0..ancho {
        let indice = indice_de_columna(columna, ancho, puntos);
        let Some(punto) = serie.points.get(indice) else {
            spans.push(Span::styled(" ".to_string(), theme.normal));
            continue;
        };
        let (caracter, estilo) = if punto.future {
            (' ', theme.normal)
        } else if punto.gap {
            (HUECO, theme.dim)
        } else if punto.total() == 0 || maximo == 0 {
            ('▁', theme.dim)
        } else {
            let nivel = ((punto.total() as f64 / maximo as f64) * 7.0).round() as usize;
            (BLOQUES[nivel.min(7)], theme.accent)
        };
        spans.push(Span::styled(caracter.to_string(), estilo));
    }
    Line::from(spans)
}

/// Estado de presencia que solapa una ventana temporal.
pub fn estado_en_ventana(tramos: &[PresenceSpan], inicio: i64, fin: i64) -> Option<PresenceState> {
    let mut encontrado: Option<PresenceState> = None;
    for tramo in tramos {
        if tramo.end <= inicio || tramo.start >= fin {
            continue;
        }
        match tramo.state {
            PresenceState::Present => return Some(PresenceState::Present),
            PresenceState::Absent => {
                if encontrado != Some(PresenceState::Present) {
                    encontrado = Some(PresenceState::Absent);
                }
            }
            PresenceState::NoData => {
                encontrado.get_or_insert(PresenceState::NoData);
            }
        }
    }
    encontrado
}

/// Carácter y estilo de una celda de presencia.
fn caracter_presencia(
    estado: Option<PresenceState>,
    theme: &Theme,
) -> (char, ratatui::style::Style) {
    match estado {
        Some(PresenceState::Present) => (PRESENTE, theme.online),
        Some(PresenceState::Absent) => (AUSENTE, theme.normal),
        Some(PresenceState::NoData) | None => (HUECO, theme.dim),
    }
}

/// Fila de presencia del detalle, sobre el mismo eje que la fila de tráfico.
pub fn fila_presencia(
    tramos: &[PresenceSpan],
    range: Range,
    ahora: i64,
    ancho: u16,
    theme: &Theme,
) -> Line<'static> {
    let ancho = usize::from(ancho);
    let puntos = range.points();
    let resolucion = range.resolution_s();
    let inicio_rango = ahora - range.dur_s();
    let mut spans = Vec::with_capacity(ancho);
    for columna in 0..ancho {
        let indice = indice_de_columna(columna, ancho, puntos);
        let inicio = inicio_rango + indice as i64 * resolucion;
        let fin = inicio + resolucion;
        if inicio > ahora {
            spans.push(Span::styled(" ".to_string(), theme.normal));
            continue;
        }
        let (caracter, estilo) = caracter_presencia(estado_en_ventana(tramos, inicio, fin), theme);
        spans.push(Span::styled(caracter.to_string(), estilo));
    }
    Line::from(spans)
}

/// Rejilla de presencia de los últimos 7 días locales, 24 horas por fila.
///
/// Devuelve una cabecera con las horas y siete filas (de más antigua a hoy).
/// Una celda es presente si el equipo estuvo presente en algún momento de ella;
/// el tiempo que aún no ha pasado se deja en blanco.
pub fn rejilla_presencia(tramos: &[PresenceSpan], ahora: i64, theme: &Theme) -> Vec<Line<'static>> {
    let mut lineas = Vec::with_capacity(9);
    lineas.push(cabecera_rejilla(theme));
    let hoy = crate::history::LocalDay::from_unix(ahora);
    for atras in (0..7).rev() {
        let dia = hoy.sumar_dias(-atras);
        let (inicio, fin) = dia.limits();
        let mut spans = Vec::with_capacity(24 + 1);
        spans.push(Span::styled(
            format!("{} ", etiqueta_dia_corto(inicio)),
            theme.dim,
        ));
        for hora in 0..24 {
            let desde = inicio + (fin - inicio) * hora / 24;
            let hasta = inicio + (fin - inicio) * (hora + 1) / 24;
            if desde > ahora {
                spans.push(Span::styled(" ".to_string(), theme.normal));
                continue;
            }
            let (caracter, estilo) =
                caracter_presencia(estado_en_ventana(tramos, desde, hasta), theme);
            spans.push(Span::styled(caracter.to_string(), estilo));
        }
        lineas.push(Line::from(spans));
    }
    lineas
}

/// Cabecera de la rejilla de presencia con las horas de referencia.
fn cabecera_rejilla(theme: &Theme) -> Line<'static> {
    let mut texto = vec![' '; 7 + 24];
    for hora in [0usize, 6, 12, 18] {
        let etiqueta = hora.to_string();
        for (posicion, caracter) in etiqueta.chars().enumerate() {
            if let Some(celda) = texto.get_mut(7 + hora + posicion) {
                *celda = caracter;
            }
        }
    }
    Line::from(Span::styled(
        texto.into_iter().collect::<String>(),
        theme.dim,
    ))
}

/// Etiqueta corta de un día («jue 5»).
pub fn etiqueta_dia_corto(unix: i64) -> String {
    let completa = crate::history::localtime::format_dia_local(unix);
    let mut partes = completa.split_whitespace();
    match (partes.next(), partes.next()) {
        (Some(dia_semana), Some(dia)) => format!("{dia_semana} {dia}"),
        _ => completa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::SeriesPoint;
    use crate::tui::theme::Theme;

    fn serie(puntos: usize, range: Range) -> Series {
        let points = (0..puntos)
            .map(|indice| SeriesPoint {
                at: 1_760_000_000 + indice as i64 * 1800,
                bytes_down: (indice as u64 + 1) * 1000,
                bytes_up: 100,
                gap: indice == 1,
                future: indice + 1 == puntos,
            })
            .collect();
        Series {
            range,
            points,
            total_down: 1000,
            total_up: 100,
            max: Some((puntos - 2, 10_000)),
        }
    }

    fn texto(lineas: &[Line]) -> String {
        lineas
            .iter()
            .flat_map(|linea| linea.spans.iter())
            .map(|span| span.content.clone())
            .collect()
    }

    #[test]
    fn los_huecos_se_formatean_en_horas_y_minutos() {
        assert_eq!(formatear_hueco(45), "45 s");
        assert_eq!(formatear_hueco(120), "2 min");
        assert_eq!(formatear_hueco(3600), "1 h");
        assert_eq!(formatear_hueco(3600 * 8 + 60 * 21), "8 h 21 min");
        assert_eq!(formatear_hueco(86_400 * 2), "2 d");
        assert_eq!(formatear_hueco(-5), "0 s");
    }

    #[test]
    fn la_resolucion_y_las_etiquetas_siguen_el_rango() {
        assert_eq!(formatear_resolucion(Range::Hours24), "puntos de 30 min");
        assert_eq!(formatear_resolucion(Range::Days7), "puntos de 3 h");
        assert_eq!(formatear_resolucion(Range::Days30), "por día");
        assert_eq!(formatear_resolucion(Range::Year1), "por semana");
        assert!(etiqueta_punto(1_760_000_000, Range::Hours24).contains(':'));
        assert!(!etiqueta_punto(1_760_000_000, Range::Days30).contains(':'));
        assert_eq!(formatear_pct(42.4), "42 %");
    }

    #[test]
    fn las_barras_dibujan_huecos_y_dejan_blanco_el_futuro() {
        let theme = Theme::new(true);
        let puntos = vec![
            BarraPunto {
                total: 100,
                hueco: false,
                futuro: false,
            },
            BarraPunto {
                total: 0,
                hueco: true,
                futuro: false,
            },
            BarraPunto {
                total: 50,
                hueco: false,
                futuro: true,
            },
        ];
        let lineas = barras(&puntos, 100, 3, 3, Some(0), &theme);
        assert_eq!(lineas.len(), 3);
        let dibujo = texto(&lineas);
        assert!(dibujo.contains('█'), "la barra se dibuja");
        assert!(dibujo.contains(HUECO), "el hueco se marca con ░");
        // La última columna (futuro) está en blanco en todas las filas.
        for linea in &lineas {
            assert_eq!(
                linea.spans.last().map(|span| span.content.as_ref()),
                Some(" ")
            );
        }
    }

    #[test]
    fn el_cursor_resalta_su_columna() {
        let theme = Theme::new(false);
        let puntos = vec![BarraPunto {
            total: 100,
            hueco: false,
            futuro: false,
        }];
        let lineas = barras(&puntos, 100, 2, 2, Some(0), &theme);
        for linea in &lineas {
            for span in &linea.spans {
                assert_eq!(span.style, theme.selected);
            }
        }
    }

    #[test]
    fn el_eje_de_fechas_cabe_en_el_ancho() {
        let theme = Theme::new(false);
        let serie = serie(48, Range::Hours24);
        let linea = eje_fechas(&serie, 76, &theme);
        let ancho: usize = linea
            .spans
            .iter()
            .map(|span| span.content.chars().count())
            .sum();
        assert_eq!(ancho, 76);
        assert!(texto(&[linea]).contains(':'));
    }

    #[test]
    fn la_fila_de_trafico_respeta_el_ancho_y_marca_huecos() {
        let theme = Theme::new(true);
        let serie = serie(48, Range::Hours24);
        let linea = fila_trafico(&serie, 40, &theme);
        let ancho: usize = linea
            .spans
            .iter()
            .map(|span| span.content.chars().count())
            .sum();
        assert_eq!(ancho, 40);
        assert!(texto(&[linea]).contains(HUECO));
    }

    #[test]
    fn la_presencia_distingue_presente_ausente_y_sin_datos() {
        let theme = Theme::new(true);
        let ahora = 1_760_000_000;
        let tramos = vec![
            PresenceSpan {
                start: ahora - 3600,
                end: ahora - 1800,
                state: PresenceState::Present,
            },
            PresenceSpan {
                start: ahora - 1800,
                end: ahora - 900,
                state: PresenceState::Absent,
            },
        ];
        let linea = fila_presencia(&tramos, Range::Hours24, ahora, 76, &theme);
        let dibujo = texto(&[linea]);
        assert!(dibujo.contains(PRESENTE));
        assert!(dibujo.contains(AUSENTE));
        assert!(dibujo.contains(HUECO));
    }

    #[test]
    fn la_rejilla_de_presencia_tiene_siete_dias_y_cabecera() {
        let theme = Theme::new(false);
        let ahora = 1_760_000_000;
        let tramos = vec![PresenceSpan {
            start: ahora - 7200,
            end: ahora,
            state: PresenceState::Present,
        }];
        let lineas = rejilla_presencia(&tramos, ahora, &theme);
        assert_eq!(lineas.len(), 8, "cabecera más siete días");
        let cabecera = texto(&lineas[..1]);
        assert!(cabecera.contains('0'));
        assert!(cabecera.contains("18"));
        let hoy = texto(&lineas[7..]);
        assert!(hoy.contains(PRESENTE), "la última fila es hoy");
    }

    #[test]
    fn el_estado_en_ventana_prioriza_presente() {
        let tramos = vec![
            PresenceSpan {
                start: 0,
                end: 100,
                state: PresenceState::Absent,
            },
            PresenceSpan {
                start: 50,
                end: 60,
                state: PresenceState::Present,
            },
        ];
        assert_eq!(
            estado_en_ventana(&tramos, 0, 100),
            Some(PresenceState::Present)
        );
        assert_eq!(
            estado_en_ventana(&tramos, 100, 200),
            None,
            "fuera de los tramos no hay dato"
        );
    }

    #[test]
    fn la_etiqueta_corta_del_dia_no_lleva_el_mes() {
        let etiqueta = etiqueta_dia_corto(1_760_000_000);
        assert_eq!(etiqueta.split_whitespace().count(), 2, "{etiqueta}");
    }
}
