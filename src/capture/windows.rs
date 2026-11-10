//! Ventanas deslizantes en memoria de longitud fija para los sparklines.
//!
//! Cada ventana es un anillo de 60 buckets: uno por segundo en la ventana de
//! 60 s y uno cada 5 s en la de 5 min. Los datos se agregan en el bucket que
//! corresponde al instante del paquete ([Instant] monótono) y la ventana avanza
//! con [Windows::advance] rellenando con ceros los huecos.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Número de puntos de la ventana de 60 s (1 punto por segundo).
pub const LEN_60S: usize = 60;
/// Número de puntos de la ventana de 5 min (1 punto cada 5 s).
pub const LEN_5MIN: usize = 60;
/// Periodo de un punto de la ventana de 60 s.
pub const BUCKET_60S: Duration = Duration::from_secs(1);
/// Periodo de un punto de la ventana de 5 min.
pub const BUCKET_5MIN: Duration = Duration::from_secs(5);

/// Anillo de buckets de longitud fija para una serie temporal en memoria.
///
/// Los buckets se indexan por `(ts - origin) / period`: el bucket más reciente
/// se empuja por la derecha y el más antiguo se descarta por la izquierda. La
/// ventana arranca a cero (sparklines vacíos hasta el primer paquete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Windows {
    /// Instante que corresponde al bucket 0.
    origin: Instant,
    /// Duración de cada bucket (1 s o 5 s).
    period: Duration,
    /// Buckets de más antiguo (frente) a más reciente (fondo); siempre 60.
    buckets: VecDeque<u64>,
    /// Índice absoluto del bucket más reciente.
    last_index: u64,
}

impl Windows {
    /// Ventana de 60 s: 60 puntos, uno por segundo.
    pub fn new_60s(origin: Instant) -> Self {
        Self::nueva(origin, BUCKET_60S, LEN_60S)
    }

    /// Ventana de 5 min: 60 puntos, uno cada 5 s.
    pub fn new_5min(origin: Instant) -> Self {
        Self::nueva(origin, BUCKET_5MIN, LEN_5MIN)
    }

    fn nueva(origin: Instant, period: Duration, len: usize) -> Self {
        let mut buckets = VecDeque::with_capacity(len);
        buckets.resize(len, 0);
        Self {
            origin,
            period,
            buckets,
            last_index: 0,
        }
    }

    /// Índice absoluto del bucket que contiene `ts`.
    ///
    /// Los instantes anteriores al origen se asignan al bucket actual (0): no
    /// pueden retroceder la ventana y tampoco deben perderse.
    fn indice(&self, ts: Instant) -> u64 {
        match ts.checked_duration_since(self.origin) {
            Some(transcurrido) => {
                let periodos = transcurrido.as_nanos() / self.period.as_nanos();
                u64::try_from(periodos).unwrap_or(u64::MAX)
            }
            None => 0,
        }
    }

    /// Suma `bytes` al bucket que corresponde a `ts`.
    ///
    /// Si `ts` cae en un bucket futuro, la ventana avanza antes de sumar. Si cae
    /// en un bucket que ya salió de la ventana, el dato se descarta.
    pub fn push(&mut self, ts: Instant, bytes: u64) {
        let indice = self.indice(ts);
        if indice > self.last_index {
            self.avanzar_hasta(indice);
        }
        let atraso = self.last_index.saturating_sub(indice);
        if atraso >= self.buckets.len() as u64 {
            return;
        }
        let posicion = self.buckets.len() - 1 - atraso as usize;
        if let Some(bucket) = self.buckets.get_mut(posicion) {
            *bucket = bucket.saturating_add(bytes);
        }
    }

    /// Avanza la ventana hasta `now`, rellenando con ceros los buckets nuevos.
    ///
    /// Nunca retrocede: un `now` anterior al último bucket no cambia nada.
    pub fn advance(&mut self, now: Instant) {
        let indice = self.indice(now);
        if indice > self.last_index {
            self.avanzar_hasta(indice);
        }
    }

    /// Desplaza el anillo `indice - last_index` buckets como máximo (el anillo
    /// completo si el hueco es mayor que la ventana).
    fn avanzar_hasta(&mut self, indice: u64) {
        let saltos = indice
            .saturating_sub(self.last_index)
            .min(self.buckets.len() as u64) as usize;
        for _ in 0..saltos {
            self.buckets.pop_front();
            self.buckets.push_back(0);
        }
        self.last_index = indice;
    }

    /// Serie de 60 puntos de la ventana de 60 s (más antiguo a más reciente).
    pub fn series_60s(&self) -> [u64; LEN_60S] {
        std::array::from_fn(|i| self.buckets.get(i).copied().unwrap_or(0))
    }

    /// Serie de 60 puntos de la ventana de 5 min (más antiguo a más reciente).
    pub fn series_5min(&self) -> [u64; LEN_5MIN] {
        std::array::from_fn(|i| self.buckets.get(i).copied().unwrap_or(0))
    }

    /// Suma de los 60 buckets de la ventana.
    pub fn total(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |acumulado, valor| acumulado.saturating_add(*valor))
    }

    /// Valor del bucket más reciente (último segundo o últimos 5 s).
    pub fn last(&self) -> u64 {
        self.buckets.back().copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origen() -> Instant {
        Instant::now()
    }

    #[test]
    fn arranca_a_cero_hasta_el_primer_paquete() {
        let origen = origen();
        let ventana = Windows::new_60s(origen);
        assert_eq!(ventana.series_60s(), [0u64; LEN_60S]);
        assert_eq!(ventana.total(), 0);
        assert_eq!(ventana.last(), 0);
    }

    #[test]
    fn push_suma_al_bucket_actual() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, 120);
        ventana.push(origen, 30);
        assert_eq!(ventana.last(), 150);
        assert_eq!(ventana.total(), 150);
    }

    #[test]
    fn push_ordena_los_buckets_del_mas_antiguo_al_mas_reciente() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, 10);
        ventana.push(origen + Duration::from_secs(1), 20);
        ventana.push(origen + Duration::from_secs(2), 30);
        let serie = ventana.series_60s();
        assert_eq!(serie[LEN_60S - 3], 10);
        assert_eq!(serie[LEN_60S - 2], 20);
        assert_eq!(serie[LEN_60S - 1], 30);
        assert_eq!(serie[..LEN_60S - 3], [0u64; LEN_60S - 3]);
    }

    #[test]
    fn advance_rellena_los_huecos_con_ceros() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, 100);
        ventana.advance(origen + Duration::from_secs(3));
        let serie = ventana.series_60s();
        assert_eq!(serie[LEN_60S - 4], 100);
        assert_eq!(serie[LEN_60S - 3], 0);
        assert_eq!(serie[LEN_60S - 2], 0);
        assert_eq!(serie[LEN_60S - 1], 0);
        assert_eq!(ventana.last(), 0);
        assert_eq!(ventana.total(), 100);
    }

    #[test]
    fn advance_nunca_retrocede_la_ventana() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.advance(origen + Duration::from_secs(5));
        ventana.push(origen + Duration::from_secs(5), 42);
        ventana.advance(origen + Duration::from_secs(2));
        assert_eq!(ventana.last(), 42);
        assert_eq!(ventana.total(), 42);
    }

    #[test]
    fn el_dato_sale_de_la_ventana_al_pasar_60_segundos() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, 77);
        // A los 59 s el dato sigue dentro (bucket más antiguo).
        ventana.advance(origen + Duration::from_secs(59));
        assert_eq!(ventana.series_60s()[0], 77);
        assert_eq!(ventana.total(), 77);
        // A los 60 s ya ha salido de la ventana.
        ventana.advance(origen + Duration::from_secs(60));
        assert_eq!(ventana.total(), 0);
    }

    #[test]
    fn la_ventana_de_5min_agrupa_en_buckets_de_5_segundos() {
        let origen = origen();
        let mut ventana = Windows::new_5min(origen);
        ventana.push(origen, 10);
        ventana.push(origen + Duration::from_secs(4), 5);
        ventana.push(origen + Duration::from_secs(5), 20);
        let serie = ventana.series_5min();
        assert_eq!(serie[LEN_5MIN - 2], 15);
        assert_eq!(serie[LEN_5MIN - 1], 20);
        assert_eq!(ventana.total(), 35);
    }

    #[test]
    fn un_hueco_mayor_que_la_ventana_la_deja_a_cero() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, 99);
        ventana.advance(origen + Duration::from_secs(10_000));
        assert_eq!(ventana.total(), 0);
        assert_eq!(ventana.series_60s(), [0u64; LEN_60S]);
    }

    #[test]
    fn un_push_anterior_al_origen_va_al_bucket_actual() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        // Instant es monótono: solo se puede simular un instante anterior al
        // origen si el origen se fija en el futuro.
        let futuro = Instant::now() + Duration::from_secs(10);
        let mut ventana_futura = Windows::new_60s(futuro);
        ventana_futura.push(Instant::now(), 33);
        assert_eq!(ventana_futura.last(), 33);
        // Y la ventana normal ignora el dato, pero no paniquea.
        ventana.push(
            origen.checked_sub(Duration::from_secs(1)).unwrap_or(origen),
            1,
        );
        assert_eq!(ventana.total(), 1);
    }

    #[test]
    fn push_y_advance_coinciden_en_el_mismo_bucket() {
        let origen = origen();
        let mut por_push = Windows::new_60s(origen);
        let mut por_advance = Windows::new_60s(origen);
        por_push.push(origen + Duration::from_secs(7), 40);
        por_advance.advance(origen + Duration::from_secs(7));
        por_advance.push(origen + Duration::from_secs(7), 40);
        assert_eq!(por_push.series_60s(), por_advance.series_60s());
        assert_eq!(por_push.last(), 40);
    }

    #[test]
    fn la_suma_satura_en_vez_de_desbordar() {
        let origen = origen();
        let mut ventana = Windows::new_60s(origen);
        ventana.push(origen, u64::MAX);
        ventana.push(origen, 10);
        assert_eq!(ventana.last(), u64::MAX);
        assert_eq!(ventana.total(), u64::MAX);
    }
}
