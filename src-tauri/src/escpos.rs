//! Utilidades ESC/POS de SOLO LECTURA/filtrado sobre los bytes que llegan de
//! la web — sin tocar ninguna API del sistema, así que se prueba en
//! cualquier plataforma.
//!
//! Para qué sirve (ronda 10b):
//!   * `count_drawer_pulses`: detectar si el ticket trae el comando de
//!     apertura de gaveta, para dejar constancia en `gaveta.jsonl` (quién
//!     abrió la gaveta y cuándo — antes no quedaba ningún rastro).
//!   * `strip_drawer_pulses`: un ticket que se reintenta desde la cola horas
//!     después NO debe abrir la gaveta "solo", a destiempo.
//!   * `DrawerLog`: el archivo de eventos que la web sincroniza al backend
//!     (auditoría `drawer.open`).
//!
//! OJO con los falsos positivos: dentro de un bloque raster de imagen (el
//! logo, `GS v 0`) pueden aparecer por casualidad los bytes `1B 70 ..`. Por
//! eso el escáner SALTA los bloques de datos binarios conocidos en vez de
//! buscar el patrón a ciegas sobre todo el buffer.

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Recorre el buffer y devuelve las posiciones (offset, longitud) de cada
/// comando de apertura de gaveta encontrado fuera de bloques binarios.
fn find_pulses(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let n = data.len();
    let mut i = 0usize;
    while i < n {
        let b = data[i];
        // GS v 0 m xL xH yL yH d1..dk  (imagen raster)
        if b == 0x1D && i + 7 < n && data[i + 1] == 0x76 && data[i + 2] == 0x30 {
            let xl = data[i + 4] as usize;
            let xh = data[i + 5] as usize;
            let yl = data[i + 6] as usize;
            let yh = data[i + 7] as usize;
            let k = (xl + xh * 256).saturating_mul(yl + yh * 256);
            i = i.saturating_add(8).saturating_add(k);
            continue;
        }
        // ESC * m nL nH d1..dk  (imagen en columnas)
        if b == 0x1B && i + 4 < n && data[i + 1] == 0x2A {
            let m = data[i + 2];
            let cols = data[i + 3] as usize + data[i + 4] as usize * 256;
            let bytes_per_col = if m == 32 || m == 33 { 3 } else { 1 };
            i = i.saturating_add(5).saturating_add(cols.saturating_mul(bytes_per_col));
            continue;
        }
        // GS ( L pL pH ...  y  GS 8 L p1 p2 p3 p4 ... (gráficos con longitud explícita)
        if b == 0x1D && i + 4 < n && data[i + 1] == 0x28 && data[i + 2] == 0x4C {
            let len = data[i + 3] as usize + data[i + 4] as usize * 256;
            i = i.saturating_add(5).saturating_add(len);
            continue;
        }
        if b == 0x1D && i + 6 < n && data[i + 1] == 0x38 && data[i + 2] == 0x4C {
            let len = data[i + 3] as usize
                | (data[i + 4] as usize) << 8
                | (data[i + 5] as usize) << 16
                | (data[i + 6] as usize) << 24;
            i = i.saturating_add(7).saturating_add(len);
            continue;
        }
        // ESC p m t1 t2  (pulso de gaveta). m = 0/1 (o '0'/'1' en ASCII).
        if b == 0x1B && i + 4 < n && data[i + 1] == 0x70 && matches!(data[i + 2], 0 | 1 | 0x30 | 0x31) {
            out.push((i, 5));
            i += 5;
            continue;
        }
        // DLE DC4 fn=1 m t  (pulso en tiempo real)
        if b == 0x10 && i + 4 < n && data[i + 1] == 0x14 && data[i + 2] == 0x01 && matches!(data[i + 3], 0 | 1) {
            out.push((i, 5));
            i += 5;
            continue;
        }
        i += 1;
    }
    out
}

pub fn count_drawer_pulses(data: &[u8]) -> usize {
    find_pulses(data).len()
}

/// Copia del buffer SIN los comandos de apertura de gaveta.
pub fn strip_drawer_pulses(data: &[u8]) -> Vec<u8> {
    let pulses = find_pulses(data);
    if pulses.is_empty() {
        return data.to_vec();
    }
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0usize;
    for (off, len) in pulses {
        out.extend_from_slice(&data[pos..off]);
        pos = off + len;
    }
    out.extend_from_slice(&data[pos..]);
    out
}

// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DrawerEvent {
    /// Segundos Unix.
    pub ts: u64,
    #[serde(rename = "jobId")]
    pub job_id: Option<String>,
    pub printer: String,
    pub pulses: usize,
}

const LOG_FILE: &str = "gaveta.jsonl";
const MAX_BYTES: u64 = 1_000_000;
const KEEP_LINES: usize = 2000;

pub struct DrawerLog;

impl DrawerLog {
    fn path(dir: &Path) -> PathBuf {
        dir.join(LOG_FILE)
    }

    pub fn append(dir: &Path, ev: &DrawerEvent) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir);
        // Rotación barata: si pasa de ~1 MB se conservan solo las últimas líneas.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > MAX_BYTES {
                if let Ok(raw) = std::fs::read_to_string(&path) {
                    let lines: Vec<&str> = raw.lines().collect();
                    let from = lines.len().saturating_sub(KEEP_LINES);
                    let _ = std::fs::write(&path, lines[from..].join("\n") + "\n");
                }
            }
        }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let line = serde_json::to_string(ev).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        writeln!(f, "{line}")
    }

    /// Eventos con `ts > since`, del más viejo al más nuevo, máximo `limit`.
    /// Líneas dañadas se ignoran (un corte de luz a mitad de escritura no
    /// debe invalidar el resto del archivo).
    pub fn read_since(dir: &Path, since: u64, limit: usize) -> Vec<DrawerEvent> {
        let Ok(raw) = std::fs::read_to_string(Self::path(dir)) else { return Vec::new() };
        raw.lines()
            .filter_map(|l| serde_json::from_str::<DrawerEvent>(l).ok())
            .filter(|e| e.ts > since)
            .take(limit)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detecta_esc_p() {
        let mut d = b"HOLA\n".to_vec();
        d.extend_from_slice(&[0x1B, 0x70, 0x00, 0x19, 0xFA]);
        d.extend_from_slice(b"FIN");
        assert_eq!(count_drawer_pulses(&d), 1);
    }

    #[test]
    fn detecta_ascii_y_dle_dc4() {
        assert_eq!(count_drawer_pulses(&[0x1B, 0x70, 0x30, 0x32, 0x32, 0x0A]), 1);
        assert_eq!(count_drawer_pulses(&[0x10, 0x14, 0x01, 0x00, 0x02, 0x0A]), 1);
    }

    #[test]
    fn dos_pulsos() {
        let d = [0x1B, 0x70, 0, 25, 250, 0x1B, 0x70, 1, 25, 250, 0x0A];
        assert_eq!(count_drawer_pulses(&d), 2);
    }

    #[test]
    fn sin_pulso() {
        assert_eq!(count_drawer_pulses(b"Factura 123\n"), 0);
        assert_eq!(count_drawer_pulses(&[]), 0);
        // ESC p con m inválido no es pulso
        assert_eq!(count_drawer_pulses(&[0x1B, 0x70, 0x07, 1, 1, 0x0A]), 0);
    }

    #[test]
    fn no_confunde_bytes_dentro_de_raster() {
        // GS v 0 m xL=2 xH=0 yL=2 yH=0 -> 4 bytes de datos que casualmente son ESC p 0 x
        let mut d = vec![0x1D, 0x76, 0x30, 0, 2, 0, 2, 0];
        d.extend_from_slice(&[0x1B, 0x70, 0x00, 0x19]);
        d.extend_from_slice(b"fin");
        assert_eq!(count_drawer_pulses(&d), 0);
        // y un pulso REAL después del raster sí cuenta
        d.extend_from_slice(&[0x1B, 0x70, 0x00, 0x19, 0xFA]);
        assert_eq!(count_drawer_pulses(&d), 1);
    }

    #[test]
    fn no_confunde_bytes_dentro_de_esc_asterisco() {
        // ESC * 0 nL=3 nH=0 + 3 bytes de datos (1B 70 00)
        let d = [0x1B, 0x2A, 0, 3, 0, 0x1B, 0x70, 0x00, 0x0A, 0x0A];
        assert_eq!(count_drawer_pulses(&d), 0);
    }

    #[test]
    fn raster_truncado_no_revienta() {
        // Longitud declarada mayor que el buffer: no debe entrar en pánico.
        let d = [0x1D, 0x76, 0x30, 0, 0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3];
        assert_eq!(count_drawer_pulses(&d), 0);
        assert_eq!(strip_drawer_pulses(&d), d.to_vec());
    }

    #[test]
    fn strip_quita_solo_el_pulso() {
        let mut d = b"A".to_vec();
        d.extend_from_slice(&[0x1B, 0x70, 0, 25, 250]);
        d.extend_from_slice(b"B");
        d.extend_from_slice(&[0x1D, 0x76, 0x30, 0, 1, 0, 1, 0, 0x1B, 0x70, 0x00, 0x19]); // raster 1 byte? (xL=1,yL=1 -> 1 byte) + resto
        let out = strip_drawer_pulses(&d);
        assert!(out.starts_with(b"AB"));
        assert_eq!(count_drawer_pulses(&out), 0);
        assert_eq!(out.len(), d.len() - 5);
    }

    #[test]
    fn log_append_read_y_since() {
        let dir = std::env::temp_dir().join(format!("gav-{}-{}", std::process::id(), line!()));
        let _ = std::fs::remove_dir_all(&dir);
        for (i, ts) in [100u64, 200, 300].iter().enumerate() {
            DrawerLog::append(&dir, &DrawerEvent { ts: *ts, job_id: Some(format!("j{i}")), printer: "P".into(), pulses: 1 }).unwrap();
        }
        assert_eq!(DrawerLog::read_since(&dir, 0, 10).len(), 3);
        let r = DrawerLog::read_since(&dir, 100, 10);
        assert_eq!(r.iter().map(|e| e.ts).collect::<Vec<_>>(), vec![200, 300]);
        assert_eq!(DrawerLog::read_since(&dir, 0, 2).len(), 2);
        // línea dañada intercalada: se ignora
        std::fs::OpenOptions::new().append(true).open(dir.join("gaveta.jsonl")).unwrap().write_all(b"{roto\n").unwrap();
        assert_eq!(DrawerLog::read_since(&dir, 0, 10).len(), 3);
        assert!(DrawerLog::read_since(&dir.join("nada"), 0, 10).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
