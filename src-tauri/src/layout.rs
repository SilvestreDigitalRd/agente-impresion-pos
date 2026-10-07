//! Cálculo (puro, sin Win32) del tamaño del logo en la hoja A4/Carta.
//!
//! Antes el ancho del logo era fijo (35 % del ancho útil) y el alto salía de
//! la proporción — un logo cuadrado o vertical podía medir 60 mm+ de alto,
//! empujando el encabezado y, en impresoras con área imprimible chica, saliéndose
//! de la hoja ("logo cortado"). Además un escalado no entero de un bitmap 1-bit
//! pierde píxeles finos (líneas del logo desaparecen).
//!
//! Reglas ahora:
//!   * Alto máximo `max_h` y ancho máximo `max_w` (en píxeles del dispositivo).
//!   * Se conserva la proporción.
//!   * Si el logo hay que AMPLIARLO se usa el mayor múltiplo ENTERO que quepa
//!     (sin interpolación = bordes nítidos); si hay que REDUCIRLO, se reduce
//!     lo mínimo necesario para caber.
//!   * Nunca devuelve 0 de ancho/alto ni algo mayor a los máximos.

/// Devuelve `(ancho, alto)` destino en píxeles, o `None` si la entrada es inválida.
pub fn logo_dest_size(src_w: u32, src_h: u32, max_w: i32, max_h: i32) -> Option<(i32, i32)> {
    if src_w == 0 || src_h == 0 || max_w <= 0 || max_h <= 0 {
        return None;
    }
    let (sw, sh) = (src_w as f64, src_h as f64);
    // Factor máximo que cabe en ambos límites.
    let fit = (max_w as f64 / sw).min(max_h as f64 / sh);
    let scale = if fit >= 1.0 {
        fit.floor().max(1.0) // ampliación entera
    } else {
        fit // reducción mínima necesaria
    };
    let mut w = (sw * scale).round() as i32;
    let mut h = (sh * scale).round() as i32;
    // Redondeo nunca debe pasarse de los límites ni caer a 0.
    w = w.clamp(1, max_w);
    h = h.clamp(1, max_h);
    Some((w, h))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalidos() {
        assert_eq!(logo_dest_size(0, 10, 100, 100), None);
        assert_eq!(logo_dest_size(10, 0, 100, 100), None);
        assert_eq!(logo_dest_size(10, 10, 0, 100), None);
        assert_eq!(logo_dest_size(10, 10, 100, -1), None);
    }

    #[test]
    fn banner_ancho_se_limita_por_ancho() {
        // 384x96 en 1000x300 -> fit=min(2.6,3.1)=2.6 -> x2 -> 768x192
        assert_eq!(logo_dest_size(384, 96, 1000, 300), Some((768, 192)));
    }

    #[test]
    fn logo_cuadrado_se_limita_por_alto() {
        // 200x200 en 800x240 -> fit=min(4,1.2)=1.2 -> x1 (entero) -> 200x200
        assert_eq!(logo_dest_size(200, 200, 800, 240), Some((200, 200)));
    }

    #[test]
    fn reduccion_cuando_no_cabe() {
        // 1000x500 en 400x400 -> fit=0.4 -> 400x200
        assert_eq!(logo_dest_size(1000, 500, 400, 400), Some((400, 200)));
    }

    #[test]
    fn nunca_excede_limites_ni_cero() {
        for (sw, sh, mw, mh) in [(7u32, 3u32, 50, 50), (1, 1000, 100, 100), (1000, 1, 100, 100), (13, 29, 31, 37), (3000, 2000, 99, 61)] {
            let (w, h) = logo_dest_size(sw, sh, mw, mh).unwrap();
            assert!(w >= 1 && h >= 1 && w <= mw && h <= mh, "{sw}x{sh} en {mw}x{mh} -> {w}x{h}");
        }
    }

    #[test]
    fn conserva_proporcion_aprox() {
        let (w, h) = logo_dest_size(300, 120, 700, 500).unwrap();
        let r_src = 300.0 / 120.0;
        let r_dst = w as f64 / h as f64;
        assert!((r_src - r_dst).abs() < 0.02);
    }
}
