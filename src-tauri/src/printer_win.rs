//! Impresión térmica vía la API nativa de Windows (winspool), llamada
//! DIRECTAMENTE desde Rust — sin `cmd.exe`, sin `Command::new("...")`, sin
//! interpolar texto del usuario en ninguna cadena que un shell interprete.
//!
//! Esto elimina POR COMPLETO la clase de vulnerabilidad de inyección de
//! comandos: no existe ningún punto del código donde bytes que vienen de la
//! red se conviertan en un comando de sistema operativo. Los bytes ESC/POS
//! que llegan por HTTP se pasan tal cual a `WritePrinter`, que solo escribe
//! datos crudos al spooler de impresión — no los ejecuta ni los interpreta.
//!
//! Este archivo también incluye impresión de HOJA COMPLETA (A4/Carta) para
//! impresoras normales (no térmicas) — vía GDI, el mismo mecanismo que usa
//! cualquier programa de Windows para imprimir un documento. A diferencia
//! del modo térmico (bytes ESC/POS crudos), aquí SÍ necesitamos que la
//! impresora tenga un controlador instalado en Windows — por eso, para
//! impresoras de red con papel A4/Carta, la recomendación es instalarlas en
//! Windows apuntando a su IP y seleccionarlas aquí por nombre, igual que una
//! impresora local.

use serde::Deserialize;

#[derive(Deserialize, Clone)]
// Auditoría, hallazgo M16 (versión liviana — el pipeline completo con
// OpenAPI/typify queda pendiente para cuando el proyecto lo justifique):
// sin esto, un campo que el frontend cambia de nombre o elimina llega acá y
// Serde simplemente lo ignora — así se perdió `local_ticket_number` en
// silencio (ver el campo más abajo). Con `deny_unknown_fields`, un
// contrato desalineado entre frontend y agente falla la deserialización
// (el handler de `/v1/print` en http_server.rs responde 422) en vez de
// imprimir una factura con datos faltantes sin que nadie se entere.
#[serde(deny_unknown_fields)]
pub struct InvoiceItem {
    pub name: String,
    pub quantity: f64,
    pub unit_price: f64,
}

/// Logo del negocio ya convertido a bitmap monocromo 1-bit-por-píxel por el
/// frontend (misma función `logoToMonochromeRaster` que arma el logo para
/// ESC/POS térmico y ePOS-Print XML — ver ticketFormat.js). Formato: fila
/// empacada a bytes SIN relleno extra (bytesPerRow = widthPx/8, exacto
/// porque widthPx ya es múltiplo de 8 del lado del navegador), bit=1 ->
/// negro, bit=0 -> blanco, MSB primero. El agente solo tiene que reempacar
/// cada fila al múltiplo de 4 bytes que exige un DIB de Windows — no vuelve
/// a decidir umbral de blanco/negro ni redimensiona la imagen origen.
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)] // M16: ver nota en InvoiceItem
pub struct LogoRaster {
    #[serde(rename = "widthPx")]
    pub width_px: u32,
    #[serde(rename = "heightPx")]
    pub height_px: u32,
    #[serde(rename = "dataBase64")]
    pub data_base64: String,
}

#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)] // M16: ver nota en InvoiceItem
pub struct InvoiceDoc {
    pub business_name: String,
    pub tax_id: Option<String>,
    pub business_address: Option<String>,
    pub business_phone: Option<String>,
    pub created_at: String,
    // El frontend YA manda este campo (ver buildInvoiceDoc en
    // ticketFormat.js) — faltaba acá, así que Serde lo descartaba en
    // silencio (por defecto ignora claves JSON sin campo que las reciba,
    // no da ningún error), y nunca llegaba a imprimirse.
    pub local_ticket_number: Option<String>,
    pub cashier_name: String,
    pub customer_name: Option<String>,
    pub doc_type: String,
    pub ncf: Option<String>,
    pub items: Vec<InvoiceItem>,
    // Auditoría, hallazgo M16 (contrato de impuestos, antes hallazgo A1):
    // estos tres campos vienen YA CALCULADOS por el backend
    // (invoice.service.js) siguiendo la MISMA convención que
    // buildInvoiceDoc() en ticketFormat.js usa para armar este mismo
    // objeto — el precio de cada línea (`InvoiceItem.unit_price`) es un
    // precio CON ITBIS INCLUIDO, y de ahí:
    //   tax_amount = precio_con_itbis - precio_con_itbis / (1 + tasa)
    //   subtotal   = precio_con_itbis - tax_amount   (base imponible)
    //   total      = subtotal + tax_amount - descuento
    // El agente NO recalcula nada de esto — solo imprime lo que ya viene
    // calculado. Si algún día esta convención cambia, hay que cambiarla a
    // la vez en los tres lugares que la mencionan (acá, invoice.service.js
    // y ticketFormat.js), porque hoy no hay un contrato único (OpenAPI)
    // que la fije en un solo lugar — ver hallazgo M16 en la auditoría.
    pub subtotal: f64,
    pub tax_amount: f64,
    pub discount_amount: f64,
    pub total: f64,
    pub payment_method: String,
    pub footer: Option<String>,
    // Ausente/null si el negocio no tiene logo configurado, o si el
    // navegador no pudo cargarlo — mismo criterio de "nunca bloquear la
    // venta" que ya rige en térmica/red (ver ticketFormat.js).
    pub logo: Option<LogoRaster>,
}

#[cfg(target_os = "windows")]
mod win {
    use super::InvoiceDoc;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Graphics::Printing::{
        ClosePrinter, EndDocPrinter, EndPagePrinter, EnumPrintersW, GetDefaultPrinterW,
        OpenPrinterW, StartDocPrinterW, StartPagePrinter, WritePrinter, DOC_INFO_1W,
        PRINTER_ENUM_LOCAL, PRINTER_ENUM_CONNECTIONS, PRINTER_INFO_2W,
    };

    /// Normaliza el resultado de una llamada Win32 que puede volver como
    /// `BOOL` crudo (convención clásica: 0 = falla) o como el
    /// `windows_core::Result<()>` con el que windows-rs envuelve algunas
    /// funciones automáticamente. Evita tener que adivinar cuál de las dos
    /// usa cada función específica — el código funciona igual con cualquiera.
    trait Win32Ok {
        fn succeeded(&self) -> bool;
    }
    impl Win32Ok for windows::Win32::Foundation::BOOL {
        fn succeeded(&self) -> bool {
            self.as_bool()
        }
    }
    impl Win32Ok for windows::core::Result<()> {
        fn succeeded(&self) -> bool {
            self.is_ok()
        }
    }

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// RAII para HANDLE de impresora (auditoría, hallazgo B3): antes cada
    /// función que abría una impresora tenía que acordarse de llamar
    /// ClosePrinter en TODOS sus caminos de salida a mano — si algo
    /// entraba en pánico entre OpenPrinterW y el ClosePrinter correspondiente
    /// (poco probable hoy, pero un cambio futuro que agregue una operación
    /// falible en el medio lo haría fácil), el handle quedaba filtrado.
    /// Con esto, se cierra solo al salir de scope pase lo que pase.
    struct PrinterHandleGuard(HANDLE);
    impl Drop for PrinterHandleGuard {
        fn drop(&mut self) {
            unsafe { let _ = ClosePrinter(self.0); }
        }
    }

    pub fn list_printers() -> Result<Vec<String>, String> {
        unsafe {
            // Auditoría B3: antes solo PRINTER_ENUM_LOCAL — una impresora de
            // red ya CONECTADA en Windows (no instalada localmente, sino
            // agregada como conexión de red) no aparecía en la lista. Se
            // combinan los dos flags, como recomienda la documentación de
            // Win32 para listar "todo lo que este usuario puede imprimir".
            let flags = PRINTER_ENUM_LOCAL | PRINTER_ENUM_CONNECTIONS;
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;
            // Primera llamada solo para saber cuántos bytes hacen falta
            // (firma real: 6 parámetros — sin argumento de tamaño aparte,
            // el largo va implícito en el slice de `pprinterenum`).
            let _ = EnumPrintersW(
                flags,
                PCWSTR::null(),
                2,
                None,
                &mut needed,
                &mut returned,
            );
            if needed == 0 {
                return Ok(vec![]);
            }
            // Alineación (auditoría B3): un Vec<u8> solo garantiza
            // alineación de 1 byte, pero PRINTER_INFO_2W (con punteros de
            // 8 bytes en Windows de 64 bits) necesita alineación de 8 —
            // leerlo de un buffer de bytes crudo es, técnicamente,
            // comportamiento indefinido, aunque en la práctica el
            // allocator casi siempre devuelva memoria ya alineada así.
            // Alojar como Vec<u64> (redondeando hacia arriba) fuerza la
            // alineación correcta, y se lo pasa a la API como puntero a
            // bytes igual — sigue escribiendo la misma cantidad de bytes.
            let words = needed.div_ceil(8) as usize;
            let mut buf: Vec<u64> = vec![0u64; words];
            let buf_bytes: &mut [u8] = std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, needed as usize);
            let ok = EnumPrintersW(
                flags,
                PCWSTR::null(),
                2,
                Some(buf_bytes),
                &mut needed,
                &mut returned,
            );
            if ok.is_err() {
                return Err("No se pudo enumerar las impresoras instaladas.".into());
            }
            let items = std::slice::from_raw_parts(
                buf.as_ptr() as *const PRINTER_INFO_2W,
                returned as usize,
            );
            let mut names = Vec::new();
            for item in items {
                if !item.pPrinterName.is_null() {
                    names.push(item.pPrinterName.to_string().unwrap_or_default());
                }
            }
            names.sort();
            names.dedup(); // una impresora local y su conexión de red podrían listarse dos veces
            Ok(names)
        }
    }

    pub fn default_printer() -> Option<String> {
        unsafe {
            let mut size: u32 = 0;
            // GetDefaultPrinterW toma PWSTR (no PCWSTR) y *mut u32 directo
            // (no Option) — confirmado por el propio mensaje del compilador
            // en el intento anterior. Devuelve BOOL crudo, no Result.
            GetDefaultPrinterW(PWSTR::null(), &mut size);
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u16; size as usize];
            let ok = GetDefaultPrinterW(PWSTR(buf.as_mut_ptr()), &mut size);
            if !ok.as_bool() {
                return None;
            }
            let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            Some(String::from_utf16_lossy(&buf[..end]))
        }
    }

    /// Envía bytes crudos (ESC/POS) directo al spooler, en modo RAW —
    /// tal cual llegaron por HTTP, sin pasar por ningún intérprete.
    pub fn print_raw(printer_name: &str, data: &[u8]) -> Result<(), String> {
        unsafe {
            let wide_name = to_wide(printer_name);
            let mut handle = HANDLE::default();
            OpenPrinterW(PCWSTR(wide_name.as_ptr()), &mut handle, None)
                .map_err(|e| format!("No se pudo abrir la impresora '{printer_name}': {e}"))?;
            // A partir de acá el handle se cierra SOLO al salir de scope,
            // sin importar por cuál `return`/pánico salga esta función —
            // ya no hace falta acordarse de ClosePrinter en cada camino.
            let _guard = PrinterHandleGuard(handle);

            let doc_name = to_wide("Ticket de venta");
            let datatype = to_wide("RAW");
            let doc_info = DOC_INFO_1W {
                pDocName: PWSTR(doc_name.as_ptr() as *mut u16),
                pOutputFile: PWSTR::null(),
                pDatatype: PWSTR(datatype.as_ptr() as *mut u16),
            };

            let job_id = StartDocPrinterW(handle, 1, &doc_info);
            if job_id == 0 {
                return Err("No se pudo iniciar el trabajo de impresión (StartDocPrinter).".into());
            }

            if !StartPagePrinter(handle).succeeded() {
                let _ = EndDocPrinter(handle);
                return Err("No se pudo iniciar la página de impresión.".into());
            }

            let mut written: u32 = 0;
            let write_ok = WritePrinter(handle, data.as_ptr() as _, data.len() as u32, &mut written);

            let _ = EndPagePrinter(handle);
            let _ = EndDocPrinter(handle);

            if !write_ok.succeeded() || (written as usize) != data.len() {
                return Err("Fallo al escribir los datos en el spooler de impresión.".into());
            }
            Ok(())
        }
    }

    /// Dibuja el logo (bitmap monocromo 1-bit ya armado por el navegador)
    /// dentro del contexto de impresión vía `StretchDIBits` — el mismo
    /// mecanismo GDI que usa cualquier programa de Windows para pintar una
    /// imagen, distinto del raster ESC/POS que ya usa el modo térmico.
    /// Devuelve el alto real (en píxeles del dispositivo) que ocupó, para
    /// que el llamador pueda avancer `y` después de dibujarlo.
    ///
    /// Nota de verificación: el resto de este archivo (imports de GDI,
    /// GetDeviceCaps con su newtype, StartDocW/EndDoc en Storage::Xps) tuvo
    /// varias rondas de CI hasta encontrar la firma exacta de windows-rs
    /// 0.58 — esta función se armó cruzando la documentación pública de esa
    /// misma versión (BITMAPINFOHEADER con biCompression: u32 plano, no un
    /// newtype; StretchDIBits con lpbits: Option<*const c_void>, iusage:
    /// DIB_USAGE, rop: ROP_CODE), pero **sin poder compilarla en este
    /// sandbox** (mismo límite de siempre: sin Rust real para Windows acá).
    /// Pendiente de confirmar en el próximo CI real, igual que el resto de
    /// GDI en este proyecto.
    fn draw_logo(
        hdc: windows::Win32::Graphics::Gdi::HDC,
        x: i32,
        y: i32,
        dest_w: i32,
        logo: &super::LogoRaster,
    ) -> Result<i32, String> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use windows::Win32::Graphics::Gdi::{
            StretchDIBits, BITMAPINFO, BITMAPINFOHEADER, DIB_RGB_COLORS, RGBQUAD, SRCCOPY,
        };

        let width = logo.width_px as usize;
        let height = logo.height_px as usize;
        if width == 0 || height == 0 {
            return Err("El logo llegó con dimensiones inválidas.".into());
        }

        let bits = STANDARD
            .decode(&logo.data_base64)
            .map_err(|_| "El logo llegó en base64 inválido.".to_string())?;

        // Formato de origen (armado por el navegador, ver LogoRaster): sin
        // relleno extra, exacto porque width ya es múltiplo de 8 ahí.
        let src_bytes_per_row = (width + 7) / 8;
        if bits.len() != src_bytes_per_row * height {
            return Err("El logo no coincide con las dimensiones declaradas.".into());
        }

        // Un DIB de Windows exige que cada fila termine en un múltiplo de 4
        // bytes (frontera DWORD) — distinto del empaquetado "sin relleno"
        // que usa ESC/POS, así que hay que reempacar fila por fila.
        let dib_bytes_per_row = ((width + 31) / 32) * 4;
        let mut dib_bits = vec![0u8; dib_bytes_per_row * height];
        for row in 0..height {
            let src_start = row * src_bytes_per_row;
            let dst_start = row * dib_bytes_per_row;
            dib_bits[dst_start..dst_start + src_bytes_per_row]
                .copy_from_slice(&bits[src_start..src_start + src_bytes_per_row]);
        }

        // BITMAPINFO real solo reserva 1 entrada de color en su struct C
        // (arreglo flexible) — necesitamos 2 (blanco/negro) para 1bpp, así
        // que se arma a mano el layout exacto que Windows espera leer en
        // memoria (header seguido de la paleta), y se pasa el puntero como
        // *const BITMAPINFO para calzar con la firma de la función.
        #[repr(C)]
        struct BitmapInfo1Bpp {
            header: BITMAPINFOHEADER,
            colors: [RGBQUAD; 2],
        }
        let bmi = BitmapInfo1Bpp {
            header: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width as i32,
                // Negativo = DIB top-down (origen arriba-izquierda) — así
                // no hace falta invertir las filas, ya vienen en ese orden
                // desde el canvas del navegador.
                biHeight: -(height as i32),
                biPlanes: 1,
                biBitCount: 1,
                biCompression: 0, // BI_RGB
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            colors: [
                RGBQUAD { rgbBlue: 255, rgbGreen: 255, rgbRed: 255, rgbReserved: 0 }, // índice 0 = blanco (bit 0)
                RGBQUAD { rgbBlue: 0, rgbGreen: 0, rgbRed: 0, rgbReserved: 0 },       // índice 1 = negro (bit 1)
            ],
        };

        let dest_h = ((height as f64) * (dest_w as f64) / (width as f64)).round() as i32;

        unsafe {
            let drawn = StretchDIBits(
                hdc,
                x,
                y,
                dest_w,
                dest_h,
                0,
                0,
                width as i32,
                height as i32,
                Some(dib_bits.as_ptr() as *const core::ffi::c_void),
                &bmi as *const BitmapInfo1Bpp as *const BITMAPINFO,
                DIB_RGB_COLORS,
                SRCCOPY,
            );
            if drawn <= 0 {
                return Err("No se pudo dibujar el logo (StretchDIBits).".into());
            }
        }
        Ok(dest_h)
    }

    /// Imprime una factura como HOJA COMPLETA (A4 o Carta) en una impresora
    /// normal instalada en Windows, dibujando el contenido vía GDI —
    /// exactamente el mismo mecanismo que usa cualquier programa de Windows
    /// para imprimir un documento (no son bytes ESC/POS).
    ///
    /// Deliberadamente usa la fuente POR DEFECTO del dispositivo (no crea
    /// una fuente personalizada) para mantener acotada la superficie de la
    /// API de Win32 usada aquí — el resultado es más simple visualmente que
    /// el diseño del navegador, pero confiable.
    ///
    /// Auditoría, hallazgo M6 (corregido): antes se calculaba el alto de
    /// página (`GetDeviceCaps(..., VERTRES)`) pero JAMÁS se comparaba contra
    /// nada — una sola `StartPage`/`EndPage` para toda la factura, así que
    /// una venta con muchas líneas se dibujaba fuera de la hoja física
    /// (truncada, sin totales ni pie). Ahora:
    ///   1. El encabezado (logo + datos del negocio + datos del comprobante)
    ///      se armó como closure (`draw_page_header`) para poder repetirlo
    ///      igual en cada página nueva.
    ///   2. `ensure_space` compara la posición actual contra el alto real de
    ///      la página (con margen inferior) antes de dibujar cada bloque; si
    ///      no alcanza, hace `EndPage`/`StartPage` y vuelve a dibujar el
    ///      encabezado antes de seguir.
    ///   3. El bloque final (Subtotal/ITBIS/Descuento/TOTAL/pago/pie) se
    ///      reserva como una unidad ANTES de dibujar el último renglón que
    ///      cupiera — así nunca queda un renglón de producto en una página y
    ///      el total solo en la siguiente, ni el pie cortado a la mitad.
    ///   4. Nombres de producto, dirección del negocio y pie de página pasan
    ///      por `wrap_text` (medido con `GetTextExtentPoint32W`, la misma
    ///      fuente por defecto que ya usa `draw`) — un nombre largo ahora
    ///      ocupa varias líneas en vez de salirse del ancho de la hoja.
    pub fn print_a4_document(printer_name: &str, paper_size: &str, invoice: &InvoiceDoc) -> Result<(), String> {
        use windows::Win32::Foundation::SIZE;
        use windows::Win32::Graphics::Gdi::{
            CreateDCW, DeleteDC, LineTo, MoveToEx, TextOutW, GetDeviceCaps, GetTextExtentPoint32W,
            GET_DEVICE_CAPS_INDEX, HDC,
        };
        // StartDocW/EndDoc/StartPage/EndPage/DOCINFOW viven en Storage::Xps
        // en esta versión del crate, no en Graphics::Gdi (confirmado por el
        // propio compilador — no es un error de shell/inyección, es solo
        // dónde windows-rs decidió categorizar estas funciones).
        use windows::Win32::Storage::Xps::{DOCINFOW, EndDoc, EndPage, StartDocW, StartPage};

        // Índices de GetDeviceCaps — constantes de wingdi.h, estables desde
        // Windows 3.1 (HORZRES=8, VERTRES=10, LOGPIXELSX=88, LOGPIXELSY=90).
        // Esta versión exige el newtype GET_DEVICE_CAPS_INDEX, no un i32 crudo.
        const HORZRES: GET_DEVICE_CAPS_INDEX = GET_DEVICE_CAPS_INDEX(8);
        const VERTRES: GET_DEVICE_CAPS_INDEX = GET_DEVICE_CAPS_INDEX(10);
        const LOGPIXELSX: GET_DEVICE_CAPS_INDEX = GET_DEVICE_CAPS_INDEX(88);
        const LOGPIXELSY: GET_DEVICE_CAPS_INDEX = GET_DEVICE_CAPS_INDEX(90);

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }
        let money = |n: f64| format!("RD$ {:.2}", n);

        unsafe {
            let device_name = to_wide(printer_name);
            // Para imprimir, GDI recomienda pasar NULL como driver; el nombre
            // del dispositivo es el que identifica la impresora instalada.
            let hdc = CreateDCW(PCWSTR::null(), PCWSTR(device_name.as_ptr()), PCWSTR::null(), None);
            if hdc.0.is_null() {
                return Err(format!("No se pudo crear el contexto de impresión para '{printer_name}'."));
            }

            let px_x = GetDeviceCaps(hdc, LOGPIXELSX) as f64 / 25.4; // píxeles por mm (horizontal)
            let px_y = GetDeviceCaps(hdc, LOGPIXELSY) as f64 / 25.4; // píxeles por mm (vertical)
            let page_w = GetDeviceCaps(hdc, HORZRES) as f64;
            // M6: antes `_page_h` (con guion bajo — Rust ya avisaba que no se
            // usaba en ningún lado). Ahora sí se usa, en `ensure_space`.
            let page_h = GetDeviceCaps(hdc, VERTRES) as f64;
            let _ = paper_size; // el tamaño real lo define la bandeja/config ya establecida en el driver de Windows

            let margin = 12.0 * px_x; // ~12mm de margen — se reutiliza como margen inferior también, igual que ya hacía el código original al usarlo como "y" inicial
            let line_h = 5.5 * px_y;  // alto de línea aproximado
            let col2 = page_w - margin - (55.0 * px_x); // columna derecha (montos)
            let content_width = page_w - margin * 2.0; // ancho disponible para texto (para word-wrap)

            let doc_name = to_wide("Factura");
            let doc_info = DOCINFOW {
                cbSize: std::mem::size_of::<DOCINFOW>() as i32,
                lpszDocName: PCWSTR(doc_name.as_ptr()),
                lpszOutput: PCWSTR::null(),
                lpszDatatype: PCWSTR::null(),
                fwType: 0,
            };

            if StartDocW(hdc, &doc_info) <= 0 {
                let _ = DeleteDC(hdc);
                return Err("No se pudo iniciar el trabajo de impresión (StartDoc).".into());
            }
            if StartPage(hdc) <= 0 {
                let _ = EndDoc(hdc);
                let _ = DeleteDC(hdc);
                return Err("No se pudo iniciar la página de impresión.".into());
            }

            let draw = |hdc: HDC, x: f64, y: f64, text: &str| {
                let wide = to_wide(text);
                let _ = TextOutW(hdc, x as i32, y as i32, &wide[..wide.len().saturating_sub(1)]);
            };
            let divider = |hdc: HDC, y: f64| {
                let mut prev = windows::Win32::Foundation::POINT::default();
                let _ = MoveToEx(hdc, margin as i32, y as i32, Some(&mut prev));
                let _ = LineTo(hdc, (page_w - margin) as i32, y as i32);
            };

            // M6, punto 8: ancho de texto real vía GetTextExtentPoint32W —
            // mismo criterio de medición que usa cualquier programa de
            // Windows, con la fuente por defecto ya seleccionada en el DC
            // (la misma que usa `draw`/TextOutW, no se cambia ninguna fuente
            // a propósito, ver comentario de la función).
            let measure_width = |hdc: HDC, text: &str| -> f64 {
                let wide = to_wide(text);
                let slice = &wide[..wide.len().saturating_sub(1)];
                let mut size = SIZE::default();
                if GetTextExtentPoint32W(hdc, slice, &mut size).as_bool() {
                    size.cx as f64
                } else {
                    0.0 // no se pudo medir: se sigue de largo sin envolver esa línea, no se aborta la impresión
                }
            };
            // Envuelve por palabra (sin cortar una palabra sola que ya
            // exceda el ancho — sería más código para un caso raro; una
            // palabra suelta larguísima simplemente se sale un poco, igual
            // que antes, pero deja de pasar con nombres de producto normales
            // como "Coca Cola botella retornable 2.5 litros...").
            let wrap_text = |hdc: HDC, text: &str, max_width: f64| -> Vec<String> {
                let mut lines: Vec<String> = Vec::new();
                let mut current = String::new();
                for word in text.split_whitespace() {
                    let candidate = if current.is_empty() { word.to_string() } else { format!("{current} {word}") };
                    if !current.is_empty() && measure_width(hdc, &candidate) > max_width {
                        lines.push(current);
                        current = word.to_string();
                    } else {
                        current = candidate;
                    }
                }
                if !current.is_empty() {
                    lines.push(current);
                }
                lines
            };

            // M6, puntos 6-7: encabezado extraído a closure para poder
            // repetirlo igual en cada página nueva — antes vivía mezclado
            // en medio de la función y solo se dibujaba una vez.
            let draw_page_header = |hdc: HDC, y: &mut f64| {
                // Logo (si el negocio tiene uno configurado) — bitmap ya
                // armado por el navegador. Un logo roto o que no dibuja
                // nunca debe bloquear la impresión (mismo criterio que
                // térmica/red).
                if let Some(logo) = &invoice.logo {
                    let logo_w = content_width * 0.35; // banner discreto, no domina la hoja
                    let logo_x = margin + (content_width - logo_w) / 2.0; // centrado
                    match draw_logo(hdc, logo_x as i32, *y as i32, logo_w as i32, logo) {
                        Ok(drawn_h) => *y += drawn_h as f64 + line_h * 0.5,
                        Err(_) => { /* logo roto: se sigue sin él, no se aborta la impresión */ }
                    }
                }

                draw(hdc, margin, *y, &invoice.business_name);
                *y += line_h;
                if let Some(t) = &invoice.tax_id { draw(hdc, margin, *y, &format!("RNC: {t}")); *y += line_h; }
                if let Some(a) = &invoice.business_address {
                    for line in wrap_text(hdc, a, content_width) { draw(hdc, margin, *y, &line); *y += line_h; }
                }
                if let Some(p) = &invoice.business_phone { draw(hdc, margin, *y, &format!("Tel: {p}")); *y += line_h; }
                *y += line_h * 0.4;
                divider(hdc, *y);
                *y += line_h;

                draw(hdc, margin, *y, &format!("Fecha: {}", invoice.created_at)); *y += line_h;
                if let Some(n) = &invoice.local_ticket_number { draw(hdc, margin, *y, n); *y += line_h; }
                draw(hdc, margin, *y, &format!("Atendido por: {}", invoice.cashier_name)); *y += line_h;
                if let Some(c) = &invoice.customer_name { draw(hdc, margin, *y, &format!("Cliente: {c}")); *y += line_h; }
                let doc_type_line = if invoice.doc_type == "fiscal" {
                    format!("NCF: {}", invoice.ncf.as_deref().unwrap_or("—"))
                } else {
                    "Ticket de venta (sin valor fiscal)".to_string()
                };
                draw(hdc, margin, *y, &doc_type_line);
                *y += line_h;
                divider(hdc, *y);
                *y += line_h * 1.2;
            };

            let mut y = margin;
            draw_page_header(hdc, &mut y);

            // M6, punto 6: garantiza que quepan `required` unidades de alto
            // antes de seguir dibujando — si no, cierra la página actual,
            // abre una nueva y vuelve a dibujar el encabezado antes de
            // continuar. `margin` hace de margen inferior también, igual
            // que ya lo usaba el código original como margen superior/`y`
            // inicial.
            let ensure_space = |hdc: HDC, y: &mut f64, required: f64| -> Result<(), String> {
                if *y + required > page_h - margin {
                    if EndPage(hdc) <= 0 {
                        return Err("No se pudo cerrar la página para pasar a la siguiente.".into());
                    }
                    if StartPage(hdc) <= 0 {
                        return Err("No se pudo iniciar una nueva página.".into());
                    }
                    *y = margin;
                    draw_page_header(hdc, y);
                }
                Ok(())
            };

            for item in &invoice.items {
                let name_lines = wrap_text(hdc, &item.name, content_width);
                let name_line_count = name_lines.len().max(1) as f64;
                // Alto que ocupa ESTE renglón completo (nombre, tal vez en
                // varias líneas, + la línea de cantidad/precio) — se mide
                // ANTES de dibujar nada, para poder decidir si hace falta
                // saltar de página primero.
                let item_h = line_h * name_line_count + line_h * 1.1;
                ensure_space(hdc, &mut y, item_h)?;

                if name_lines.is_empty() {
                    draw(hdc, margin, y, &item.name);
                    y += line_h;
                } else {
                    for line in &name_lines {
                        draw(hdc, margin, y, line);
                        y += line_h;
                    }
                }
                let qty_line = format!("  {} x {}", item.quantity, money(item.unit_price));
                draw(hdc, margin, y, &qty_line);
                draw(hdc, col2, y, &money(item.quantity * item.unit_price));
                y += line_h * 1.1;
            }

            // M6, punto 6 (la parte que evita el caso peor): el bloque final
            // se reserva COMPLETO de una vez — divisor + subtotal + ITBIS +
            // (descuento) + TOTAL + método de pago + pie — antes de dibujar
            // el primer renglón de esta sección. Así nunca queda el TOTAL
            // solo en una página nueva mientras el último producto quedó en
            // la anterior.
            let footer_lines = invoice.footer.as_deref()
                .map(|f| wrap_text(hdc, f, content_width))
                .unwrap_or_default();
            let footer_reserved =
                line_h                                                    // divisor
                + line_h * 2.0                                            // Subtotal + ITBIS
                + if invoice.discount_amount > 0.0 { line_h } else { 0.0 } // Descuento (si aplica)
                + line_h * 1.3                                            // TOTAL
                + line_h * 1.5                                            // Método de pago
                + line_h * footer_lines.len() as f64;                     // pie (si lo hay)
            ensure_space(hdc, &mut y, footer_reserved)?;

            divider(hdc, y);
            y += line_h;
            draw(hdc, margin, y, "Subtotal"); draw(hdc, col2, y, &money(invoice.subtotal)); y += line_h;
            draw(hdc, margin, y, "ITBIS"); draw(hdc, col2, y, &money(invoice.tax_amount)); y += line_h;
            if invoice.discount_amount > 0.0 {
                draw(hdc, margin, y, "Descuento"); draw(hdc, col2, y, &format!("-{}", money(invoice.discount_amount))); y += line_h;
            }
            draw(hdc, margin, y, "TOTAL"); draw(hdc, col2, y, &money(invoice.total)); y += line_h * 1.3;
            draw(hdc, margin, y, &format!("Método de pago: {}", invoice.payment_method));
            y += line_h * 1.5;

            for line in &footer_lines {
                draw(hdc, margin, y, line);
                y += line_h;
            }

            let _ = EndPage(hdc);
            let _ = EndDoc(hdc);
            let _ = DeleteDC(hdc);
            Ok(())
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod win {
    use super::InvoiceDoc;
    // El agente distribuido es para Windows (el sistema operativo del 100%
    // de los POS objetivo). En otras plataformas, estas funciones existen
    // solo para que el proyecto compile durante desarrollo/pruebas.
    pub fn list_printers() -> Result<Vec<String>, String> {
        Err("La impresión nativa solo está implementada para Windows.".into())
    }
    pub fn default_printer() -> Option<String> {
        None
    }
    pub fn print_raw(_printer_name: &str, _data: &[u8]) -> Result<(), String> {
        Err("La impresión nativa solo está implementada para Windows.".into())
    }
    pub fn print_a4_document(_printer_name: &str, _paper_size: &str, _invoice: &InvoiceDoc) -> Result<(), String> {
        Err("La impresión nativa solo está implementada para Windows.".into())
    }
}

pub use win::{default_printer, list_printers, print_a4_document, print_raw};
