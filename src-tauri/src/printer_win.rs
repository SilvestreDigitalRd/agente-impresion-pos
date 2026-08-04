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
pub struct InvoiceItem {
    pub name: String,
    pub quantity: f64,
    pub unit_price: f64,
}

#[derive(Deserialize, Clone)]
pub struct InvoiceDoc {
    pub business_name: String,
    pub tax_id: Option<String>,
    pub business_address: Option<String>,
    pub business_phone: Option<String>,
    pub created_at: String,
    pub cashier_name: String,
    pub customer_name: Option<String>,
    pub doc_type: String,
    pub ncf: Option<String>,
    pub items: Vec<InvoiceItem>,
    pub subtotal: f64,
    pub tax_amount: f64,
    pub discount_amount: f64,
    pub total: f64,
    pub payment_method: String,
    pub footer: Option<String>,
}

#[cfg(target_os = "windows")]
mod win {
    use super::InvoiceDoc;
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Graphics::Printing::{
        ClosePrinter, EndDocPrinter, EndPagePrinter, EnumPrintersW, GetDefaultPrinterW,
        OpenPrinterW, StartDocPrinterW, StartPagePrinter, WritePrinter, DOC_INFO_1W,
        PRINTER_ENUM_LOCAL, PRINTER_INFO_2W,
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

    pub fn list_printers() -> Result<Vec<String>, String> {
        unsafe {
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;
            // Primera llamada solo para saber cuántos bytes hacen falta
            // (firma real: 6 parámetros — sin argumento de tamaño aparte,
            // el largo va implícito en el slice de `pprinterenum`).
            let _ = EnumPrintersW(
                PRINTER_ENUM_LOCAL,
                PCWSTR::null(),
                2,
                None,
                &mut needed,
                &mut returned,
            );
            if needed == 0 {
                return Ok(vec![]);
            }
            let mut buf = vec![0u8; needed as usize];
            let ok = EnumPrintersW(
                PRINTER_ENUM_LOCAL,
                PCWSTR::null(),
                2,
                Some(&mut buf),
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

            let doc_name = to_wide("Ticket de venta");
            let datatype = to_wide("RAW");
            let doc_info = DOC_INFO_1W {
                pDocName: PWSTR(doc_name.as_ptr() as *mut u16),
                pOutputFile: PWSTR::null(),
                pDatatype: PWSTR(datatype.as_ptr() as *mut u16),
            };

            let job_id = StartDocPrinterW(handle, 1, &doc_info);
            if job_id == 0 {
                let _ = ClosePrinter(handle);
                return Err("No se pudo iniciar el trabajo de impresión (StartDocPrinter).".into());
            }

            if !StartPagePrinter(handle).succeeded() {
                let _ = EndDocPrinter(handle);
                let _ = ClosePrinter(handle);
                return Err("No se pudo iniciar la página de impresión.".into());
            }

            let mut written: u32 = 0;
            let write_ok = WritePrinter(handle, data.as_ptr() as _, data.len() as u32, &mut written);

            let _ = EndPagePrinter(handle);
            let _ = EndDocPrinter(handle);
            let _ = ClosePrinter(handle);

            if !write_ok.succeeded() || (written as usize) != data.len() {
                return Err("Fallo al escribir los datos en el spooler de impresión.".into());
            }
            Ok(())
        }
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
    pub fn print_a4_document(printer_name: &str, paper_size: &str, invoice: &InvoiceDoc) -> Result<(), String> {
        use windows::Win32::Graphics::Gdi::{
            CreateDCW, DeleteDC, EndDoc, EndPage, LineTo, MoveToEx, StartDocW, StartPage,
            TextOutW, GetDeviceCaps, DOCINFOW,
        };

        // Índices de GetDeviceCaps — constantes de wingdi.h, estables desde
        // Windows 3.1 (HORZRES=8, VERTRES=10, LOGPIXELSX=88, LOGPIXELSY=90).
        const HORZRES: i32 = 8;
        const VERTRES: i32 = 10;
        const LOGPIXELSX: i32 = 88;
        const LOGPIXELSY: i32 = 90;

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

            let px_x = GetDeviceCaps(Some(hdc), LOGPIXELSX) as f64 / 25.4; // píxeles por mm (horizontal)
            let px_y = GetDeviceCaps(Some(hdc), LOGPIXELSY) as f64 / 25.4; // píxeles por mm (vertical)
            let page_w = GetDeviceCaps(Some(hdc), HORZRES) as f64;
            let _page_h = GetDeviceCaps(Some(hdc), VERTRES) as f64;
            let _ = paper_size; // el tamaño real lo define la bandeja/config ya establecida en el driver de Windows

            let margin = 12.0 * px_x; // ~12mm de margen
            let line_h = 5.5 * px_y;  // alto de línea aproximado
            let col2 = page_w - margin - (55.0 * px_x); // columna derecha (montos)

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

            let mut y = margin;
            let mut draw = |hdc: windows::Win32::Graphics::Gdi::HDC, x: f64, y: f64, text: &str| {
                let wide = to_wide(text);
                let _ = TextOutW(hdc, x as i32, y as i32, &wide[..wide.len().saturating_sub(1)]);
            };
            let mut divider = |hdc: windows::Win32::Graphics::Gdi::HDC, y: f64| {
                let mut prev = windows::Win32::Foundation::POINT::default();
                let _ = MoveToEx(hdc, margin as i32, y as i32, Some(&mut prev));
                let _ = LineTo(hdc, (page_w - margin) as i32, y as i32);
            };

            draw(hdc, margin, y, &invoice.business_name);
            y += line_h;
            if let Some(t) = &invoice.tax_id { draw(hdc, margin, y, &format!("RNC: {t}")); y += line_h; }
            if let Some(a) = &invoice.business_address { draw(hdc, margin, y, a); y += line_h; }
            if let Some(p) = &invoice.business_phone { draw(hdc, margin, y, &format!("Tel: {p}")); y += line_h; }
            y += line_h * 0.4;
            divider(hdc, y);
            y += line_h;

            draw(hdc, margin, y, &format!("Fecha: {}", invoice.created_at)); y += line_h;
            draw(hdc, margin, y, &format!("Atendido por: {}", invoice.cashier_name)); y += line_h;
            if let Some(c) = &invoice.customer_name { draw(hdc, margin, y, &format!("Cliente: {c}")); y += line_h; }
            draw(hdc, margin, y, if invoice.doc_type == "fiscal" {
                &format!("NCF: {}", invoice.ncf.as_deref().unwrap_or("—"))
            } else { "Ticket de venta (sin valor fiscal)" });
            y += line_h;
            divider(hdc, y);
            y += line_h * 1.2;

            for item in &invoice.items {
                draw(hdc, margin, y, &item.name);
                y += line_h;
                let line = format!("  {} x {}", item.quantity, money(item.unit_price));
                draw(hdc, margin, y, &line);
                draw(hdc, col2, y, &money(item.quantity * item.unit_price));
                y += line_h * 1.1;
            }

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

            if let Some(f) = &invoice.footer { draw(hdc, margin, y, f); }

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
