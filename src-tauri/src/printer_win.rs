//! Impresión térmica vía la API nativa de Windows (winspool), llamada
//! DIRECTAMENTE desde Rust — sin `cmd.exe`, sin `Command::new("...")`, sin
//! interpolar texto del usuario en ninguna cadena que un shell interprete.
//!
//! Esto elimina POR COMPLETO la clase de vulnerabilidad de inyección de
//! comandos: no existe ningún punto del código donde bytes que vienen de la
//! red se conviertan en un comando de sistema operativo. Los bytes ESC/POS
//! que llegan por HTTP se pasan tal cual a `WritePrinter`, que solo escribe
//! datos crudos al spooler de impresión — no los ejecuta ni los interpreta.

#[cfg(target_os = "windows")]
mod win {
    use windows::core::PCWSTR;
    use windows::Win32::Graphics::Printing::{
        ClosePrinter, EndDocPrinter, EndPagePrinter, EnumPrintersW, GetDefaultPrinterW,
        OpenPrinterW, StartDocPrinterW, StartPagePrinter, WritePrinter, DOC_INFO_1W,
        PRINTER_ENUM_LOCAL, PRINTER_INFO_2W,
    };

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn list_printers() -> Result<Vec<String>, String> {
        unsafe {
            let mut needed: u32 = 0;
            let mut returned: u32 = 0;
            // Primera llamada solo para saber cuántos bytes hacen falta.
            let _ = EnumPrintersW(
                PRINTER_ENUM_LOCAL,
                PCWSTR::null(),
                2,
                None,
                0,
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
                needed,
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
            let _ = GetDefaultPrinterW(PCWSTR::null(), Some(&mut size));
            if size == 0 {
                return None;
            }
            let mut buf = vec![0u16; size as usize];
            let ok = GetDefaultPrinterW(PCWSTR(buf.as_mut_ptr()), Some(&mut size));
            if ok.is_err() {
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
            let mut handle = Default::default();
            OpenPrinterW(PCWSTR(wide_name.as_ptr()), &mut handle, None)
                .map_err(|e| format!("No se pudo abrir la impresora '{printer_name}': {e}"))?;

            let doc_name = to_wide("Ticket de venta");
            let datatype = to_wide("RAW");
            let doc_info = DOC_INFO_1W {
                pDocName: windows::core::PWSTR(doc_name.as_ptr() as *mut u16),
                pOutputFile: windows::core::PWSTR::null(),
                pDatatype: windows::core::PWSTR(datatype.as_ptr() as *mut u16),
            };

            let job_id = StartDocPrinterW(handle, 1, &doc_info);
            if job_id == 0 {
                ClosePrinter(handle).ok();
                return Err("No se pudo iniciar el trabajo de impresión (StartDocPrinter).".into());
            }

            if StartPagePrinter(handle).as_bool() == false {
                EndDocPrinter(handle).ok();
                ClosePrinter(handle).ok();
                return Err("No se pudo iniciar la página de impresión.".into());
            }

            let mut written: u32 = 0;
            let ok = WritePrinter(handle, data.as_ptr() as _, data.len() as u32, &mut written);

            EndPagePrinter(handle).ok();
            EndDocPrinter(handle).ok();
            ClosePrinter(handle).ok();

            if ok.is_err() || (written as usize) != data.len() {
                return Err("Fallo al escribir los datos en el spooler de impresión.".into());
            }
            Ok(())
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod win {
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
}

pub use win::{default_printer, list_printers, print_raw};
