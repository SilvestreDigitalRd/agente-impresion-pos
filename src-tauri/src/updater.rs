//! Actualizador del agente (auditoría, hallazgo B5).
//!
//! No había updater ni firma de código configurada — parchear una
//! vulnerabilidad exigía reinstalar a mano en cada PC. Este módulo agrega
//! `tauri-plugin-updater`, pero TODO el flujo (comprobar, descargar,
//! instalar) pasa por los dos comandos de Rust definidos acá abajo — el
//! WebView de la ventana de configuración nunca recibe ningún permiso
//! `updater:*` (revisá `capabilities/default.json`: no cambió, y no hacía
//! falta). Mismo criterio que ya describe ese archivo para el resto del
//! agente: *"todo lo que el agente hace... pasa por comandos de Rust
//! escritos a medida, nunca por plugins genéricos de Tauri"*.
//!
//! Dos firmas distintas, para no confundirlas (quedó validado en la
//! conversación antes de escribir esto):
//!   - Firma del PAQUETE de actualización (Tauri): OBLIGATORIA, no se
//!     puede desactivar. Es lo que impide que alguien que comprometa
//!     GitHub Releases/el CDN pueda sustituir el instalador por uno
//!     malicioso — sin la clave privada (que vive SOLO en el pipeline de
//!     release, nunca en este repo ni en la PC del cliente), la firma no
//!     valida y el agente rechaza la actualización.
//!   - Certificado Authenticode de Windows: aparte, sirve para
//!     SmartScreen/confianza de Windows. NO es requisito para que esto
//!     funcione — se puede agregar más adelante sin cambiar nada de acá.
//!
//! Offline-first: un chequeo que falla (sin Internet, servidor caído,
//! timeout) nunca es un error duro — se registra en el log y se sigue
//! funcionando con total normalidad. El agente jamás exige "estar
//! actualizado" para imprimir.
//!
//! Simplificación deliberada frente al diseño discutido: la idea original
//! era descargar en segundo plano y recién instalar cuando el agente
//! estuviera idle (dos fases separadas). Achiqué esto a UNA sola fase
//! (descargar + instalar juntos, solo si en ESE momento no hay ninguna
//! impresión en curso) porque `Update::download_and_install` es el único
//! método que pude confirmar contra la documentación pública sin
//! compilarlo — separar descarga e instalación exige otros métodos del
//! mismo `Update` que no pude verificar con certeza en este sandbox (sin
//! toolchain de Rust). El resultado práctico es casi idéntico: nunca
//! instala a media impresión, solo que además pospone la descarga misma
//! hasta ese momento, en vez de adelantarla. Ver LEEME para el pendiente
//! de separar las dos fases una vez que se pueda compilar y confirmar la
//! firma exacta de esos métodos.

use crate::state::{log_line, AppState};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};

/// Guarda la última actualización que `check_agent_update` encontró
/// disponible, para que `install_agent_update` no tenga que volver a
/// pedirle al servidor los mismos datos — se registra UNA vez en
/// `main.rs` (`.manage(PendingUpdate::default())`), nunca dentro de un
/// comando (`AppHandle::manage` no sobreescribe si el tipo ya está
/// gestionado, así que hacerlo ahí perdería la versión más nueva en el
/// segundo chequeo).
#[derive(Default)]
pub struct PendingUpdate(pub Mutex<Option<Update>>);

#[derive(serde::Serialize, Clone)]
pub struct UpdateStatus {
    pub available: bool,
    pub version: Option<String>,
    pub current_version: String,
    pub notes: Option<String>,
    /// Ronda 10b: `Some(mensaje)` si la comprobación NO pudo completarse (sin
    /// Internet, release en borrador/privado → 404, firma o JSON inválidos…).
    /// Antes todo eso se devolvía como `available:false` y la ventana decía
    /// "Ya tienes la última versión" aunque nunca se hubiera podido comprobar.
    pub error: Option<String>,
}

#[derive(serde::Serialize, Clone)]
#[serde(tag = "phase")]
pub enum InstallProgress {
    #[serde(rename = "downloading")]
    Downloading { downloaded: u64, total: Option<u64> },
    #[serde(rename = "installing")]
    Installing,
}

/// Comprueba si hay una versión más nueva — invocado por el botón "Buscar
/// actualización" de la ventana de configuración (ver ui/app.js) y por el
/// chequeo automático (`spawn_periodic_check`, más abajo). Nunca devuelve
/// `Err` por un problema de red: offline/timeout/servidor caído se
/// informan como "no hay actualización" (`available: false`), no como
/// falla — el criterio de siempre en este agente (ver `/health`,
/// `default_printer`, etc.): un problema externo nunca debe verse como un
/// error del agente en sí.
#[tauri::command]
pub async fn check_agent_update(app: AppHandle) -> Result<UpdateStatus, String> {
    let current_version = env!("CARGO_PKG_VERSION").to_string();

    let updater = app
        .updater_builder()
        // Debido a una limitación de los instaladores de Windows, Tauri
        // cierra el proceso actual antes de instalar — esto deja
        // constancia en el log de que el cierre fue esperado (actualizar),
        // no un crash, para no confundir un futuro diagnóstico remoto
        // (ver log_line/agente.log, hallazgo M17 original).
        .on_before_exit(|| {
            log_line("El agente se va a cerrar para completar la instalación de una actualización (Windows lo exige).");
        })
        .build();

    let updater = match updater {
        Ok(u) => u,
        Err(e) => {
            log_line(&format!("No se pudo inicializar el actualizador: {e}"));
            return Ok(UpdateStatus { available: false, version: None, current_version, notes: None, error: Some(format!("No se pudo inicializar el actualizador: {e}")) });
        }
    };

    match updater.check().await {
        Ok(Some(update)) => {
            log_line(&format!("Actualización disponible: {current_version} -> {}", update.version));
            let version = update.version.clone();
            let notes = update.body.clone();
            let pending = app.state::<PendingUpdate>();
            *pending.0.lock().unwrap_or_else(|p| p.into_inner()) = Some(update);
            Ok(UpdateStatus { available: true, version: Some(version), current_version, notes, error: None })
        }
        Ok(None) => {
            log_line(&format!("Comprobación de actualización: sin novedades (versión instalada {current_version})"));
            Ok(UpdateStatus { available: false, version: None, current_version, notes: None, error: None })
        }
        Err(e) => {
            // Acá caen: sin Internet, DNS, timeout, 4xx/5xx del servidor de
            // releases, JSON del manifest inválido, etc. — todos el mismo
            // caso para quien llama: "seguí como si no hubiera nada nuevo".
            log_line(&format!("No se pudo comprobar actualización (se sigue trabajando con normalidad): {e}"));
            Ok(UpdateStatus { available: false, version: None, current_version, notes: None, error: Some(e.to_string()) })
        }
    }
}

/// Núcleo real de "descargar + instalar", sin nada específico de canal
/// IPC — tanto el comando expuesto a la ventana de configuración como el
/// chequeo automático en segundo plano llaman a esto, cada uno con su
/// propia forma de reportar avance (un Channel hacia el WebView, o
/// directamente nada más que el log, respectivamente). Se separó así a
/// propósito para NO tener que fabricar un `tauri::ipc::Channel` sin un
/// WebView real del otro lado — no pude confirmar esa construcción sin
/// compilar, así que preferí evitarla del todo en vez de arriesgar algo
/// que no puedo verificar.
///
/// Se niega a arrancar si hay una impresión física en curso en ESTE
/// momento (`AppState::active_prints`, incrementado por
/// `ActivePrintGuard` en http_server.rs) — devuelve `PRINT_IN_PROGRESS` y
/// no toca nada.
async fn download_and_install_pending(
    app: &AppHandle,
    mut on_progress: impl FnMut(u64, Option<u64>),
    mut on_installing: impl FnMut(),
) -> Result<(), String> {
    let state = app.state::<Arc<AppState>>();
    if state.active_prints.load(Ordering::SeqCst) > 0 {
        return Err("PRINT_IN_PROGRESS".into());
    }

    let update = {
        let pending = app.state::<PendingUpdate>();
        let mut guard = pending.0.lock().unwrap_or_else(|p| p.into_inner());
        guard.take()
    };
    let Some(update) = update else {
        return Err("NO_PENDING_UPDATE".into());
    };

    log_line(&format!(
        "Instalando actualización del agente: {} -> {}",
        update.current_version, update.version
    ));

    let mut downloaded: u64 = 0;
    let result = update
        .download_and_install(
            |chunk_length, content_length| {
                downloaded += chunk_length as u64;
                on_progress(downloaded, content_length);
            },
            || on_installing(),
        )
        .await;

    match result {
        Ok(()) => {
            log_line("Actualización descargada e instalada — Windows va a reiniciar el proceso del agente.");
            Ok(())
        }
        Err(e) => {
            log_line(&format!("Fallo al descargar/instalar la actualización: {e}"));
            Err(format!("No se pudo instalar la actualización: {e}"))
        }
    }
}

/// Comando invocado por el botón "Buscar actualización" de la ventana de
/// configuración, DESPUÉS de que `check_agent_update` encontró una
/// versión nueva. `on_event` es un canal hacia el frontend con el
/// progreso de la descarga — puramente informativo.
#[tauri::command]
pub async fn install_agent_update(
    app: AppHandle,
    on_event: tauri::ipc::Channel<InstallProgress>,
) -> Result<(), String> {
    download_and_install_pending(
        &app,
        |downloaded, total| {
            let _ = on_event.send(InstallProgress::Downloading { downloaded, total });
        },
        || {
            let _ = on_event.send(InstallProgress::Installing);
        },
    )
    .await
}

/// Chequeo automático: una vez al arrancar (con una demora corta, para no
/// competir con el arranque del servidor HTTP ni de la bandeja) y después
/// cada 6 horas. Si encuentra una versión nueva Y en ese instante no hay
/// ninguna impresión en curso, instala sola — sin diálogo ni
/// confirmación (modo `passive` en Windows: una ventanita de progreso,
/// sin que el cajero tenga que hacer nada). Si justo hay una impresión en
/// curso, no reintenta enseguida — se posterga a la próxima vuelta del
/// timer (o a que alguien use el botón manual de la ventana de
/// configuración, que sí puede reintentar al toque).
///
/// Sin Internet, sin servidor de releases, o cualquier otro fallo: se
/// registra en el log y no pasa nada más — el agente jamás deja de
/// imprimir por esto (criterio offline-first, ver comentario del módulo).
pub fn spawn_periodic_check(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        // Demora inicial corta — deja que el agente termine de arrancar
        // (servidor HTTP, bandeja) antes de gastar el primer chequeo.
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        loop {
            match check_agent_update(app.clone()).await {
                Ok(status) if status.available => {
                    match download_and_install_pending(&app, |_, _| {}, || {}).await {
                        Ok(()) => { /* Windows va a cerrar el proceso para completar la instalación */ }
                        Err(e) if e == "PRINT_IN_PROGRESS" => {
                            log_line("Actualización disponible pero hay una impresión en curso — se reintenta en el próximo chequeo (6h) o desde el botón manual.");
                        }
                        Err(e) => {
                            log_line(&format!("No se pudo instalar la actualización automática: {e}"));
                        }
                    }
                }
                Ok(_) => { /* sin novedades — nada que hacer */ }
                Err(e) => {
                    // check_agent_update ya devuelve Ok(...) para casi todo
                    // (ver su propio comentario) — este brazo es solo para
                    // un panic/bug interno inesperado, no para "sin Internet".
                    log_line(&format!("Error inesperado en el chequeo automático de actualización: {e}"));
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(6 * 60 * 60)).await;
        }
    });
}
