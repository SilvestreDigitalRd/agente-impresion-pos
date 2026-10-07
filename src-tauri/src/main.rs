// No abrir una consola visible en Windows al iniciar (arranca silencioso
// en la bandeja del sistema, como cualquier programa de fondo).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod escpos;
mod http_server;
mod layout;
mod printer_win;
mod queue;
mod state;
mod updater;

use state::{AgentConfig, AppState};
use std::sync::Arc;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State as TauriState};
use updater::PendingUpdate;

// Ícono de la bandeja, incrustado en el binario en tiempo de COMPILACIÓN
// (no en tiempo de ejecución) — si el archivo estuviera corrupto, el build
// fallaría aquí mismo con un error claro, en vez de arriesgar un crash
// silencioso del programa ya instalado en la PC del cliente.
// Ruta resuelta desde CARGO_MANIFEST_DIR (src-tauri/), no desde este archivo.
const TRAY_ICON: tauri::image::Image<'_> = tauri::include_image!("icons/32x32.png");

#[derive(serde::Serialize)]
struct StatusPayload {
    pairing_token: String,
    allowed_origin: String,
    port: u16,
    default_printer: Option<String>,
    autostart: bool,
    agent_version: &'static str,
    legacy_routes: bool,
    /// Puerto en el que el servidor escucha de verdad ahora (0 = ninguno).
    bound_port: u16,
    /// Mensaje si el puerto no se pudo abrir (None = todo bien).
    bind_error: Option<String>,
    /// Trabajos de impresión esperando reintento.
    queued: usize,
}

#[tauri::command]
fn get_status(state: TauriState<Arc<AppState>>) -> StatusPayload {
    let cfg = state.lock();
    StatusPayload {
        pairing_token: cfg.pairing_token.clone(),
        allowed_origin: cfg.allowed_origin.clone(),
        port: cfg.port,
        default_printer: cfg.default_printer.clone().or_else(printer_win::default_printer),
        autostart: cfg.autostart,
        agent_version: env!("CARGO_PKG_VERSION"),
        legacy_routes: cfg.legacy_routes,
        bound_port: state.bound_port.load(std::sync::atomic::Ordering::SeqCst),
        bind_error: state.bind_error(),
        queued: state.queue().len(),
    }
}

#[tauri::command]
fn regenerate_token(state: TauriState<Arc<AppState>>) -> String {
    let mut cfg = state.lock();
    cfg.regenerate_token();
    cfg.pairing_token.clone()
}

#[tauri::command]
fn list_printers_cmd() -> Result<Vec<String>, String> {
    printer_win::list_printers()
}

#[tauri::command]
fn save_settings(
    app: tauri::AppHandle,
    state: TauriState<Arc<AppState>>,
    allowed_origin: String,
    default_printer: Option<String>,
    autostart: bool,
    port: u16,
    legacy_routes: bool,
) -> Result<Option<String>, String> {
    // Puertos < 1024 son privilegiados y 0 no es un puerto: se rechaza antes
    // de guardar nada (un valor inválido dejaba al agente sin servidor).
    if port < 1024 {
        return Err("El puerto debe estar entre 1024 y 65535.".into());
    }
    // Antes esta función encadenaba con `?`: si `enable()`/`disable()` del
    // plugin de autostart fallaba por CUALQUIER motivo (la app corriendo sin
    // instalar del todo, permisos del registro de Windows, etc.), la función
    // cortaba ahí mismo y `cfg.save()` nunca se ejecutaba — el cambio de
    // impresora u origen que el usuario acababa de hacer se perdía en
    // silencio, sin relación alguna con el checkbox de autostart. Ahora: se
    // INTENTA sincronizar autostart, pero si falla no bloquea nada más — el
    // resto de la configuración se guarda igual, y el fallo de autostart se
    // devuelve aparte como aviso (Some(mensaje)) en vez de perderse todo.
    use tauri_plugin_autostart::ManagerExt;
    let autolaunch = app.autolaunch();
    let sync_result = if autostart { autolaunch.enable() } else { autolaunch.disable() };
    let autostart_warning = sync_result
        .err()
        .map(|e| format!("No se pudo actualizar el inicio automático de Windows: {e}"));

    // Ronda 10b: puerto y rutas legacy también se aplican en caliente — el
    // servidor (http_server::run) se reinicia solo al recibir `server_reload`.
    // El origen permitido ya se releía en cada petición (auditoría B4).
    let needs_reload;
    {
        let mut cfg = state.lock();
        needs_reload = cfg.port != port || cfg.legacy_routes != legacy_routes;
        cfg.allowed_origin = allowed_origin;
        cfg.default_printer = default_printer;
        cfg.autostart = autostart;
        cfg.port = port;
        cfg.legacy_routes = legacy_routes;
        cfg.save();
    }
    if needs_reload {
        crate::state::log_line(&format!("Configuración cambiada: puerto {port}, rutas legacy {legacy_routes} — reiniciando servidor local"));
        state.server_reload.notify_one();
    }
    Ok(autostart_warning)
}

fn main() {
    let config = AgentConfig::load_or_create();
    crate::state::log_line(&format!("Agente iniciado — versión {}", env!("CARGO_PKG_VERSION")));
    let initial_autostart = config.autostart;
    let shared = Arc::new(AppState::new(config));
    let http_state = shared.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        // Auditoría, hallazgo B5: el plugin SOLO se registra acá — el
        // WebView no tiene ningún permiso `updater:*` en
        // capabilities/default.json (no hacía falta agregarlo: los
        // comandos de abajo son comandos de app comunes, no del plugin).
        // Ver el comentario largo en updater.rs para el porqué completo.
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(shared)
        .manage(PendingUpdate::default())
        .invoke_handler(tauri::generate_handler![
            get_status,
            regenerate_token,
            list_printers_cmd,
            save_settings,
            updater::check_agent_update,
            updater::install_agent_update
        ])
        .setup(move |app| {
            // Sincroniza el registro REAL de Windows con lo que dice
            // config.json en cada arranque — no alcanza con hacerlo una
            // sola vez al instalar: si el usuario lo saca a mano de
            // "Aplicaciones de inicio" de Windows (sin pasar por esta
            // configuración), el agente lo vuelve a registrar solo la
            // próxima vez que arranque, en vez de quedar desincronizado
            // en silencio para siempre.
            use tauri_plugin_autostart::ManagerExt;
            let autolaunch = app.autolaunch();
            let sync_result = if initial_autostart { autolaunch.enable() } else { autolaunch.disable() };
            if let Err(e) = sync_result {
                eprintln!("AVISO: no se pudo sincronizar el inicio automático con Windows al arrancar: {e}");
            }

            // Servidor HTTP en un hilo async separado — nunca bloquea la UI.
            tauri::async_runtime::spawn(http_server::run(http_state));

            // Auditoría, hallazgo B5: chequeo automático de actualización —
            // al arrancar (con demora corta) y cada 6 horas. Ver el
            // comentario largo en updater.rs — nunca bloquea ni exige
            // Internet para que el agente funcione.
            updater::spawn_periodic_check(app.handle().clone());

            // Ícono de bandeja: clic izquierdo abre/oculta la ventana de
            // configuración; clic derecho da acceso a "Buscar
            // actualización" y "Salir".
            let show_i = MenuItem::with_id(app, "show", "Configuración…", true, None::<&str>)?;
            let check_update_i = MenuItem::with_id(app, "check_update", "Buscar actualización", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &check_update_i, &quit_i])?;

            let _tray = TrayIconBuilder::new()
                .icon(TRAY_ICON)
                .menu(&menu)
                .tooltip("Agente de Impresión Facturación")
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "show" => {
                        if let Some(w) = app.get_webview_window("settings") {
                            w.show().ok();
                            w.set_focus().ok();
                        }
                    }
                    // Abre la ventana de configuración (misma que
                    // "Configuración…") y le pide al frontend que arranque
                    // el chequeo — así el cajero VE el resultado (versión
                    // actual, si hay una nueva, progreso de instalación) en
                    // vez de que pase en silencio en la bandeja sin que
                    // nadie se entere de si funcionó o no.
                    "check_update" => {
                        if let Some(w) = app.get_webview_window("settings") {
                            w.show().ok();
                            w.set_focus().ok();
                            let _ = w.eval("window.__checkAgentUpdateFromTray && window.__checkAgentUpdateFromTray()");
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                })
                .build(app)?;

            Ok(())
        })
        // Cerrar la ventana (X) solo la oculta — el agente sigue corriendo
        // en la bandeja, que es justamente el punto de "segundo plano".
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                window.hide().ok();
                api.prevent_close();
            }
        })
        .run(tauri::generate_context!())
        .expect("error al iniciar la aplicación Tauri");
}
