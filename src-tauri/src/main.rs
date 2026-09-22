// No abrir una consola visible en Windows al iniciar (arranca silencioso
// en la bandeja del sistema, como cualquier programa de fondo).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod http_server;
mod printer_win;
mod state;

use state::{AgentConfig, AppState};
use std::sync::{Arc, Mutex};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{Manager, State as TauriState};

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
    state: TauriState<Arc<AppState>>,
    allowed_origin: String,
    default_printer: Option<String>,
    autostart: bool,
) -> Result<(), String> {
    // El puerto NO se puede cambiar en caliente sin reiniciar el servidor
    // (queda fijo tras el primer arranque); todo lo demás sí se aplica ya.
    let mut cfg = state.lock();
    cfg.allowed_origin = allowed_origin;
    cfg.default_printer = default_printer;
    cfg.autostart = autostart;
    cfg.save();
    Ok(())
    // Nota: cambiar allowed_origin aquí solo actualiza el archivo de config;
    // el CORS del servidor Axum ya en ejecución mantiene el valor con el que
    // arrancó. Reiniciar el agente aplica el nuevo origen al servidor HTTP.
}

fn main() {
    let config = AgentConfig::load_or_create();
    let shared = Arc::new(AppState(Mutex::new(config)));
    let http_state = shared.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .manage(shared)
        .invoke_handler(tauri::generate_handler![
            get_status,
            regenerate_token,
            list_printers_cmd,
            save_settings
        ])
        .setup(move |app| {
            // Servidor HTTP en un hilo async separado — nunca bloquea la UI.
            tauri::async_runtime::spawn(http_server::run(http_state));

            // Ícono de bandeja: clic izquierdo abre/oculta la ventana de
            // configuración; clic derecho da acceso a "Salir".
            let show_i = MenuItem::with_id(app, "show", "Configuración…", true, None::<&str>)?;
            let quit_i = MenuItem::with_id(app, "quit", "Salir", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &quit_i])?;

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
