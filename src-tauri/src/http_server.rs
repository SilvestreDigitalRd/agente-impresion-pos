//! Servidor HTTP local del agente.
//!
//! Capas de seguridad aplicadas (en el orden en que se ejecutan por petición):
//!   1. Bind exclusivo a 127.0.0.1 — ver `run()`. Nunca 0.0.0.0.
//!   2. CORS estricto: solo el origen exacto configurado recibe las
//!      cabeceras Access-Control-Allow-*; el navegador bloquea la lectura
//!      de la respuesta para cualquier otro origen (incluida la petición
//!      OPTIONS de preflight, que SIEMPRE ocurre porque exigimos
//!      Content-Type: application/json + el header X-Agent-Token, lo que
//!      hace que la petición deje de ser "simple" para el navegador).
//!   3. Verificación de token en el servidor (no solo confiar en el Origin,
//!      que en teoría podría llegar falseado desde un cliente que no sea
//!      un navegador real) — comparación en tiempo constante.
//!
//! Fuera de alcance: un programa malicioso que YA corre con los permisos
//! del usuario en esa misma PC (no una pestaña del navegador) podría en
//! teoría leer el archivo de configuración y obtener el token igual que
//! cualquier otro proceso local — eso es un problema de seguridad del
//! sistema operativo del cliente, no algo que un servidor en loopback
//! pueda prevenir por sí mismo.

use crate::printer_win;
use crate::state::{tokens_match, AppState};
use axum::{
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct Ctx {
    state: Arc<AppState>,
}

#[derive(Serialize)]
struct HealthResp {
    ok: bool,
    version: &'static str,
    default_printer: Option<String>,
}

#[derive(Serialize)]
struct PrintersResp {
    printers: Vec<String>,
}

#[derive(Deserialize)]
struct PrintReq {
    #[serde(rename = "dataBase64")]
    data_base64: String,
    #[serde(rename = "printerName")]
    printer_name: Option<String>,
}

#[derive(Serialize)]
struct ErrorResp {
    error: String,
    detail: String,
}

fn check_token(headers: &HeaderMap, ctx: &Ctx) -> Result<(), (StatusCode, Json<ErrorResp>)> {
    let provided = headers
        .get("x-agent-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let expected = ctx.state.0.lock().unwrap().pairing_token.clone();
    if provided.is_empty() || !tokens_match(provided, &expected) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResp {
                error: "TOKEN_INVALIDO".into(),
                detail: "Falta o es incorrecta la clave de emparejamiento (X-Agent-Token).".into(),
            }),
        ));
    }
    Ok(())
}

async fn health(State(ctx): State<Ctx>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    Json(HealthResp {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
        default_printer: printer_win::default_printer(),
    })
    .into_response()
}

async fn printers(State(ctx): State<Ctx>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    match printer_win::list_printers() {
        Ok(list) => Json(PrintersResp { printers: list }).into_response(),
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "NO_SE_PUDO_LISTAR".into(), detail: msg }),
        )
            .into_response(),
    }
}

async fn print(
    State(ctx): State<Ctx>,
    headers: HeaderMap,
    Json(body): Json<PrintReq>,
) -> impl IntoResponse {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = match STANDARD.decode(&body.data_base64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResp { error: "BASE64_INVALIDO".into(), detail: "".into() }),
            )
                .into_response()
        }
    };

    let printer_name = body
        .printer_name
        .filter(|n| !n.trim().is_empty())
        .or_else(|| ctx.state.0.lock().unwrap().default_printer.clone())
        .or_else(printer_win::default_printer);

    let Some(printer_name) = printer_name else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResp {
                error: "SIN_IMPRESORA_CONFIGURADA".into(),
                detail: "No hay impresora predeterminada ni configurada en este equipo.".into(),
            }),
        )
            .into_response();
    };

    // Único punto de contacto con el sistema operativo: escribir bytes
    // crudos al spooler vía la API nativa de Win32. Nunca un shell.
    match printer_win::print_raw(&printer_name, &bytes) {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: msg }),
        )
            .into_response(),
    }
}

pub async fn run(state: Arc<AppState>) {
    let port = state.0.lock().unwrap().port;
    let allowed_origin = state.0.lock().unwrap().allowed_origin.clone();

    let origin: HeaderValue = allowed_origin
        .parse()
        .unwrap_or_else(|_| HeaderValue::from_static("https://invalid.example"));

    // CORS ESTRICTO: un único origen exacto, nunca '*' ni un patrón amplio.
    // Como exigimos Content-Type: application/json + header custom, CUALQUIER
    // petición cross-origin dispara preflight (OPTIONS) obligatorio — una
    // página maliciosa no puede evitarlo ni leer la respuesta si su origen
    // no es exactamente este.
    let cors = CorsLayer::new()
        .allow_origin(origin)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-agent-token"),
        ]);

    let ctx = Ctx { state: state.clone() };
    let app = Router::new()
        .route("/health", get(health))
        .route("/printers", get(printers))
        .route("/print", post(print))
        .layer(cors)
        .with_state(ctx);

    // Bind EXCLUSIVO a loopback. 0.0.0.0 expondría el agente a toda la LAN
    // (cualquier otra PC/celular en el WiFi del negocio podría llamarlo).
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            println!("Agente escuchando en http://{addr} (solo loopback)");
            axum::serve(listener, app).await.ok();
        }
        Err(e) => eprintln!("No se pudo iniciar el servidor local en {addr}: {e}"),
    }
}
