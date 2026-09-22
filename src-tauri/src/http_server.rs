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
use tower_http::limit::RequestBodyLimitLayer;

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
    // Modo térmico (existente): bytes ESC/POS ya armados en el navegador.
    #[serde(rename = "dataBase64")]
    data_base64: Option<String>,
    #[serde(rename = "printerName")]
    printer_name: Option<String>,
    // Modo hoja completa (A4/Carta): el agente arma la página con GDI a
    // partir de datos estructurados — no llegan bytes de impresora crudos.
    #[serde(rename = "paperSize")]
    paper_size: Option<String>, // "a4" | "letter"
    invoice: Option<printer_win::InvoiceDoc>,
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
    let expected = ctx.state.lock().pairing_token.clone();
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

    let printer_name = body
        .printer_name
        .filter(|n| !n.trim().is_empty())
        .or_else(|| ctx.state.lock().default_printer.clone())
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

    // ---- Modo hoja completa (A4/Carta): datos estructurados + GDI --------
    if let (Some(paper_size), Some(invoice)) = (body.paper_size.clone(), body.invoice.clone()) {
        // spawn_blocking: print_a4_document hace llamadas Win32 SÍNCRONAS
        // (StartDocW, StretchDIBits, etc.) — corridas directo en el handler
        // async, una impresora lenta o atascada bloquearía este hilo del
        // runtime de tokio, dejando /health y /printers sin responder
        // mientras dura. spawn_blocking las manda a un hilo dedicado para
        // trabajo bloqueante, sin retener el runtime async.
        let printer_name_owned = printer_name.clone();
        let join_result = tokio::task::spawn_blocking(move || {
            printer_win::print_a4_document(&printer_name_owned, &paper_size, &invoice)
        })
        .await;

        return match join_result {
            Ok(Ok(())) => Json(serde_json::json!({ "ok": true })).into_response(),
            Ok(Err(msg)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: msg }),
            )
                .into_response(),
            // El hilo de impresión entró en pánico (ej. un bug real en el
            // layout manual del logo, ver printer_win.rs) — se informa como
            // error de impresión en vez de tumbar el proceso entero, que es
            // lo que pasaría si el pánico llegara sin atajar hasta acá.
            Err(join_err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: join_err.to_string() }),
            )
                .into_response(),
        };
    }

    // ---- Modo térmico (existente): bytes ESC/POS crudos -------------------
    let Some(data_base64) = &body.data_base64 else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResp { error: "FALTA_DATA_BASE64_O_INVOICE".into(), detail: "".into() }),
        )
            .into_response();
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = match STANDARD.decode(data_base64) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResp { error: "BASE64_INVALIDO".into(), detail: "".into() }),
            )
                .into_response()
        }
    };

    // Único punto de contacto con el sistema operativo: escribir bytes
    // crudos al spooler vía la API nativa de Win32. Nunca un shell.
    // Mismo motivo que arriba: spawn_blocking para no retener el runtime
    // async mientras el spooler procesa el trabajo.
    let join_result = tokio::task::spawn_blocking(move || printer_win::print_raw(&printer_name, &bytes)).await;
    match join_result {
        Ok(Ok(())) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(Err(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: msg }),
        )
            .into_response(),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: join_err.to_string() }),
        )
            .into_response(),
    }
}

pub async fn run(state: Arc<AppState>) {
    let port = state.lock().port;
    let allowed_origin = state.lock().allowed_origin.clone();

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
        // Límite explícito de tamaño de body — antes no había ninguno, así
        // que /print aceptaba un dataBase64/logo.dataBase64 de cualquier
        // tamaño. Un payload de cientos de MB (token filtrado, o frontend
        // comprometido) podía agotar la memoria del proceso y colgar el
        // agente de esa caja. 10MB sobra de sobra para un ticket térmico o
        // un logo — se aplica DESPUÉS de cors (como capa más externa), para
        // que corte el body antes de que cualquier otra capa lo procese.
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
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
