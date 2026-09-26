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
    http::{HeaderMap, Method, StatusCode},
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
    print_guard: Arc<PrintGuard>,
}

/**
 * Auditoría, hallazgo M5: antes CADA /print lanzaba su propio
 * spawn_blocking sin ningún límite — si el spooler de Windows se
 * atascaba, los hilos bloqueantes se iban acumulando sin techo (hasta el
 * tope de 512 de Tokio). Tampoco había forma de detectar un reintento del
 * mismo trabajo (el usuario hace doble clic, o el frontend reintenta tras
 * un timeout) — eso imprimía el ticket dos veces, y si el comando abre la
 * gaveta de dinero (bytes ESC/POS), la abría dos veces también.
 */
struct PrintGuard {
    // Como mucho 2 impresiones físicas en simultáneo — de sobra para una
    // caja con impresora de recibo + una de cocina, por ejemplo, pero
    // acota el problema de raíz si el spooler se cuelga.
    semaphore: tokio::sync::Semaphore,
    recent_jobs: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl PrintGuard {
    fn new() -> Self {
        Self {
            semaphore: tokio::sync::Semaphore::new(2),
            recent_jobs: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// true si este jobId ya se procesó hace menos de 60s — se descarta
    /// como duplicado en vez de imprimir de nuevo. Limpieza barata de
    /// entradas viejas en cada llamada, sin tarea de fondo aparte.
    fn is_duplicate(&self, job_id: &str) -> bool {
        let mut jobs = self.recent_jobs.lock().unwrap_or_else(|p| p.into_inner());
        jobs.retain(|_, t| t.elapsed() < std::time::Duration::from_secs(60));
        if jobs.contains_key(job_id) {
            return true;
        }
        jobs.insert(job_id.to_string(), std::time::Instant::now());
        false
    }
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
#[serde(deny_unknown_fields)] // M16 (versión liviana) — ver nota en printer_win.rs::InvoiceItem
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
    // Auditoría, hallazgo M5: id estable del trabajo (el frontend manda
    // invoice.id) — permite descartar un reintento del MISMO trabajo sin
    // imprimir dos veces. Opcional por compatibilidad con un frontend
    // viejo que todavía no lo mande.
    #[serde(rename = "jobId")]
    job_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)] // M16 (versión liviana) — ver nota en printer_win.rs::InvoiceItem
struct PrintNetworkReq {
    #[serde(rename = "networkIp")]
    network_ip: String,
    #[serde(rename = "xmlBody")]
    xml_body: String,
}

#[derive(Serialize)]
struct ErrorResp {
    error: String,
    detail: String,
}

/**
 * Verifica el token (ver arriba) y, además (auditoría, hallazgo B4),
 * Origin/Host — el token ya mitiga un ataque de DNS rebinding (sin el
 * token correcto, no importa desde qué Host/Origin llegue la petición,
 * se rechaza igual), pero conviene rechazarlo en la capa de red también:
 * más barato (no hay que gastar tiempo en la comparación del token) y
 * una capa extra por si algún día el token se maneja distinto.
 */
fn check_origin_and_host(headers: &HeaderMap, ctx: &Ctx) -> Result<(), (StatusCode, Json<ErrorResp>)> {
    let expected_origin = ctx.state.lock().allowed_origin.clone();
    if let Some(origin) = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        if origin != expected_origin {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResp { error: "ORIGEN_NO_PERMITIDO".into(), detail: "".into() }),
            ));
        }
    }
    if let Some(host) = headers.get(axum::http::header::HOST).and_then(|v| v.to_str().ok()) {
        let host_only = host.split(':').next().unwrap_or(host);
        if host_only != "127.0.0.1" && host_only != "localhost" {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResp { error: "HOST_NO_PERMITIDO".into(), detail: "".into() }),
            ));
        }
    }
    Ok(())
}

fn check_token(headers: &HeaderMap, ctx: &Ctx) -> Result<(), (StatusCode, Json<ErrorResp>)> {
    check_origin_and_host(headers, ctx)?;
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
    // Auditoría B3: default_printer() hace una llamada Win32 síncrona —
    // corrida directo acá, un problema del subsistema de impresión podía
    // colgar hasta /health, el endpoint que se supone confirma que el
    // agente sigue vivo.
    let default_printer = tokio::task::spawn_blocking(printer_win::default_printer)
        .await
        .unwrap_or(None);
    Json(HealthResp {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
        default_printer,
    })
    .into_response()
}

async fn printers(State(ctx): State<Ctx>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    // Mismo motivo que en health(): EnumPrintersW es una llamada Win32
    // síncrona (auditoría B3).
    let result = tokio::task::spawn_blocking(printer_win::list_printers).await;
    match result {
        Ok(Ok(list)) => Json(PrintersResp { printers: list }).into_response(),
        Ok(Err(msg)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "NO_SE_PUDO_LISTAR".into(), detail: msg }),
        )
            .into_response(),
        Err(join_err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResp { error: "NO_SE_PUDO_LISTAR".into(), detail: join_err.to_string() }),
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

    // Dedup por jobId (auditoría M5) — un reintento del MISMO trabajo
    // dentro de los últimos 60s se descarta como éxito silencioso en vez
    // de volver a imprimir. Sin jobId (frontend viejo), no hay nada que
    // deduplicar — se sigue de largo como siempre.
    if let Some(job_id) = &body.job_id {
        if ctx.print_guard.is_duplicate(job_id) {
            return Json(serde_json::json!({ "ok": true, "deduped": true })).into_response();
        }
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
        // Semáforo (M5): espera si ya hay 2 impresiones físicas en curso,
        // en vez de lanzar un hilo bloqueante más sin límite.
        let _permit = ctx.print_guard.semaphore.acquire().await;
        // Timeout (M5): si el spooler se cuelga, quien llamó a /print no
        // se queda esperando para siempre — a los 30s se le devuelve un
        // error igual. OJO: esto NO cancela el trabajo bloqueante en sí
        // (Win32 no da forma de cancelar una llamada síncrona a mitad de
        // camino) — el hilo sigue corriendo de fondo; el timeout acota
        // cuánto espera el HTTP, no cuánto tarda realmente la impresora.
        let join_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                printer_win::print_a4_document(&printer_name_owned, &paper_size, &invoice)
            }),
        )
        .await;

        return match join_result {
            Ok(Ok(Ok(()))) => Json(serde_json::json!({ "ok": true })).into_response(),
            Ok(Ok(Err(msg))) => {
                crate::state::log_line(&format!("Fallo de impresión (A4/hoja completa): {msg}"));
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: msg }),
                )
                    .into_response()
            }
            // El hilo de impresión entró en pánico (ej. un bug real en el
            // layout manual del logo, ver printer_win.rs) — se informa como
            // error de impresión en vez de tumbar el proceso entero, que es
            // lo que pasaría si el pánico llegara sin atajar hasta acá.
            Ok(Err(join_err)) => {
                crate::state::log_line(&format!("Pánico en el hilo de impresión (A4): {join_err}"));
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: join_err.to_string() }),
                )
                    .into_response()
            }
            Err(_elapsed) => {
                crate::state::log_line("Impresión A4 excedió el tiempo límite (30s)");
                (
                    StatusCode::GATEWAY_TIMEOUT,
                    Json(ErrorResp { error: "IMPRESION_TIMEOUT".into(), detail: "La impresora no respondió a tiempo (30s).".into() }),
                )
                    .into_response()
            }
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
    // async mientras el spooler procesa el trabajo, más semáforo+timeout
    // (M5) igual que el modo A4.
    let _permit = ctx.print_guard.semaphore.acquire().await;
    let join_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || printer_win::print_raw(&printer_name, &bytes)),
    )
    .await;
    match join_result {
        Ok(Ok(Ok(()))) => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(Ok(Err(msg))) => {
            crate::state::log_line(&format!("Fallo de impresión (térmica): {msg}"));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: msg }),
            )
                .into_response()
        }
        Ok(Err(join_err)) => {
            crate::state::log_line(&format!("Pánico en el hilo de impresión (térmica): {join_err}"));
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp { error: "FALLO_DE_IMPRESION".into(), detail: join_err.to_string() }),
            )
                .into_response()
        }
        Err(_elapsed) => {
            crate::state::log_line("Impresión térmica excedió el tiempo límite (30s)");
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(ErrorResp { error: "IMPRESION_TIMEOUT".into(), detail: "La impresora no respondió a tiempo (30s).".into() }),
            )
                .into_response()
        }
    }
}

/**
 * POST /print-network — reenvía un documento ePOS-Print (XML ya armado
 * por el frontend) hacia una impresora de red en la LAN.
 *
 * Auditoría, hallazgo A9: antes el NAVEGADOR le hacía fetch() directo a
 * http://<ip-lan> — con el frontend en HTTPS (Vercel), eso es contenido
 * mixto activo y los navegadores lo bloquean, así que "Impresora de red"
 * ya no imprimía nada en producción. Un `fetch` de acá (proceso nativo,
 * no un navegador) no tiene esa restricción — 127.0.0.1 SÍ es de
 * confianza para el navegador (por eso /print ya funcionaba), la LAN NO.
 *
 * `is_private()` (además del `X-Agent-Token` de siempre) evita que este
 * endpoint se use como un proxy HTTP abierto hacia cualquier IP —
 * defensa en profundidad, aunque el backend YA valida que network_ip sea
 * una IPv4 privada antes de guardarlo.
 */
async fn print_network(State(ctx): State<Ctx>, headers: HeaderMap, Json(body): Json<PrintNetworkReq>) -> impl IntoResponse {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }

    let Ok(ip) = body.network_ip.parse::<std::net::Ipv4Addr>() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResp { error: "IP_INVALIDA".into(), detail: "".into() }),
        )
            .into_response();
    };
    if !(ip.is_private() || ip.is_loopback() || ip.is_link_local()) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ErrorResp {
                error: "IP_NO_PRIVADA".into(),
                detail: "Solo se permite reenviar a direcciones de red local (LAN).".into(),
            }),
        )
            .into_response();
    }

    let url = format!("http://{ip}/cgi-bin/epos/service.cgi?devid=local_printer&timeout=10000");
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResp { error: "CLIENTE_HTTP_FALLO".into(), detail: e.to_string() }),
            )
                .into_response()
        }
    };

    match client
        .post(&url)
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("If-Modified-Since", "Thu, 01 Jan 1970 00:00:00 GMT")
        .body(body.xml_body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => Json(serde_json::json!({ "ok": true })).into_response(),
        Ok(resp) => {
            crate::state::log_line(&format!("Impresora de red respondió error: HTTP {}", resp.status()));
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResp { error: "IMPRESORA_RED_ERROR".into(), detail: format!("HTTP {}", resp.status()) }),
            )
                .into_response()
        }
        Err(e) => {
            crate::state::log_line(&format!("Impresora de red inalcanzable ({ip}): {e}"));
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorResp { error: "IMPRESORA_RED_INALCANZABLE".into(), detail: e.to_string() }),
            )
                .into_response()
        }
    }
}

pub async fn run(state: Arc<AppState>) {
    let port = state.lock().port;

    // CORS ESTRICTO: un único origen exacto, nunca '*' ni un patrón amplio.
    // Como exigimos Content-Type: application/json + header custom, CUALQUIER
    // petición cross-origin dispara preflight (OPTIONS) obligatorio — una
    // página maliciosa no puede evitarlo ni leer la respuesta si su origen
    // no es exactamente este.
    //
    // Auditoría, hallazgo B4: antes `allowed_origin` se leía UNA vez acá y
    // quedaba fijo en el CorsLayer para toda la vida del proceso — cambiar
    // el origen permitido (Configuración → Agente local) exigía reiniciar
    // el agente para que surtiera efecto. Con `AllowOrigin::predicate`, el
    // origen se relee del estado compartido EN CADA petición — el mismo
    // Arc<AppState> que ya usan los handlers, así que un cambio de
    // configuración aplica de inmediato, sin reiniciar nada.
    let state_for_cors = state.clone();
    let cors = CorsLayer::new()
        .allow_origin(tower_http::cors::AllowOrigin::predicate(move |origin, _parts| {
            let expected = state_for_cors.lock().allowed_origin.clone();
            origin.as_bytes() == expected.as_bytes()
        }))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderName::from_static("x-agent-token"),
        ])
        // Chrome exige esto en el preflight para que una página normal
        // pueda hablarle a un servidor en loopback/red local (Private
        // Network Access) — sin esto, versiones recientes de Chrome
        // empiezan a bloquear la petición de entrada, aunque el resto de
        // la configuración de CORS esté perfecta (auditoría B4).
        .allow_private_network(true);

    let ctx = Ctx { state: state.clone(), print_guard: Arc::new(PrintGuard::new()) };
    // Auditoría, hallazgo M16 (versión liviana): antes las rutas no tenían
    // versión (`/health`, `/print`, ...) — con el sistema offline-first,
    // una PC puede quedar con un agente viejo corriendo semanas mientras el
    // resto ya se actualizó; sin versión en la ruta, un cambio incompatible
    // en el contrato (agregar un campo obligatorio, cambiar un tipo) no
    // tiene forma de convivir con el agente viejo en la misma URL. Con
    // `/v1/...`, un cambio incompatible el día de mañana se sirve en
    // `/v2/...` y el frontend puede seguir hablándole a `/v1/...` a las PCs
    // que todavía no actualizaron el agente.
    //
    // Las rutas SIN prefijo se mantienen apuntando a los mismos handlers,
    // como compatibilidad TEMPORAL: hoy no existe un actualizador (hallazgo
    // B5, todavía pendiente) que reinstale el agente solo, así que forzar
    // el corte ahora dejaría sin imprimir a cualquier PC que no se
    // reinstale a mano el mismo día que se despliegue el frontend nuevo.
    // Cuando B5 esté resuelto y el parque de agentes instalados ya hable
    // `/v1` (se puede confirmar mirando qué rutas llegan a pedir en el
    // log), estas quedan para borrar.
    let app = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/printers", get(printers))
        .route("/v1/print", post(print))
        .route("/v1/print-network", post(print_network))
        // TODO(B5): borrar estas 4 rutas una vez que el updater esté andando
        // y el parque instalado ya haya migrado a /v1.
        .route("/health", get(health))
        .route("/printers", get(printers))
        .route("/print", post(print))
        .route("/print-network", post(print_network))
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
