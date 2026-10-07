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
//!
//! Ronda 10b: cola de reintentos de impresión (`retry:true`), registro de
//! aperturas de gaveta (`/v1/drawer-log`), rutas legacy sin `/v1` opcionales,
//! reinicio del servidor al cambiar el puerto y error de bind visible.
use crate::escpos::{self, DrawerEvent, DrawerLog};
use crate::printer_win;
use crate::queue::{EnqueueResult, FailOutcome};
use crate::state::{tokens_match, AppState};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Json, Response},
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

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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

    /// Ronda 10b (bug previo): un trabajo que FALLÓ seguía marcado como
    /// "reciente" durante 60s, así que el reintento manual del cajero se
    /// contestaba `{ok:true, deduped:true}` SIN imprimir nada. Ahora, al
    /// fallar, se olvida el jobId para que el reintento sí imprima.
    fn forget(&self, job_id: &str) {
        self.recent_jobs.lock().unwrap_or_else(|p| p.into_inner()).remove(job_id);
    }
}

#[derive(Serialize)]
struct HealthResp {
    ok: bool,
    version: &'static str,
    default_printer: Option<String>,
    queued: usize,
}

#[derive(Serialize)]
struct PrintersResp {
    printers: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone)]
struct PrintReq {
    // Modo térmico (existente): bytes ESC/POS ya armados en el navegador.
    #[serde(rename = "dataBase64", skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
    #[serde(rename = "printerName", skip_serializing_if = "Option::is_none")]
    printer_name: Option<String>,
    // Modo hoja completa (A4/Carta): el agente arma la página con GDI a
    // partir de datos estructurados — no llegan bytes de impresora crudos.
    #[serde(rename = "paperSize", skip_serializing_if = "Option::is_none")]
    paper_size: Option<String>, // "a4" | "letter"
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice: Option<printer_win::InvoiceDoc>,
    // Auditoría, hallazgo M5: id estable del trabajo (el frontend manda
    // invoice.id) — permite descartar un reintento del MISMO trabajo sin
    // imprimir dos veces. Opcional por compatibilidad con un frontend
    // viejo que todavía no lo mande.
    #[serde(rename = "jobId", skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    // Ronda 10b: si la impresión falla de forma definitiva, en vez de
    // devolver error se guarda en la cola persistente y se reintenta sola
    // (pensado para comprobantes fiscales ya emitidos). Requiere `jobId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retry: Option<bool>,
}

#[derive(Deserialize)]
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
    let queued = ctx.state.queue().len();
    Json(HealthResp {
        ok: true,
        version: env!("CARGO_PKG_VERSION"),
        default_printer,
        queued,
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

// ---------------------------------------------------------------------------
// Núcleo de impresión (lo usan el handler /print y el worker de la cola)
// ---------------------------------------------------------------------------

struct PrintFail {
    status: StatusCode,
    code: &'static str,
    detail: String,
    /// true = el fallo es DEFINITIVO (la impresora rechazó/falló) y es seguro
    /// reintentar sin riesgo de imprimir doble. Un timeout NO lo es: el hilo
    /// de Win32 no se puede cancelar y el ticket pudo haber salido igual.
    retriable: bool,
}

impl PrintFail {
    fn new(status: StatusCode, code: &'static str, detail: impl Into<String>, retriable: bool) -> Self {
        Self { status, code, detail: detail.into(), retriable }
    }
    fn into_response(self) -> Response {
        (self.status, Json(ErrorResp { error: self.code.into(), detail: self.detail })).into_response()
    }
}

struct PrintDone {
    pulses: usize,
}

/// Ejecuta UN trabajo de impresión. `strip_drawer`: quita los comandos de
/// apertura de gaveta (reintentos desde la cola — no abrir la gaveta horas
/// después, a destiempo).
async fn run_print(
    state: &Arc<AppState>,
    guard: &PrintGuard,
    body: &PrintReq,
    strip_drawer: bool,
) -> Result<PrintDone, PrintFail> {
    let printer_name = body
        .printer_name
        .clone()
        .filter(|n| !n.trim().is_empty())
        .or_else(|| state.lock().default_printer.clone())
        .or_else(printer_win::default_printer);

    let Some(printer_name) = printer_name else {
        return Err(PrintFail::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SIN_IMPRESORA_CONFIGURADA",
            "No hay impresora predeterminada ni configurada en este equipo.",
            false,
        ));
    };

    // Auditoría, hallazgo B5: desde acá hasta el final de esta función hay
    // una impresión física en curso — el actualizador del agente
    // (updater.rs) nunca instala mientras este contador esté por encima de
    // cero. RAII: se decrementa solo al salir, sea cual sea el camino.
    let _active_print = crate::state::ActivePrintGuard::new(state);

    // ---- Modo hoja completa (A4/Carta): datos estructurados + GDI --------
    if let (Some(paper_size), Some(invoice)) = (body.paper_size.clone(), body.invoice.clone()) {
        let printer_name_owned = printer_name.clone();
        // Semáforo (M5): espera si ya hay 2 impresiones físicas en curso.
        let _permit = guard.semaphore.acquire().await;
        // Timeout (M5): NO cancela el trabajo bloqueante en sí (Win32 no
        // permite cancelar una llamada síncrona) — acota la espera del HTTP.
        let join_result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                printer_win::print_a4_document(&printer_name_owned, &paper_size, &invoice)
            }),
        )
        .await;

        return match join_result {
            Ok(Ok(Ok(()))) => Ok(PrintDone { pulses: 0 }),
            Ok(Ok(Err(msg))) => {
                crate::state::log_line(&format!("Fallo de impresión (A4/hoja completa): {msg}"));
                Err(PrintFail::new(StatusCode::INTERNAL_SERVER_ERROR, "FALLO_DE_IMPRESION", msg, true))
            }
            Ok(Err(join_err)) => {
                crate::state::log_line(&format!("Pánico en el hilo de impresión (A4): {join_err}"));
                Err(PrintFail::new(StatusCode::INTERNAL_SERVER_ERROR, "FALLO_DE_IMPRESION", join_err.to_string(), true))
            }
            Err(_elapsed) => {
                crate::state::log_line("Impresión A4 excedió el tiempo límite (30s)");
                Err(PrintFail::new(
                    StatusCode::GATEWAY_TIMEOUT,
                    "IMPRESION_TIMEOUT",
                    "La impresora no respondió a tiempo (30s).",
                    false,
                ))
            }
        };
    }

    // ---- Modo térmico (existente): bytes ESC/POS crudos -------------------
    let Some(data_base64) = &body.data_base64 else {
        return Err(PrintFail::new(StatusCode::UNPROCESSABLE_ENTITY, "FALTA_DATA_BASE64_O_INVOICE", "", false));
    };

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut bytes = match STANDARD.decode(data_base64) {
        Ok(b) => b,
        Err(_) => {
            return Err(PrintFail::new(StatusCode::UNPROCESSABLE_ENTITY, "BASE64_INVALIDO", "", false));
        }
    };
    if strip_drawer {
        bytes = escpos::strip_drawer_pulses(&bytes);
    }
    let pulses = escpos::count_drawer_pulses(&bytes);

    // Único punto de contacto con el sistema operativo: escribir bytes
    // crudos al spooler vía la API nativa de Win32. Nunca un shell.
    let _permit = guard.semaphore.acquire().await;
    let printer_for_log = printer_name.clone();
    let join_result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        tokio::task::spawn_blocking(move || printer_win::print_raw(&printer_name, &bytes)),
    )
    .await;
    match join_result {
        Ok(Ok(Ok(()))) => {
            // Ronda 10b: rastro de cada apertura de gaveta (antes ninguno).
            if pulses > 0 {
                let ev = DrawerEvent {
                    ts: now_secs(),
                    job_id: body.job_id.clone(),
                    printer: printer_for_log,
                    pulses,
                };
                if let Err(e) = DrawerLog::append(&state.data_dir, &ev) {
                    crate::state::log_line(&format!("No se pudo registrar la apertura de gaveta: {e}"));
                }
            }
            Ok(PrintDone { pulses })
        }
        Ok(Ok(Err(msg))) => {
            crate::state::log_line(&format!("Fallo de impresión (térmica): {msg}"));
            Err(PrintFail::new(StatusCode::INTERNAL_SERVER_ERROR, "FALLO_DE_IMPRESION", msg, true))
        }
        Ok(Err(join_err)) => {
            crate::state::log_line(&format!("Pánico en el hilo de impresión (térmica): {join_err}"));
            Err(PrintFail::new(StatusCode::INTERNAL_SERVER_ERROR, "FALLO_DE_IMPRESION", join_err.to_string(), true))
        }
        Err(_elapsed) => {
            crate::state::log_line("Impresión térmica excedió el tiempo límite (30s)");
            Err(PrintFail::new(
                StatusCode::GATEWAY_TIMEOUT,
                "IMPRESION_TIMEOUT",
                "La impresora no respondió a tiempo (30s).",
                false,
            ))
        }
    }
}

async fn print(State(ctx): State<Ctx>, headers: HeaderMap, Json(body): Json<PrintReq>) -> Response {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }

    // Ya está en la cola de reintentos: no se imprime otra vez ni se vuelve
    // a encolar — se informa que sigue pendiente.
    if let Some(job_id) = &body.job_id {
        if ctx.state.queue().contains(job_id) {
            return (
                StatusCode::ACCEPTED,
                Json(serde_json::json!({ "ok": false, "queued": true, "deduped": true, "jobId": job_id })),
            )
                .into_response();
        }
        // Dedup por jobId (auditoría M5) — un reintento del MISMO trabajo
        // dentro de los últimos 60s se descarta como éxito silencioso.
        if ctx.print_guard.is_duplicate(job_id) {
            return Json(serde_json::json!({ "ok": true, "deduped": true })).into_response();
        }
    }

    match run_print(&ctx.state, &ctx.print_guard, &body, false).await {
        Ok(done) => Json(serde_json::json!({
            "ok": true,
            "drawerOpened": done.pulses > 0,
        }))
        .into_response(),
        Err(fail) => {
            if let Some(job_id) = &body.job_id {
                ctx.print_guard.forget(job_id);
            }
            let wants_retry = body.retry.unwrap_or(false);
            if let (true, true, Some(job_id)) = (wants_retry, fail.retriable, body.job_id.clone()) {
                let payload = serde_json::to_value(&body).unwrap_or(serde_json::Value::Null);
                let enq = ctx.state.queue().enqueue(&job_id, payload, now_secs(), &format!("{}: {}", fail.code, fail.detail));
                match enq {
                    EnqueueResult::Queued | EnqueueResult::AlreadyQueued => {
                        crate::state::log_line(&format!("Trabajo {job_id} a la cola de reintentos ({}: {})", fail.code, fail.detail));
                        return (
                            StatusCode::ACCEPTED,
                            Json(serde_json::json!({
                                "ok": false,
                                "queued": true,
                                "jobId": job_id,
                                "error": fail.code,
                                "detail": fail.detail,
                                "drawerOpened": false,
                            })),
                        )
                            .into_response();
                    }
                    EnqueueResult::Full => {
                        crate::state::log_line("Cola de reintentos llena: se devuelve el error original");
                    }
                }
            }
            fail.into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Cola y registro de gaveta
// ---------------------------------------------------------------------------

async fn queue_list(State(ctx): State<Ctx>, headers: HeaderMap) -> Response {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    let q = ctx.state.queue();
    Json(serde_json::json!({ "count": q.len(), "jobs": q.summary(), "expired": q.expired() })).into_response()
}

#[derive(Deserialize)]
struct JobIdReq {
    #[serde(rename = "jobId")]
    job_id: String,
}

async fn queue_cancel(State(ctx): State<Ctx>, headers: HeaderMap, Json(b): Json<JobIdReq>) -> Response {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    let ok = ctx.state.queue().cancel(&b.job_id);
    if ok {
        crate::state::log_line(&format!("Trabajo {} cancelado de la cola por el usuario", b.job_id));
    }
    Json(serde_json::json!({ "ok": ok })).into_response()
}

async fn queue_retry_now(State(ctx): State<Ctx>, headers: HeaderMap, Json(b): Json<JobIdReq>) -> Response {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    let ok = ctx.state.queue().retry_now(&b.job_id, now_secs());
    Json(serde_json::json!({ "ok": ok })).into_response()
}

#[derive(Deserialize)]
struct DrawerQuery {
    since: Option<u64>,
    limit: Option<usize>,
}

async fn drawer_log(State(ctx): State<Ctx>, headers: HeaderMap, Query(q): Query<DrawerQuery>) -> Response {
    if let Err(e) = check_token(&headers, &ctx) {
        return e.into_response();
    }
    let dir = ctx.state.data_dir.clone();
    let since = q.since.unwrap_or(0);
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let events = tokio::task::spawn_blocking(move || DrawerLog::read_since(&dir, since, limit))
        .await
        .unwrap_or_default();
    Json(serde_json::json!({ "events": events })).into_response()
}

/// Worker: cada 2 s toma los trabajos vencidos de la cola y los reintenta.
async fn queue_worker(state: Arc<AppState>, guard: Arc<PrintGuard>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let due = state.queue().take_due(now_secs());
        for job in due {
            let req = match serde_json::from_value::<PrintReq>(job.payload.clone()) {
                Ok(r) => r,
                Err(e) => {
                    crate::state::log_line(&format!("Trabajo {} en cola con datos ilegibles ({e}) — se descarta", job.job_id));
                    state.queue().cancel(&job.job_id);
                    continue;
                }
            };
            match run_print(&state, &guard, &req, true).await {
                Ok(_) => {
                    state.queue().complete(&job.job_id);
                    crate::state::log_line(&format!("Trabajo {} impreso desde la cola (intento {})", job.job_id, job.attempts + 1));
                }
                Err(f) => {
                    let out = state.queue().fail(&job.job_id, now_secs(), &format!("{}: {}", f.code, f.detail));
                    match out {
                        FailOutcome::Expired => crate::state::log_line(&format!(
                            "Trabajo {} VENCIÓ en la cola sin poder imprimirse ({}: {})",
                            job.job_id, f.code, f.detail
                        )),
                        _ => {}
                    }
                }
            }
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

    // Auditoría, hallazgo B5: mismo criterio que en run_print — esto también
    // es una impresión física en curso (reenviada a una impresora de red),
    // el actualizador tampoco debe instalar mientras esto está en vuelo.
    let _active_print = crate::state::ActivePrintGuard::new(&ctx.state);

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

fn build_router(state: &Arc<AppState>, print_guard: Arc<PrintGuard>, legacy_routes: bool) -> Router {
    // CORS ESTRICTO: un único origen exacto, nunca '*' ni un patrón amplio.
    // Como exigimos Content-Type: application/json + header custom, CUALQUIER
    // petición cross-origin dispara preflight (OPTIONS) obligatorio — una
    // página maliciosa no puede evitarlo ni leer la respuesta si su origen
    // no es exactamente este.
    //
    // Auditoría, hallazgo B4: con `AllowOrigin::predicate` el origen se relee
    // del estado compartido EN CADA petición — un cambio de configuración
    // aplica de inmediato, sin reiniciar nada.
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
        // Network Access) (auditoría B4).
        .allow_private_network(true);

    let ctx = Ctx { state: state.clone(), print_guard };
    let mut app = Router::new()
        // Contrato versionado bajo /v1 (auditoría M16).
        .route("/v1/health", get(health))
        .route("/v1/printers", get(printers))
        .route("/v1/print", post(print))
        .route("/v1/print-network", post(print_network))
        // Ronda 10b: cola de reintentos y registro de gaveta.
        .route("/v1/queue", get(queue_list))
        .route("/v1/queue/cancel", post(queue_cancel))
        .route("/v1/queue/retry-now", post(queue_retry_now))
        .route("/v1/drawer-log", get(drawer_log));
    if legacy_routes {
        // Ronda 10b (TODO B5 resuelto): las rutas SIN prefijo ya no se
        // exponen salvo que la config tenga `legacy_routes: true` (webs viejas
        // en caché). Instalaciones nuevas nacen con `false`; se apaga desde
        // la ventana del agente.
        app = app
            .route("/health", get(health))
            .route("/printers", get(printers))
            .route("/print", post(print))
            .route("/print-network", post(print_network));
    }
    app.layer(cors)
        // Límite explícito de tamaño de body: 10MB sobra de sobra para un
        // ticket térmico o un logo — se aplica DESPUÉS de cors (capa más
        // externa) para cortar el body antes de que otra capa lo procese.
        .layer(RequestBodyLimitLayer::new(10 * 1024 * 1024))
        .with_state(ctx)
}

/// Supervisor del servidor: abre el puerto configurado; si falla (puerto
/// ocupado), deja el error visible en el estado y reintenta cada 10 s o
/// apenas el usuario cambie el puerto. Cambiar puerto/rutas legacy reinicia
/// el listener solo, sin cerrar el agente.
pub async fn run(state: Arc<AppState>) {
    let guard = Arc::new(PrintGuard::new());
    tokio::spawn(queue_worker(state.clone(), guard.clone()));

    loop {
        let (port, legacy) = {
            let c = state.lock();
            (c.port, c.legacy_routes)
        };
        // Bind EXCLUSIVO a loopback. 0.0.0.0 expondría el agente a toda la LAN
        // (cualquier otra PC/celular en el WiFi del negocio podría llamarlo).
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                state.set_bind_error(None);
                state.bound_port.store(port, std::sync::atomic::Ordering::SeqCst);
                crate::state::log_line(&format!("Servidor local escuchando en http://{addr} (solo loopback)"));
                let app = build_router(&state, guard.clone(), legacy);
                let st = state.clone();
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async move { st.server_reload.notified().await })
                    .await;
                state.bound_port.store(0, std::sync::atomic::Ordering::SeqCst);
                crate::state::log_line("Servidor local reiniciando (cambio de configuración)");
            }
            Err(e) => {
                let msg = format!(
                    "No se pudo abrir el puerto {port} ({e}). Otro programa lo está usando — cambia el puerto en la configuración del agente."
                );
                crate::state::log_line(&msg);
                state.set_bind_error(Some(msg));
                state.bound_port.store(0, std::sync::atomic::Ordering::SeqCst);
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                    _ = state.server_reload.notified() => {}
                }
            }
        }
    }
}
