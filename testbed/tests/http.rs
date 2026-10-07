use agentcore::http_server;
use agentcore::state::{AgentConfig, AppState};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

// El env de la impresora falsa es global del proceso -> serializar los tests.
static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const ORIGIN: &str = "https://facturacion-web-nine.vercel.app";
const PULSE: [u8; 5] = [0x1B, 0x70, 0x00, 0x19, 0xFA];

struct Env {
    state: Arc<AppState>,
    port: u16,
    token: String,
    printer_dir: PathBuf,
    data_dir: PathBuf,
    c: reqwest::Client,
}

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agt-{}-{}-{}", std::process::id(), tag, free_port()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

async fn start(tag: &str, legacy: bool) -> Env {
    let printer_dir = tmpdir(&format!("{tag}-p"));
    let data_dir = tmpdir(&format!("{tag}-d"));
    std::env::set_var("AGENTE_FAKE_PRINTER_DIR", &printer_dir);
    std::env::set_var("AGENTE_DATA_DIR", &data_dir);
    let mut cfg = AgentConfig::default();
    cfg.port = free_port();
    cfg.legacy_routes = legacy;
    let token = cfg.pairing_token.clone();
    let port = cfg.port;
    let state = Arc::new(AppState::new_in(cfg, data_dir.clone()));
    tokio::spawn(http_server::run(state.clone()));
    let e = Env { state, port, token, printer_dir, data_dir, c: reqwest::Client::new() };
    for _ in 0..50 {
        if e.get("/v1/health").await.0 == 200 {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("el servidor no arrancó");
}

impl Env {
    fn url(&self, p: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.port, p)
    }
    async fn get(&self, p: &str) -> (u16, Value) {
        let r = self.c.get(self.url(p)).header("Origin", ORIGIN).header("X-Agent-Token", &self.token).send().await;
        match r {
            Ok(r) => { let s = r.status().as_u16(); (s, r.json().await.unwrap_or(Value::Null)) }
            Err(_) => (0, Value::Null),
        }
    }
    async fn post(&self, p: &str, body: Value) -> (u16, Value) {
        let r = self.c.post(self.url(p)).header("Origin", ORIGIN).header("X-Agent-Token", &self.token).json(&body).send().await.unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }
    fn jobs(&self) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir(&self.printer_dir).unwrap().filter_map(|e| e.ok()).map(|e| e.path())
            .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("job-")).collect();
        v.sort();
        v
    }
    fn fail(&self, on: bool) {
        let f = self.printer_dir.join("FAIL");
        if on { std::fs::write(f, "x").unwrap(); } else { let _ = std::fs::remove_file(f); }
    }
}

fn ticket(with_pulse: bool) -> String {
    let mut d = b"TICKET\n".to_vec();
    if with_pulse { d.extend_from_slice(&PULSE); }
    d.extend_from_slice(b"FIN\n");
    STANDARD.encode(d)
}

fn invoice_json() -> Value {
    json!({
        "business_name":"Mi Negocio","tax_id":"131000000","business_address":"Calle 1","business_phone":"809",
        "created_at":"2026-01-01","local_ticket_number":"T-1","cashier_name":"Ana","customer_name":null,
        "doc_type":"B01","ncf":"B0100000001","items":[{"name":"Cafe","quantity":2.0,"unit_price":118.0}],
        "subtotal":200.0,"tax_amount":36.0,"discount_amount":0.0,"total":236.0,"payment_method":"cash",
        "footer":"Gracias","logo":null
    })
}

#[tokio::test]
async fn seguridad_y_rutas_legacy() {
    let _g = LOCK.lock().await;
    let e = start("seg", false).await;
    // sin token
    let r = e.c.get(e.url("/v1/health")).header("Origin", ORIGIN).send().await.unwrap();
    assert_eq!(r.status(), 401);
    // origen incorrecto
    let r = e.c.get(e.url("/v1/health")).header("Origin", "https://evil.com").header("X-Agent-Token", &e.token).send().await.unwrap();
    assert_eq!(r.status(), 403);
    // legacy apagado -> 404 en rutas sin /v1
    let r = e.c.get(e.url("/health")).header("Origin", ORIGIN).header("X-Agent-Token", &e.token).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let (s, h) = e.get("/v1/health").await;
    assert_eq!(s, 200);
    assert_eq!(h["queued"], 0);
}

#[tokio::test]
async fn legacy_activado_responde() {
    let _g = LOCK.lock().await;
    let e = start("leg", true).await;
    assert_eq!(e.get("/health").await.0, 200);
    assert_eq!(e.get("/v1/health").await.0, 200);
}

#[tokio::test]
async fn config_defaults_y_migracion() {
    let c = AgentConfig::default();
    assert_eq!(c.port, 17890);
    assert!(!c.legacy_routes);
    // config vieja (sin legacy_routes, puerto 9100): conserva puerto y legacy=true
    let old = json!({"pairing_token":"t","allowed_origin":"o","port":9100,"default_printer":null,"autostart":true});
    let c2: AgentConfig = serde_json::from_value(old).unwrap();
    assert_eq!(c2.port, 9100);
    assert!(c2.legacy_routes);
}

#[tokio::test]
async fn imprime_registra_gaveta_y_filtra_since() {
    let _g = LOCK.lock().await;
    let e = start("gav", false).await;
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(true), "jobId":"j1"})).await;
    assert_eq!((s, b["ok"].clone(), b["drawerOpened"].clone()), (200, json!(true), json!(true)));
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(false), "jobId":"j2"})).await;
    assert_eq!((s, b["drawerOpened"].clone()), (200, json!(false)));
    assert_eq!(e.jobs().len(), 2);
    let (_, log) = e.get("/v1/drawer-log").await;
    let ev = log["events"].as_array().unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["jobId"], "j1");
    assert_eq!(ev[0]["pulses"], 1);
    let ts = ev[0]["ts"].as_u64().unwrap();
    let (_, log2) = e.get(&format!("/v1/drawer-log?since={ts}")).await;
    assert_eq!(log2["events"].as_array().unwrap().len(), 0);
    let (_, log3) = e.get(&format!("/v1/drawer-log?since={}", ts - 1)).await;
    assert_eq!(log3["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn dedupe_mismo_jobid() {
    let _g = LOCK.lock().await;
    let e = start("dup", false).await;
    let (_, a) = e.post("/v1/print", json!({"dataBase64": ticket(true), "jobId":"same"})).await;
    assert_eq!(a["ok"], true);
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(true), "jobId":"same"})).await;
    assert_eq!(s, 200);
    assert_eq!(b["deduped"], true);
    assert_eq!(e.jobs().len(), 1);
    // la gaveta tampoco se registra dos veces
    assert_eq!(e.get("/v1/drawer-log").await.1["events"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn fallo_no_queda_como_duplicado() {
    let _g = LOCK.lock().await;
    let e = start("forget", false).await;
    e.fail(true);
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(false), "jobId":"x1"})).await;
    assert_eq!((s, b["error"].clone()), (500, json!("FALLO_DE_IMPRESION")));
    assert_eq!(e.get("/v1/queue").await.1["count"], 0, "sin retry no se encola");
    e.fail(false);
    // reintento manual inmediato: DEBE imprimir (antes devolvía deduped sin imprimir)
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(false), "jobId":"x1"})).await;
    assert_eq!(s, 200);
    assert!(b.get("deduped").is_none());
    assert_eq!(e.jobs().len(), 1);
}

#[tokio::test]
async fn cola_reintenta_sin_abrir_gaveta() {
    let _g = LOCK.lock().await;
    let e = start("q", false).await;
    e.fail(true);
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(true), "jobId":"fis-1", "retry": true})).await;
    assert_eq!(s, 202);
    assert_eq!((b["queued"].clone(), b["ok"].clone(), b["drawerOpened"].clone()), (json!(true), json!(false), json!(false)));
    let q = e.get("/v1/queue").await.1;
    assert_eq!(q["count"], 1);
    assert!(q["jobs"][0].get("payload").is_none());
    // reenvío del mismo job mientras está en cola: no duplica
    let (s, b) = e.post("/v1/print", json!({"dataBase64": ticket(true), "jobId":"fis-1", "retry": true})).await;
    assert_eq!((s, b["deduped"].clone()), (202, json!(true)));
    assert_eq!(e.get("/v1/queue").await.1["count"], 1);
    // sigue fallando: se reprograma, no se pierde
    assert_eq!(e.post("/v1/queue/retry-now", json!({"jobId":"fis-1"})).await.1["ok"], true);
    tokio::time::sleep(Duration::from_millis(3500)).await;
    let q = e.get("/v1/queue").await.1;
    assert_eq!(q["count"], 1);
    assert!(q["jobs"][0]["attempts"].as_u64().unwrap() >= 2);
    // vuelve la impresora
    e.fail(false);
    e.post("/v1/queue/retry-now", json!({"jobId":"fis-1"})).await;
    let mut ok = false;
    for _ in 0..40 {
        if e.get("/v1/queue").await.1["count"] == 0 { ok = true; break; }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(ok, "la cola debía vaciarse");
    let jobs = e.jobs();
    assert_eq!(jobs.len(), 1);
    let bytes = std::fs::read(&jobs[0]).unwrap();
    assert!(bytes.starts_with(b"TICKET"));
    assert!(!bytes.windows(2).any(|w| w == [0x1B, 0x70]), "el reintento NO debe llevar pulso de gaveta");
    assert_eq!(e.get("/v1/drawer-log").await.1["events"].as_array().unwrap().len(), 0);
    // y como ya salió, ahora un reenvío del mismo job imprime? no: ya no está en cola ni en reciente -> imprime otra vez (decisión de la web)
}

#[tokio::test]
async fn errores_de_validacion_no_se_encolan() {
    let _g = LOCK.lock().await;
    let e = start("val", false).await;
    let (s, b) = e.post("/v1/print", json!({"dataBase64": "###", "jobId":"v1", "retry": true})).await;
    assert_eq!((s, b["error"].clone()), (422, json!("BASE64_INVALIDO")));
    let (s, _) = e.post("/v1/print", json!({"jobId":"v2", "retry": true})).await;
    assert_eq!(s, 422);
    assert_eq!(e.get("/v1/queue").await.1["count"], 0);
}

#[tokio::test]
async fn retry_sin_jobid_no_encola() {
    let _g = LOCK.lock().await;
    let e = start("nojob", false).await;
    e.fail(true);
    let (s, _) = e.post("/v1/print", json!({"dataBase64": ticket(false), "retry": true})).await;
    assert_eq!(s, 500);
    assert_eq!(e.get("/v1/queue").await.1["count"], 0);
}

#[tokio::test]
async fn cancelar_de_la_cola() {
    let _g = LOCK.lock().await;
    let e = start("cancel", false).await;
    e.fail(true);
    e.post("/v1/print", json!({"dataBase64": ticket(false), "jobId":"c1", "retry": true})).await;
    assert_eq!(e.post("/v1/queue/cancel", json!({"jobId":"c1"})).await.1["ok"], true);
    assert_eq!(e.post("/v1/queue/cancel", json!({"jobId":"c1"})).await.1["ok"], false);
    assert_eq!(e.get("/v1/queue").await.1["count"], 0);
}

#[tokio::test]
async fn a4_se_encola_y_reimprime_con_el_mismo_contenido() {
    let _g = LOCK.lock().await;
    let e = start("a4", false).await;
    e.fail(true);
    let (s, _) = e.post("/v1/print", json!({"paperSize":"a4","invoice": invoice_json(), "jobId":"a4-1", "retry": true})).await;
    assert_eq!(s, 202);
    e.fail(false);
    e.post("/v1/queue/retry-now", json!({"jobId":"a4-1"})).await;
    for _ in 0..40 {
        if e.get("/v1/queue").await.1["count"] == 0 { break; }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let jobs = e.jobs();
    assert_eq!(jobs.len(), 1);
    let doc: Value = serde_json::from_slice(&std::fs::read(&jobs[0]).unwrap()).unwrap();
    assert_eq!(doc["ncf"], "B0100000001");
    assert_eq!(doc["total"], 236.0);
    assert_eq!(doc["items"][0]["name"], "Cafe");
}

#[tokio::test]
async fn cola_sobrevive_a_reinicio() {
    let _g = LOCK.lock().await;
    let e = start("persist", false).await;
    e.fail(true);
    e.post("/v1/print", json!({"dataBase64": ticket(false), "jobId":"p1", "retry": true})).await;
    let dir = e.data_dir.clone();
    // "reinicio": un AppState nuevo sobre la misma carpeta ve el trabajo
    let st2 = AppState::new_in(AgentConfig::default(), dir);
    assert_eq!(st2.queue().len(), 1);
    assert!(st2.queue().contains("p1"));
}

#[tokio::test]
async fn bind_ocupado_se_reporta_y_se_recupera_al_cambiar_puerto() {
    let _g = LOCK.lock().await;
    let printer_dir = tmpdir("bind-p");
    let data_dir = tmpdir("bind-d");
    std::env::set_var("AGENTE_FAKE_PRINTER_DIR", &printer_dir);
    std::env::set_var("AGENTE_DATA_DIR", &data_dir);
    let ocupado = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy_port = ocupado.local_addr().unwrap().port();
    let mut cfg = AgentConfig::default();
    cfg.port = busy_port;
    let token = cfg.pairing_token.clone();
    let state = Arc::new(AppState::new_in(cfg, data_dir));
    tokio::spawn(http_server::run(state.clone()));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let err = state.bind_error().expect("debe reportar el error de bind");
    assert!(err.contains(&busy_port.to_string()));
    assert_eq!(state.bound_port.load(std::sync::atomic::Ordering::SeqCst), 0);
    // el usuario cambia el puerto -> el servidor se recupera solo
    let new_port = free_port();
    state.lock().port = new_port;
    state.server_reload.notify_one();
    let c = reqwest::Client::new();
    let mut ok = false;
    for _ in 0..30 {
        if let Ok(r) = c.get(format!("http://127.0.0.1:{new_port}/v1/health")).header("X-Agent-Token", &token).send().await {
            if r.status() == 200 { ok = true; break; }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok);
    assert!(state.bind_error().is_none());
    assert_eq!(state.bound_port.load(std::sync::atomic::Ordering::SeqCst), new_port);
    drop(ocupado);
}

#[tokio::test]
async fn cambio_de_puerto_en_caliente_cierra_el_viejo() {
    let _g = LOCK.lock().await;
    let e = start("hot", false).await;
    let old = e.port;
    let newp = free_port();
    e.state.lock().port = newp;
    e.state.server_reload.notify_one();
    let c = reqwest::Client::new();
    let mut ok = false;
    for _ in 0..30 {
        if let Ok(r) = c.get(format!("http://127.0.0.1:{newp}/v1/health")).header("X-Agent-Token", &e.token).send().await {
            if r.status() == 200 { ok = true; break; }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(ok, "debe atender en el puerto nuevo");
    assert!(c.get(format!("http://127.0.0.1:{old}/v1/health")).send().await.is_err(), "el puerto viejo debe cerrarse");
}
