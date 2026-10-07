use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

/// Configuración persistente del agente. Se guarda en
/// `%APPDATA%\AgenteImpresionFacturacion\config.json` — NUNCA en un lugar
/// accesible por la web ni transmitido salvo el campo que corresponde a cada
/// endpoint.
#[derive(Serialize, Deserialize, Clone)]
pub struct AgentConfig {
    /// Clave de emparejamiento. Cada petición HTTP de la web debe traerla
    /// exacta en el encabezado `X-Agent-Token`. Se genera aleatoriamente al
    /// primer arranque — nunca se deriva de nada del backend SaaS, así que
    /// aunque alguien descompile este binario no obtiene ningún secreto que
    /// sirva contra otros tenants ni contra el backend.
    pub pairing_token: String,
    /// Origen exacto permitido (ej. "https://facturacion-web-nine.vercel.app").
    /// Cualquier petición cuyo header Origin no coincida EXACTO es rechazada
    /// antes de tocar la impresora.
    pub allowed_origin: String,
    pub port: u16,
    pub default_printer: Option<String>,
    pub autostart: bool,
    /// Rutas SIN prefijo `/v1` (`/print`, `/health`…) para webs viejas en
    /// caché. Una config existente que no tiene el campo conserva `true`
    /// (para no romper instalaciones ya emparejadas); una instalación NUEVA
    /// nace con `false`. Se puede apagar desde la ventana del agente.
    #[serde(default = "default_true")]
    pub legacy_routes: bool,
}

fn default_true() -> bool {
    true
}

/// Puerto por defecto. El 9100 es el puerto estándar de impresión RAW
/// (JetDirect) de las impresoras de red — chocaba con servicios de
/// impresión y con la propia impresora si el POS comparte equipo/red.
pub const DEFAULT_PORT: u16 = 17890;

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            pairing_token: generate_token(),
            allowed_origin: "https://facturacion-web-nine.vercel.app".to_string(),
            port: DEFAULT_PORT,
            default_printer: None,
            autostart: true,
            legacy_routes: false,
        }
    }
}

fn generate_token() -> String {
    // 32 bytes de entropía criptográfica → 64 caracteres hex. No es un JWT
    // ni depende de ningún secreto compartido con el backend: es una clave
    // de emparejamiento local, exclusiva de esta instalación del agente.
    let bytes: [u8; 32] = rand::thread_rng().gen();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Carpeta de datos del agente (`%APPDATA%\AgenteImpresionFacturacion`).
/// `AGENTE_DATA_DIR` la reemplaza (solo para pruebas automatizadas).
pub fn data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("AGENTE_DATA_DIR") {
        let p = PathBuf::from(d);
        fs::create_dir_all(&p).ok();
        return p;
    }
    let mut dir = dirs::config_dir().unwrap_or_else(|| PathBuf::from("."));
    dir.push("AgenteImpresionFacturacion");
    fs::create_dir_all(&dir).ok();
    dir
}

fn config_path() -> PathBuf {
    data_dir().join("config.json")
}

/// Log en disco muy simple — `eprintln!` no sirve para nada acá porque
/// `windows_subsystem = "windows"` (sin consola) se traga toda salida
/// estándar; sin esto, un problema en una PC de un cliente era
/// invisible por completo (auditoría, hallazgo M17). Sin rotación ni
/// dependencias nuevas a propósito — un archivo de texto plano que se
/// puede abrir y mandar por WhatsApp si hace falta soporte remoto.
pub fn log_line(msg: &str) {
    use std::io::Write;
    let dir = data_dir().join("agente.log");
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&dir) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = writeln!(f, "[{now}] {msg}");
    }
}

impl AgentConfig {
    pub fn load_or_create() -> Self {
        let path = config_path();
        if let Ok(raw) = fs::read_to_string(&path) {
            match serde_json::from_str::<AgentConfig>(&raw) {
                Ok(cfg) => return cfg,
                Err(e) => {
                    // Auditoría M17: antes esto pisaba el archivo corrupto en
                    // silencio con una config nueva — CON UN pairing_token
                    // NUEVO, lo que rompe el emparejamiento con el backend
                    // sin ningún aviso. Ahora el archivo dañado se guarda
                    // aparte (para poder mirarlo/recuperarlo a mano) y queda
                    // registrado en el log.
                    log_line(&format!("config.json no se pudo leer ({e}) — se hace backup y se crea una config nueva"));
                    let mut backup = path.clone();
                    backup.set_file_name("config.json.corrupto");
                    let _ = fs::rename(&path, &backup);
                }
            }
        }
        let cfg = AgentConfig::default();
        cfg.save();
        log_line("config.json creado desde cero (primera vez, o el anterior estaba corrupto)");
        cfg
    }

    pub fn save(&self) {
        let path = config_path();
        let Ok(json) = serde_json::to_string_pretty(self) else { return };
        // Escritura atómica (auditoría M17): escribir directo al archivo
        // final significa que un corte de luz/crash a mitad de la escritura
        // deja config.json truncado — el próximo arranque lo trataría como
        // corrupto (ver load_or_create) y regeneraría el pairing_token sin
        // que nadie lo pidiera. Escribir a un .tmp y renombrar es atómico
        // en el mismo filesystem: o queda el archivo viejo completo, o
        // queda el nuevo completo, nunca algo a medias.
        let mut tmp_path = path.clone();
        tmp_path.set_extension("json.tmp");
        if fs::write(&tmp_path, json).is_ok() {
            let _ = fs::rename(&tmp_path, &path);
        }
    }

    pub fn regenerate_token(&mut self) {
        self.pairing_token = generate_token();
        self.save();
    }
}

/// Comparación en tiempo constante — evita que un atacante mida diferencias
/// de tiempo de respuesta para adivinar la clave carácter por carácter.
/// El chequeo de longitud es intencionalmente EN TIEMPO CONSTANTE también
/// (no un `!=` corto-circuito): la longitud del token es fija (64 hex) y
/// pública, así que en la práctica no filtra nada — pero cerrar el vector
/// por completo no cuesta nada acá, así que se hace de una vez.
pub fn tokens_match(provided: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    // Normaliza ambos a un buffer de largo fijo (rellenado con ceros) antes
    // de comparar — ct_eq sobre buffers de largo distinto no compila (el
    // trait lo exige del mismo tamaño), así que esto es lo que permite
    // quitar el `if provided.len() != expected.len()` de antes sin perder
    // la comparación real.
    const MAX_LEN: usize = 128;
    let mut a = [0u8; MAX_LEN];
    let mut b = [0u8; MAX_LEN];
    let pb = provided.as_bytes();
    let eb = expected.as_bytes();
    if pb.len() > MAX_LEN || eb.len() > MAX_LEN {
        return false; // un token real (64 hex) nunca llega ni cerca de esto
    }
    a[..pb.len()].copy_from_slice(pb);
    b[..eb.len()].copy_from_slice(eb);
    // La longitud real todavía tiene que coincidir — si no, comparar el
    // contenido no alcanza (rellenar con ceros haría que "abc" calce contra
    // "abc\0\0\0..."). Se compara como enteros en vez de con `!=` sobre los
    // `usize` para no reintroducir la rama corto-circuito que se quería
    // evitar — aunque, igual que antes, la longitud de un token real ya es
    // pública y fija, esto es simplemente prolijidad, no una protección real.
    let len_matches: bool = pb.len().to_be_bytes().ct_eq(&eb.len().to_be_bytes()).into();
    let content_matches: bool = a.ct_eq(&b).into();
    len_matches & content_matches
}

pub struct AppState {
    config: Mutex<AgentConfig>,
    /// Carpeta de datos (cola de reintentos, gaveta.jsonl, logs).
    pub data_dir: PathBuf,
    /// Cola persistente de reintentos de impresión (ver queue.rs). Lock
    /// SIEMPRE breve y nunca a través de un `.await`.
    pub queue: Mutex<crate::queue::RetryQueue>,
    /// Último error al abrir el puerto (None = escuchando bien). La ventana
    /// del agente lo muestra — antes solo iba a `eprintln!`, invisible.
    pub bind_error: Mutex<Option<String>>,
    /// Puerto en el que el servidor está escuchando de verdad ahora (0 = ninguno).
    pub bound_port: std::sync::atomic::AtomicU16,
    /// Se dispara cuando cambian puerto o rutas legacy: el servidor se
    /// reinicia solo, sin cerrar el agente.
    pub server_reload: tokio::sync::Notify,
    // Auditoría, hallazgo B5: el actualizador nunca debe instalar a media
    // impresión — este contador (incrementado/decrementado por
    // `ActivePrintGuard`, ver más abajo) es lo que consulta
    // `install_agent_update` (en updater.rs) antes de descargar e instalar.
    // Vive acá (no en http_server.rs) porque tanto el servidor HTTP como
    // el comando de Tauri del updater necesitan verlo, y los dos ya
    // comparten este mismo `Arc<AppState>`.
    pub active_prints: std::sync::atomic::AtomicUsize,
}

impl AppState {
    pub fn new(config: AgentConfig) -> Self {
        Self::new_in(config, data_dir())
    }

    pub fn new_in(config: AgentConfig, dir: PathBuf) -> Self {
        let queue = crate::queue::RetryQueue::load(dir.join("cola_impresion.json"));
        Self {
            config: Mutex::new(config),
            data_dir: dir,
            queue: Mutex::new(queue),
            bind_error: Mutex::new(None),
            bound_port: std::sync::atomic::AtomicU16::new(0),
            server_reload: tokio::sync::Notify::new(),
            active_prints: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn queue(&self) -> std::sync::MutexGuard<'_, crate::queue::RetryQueue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn set_bind_error(&self, e: Option<String>) {
        *self.bind_error.lock().unwrap_or_else(|p| p.into_inner()) = e;
    }

    pub fn bind_error(&self) -> Option<String> {
        self.bind_error.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

/// RAII (auditoría, hallazgo B5 — mismo criterio que `PrinterHandleGuard`
/// en printer_win.rs para el HANDLE de impresora): se crea justo antes de
/// empezar a imprimir de verdad y se mantiene viva hasta el final de la
/// función que la creó, así que decrementa el contador SIEMPRE que esa
/// función retorna — éxito, error, pánico capturado por `spawn_blocking`,
/// o el camino de timeout que corta la espera sin cancelar el hilo de
/// fondo (ver comentario en http_server.rs::print). Sin esto, ese camino
/// de timeout dejaría el contador incrementado para siempre y el
/// actualizador nunca instalaría nada, creyendo que siempre hay una
/// impresión en curso.
pub struct ActivePrintGuard<'a> {
    state: &'a AppState,
}

impl<'a> ActivePrintGuard<'a> {
    pub fn new(state: &'a AppState) -> Self {
        state.active_prints.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Self { state }
    }
}

impl<'a> Drop for ActivePrintGuard<'a> {
    fn drop(&mut self) {
        self.state.active_prints.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl AppState {
    /// Lock que nunca se envenena. Antes, todo acceso usaba
    /// `state.0.lock().unwrap()` directo — si algún handler entraba en
    /// pánico sosteniendo el lock, el Mutex quedaba envenenado y TODA
    /// petición HTTP subsiguiente (incluido /health) empezaba a fallar,
    /// sin ningún log de la causa raíz, en una app pensada para correr
    /// desatendida en la bandeja del sistema. Ahora se recupera el estado
    /// que había en el momento del pánico (que sigue siendo válido — un
    /// pánico no corrompe los datos ya escritos) y se sigue, dejando un
    /// aviso en el log para poder investigar después.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, AgentConfig> {
        self.config.lock().unwrap_or_else(|poisoned| {
            eprintln!("AVISO: se recuperó el estado del agente después de un error interno (mutex envenenado) — revisar el log de arriba para la causa.");
            poisoned.into_inner()
        })
    }
}
