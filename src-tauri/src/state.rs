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
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            pairing_token: generate_token(),
            allowed_origin: "https://facturacion-web-nine.vercel.app".to_string(),
            port: 9100,
            default_printer: None,
            autostart: true,
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

fn config_path() -> PathBuf {
    let mut dir = dirs::config_dir().expect("no se pudo resolver %APPDATA%");
    dir.push("AgenteImpresionFacturacion");
    fs::create_dir_all(&dir).ok();
    dir.push("config.json");
    dir
}

impl AgentConfig {
    pub fn load_or_create() -> Self {
        let path = config_path();
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<AgentConfig>(&raw) {
                return cfg;
            }
        }
        let cfg = AgentConfig::default();
        cfg.save();
        cfg
    }

    pub fn save(&self) {
        let path = config_path();
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
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

pub struct AppState(pub Mutex<AgentConfig>);

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
        self.0.lock().unwrap_or_else(|poisoned| {
            eprintln!("AVISO: se recuperó el estado del agente después de un error interno (mutex envenenado) — revisar el log de arriba para la causa.");
            poisoned.into_inner()
        })
    }
}
