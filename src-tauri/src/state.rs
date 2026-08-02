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
pub fn tokens_match(provided: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if provided.len() != expected.len() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

pub struct AppState(pub Mutex<AgentConfig>);
