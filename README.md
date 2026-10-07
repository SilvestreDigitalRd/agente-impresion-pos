# Agente de Impresión — Facturación POS (versión Tauri / .exe)

Reemplaza al agente anterior en Node.js. Esta versión se distribuye como un
instalador `.msi`/`.exe` de Windows normal — doble clic, sin terminal, sin
instalar Node.js. Corre en la bandeja del sistema y arranca solo con Windows
(configurable).

## Novedades 1.1.0 (ronda 10b)

- **Cola de reintentos de impresión** para comprobantes fiscales (`retry:true`), persistente en disco.
- **Registro de aperturas de gaveta** (`gaveta.jsonl`, `GET /v1/drawer-log`) que la web sincroniza a la bitácora del sistema.
- **Puerto por defecto 17890** (el 9100 es el puerto de las impresoras de red); editable desde la ventana, se aplica sin reiniciar, y si el puerto está ocupado el error se muestra en la ventana en vez de perderse.
- **Rutas sin `/v1` desactivadas** en instalaciones nuevas (las existentes conservan la compatibilidad hasta que la apagues en la ventana).
- **Logo en A4/Carta**: tamaño acotado por ancho y por alto (28 mm), escalado entero al ampliar y `COLORONCOLOR` al reducir; si no cabe en la página, se omite en vez de dibujarse cortado.
- Corregido: un trabajo fallido ya no queda como "duplicado" 60 s.
- Contrato completo: `CONTRATO_WEB_AGENTE_v1.1.md`.

### Pruebas

`testbed/` compila los módulos sin Tauri y los prueba en cualquier sistema (40 pruebas: unitarias + servidor HTTP real con una impresora simulada):

```bash
cd testbed && cargo test -- --test-threads=1
```

**Lo que estas pruebas NO cubren:** todo el código específico de Windows (`printer_win.rs` módulo `win` de Windows: winspool y GDI, incluido el nuevo cálculo del logo con `SetStretchBltMode`) y `main.rs`/ventana. Esa parte hay que compilarla con el workflow de GitHub Actions y probarla con una impresora real (ticket con gaveta, A4 con logo, impresora apagada con `retry:true`).

## ⚠️ Aviso importante sobre este entregable

Este código fue escrito y revisado cuidadosamente, pero **no se compiló ni
se probó en este entorno** — el sandbox donde trabajo no tiene el toolchain
de Rust instalado (solo Node.js), así que no hay forma de verificarlo aquí
como sí hago con el resto del sistema (backend/frontend, que sí se
comprueban con `node --check` en cada entrega).

Antes de distribuirlo a un cliente real:
1. Compílalo (ver abajo — con GitHub Actions no necesitas instalar nada).
2. Pruébalo tú mismo con una impresora térmica real: listar impresoras,
   imprimir un ticket, verificar que un origen no autorizado sea rechazado.
3. Si `cargo tauri build` marca algún error, probablemente sea un ajuste
   menor de versión de alguna dependencia (windows-rs, axum o Tauri suelen
   renombrar algún método entre versiones) — son fixes de una línea, pero
   sí hace falta que alguien con Rust los revise la primera vez.

## Cómo compilar el instalador SIN instalar Rust localmente

Ya incluye un workflow de GitHub Actions (`.github/workflows/build-agent.yml`)
que compila el `.msi` y el `.exe` en un runner de Windows en la nube:

1. Sube esta carpeta a un repositorio de GitHub.
2. Ve a la pestaña **Actions** → el workflow corre solo al hacer push a
   `main` (o dispáralo manualmente con "Run workflow").
3. Cuando termine (unos 5-10 min), descarga el artefacto
   `agente-impresion-instaladores` — ahí están el `.msi` y el `.exe`.

## Cómo compilar localmente (si prefieres tener Rust instalado)

```bash
# Windows, con Rust ya instalado (https://rustup.rs)
cargo install tauri-cli --version "^2"
cargo tauri build
```

Genera los instaladores en `src-tauri/target/release/bundle/`.

## Iconos

Los archivos en `src-tauri/icons/` son un placeholder genérico (un ícono de
recibo verde) generado automáticamente — reemplázalos con el logo real del
negocio antes de distribuir. Lo más simple: pon tu logo en `logo.png`
(mínimo 1024×1024) y corre:
```bash
cargo tauri icon logo.png
```
Esto regenera automáticamente todos los tamaños/formatos necesarios.

## Qué hace y cómo se usa

1. Se instala una sola vez en la PC donde está conectada la impresora
   térmica.
2. Al abrir, muestra un ícono en la bandeja del sistema. Clic derecho →
   "Configuración…" abre una ventana pequeña con:
   - **Clave de emparejamiento** (generada automáticamente) — se copia UNA
     VEZ dentro del sistema web, en Configuración → Agente local.
   - **Origen permitido** — la URL exacta del sistema de facturación.
   - **Impresora** a usar (se detecta automáticamente, pero se puede fijar
     una específica).
   - **Iniciar con Windows** (activado por defecto).
3. Cerrar la ventana con la X solo la oculta — el agente sigue corriendo en
   segundo plano. Para cerrarlo de verdad: clic derecho en la bandeja → Salir.

## Seguridad — cómo se cubrió cada punto

| Medida | Cómo se implementó |
|---|---|
| Bind solo a loopback | `src/http_server.rs` fija `127.0.0.1` explícito — nunca `0.0.0.0` |
| CORS estricto | Un único origen exacto permitido (`tower_http::cors::CorsLayer`); como el POST exige `Content-Type: application/json` + header custom, el navegador siempre hace preflight — una pestaña maliciosa no puede leer la respuesta si su origen no coincide |
| Token de autenticación | Clave de emparejamiento aleatoria (32 bytes), generada localmente al primer arranque — nunca comparte secretos con el backend SaaS. Comparación en tiempo constante (`subtle::ConstantTimeEq`) contra ataques de timing |
| Cero inyección de comandos | Impresión 100% vía la API nativa de Windows (`OpenPrinter`/`WritePrinter` del crate `windows-rs`) — no existe ninguna llamada a `cmd.exe` ni `Command::new(...)` en todo el proyecto |
| Tauri Scoping | Sin plugins de `fs`, `shell`, `dialog` ni `http` habilitados en `Cargo.toml` ni en `capabilities/default.json`. El webview solo puede llamar 4 comandos propios (`get_status`, `regenerate_token`, `list_printers_cmd`, `save_settings`) — nada más |

**Nota sobre el diseño del token** (difiere un poco de la sugerencia
original de usar el JWT de sesión): un secreto de emparejamiento generado
localmente por el agente, en vez de derivar el token del login del backend,
evita el riesgo mucho mayor de tener que incrustar el secreto de firma JWT
del SaaS dentro de un binario que se distribuye a cada cliente — si alguien
lo extrajera por ingeniería inversa, comprometería la autenticación de
*todos* los negocios del SaaS, no solo el suyo.

**Fuera de alcance, honestamente:** un programa malicioso que ya corre en
esa misma PC con los permisos del usuario (no una pestaña de navegador)
podría leer el archivo de configuración (`%APPDATA%\AgenteImpresionFacturacion\config.json`)
igual que cualquier otro proceso local. Eso es un problema de seguridad del
sistema operativo del cliente — ningún diseño de servidor en loopback puede
prevenirlo por sí solo.
