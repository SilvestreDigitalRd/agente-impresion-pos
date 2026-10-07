// Este archivo SOLO llama a comandos de Rust definidos a medida
// (get_status, regenerate_token, list_printers_cmd, save_settings,
// check_agent_update, install_agent_update). No usa fs, shell, dialog ni
// ningún plugin genérico de Tauri — no tiene permisos para ello (ver
// src-tauri/capabilities/default.json). Los dos comandos de actualización
// tampoco están detrás de un permiso `updater:*`: son comandos de app
// comunes, iguales a los demás — el plugin del updater se usa SOLO desde
// Rust (ver updater.rs).
const { invoke, Channel } = window.__TAURI__.core;

async function loadStatus() {
  const s = await invoke('get_status');
  document.getElementById('token').value = s.pairing_token;
  document.getElementById('origin').value = s.allowed_origin;
  document.getElementById('autostart').checked = s.autostart;
  document.getElementById('agentVersion').textContent = s.agent_version;
  document.getElementById('port').value = s.port;
  document.getElementById('legacyRoutes').checked = s.legacy_routes;
  renderRuntimeStatus(s);
  await loadPrinters(s.default_printer);
}

// Estado vivo del servidor local: si el puerto no se pudo abrir (otro programa
// lo usa) se muestra aquí en rojo — antes el error se perdía sin que nadie lo viera.
function renderRuntimeStatus(s) {
  const ps = document.getElementById('portStatus');
  if (s.bind_error) {
    ps.textContent = `⚠ ${s.bind_error}`;
    ps.style.color = '#b00020';
  } else if (s.bound_port) {
    ps.textContent = `Escuchando en 127.0.0.1:${s.bound_port} ✔`;
    ps.style.color = '';
  } else {
    ps.textContent = 'Iniciando servidor…';
    ps.style.color = '';
  }
  document.getElementById('queueStatus').textContent = s.queued > 0
    ? `⏳ ${s.queued} impresión(es) pendiente(s) de reintento (se reintentan solas).`
    : '';
}

async function refreshRuntimeStatus() {
  try { renderRuntimeStatus(await invoke('get_status')); } catch (_) { /* ventana cerrándose */ }
}
setInterval(refreshRuntimeStatus, 5000);

async function loadPrinters(selected) {
  const select = document.getElementById('printerSelect');
  select.innerHTML = '<option value="">Cargando…</option>';
  try {
    const printers = await invoke('list_printers_cmd');
    select.innerHTML = '';
    if (printers.length === 0) {
      select.innerHTML = '<option value="">(ninguna impresora detectada)</option>';
      return;
    }
    for (const name of printers) {
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      if (name === selected) opt.selected = true;
      select.appendChild(opt);
    }
  } catch (e) {
    select.innerHTML = `<option value="">Error: ${e}</option>`;
  }
}

document.getElementById('copyToken').addEventListener('click', async () => {
  const token = document.getElementById('token').value;
  await navigator.clipboard.writeText(token);
  const msg = document.getElementById('tokenMsg');
  msg.textContent = 'Copiado ✔';
  setTimeout(() => (msg.textContent = ''), 2000);
});

document.getElementById('regenToken').addEventListener('click', async () => {
  if (!confirm('Esto invalida la clave anterior. Tendrás que actualizarla también en Configuración → Agente local del sistema web. ¿Continuar?')) return;
  const newToken = await invoke('regenerate_token');
  document.getElementById('token').value = newToken;
});

document.getElementById('refreshPrinters').addEventListener('click', () => loadPrinters());

document.getElementById('save').addEventListener('click', async () => {
  const msg = document.getElementById('saveMsg');
  const allowed_origin = document.getElementById('origin').value.trim();
  const default_printer = document.getElementById('printerSelect').value || null;
  const autostart = document.getElementById('autostart').checked;
  const port = parseInt(document.getElementById('port').value, 10);
  const legacy_routes = document.getElementById('legacyRoutes').checked;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) {
    msg.textContent = 'El puerto debe ser un número entre 1024 y 65535.';
    return;
  }
  try {
    // save_settings ahora devuelve Option<String>: null si todo salió bien,
    // o un aviso si autostart falló pero el resto (impresora/origen) SÍ se
    // guardó igual (antes un error de autostart perdía todo el cambio en
    // silencio — ver la nota larga en main.rs).
    const autostartWarning = await invoke('save_settings', { allowedOrigin: allowed_origin, defaultPrinter: default_printer, autostart, port, legacyRoutes: legacy_routes });
    msg.textContent = autostartWarning
      ? `Guardado ✔ — impresora y origen aplicados. ${autostartWarning}`
      : 'Guardado ✔ — los cambios (origen, puerto, rutas) ya están aplicados. Si cambiaste el puerto, actualízalo también en Configuración → Agente local del sistema web.';
    setTimeout(refreshRuntimeStatus, 800);
  } catch (e) {
    // Antes: sin try/catch, esto quedaba como una promesa rechazada sin
    // manejar — el botón "no hacía nada" porque el error nunca llegaba a
    // ningún lado visible.
    msg.textContent = `No se pudo guardar: ${e}`;
  }
  setTimeout(() => (msg.textContent = ''), 6000);
});

/**
 * Auditoría, hallazgo B5. Comprueba si hay una versión más nueva y, si la
 * hay, instala directo (mismo comportamiento que el chequeo automático en
 * segundo plano — ver spawn_periodic_check en updater.rs — la diferencia
 * es que ACÁ el cajero ve el progreso en esta ventana). Si hay una
 * impresión en curso en ese momento, `install_agent_update` lo rechaza
 * con "PRINT_IN_PROGRESS" y se lo avisamos en vez de reintentar solos.
 */
async function checkForUpdate() {
  const msg = document.getElementById('updateMsg');
  const btn = document.getElementById('checkUpdate');
  btn.disabled = true;
  msg.textContent = 'Buscando actualización…';
  try {
    const status = await invoke('check_agent_update');
    if (!status.available) {
      msg.textContent = 'Ya tenés la última versión.';
      setTimeout(() => (msg.textContent = ''), 4000);
      return;
    }
    msg.textContent = `Versión ${status.version} disponible — descargando…`;
    await installUpdate(msg);
  } catch (e) {
    msg.textContent = `No se pudo comprobar actualización: ${e}`;
  } finally {
    btn.disabled = false;
  }
}

async function installUpdate(msg) {
  // Channel: forma que expone Tauri para recibir eventos de progreso de un
  // comando de Rust de larga duración — ver InstallProgress en updater.rs.
  const onEvent = new Channel();
  onEvent.onmessage = (progress) => {
    if (progress.phase === 'downloading') {
      const pct = progress.total ? Math.round((progress.downloaded / progress.total) * 100) : null;
      msg.textContent = pct != null
        ? `Descargando actualización… ${pct}%`
        : `Descargando actualización… (${progress.downloaded} bytes)`;
    } else if (progress.phase === 'installing') {
      msg.textContent = 'Instalando — el agente se va a reiniciar solo en unos segundos.';
    }
  };
  try {
    await invoke('install_agent_update', { onEvent });
    msg.textContent = 'Actualización instalada — el agente se está reiniciando…';
  } catch (e) {
    if (e === 'PRINT_IN_PROGRESS') {
      msg.textContent = 'Hay una impresión en curso justo ahora — probá de nuevo en un momento.';
    } else {
      msg.textContent = `No se pudo instalar la actualización: ${e}`;
    }
  }
}

document.getElementById('checkUpdate').addEventListener('click', checkForUpdate);

// Llamado desde Rust cuando se toca "Buscar actualización" en el menú de
// la bandeja (ver on_menu_event en main.rs, que hace w.eval(...) contra
// esto) — el clic llegó del lado del menú nativo, no de este WebView, pero
// de acá en adelante el flujo es exactamente el mismo que tocar el botón
// de esta ventana.
window.__checkAgentUpdateFromTray = checkForUpdate;

loadStatus();
