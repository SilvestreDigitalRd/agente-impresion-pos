// Este archivo SOLO llama a comandos de Rust definidos a medida
// (get_status, regenerate_token, list_printers_cmd, save_settings).
// No usa fs, shell, dialog ni ningún plugin genérico de Tauri — no tiene
// permisos para ello (ver src-tauri/capabilities/default.json).
const { invoke } = window.__TAURI__.core;

async function loadStatus() {
  const s = await invoke('get_status');
  document.getElementById('token').value = s.pairing_token;
  document.getElementById('origin').value = s.allowed_origin;
  document.getElementById('autostart').checked = s.autostart;
  await loadPrinters(s.default_printer);
}

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
  const allowed_origin = document.getElementById('origin').value.trim();
  const default_printer = document.getElementById('printerSelect').value || null;
  const autostart = document.getElementById('autostart').checked;
  await invoke('save_settings', { allowedOrigin: allowed_origin, defaultPrinter: default_printer, autostart });
  const msg = document.getElementById('saveMsg');
  msg.textContent = 'Guardado ✔ (si cambiaste el origen permitido, reinicia el agente para aplicarlo)';
  setTimeout(() => (msg.textContent = ''), 4000);
});

loadStatus();
