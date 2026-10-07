# Contrato web ↔ agente local — v1.2 (agente 1.2.0)

Todas las rutas van bajo `/v1`, con las cabeceras de siempre: `X-Agent-Token`, `Content-Type: application/json` y el `Origin` configurado.
Puerto por defecto **17890** (antes 9100). Un agente que ya estaba instalado conserva su puerto; el negocio solo cambia `agent_url` en Configuración si cambia el puerto.

## 1. `POST /v1/print` — campos nuevos

| Campo | Tipo | Significado |
|---|---|---|
| `jobId` | string | Id estable del trabajo (usa `invoice.id`). Obligatorio para reintentos. |
| `retry` | boolean | `true` = si la impresora falla de forma definitiva, **no devuelvas error: guarda el trabajo en la cola persistente del agente** y reintenta solo. Úsalo en comprobantes fiscales ya emitidos (NCF). |

Respuestas:

| HTTP | Cuerpo | Qué hacer en la web |
|---|---|---|
| 200 | `{ok:true, drawerOpened:boolean}` | Impreso. Si `drawerOpened`, sincroniza la gaveta (§3). |
| 200 | `{ok:true, deduped:true}` | Mismo `jobId` en los últimos 60 s: **no se imprimió otra vez**. |
| **202** | `{ok:false, queued:true, jobId, error, detail}` | **No salió, pero quedó en cola** y se reintenta sola (5 s, 15 s, 30 s, 1 min, 2 min, luego cada 5 min; vence a las 24 h o 30 intentos). Muestra "Pendiente de imprimir" y consulta la cola (§2). No lo trates como error ni reintentes tú. |
| 202 | `{queued:true, deduped:true}` | Ya estaba en cola; no se duplicó. |
| 500 | `{error:"FALLO_DE_IMPRESION"}` | Falló y **no** se encoló (no mandaste `retry`/`jobId`, o la cola está llena). |
| 504 | `{error:"IMPRESION_TIMEOUT"}` | **Resultado incierto**: el ticket pudo haber salido. Nunca se encola ni se reintenta solo (evita imprimir doble un comprobante fiscal). Pregunta al cajero. |
| 422 | `BASE64_INVALIDO`, `FALTA_DATA_BASE64_O_INVOICE`, `SIN_IMPRESORA_CONFIGURADA` | Error de datos o de configuración; no se encola. |

Corrección de un bug anterior: si un trabajo **fallaba**, el mismo `jobId` quedaba marcado 60 s como "reciente" y el reintento manual del cajero respondía `deduped` **sin imprimir nada**. Ahora un fallo libera el `jobId`.

Los reintentos desde la cola **quitan el comando de abrir gaveta** del ticket: la gaveta no se abre sola horas después.

## 2. Cola de reintentos

- `GET /v1/queue` → `{count, jobs:[{jobId, createdAt, attempts, nextAt, lastError}], expired:[…]}` (sin el contenido del ticket).
- `POST /v1/queue/retry-now` `{jobId}` → adelanta el próximo intento. `{ok:boolean}`
- `POST /v1/queue/cancel` `{jobId}` → descarta el trabajo (el cajero decide reimprimir a mano). `{ok:boolean}`
- `GET /v1/health` ahora incluye `queued` (cuántos esperan).

La cola vive en `%APPDATA%\AgenteImpresionFacturacion\cola_impresion.json` y sobrevive a reinicios del agente y de la PC. Los trabajos vencidos quedan en `expired` (últimos 50) y en `agente.log`.

## 3. Aperturas de gaveta

El agente anota cada apertura (ticket impreso con `ESC p` / `DLE DC4`) en `gaveta.jsonl`.

- `GET /v1/drawer-log?since=<ts>&limit=200` → `{events:[{ts, jobId, printer, pulses}]}` (`ts` en segundos Unix, más viejo primero).
- La web, al conectarse y después de cada venta con gaveta, guarda en el navegador el último `ts` sincronizado, pide los eventos posteriores y por cada uno llama a **`POST /api/audit/drawer-open`** `{job_id, printer, pulses, occurred_at}` (idempotente por `job_id`; `occurred_at` = `new Date(ts*1000).toISOString()`).

## 4. Comanda / ticket de entrega de pedidos móviles (backend)

- `GET /api/mobile-orders/:id/ticket` → datos estructurados (negocio, cliente, dirección, zona, pago, renglones con total de línea, totales, `printed_at`, `print_count`).
- `POST /api/mobile-orders/:id/ticket-printed` `{job_id?}` → se llama **después** de que el agente confirmó. Idempotente por `job_id`. Responde `{ok, printed_at, print_count, duplicate}`.
- `GET /api/mobile-orders` ya devuelve `printed_at` y `print_count` (para mostrar "sin imprimir").

## 5. Fragmentos para `frontend/src/lib/print.js`

> `print.js` y `ticketFormat.js` no estaban en el árbol que se revisó; estos fragmentos son el contrato exacto — adáptalos a tus funciones.

```js
// Enviar un comprobante fiscal con reintento persistente
export async function printFiscal(settings, bytesBase64, invoiceId) {
  const r = await agentFetch(settings, '/v1/print', 'POST', {
    dataBase64: bytesBase64, jobId: invoiceId, retry: true,
  });
  if (r.status === 202) return { state: 'queued' };          // pendiente: el agente lo reintenta
  if (r.status === 200) return { state: 'printed', drawerOpened: !!r.body.drawerOpened, deduped: !!r.body.deduped };
  if (r.status === 504) return { state: 'unknown' };         // ¿salió? preguntar al cajero
  return { state: 'error', error: r.body?.error };
}

// Sincronizar aperturas de gaveta (llamar al abrir el POS y tras cada venta)
export async function syncDrawerLog(settings, api) {
  const key = 'drawer_last_ts';
  const since = Number(localStorage.getItem(key) || 0);
  const r = await agentFetch(settings, `/v1/drawer-log?since=${since}&limit=200`, 'GET');
  if (r.status !== 200) return;
  let last = since;
  for (const e of r.body.events) {
    const res = await api.post('/audit/drawer-open', {
      job_id: e.jobId || `drawer-${e.ts}`, printer: e.printer, pulses: e.pulses,
      occurred_at: new Date(e.ts * 1000).toISOString(),
    });
    if (res.ok) last = Math.max(last, e.ts); else break;     // reintenta mañana desde donde quedó
  }
  localStorage.setItem(key, String(last));
}

// Comanda de un pedido móvil: datos del backend → bytes ESC/POS → agente → marcar impreso
export async function printMobileOrderTicket(settings, api, orderId) {
  const t = await api.get(`/mobile-orders/${orderId}/ticket`);
  const jobId = `mo-${orderId}-${t.print_count + 1}`;
  const bytes = buildMobileOrderTicketEscPos(t);             // nueva función en ticketFormat.js
  const r = await agentFetch(settings, '/v1/print', 'POST', { dataBase64: bytes, jobId });
  if (r.status === 200) await api.post(`/mobile-orders/${orderId}/ticket-printed`, { job_id: jobId });
  return r;
}
```

## 6. Configuración del agente

Ventana del agente: **puerto** editable (se aplica sin reiniciar), estado en vivo ("Escuchando en 127.0.0.1:17890 ✔" o el error si el puerto está ocupado — se reintenta cada 10 s), cola pendiente y casilla de compatibilidad con rutas sin `/v1` (apagada en instalaciones nuevas; las existentes la conservan encendida hasta que la apagues).
