//! Cola persistente de reintentos de impresión (ronda 10b).
//!
//! Problema: una factura fiscal (NCF) YA emitida cuya impresión falla (papel
//! agotado, impresora apagada, spooler caído) se perdía: el cajero veía un
//! error y el comprobante físico nunca salía. Ahora, si la web manda
//! `retry: true` + `jobId`, un fallo DEFINITIVO de impresión no se devuelve
//! como error: el trabajo entra a esta cola, se guarda en disco (sobrevive a
//! reinicios del agente/PC) y un worker lo reintenta con espera creciente
//! hasta que imprime o vence.
//!
//! Este módulo es PURO: el reloj entra por parámetro (`now`, segundos Unix) y
//! no llama a la impresora — así se prueba en cualquier plataforma. El
//! worker real vive en http_server.rs.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

pub const MAX_ATTEMPTS: u32 = 30;
pub const MAX_AGE_SECS: u64 = 24 * 3600;
pub const MAX_QUEUE: usize = 200;
const MAX_EXPIRED_KEPT: usize = 50;

/// Espera antes del próximo intento, según los intentos ya hechos.
pub fn backoff_secs(attempts: u32) -> u64 {
    match attempts {
        0 | 1 => 5,
        2 => 15,
        3 => 30,
        4 => 60,
        5 => 120,
        _ => 300,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct QueuedJob {
    pub job_id: String,
    /// El cuerpo original del POST /v1/print (JSON), para reimprimir idéntico.
    pub payload: serde_json::Value,
    pub created_at: u64,
    pub attempts: u32,
    pub next_at: u64,
    pub last_error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExpiredJob {
    pub job_id: String,
    pub created_at: u64,
    pub expired_at: u64,
    pub attempts: u32,
    pub last_error: Option<String>,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct JobSummary {
    #[serde(rename = "jobId")]
    pub job_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    pub attempts: u32,
    #[serde(rename = "nextAt")]
    pub next_at: u64,
    #[serde(rename = "lastError")]
    pub last_error: Option<String>,
}

#[derive(Debug, PartialEq)]
pub enum FailOutcome {
    Rescheduled { next_at: u64 },
    Expired,
    Unknown,
}

#[derive(Debug, PartialEq)]
pub enum EnqueueResult {
    Queued,
    AlreadyQueued,
    Full,
}

#[derive(Serialize, Deserialize, Default)]
struct Disk {
    jobs: Vec<QueuedJob>,
    expired: Vec<ExpiredJob>,
}

pub struct RetryQueue {
    jobs: Vec<QueuedJob>,
    expired: Vec<ExpiredJob>,
    in_flight: HashSet<String>,
    path: Option<PathBuf>,
}

impl RetryQueue {
    pub fn in_memory() -> Self {
        Self { jobs: vec![], expired: vec![], in_flight: HashSet::new(), path: None }
    }

    /// Carga desde disco; archivo ausente = cola vacía; archivo corrupto se
    /// aparta como `.corrupto` (no se pierde silenciosamente) y se arranca vacía.
    pub fn load(path: PathBuf) -> Self {
        let mut q = Self::in_memory();
        if let Ok(raw) = std::fs::read_to_string(&path) {
            match serde_json::from_str::<Disk>(&raw) {
                Ok(d) => {
                    q.jobs = d.jobs;
                    q.expired = d.expired;
                }
                Err(_) => {
                    let mut bak = path.clone();
                    bak.set_extension("json.corrupto");
                    let _ = std::fs::rename(&path, &bak);
                }
            }
        }
        q.path = Some(path);
        q
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let disk = Disk { jobs: self.jobs.clone(), expired: self.expired.clone() };
        let Ok(json) = serde_json::to_string(&disk) else { return };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Escritura atómica: .tmp + rename (mismo criterio que config.json).
        let mut tmp = path.clone();
        tmp.set_extension("json.tmp");
        if std::fs::write(&tmp, json).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    pub fn len(&self) -> usize {
        self.jobs.len()
    }

    pub fn contains(&self, job_id: &str) -> bool {
        self.jobs.iter().any(|j| j.job_id == job_id)
    }

    pub fn enqueue(&mut self, job_id: &str, payload: serde_json::Value, now: u64, error: &str) -> EnqueueResult {
        if self.contains(job_id) {
            return EnqueueResult::AlreadyQueued;
        }
        if self.jobs.len() >= MAX_QUEUE {
            return EnqueueResult::Full;
        }
        self.jobs.push(QueuedJob {
            job_id: job_id.to_string(),
            payload,
            created_at: now,
            attempts: 1, // el intento original que falló ya cuenta
            next_at: now + backoff_secs(1),
            last_error: Some(error.to_string()),
        });
        self.persist();
        EnqueueResult::Queued
    }

    /// Trabajos listos para reintentar. Quedan marcados "en vuelo" para que
    /// otra vuelta del worker no los tome mientras se están imprimiendo.
    pub fn take_due(&mut self, now: u64) -> Vec<QueuedJob> {
        let due: Vec<QueuedJob> = self
            .jobs
            .iter()
            .filter(|j| j.next_at <= now && !self.in_flight.contains(&j.job_id))
            .cloned()
            .collect();
        for j in &due {
            self.in_flight.insert(j.job_id.clone());
        }
        due
    }

    pub fn complete(&mut self, job_id: &str) -> bool {
        self.in_flight.remove(job_id);
        let before = self.jobs.len();
        self.jobs.retain(|j| j.job_id != job_id);
        let removed = self.jobs.len() != before;
        if removed {
            self.persist();
        }
        removed
    }

    pub fn fail(&mut self, job_id: &str, now: u64, error: &str) -> FailOutcome {
        self.in_flight.remove(job_id);
        let Some(idx) = self.jobs.iter().position(|j| j.job_id == job_id) else {
            return FailOutcome::Unknown;
        };
        let job = &mut self.jobs[idx];
        job.attempts += 1;
        job.last_error = Some(error.to_string());
        let too_old = now.saturating_sub(job.created_at) >= MAX_AGE_SECS;
        if job.attempts >= MAX_ATTEMPTS || too_old {
            let j = self.jobs.remove(idx);
            self.expired.push(ExpiredJob {
                job_id: j.job_id,
                created_at: j.created_at,
                expired_at: now,
                attempts: j.attempts,
                last_error: j.last_error,
            });
            if self.expired.len() > MAX_EXPIRED_KEPT {
                let drop = self.expired.len() - MAX_EXPIRED_KEPT;
                self.expired.drain(0..drop);
            }
            self.persist();
            return FailOutcome::Expired;
        }
        job.next_at = now + backoff_secs(job.attempts);
        let next_at = job.next_at;
        self.persist();
        FailOutcome::Rescheduled { next_at }
    }

    /// Cancelación manual (el cajero decide reimprimir a mano / descartar).
    pub fn cancel(&mut self, job_id: &str) -> bool {
        self.complete(job_id)
    }

    /// Fuerza que el próximo ciclo del worker lo tome ya.
    pub fn retry_now(&mut self, job_id: &str, now: u64) -> bool {
        let Some(j) = self.jobs.iter_mut().find(|j| j.job_id == job_id) else { return false };
        j.next_at = now;
        self.persist();
        true
    }

    pub fn summary(&self) -> Vec<JobSummary> {
        self.jobs
            .iter()
            .map(|j| JobSummary {
                job_id: j.job_id.clone(),
                created_at: j.created_at,
                attempts: j.attempts,
                next_at: j.next_at,
                last_error: j.last_error.clone(),
            })
            .collect()
    }

    pub fn expired(&self) -> Vec<ExpiredJob> {
        self.expired.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cola-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&d);
        d.join("cola.json")
    }

    #[test]
    fn backoff_crece_y_se_estanca() {
        let v: Vec<u64> = (0..9).map(backoff_secs).collect();
        assert_eq!(v, vec![5, 5, 15, 30, 60, 120, 300, 300, 300]);
    }

    #[test]
    fn enqueue_dedup_y_lleno() {
        let mut q = RetryQueue::in_memory();
        assert_eq!(q.enqueue("a", json!({}), 100, "x"), EnqueueResult::Queued);
        assert_eq!(q.enqueue("a", json!({}), 100, "x"), EnqueueResult::AlreadyQueued);
        for i in 0..(MAX_QUEUE - 1) {
            assert_eq!(q.enqueue(&format!("j{i}"), json!({}), 100, "x"), EnqueueResult::Queued);
        }
        assert_eq!(q.enqueue("extra", json!({}), 100, "x"), EnqueueResult::Full);
        assert_eq!(q.len(), MAX_QUEUE);
    }

    #[test]
    fn due_respeta_next_at_y_en_vuelo() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({"k":1}), 100, "e");
        assert!(q.take_due(104).is_empty()); // next_at = 105
        let due = q.take_due(105);
        assert_eq!(due.len(), 1);
        assert!(q.take_due(1000).is_empty(), "en vuelo: no se toma dos veces");
        // al fallar se libera y se reprograma
        assert_eq!(q.fail("a", 110, "otra"), FailOutcome::Rescheduled { next_at: 110 + 15 });
        assert!(q.take_due(124).is_empty());
        assert_eq!(q.take_due(125).len(), 1);
    }

    #[test]
    fn complete_quita() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({}), 0, "e");
        let _ = q.take_due(10);
        assert!(q.complete("a"));
        assert!(!q.contains("a"));
        assert!(!q.complete("a"));
        // se puede volver a encolar el mismo id tras completarse
        assert_eq!(q.enqueue("a", json!({}), 20, "e"), EnqueueResult::Queued);
    }

    #[test]
    fn vence_por_intentos() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({}), 0, "e");
        let mut now = 0;
        let mut last = FailOutcome::Unknown;
        for _ in 0..MAX_ATTEMPTS {
            now += 400;
            let _ = q.take_due(now);
            last = q.fail("a", now, "e");
            if last == FailOutcome::Expired {
                break;
            }
        }
        assert_eq!(last, FailOutcome::Expired);
        assert_eq!(q.len(), 0);
        assert_eq!(q.expired().len(), 1);
        assert_eq!(q.expired()[0].job_id, "a");
    }

    #[test]
    fn vence_por_edad() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({}), 0, "e");
        let _ = q.take_due(10);
        assert_eq!(q.fail("a", MAX_AGE_SECS, "e"), FailOutcome::Expired);
    }

    #[test]
    fn fail_de_desconocido() {
        let mut q = RetryQueue::in_memory();
        assert_eq!(q.fail("zzz", 5, "e"), FailOutcome::Unknown);
    }

    #[test]
    fn persiste_y_recarga() {
        let p = tmp("persist");
        {
            let mut q = RetryQueue::load(p.clone());
            q.enqueue("a", json!({"x":[1,2,3]}), 50, "boom");
            q.enqueue("b", json!({}), 60, "boom");
            let _ = q.take_due(1000);
            q.fail("b", 1000, "otra");
            q.complete("a");
        }
        let q2 = RetryQueue::load(p.clone());
        assert_eq!(q2.len(), 1);
        let s = q2.summary();
        assert_eq!(s[0].job_id, "b");
        assert_eq!(s[0].attempts, 2); // 1 (intento original) + 1 reintento fallido
    }

    #[test]
    fn archivo_corrupto_se_aparta() {
        let p = tmp("corrupto");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "{no es json").unwrap();
        let q = RetryQueue::load(p.clone());
        assert_eq!(q.len(), 0);
        assert!(p.with_extension("json.corrupto").exists());
    }

    #[test]
    fn cancel_y_retry_now() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({}), 100, "e");
        assert!(q.retry_now("a", 101));
        assert_eq!(q.take_due(101).len(), 1);
        assert!(!q.retry_now("zzz", 1));
        assert!(q.cancel("a"));
        assert!(!q.cancel("a"));
    }

    #[test]
    fn summary_no_expone_payload() {
        let mut q = RetryQueue::in_memory();
        q.enqueue("a", json!({"dataBase64":"SECRETO"}), 1, "e");
        let s = serde_json::to_string(&q.summary()).unwrap();
        assert!(!s.contains("SECRETO"));
        assert!(s.contains("\"jobId\":\"a\""));
    }
}
