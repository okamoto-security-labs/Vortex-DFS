// metrics.rs - Vortex DFS
// Telemetria e métricas de segurança.
//
// ANTES: calculate_trust() retornava String — impossível usar em match
//        sem risco de typo, sem validação de inputs, sem penalidade.
//
// AGORA: evaluate() retorna MetricsSnapshot com TrustBand tipado.
//        calculate_trust_legacy() mantém compatibilidade com código existente.

use crate::pqc_core::{PqcVector, TrustBand};

#[derive(Debug, Clone)]
pub struct FidelityScore {
    pub distance: f64,
    pub entropy:  f64,
    pub penalty:  f64,
}

#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub score:    f64,
    pub band:     TrustBand,
    pub distance: f64,
    pub entropy:  f64,
    pub penalty:  f64,
}

#[derive(Debug, PartialEq)]
pub enum MetricsError {
    InvalidDistance(f64),
    InvalidEntropy(f64),
    InvalidPenalty(f64),
}

impl FidelityScore {
    pub fn new(distance: f64, entropy: f64) -> Result<Self, MetricsError> {
        if !(0.0..=1.0).contains(&distance) { return Err(MetricsError::InvalidDistance(distance)); }
        if !(0.0..=1.0).contains(&entropy)  { return Err(MetricsError::InvalidEntropy(entropy)); }
        Ok(Self { distance, entropy, penalty: 0.0 })
    }

    pub fn with_penalty(mut self, penalty: f64) -> Result<Self, MetricsError> {
        if !(0.0..=1.0).contains(&penalty) { return Err(MetricsError::InvalidPenalty(penalty)); }
        self.penalty = penalty;
        Ok(self)
    }

    pub fn evaluate(&self) -> Result<MetricsSnapshot, MetricsError> {
        let mut vector = PqcVector::new(self.distance, self.entropy)
            .map_err(|_| MetricsError::InvalidDistance(self.distance))?;
        if self.penalty > 0.0 { vector.apply_penalty(self.penalty); }
        Ok(MetricsSnapshot {
            score:    vector.evaluate_trust_score(),
            band:     vector.classify(),
            distance: self.distance,
            entropy:  self.entropy,
            penalty:  self.penalty,
        })
    }

    /// Compatibilidade com código legado que espera &str.
    /// Prefira evaluate() em código novo — TrustBand é tipado e seguro.
    pub fn calculate_trust_legacy(&self) -> &'static str {
        let trust = 1.0 - (self.distance * self.entropy);
        if trust > 0.95      { "HIGH_TRUST" }
        else if trust > 0.70 { "OPERATIONAL" }
        else                 { "FRAGILE_BYPASS_RISK" }
    }
}

impl MetricsSnapshot {
    pub fn is_healthy(&self) -> bool { self.band.is_operational() }

    pub fn to_log_entry(&self) -> String {
        format!(
            "band={:?} score={:.4} distance={:.4} entropy={:.4} penalty={:.4} healthy={}",
            self.band, self.score, self.distance, self.entropy, self.penalty, self.is_healthy()
        )
    }
}
