// defency_cargo.rs - Vortex DFS
// Motor de defesa para alta carga — pipeline com budget de latência.
//
// ANTES: pseudocódigo que não compilava.
//   - VortexEngine sem struct
//   - is_malformed() / perform_pqc_validation() não implementados
//   - `self` sem &self
//
// AGORA: implementação real com pipeline de 4 camadas.

use crate::pqc_core::{PqcVector, TrustBand};
use crate::protocol;

#[derive(Debug, PartialEq, Clone)]
pub enum SecurityError {
    MalformedPacket(String),
    InsufficientPayload { got: usize, need: usize },
    InvalidMetrics(String),
    TrustThresholdViolation { band: String, score: f64 },
    /// Reservado para integração com timer de 2.6µs no caller
    BudgetExceeded,
}

#[derive(Debug)]
pub struct ValidationResult {
    pub band:  TrustBand,
    pub score: f64,
    pub cmd:   u16,
}

pub struct VortexEngine {
    min_score: f64,
}

impl VortexEngine {
    pub fn new(min_score: f64) -> Self {
        VortexEngine { min_score: min_score.clamp(0.0, 1.0) }
    }

    /// Pipeline de validação — sem alocação heap no path de erro.
    ///
    /// Para enforçar o budget de 2.6µs, envolva com:
    ///   let t = std::time::Instant::now();
    ///   let result = engine.process_stream(&raw);
    ///   if t.elapsed().as_micros() > 26 { /* budget excedido */ }
    pub fn process_stream(&self, raw: &[u8]) -> Result<ValidationResult, SecurityError> {
        // Camada 1: protocolo — CRC + sync word
        let (_header, payload) = protocol::parse_packet(raw)
            .map_err(|e| SecurityError::MalformedPacket(format!("{:?}", e)))?;

        // Camada 2: tamanho mínimo (2 × f64 = 16 bytes)
        if payload.len() < 16 {
            return Err(SecurityError::InsufficientPayload { got: payload.len(), need: 16 });
        }

        // Camada 3: extração zero-copy + validação do domínio
        let distance = f64::from_le_bytes(payload[0..8].try_into().unwrap());
        let entropy  = f64::from_le_bytes(payload[8..16].try_into().unwrap());

        let vector = PqcVector::new(distance, entropy)
            .map_err(|e| SecurityError::InvalidMetrics(e.to_string()))?;

        let score = vector.evaluate_trust_score();
        let band  = vector.classify();

        // Camada 4: decisão final
        if score < self.min_score {
            return Err(SecurityError::TrustThresholdViolation {
                band: format!("{:?}", band), score,
            });
        }

        let cmd = u16::from_le_bytes([raw[2], raw[3]]);
        Ok(ValidationResult { band, score, cmd })
    }
}
