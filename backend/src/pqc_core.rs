// pqc_core.rs - Vortex DFS
// Camada de aceleração matemática vetorizada para avaliação de confiança.

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TrustBand {
    HighTrust,
    Operational,
    Fragile,
    Critical,
}

impl TrustBand {
    pub fn is_operational(&self) -> bool {
        matches!(self, TrustBand::HighTrust | TrustBand::Operational)
    }
}

#[repr(align(64))]
pub struct PqcVector {
    metrics: [f64; 8],
}

impl PqcVector {
    pub fn new(distance: f64, entropy: f64) -> Result<Self, &'static str> {
        if !(0.0..=1.0).contains(&distance) { return Err("distance fora de [0.0, 1.0]"); }
        if !(0.0..=1.0).contains(&entropy)  { return Err("entropy fora de [0.0, 1.0]"); }
        let cross = distance * entropy;
        Ok(Self {
            metrics: [distance, entropy, cross, 1.0 - cross, 0.95, 0.70, 0.0, 0.0],
        })
    }

    pub fn apply_penalty(&mut self, penalty: f64) {
        self.metrics[6] = penalty.clamp(0.0, 1.0);
    }

    #[inline(always)]
    pub fn evaluate_trust_score(&self) -> f64 {
        (self.metrics[3] - self.metrics[6]).clamp(0.0, 1.0)
    }

    pub fn classify(&self) -> TrustBand {
        let score = self.evaluate_trust_score();
        if score >= self.metrics[4]      { TrustBand::HighTrust }
        else if score >= self.metrics[5] { TrustBand::Operational }
        else if score >= 0.20            { TrustBand::Fragile }
        else                             { TrustBand::Critical }
    }

    pub fn base_score(&self) -> f64     { self.metrics[3] }
    pub fn metrics(&self) -> &[f64; 8] { &self.metrics }
}
