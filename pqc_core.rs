// pqc_core.rs - Vortex DFS
// Camada de aceleração matemática vetorizada para avaliação de confiança.
//
// PqcVector é alinhado a 64 bytes (linha de cache) para que operações
// sobre o array sejam candidatas a auto-vetorização pelo LLVM (AVX2/SSE4).
// unsafe não é necessário — o LLVM já otimiza acessos seguros a índices
// conhecidos em tempo de compilação para as mesmas instruções SIMD.

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum TrustBand {
    HighTrust,    // score >= 0.95
    Operational,  // score >= 0.70
    Fragile,      // score >= 0.20
    Critical,     // score <  0.20
}

impl TrustBand {
    pub fn is_operational(&self) -> bool {
        matches!(self, TrustBand::HighTrust | TrustBand::Operational)
    }
}

/// Layout dos 8 coeficientes f64 (64 bytes = 1 linha de cache):
///   [0] distance       — distância normalizada [0,1]
///   [1] entropy        — entropia normalizada  [0,1]
///   [2] cross          — distance × entropy
///   [3] complement     — 1.0 - cross (score base)
///   [4] weight_high    — limiar HighTrust  (0.95)
///   [5] weight_op      — limiar Operational (0.70)
///   [6] penalty        — penalidade dinâmica [0,1]
///   [7] reserved       — extensão futura
#[repr(align(64))]
pub struct PqcVector {
    metrics: [f64; 8],
}

impl PqcVector {
    /// Constrói o vetor validando os inputs.
    ///
    /// ANTES: sem validação — inputs fora de [0,1] produziam score negativo.
    pub fn new(distance: f64, entropy: f64) -> Result<Self, &'static str> {
        if !(0.0..=1.0).contains(&distance) { return Err("distance fora de [0.0, 1.0]"); }
        if !(0.0..=1.0).contains(&entropy)  { return Err("entropy fora de [0.0, 1.0]"); }
        let cross = distance * entropy;
        Ok(Self {
            metrics: [distance, entropy, cross, 1.0 - cross, 0.95, 0.70, 0.0, 0.0],
        })
    }

    /// Aplica penalidade ao score (ex: anomalia detectada pelo CyberGuardian).
    pub fn apply_penalty(&mut self, penalty: f64) {
        self.metrics[6] = penalty.clamp(0.0, 1.0);
    }

    /// Score de confiança final, clampado em [0.0, 1.0].
    ///
    /// ANTES: unsafe get_unchecked + sem clamp → resultado podia ser negativo.
    /// AGORA: safe, sempre em [0,1], com penalidade dinâmica.
    #[inline(always)]
    pub fn evaluate_trust_score(&self) -> f64 {
        (self.metrics[3] - self.metrics[6]).clamp(0.0, 1.0)
    }

    /// Converte o score contínuo para banda de confiança discreta.
    /// Integra com TrustState do engine.rs.
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
