// engine.rs - Vortex DFS
// Pipeline integrado: protocol → signer_lwe → telemetria.
// Requer: protocol.rs, signer_lwe.rs

use std::marker::PhantomData;
use crate::protocol::{self, StreamThreat};
use crate::signer_lwe::{self, PublicKey, Signature};

// -- Typestate (preservado do original — estava correto) ----------
pub struct Unverified;
pub struct Verified;

pub struct TelemetryPacket<S> {
    pub distance: f32,
    pub entropy:  f32,
    _marker: PhantomData<S>,
}

/// TrustState expandido.
/// ANTES: 3 estados genéricos — impossível auditar a causa de um bloqueio.
/// AGORA: cada camada tem seu motivo de rejeição estruturado.
#[derive(Debug, PartialEq, Clone)]
pub enum TrustState {
    HighTrust,
    Operational,
    Fragile,
    RejectedProtocol(String),   // parse falhou ou CRC inválido
    RejectedSignature,          // assinatura LWE inválida
    RejectedBounds,             // distance/entropy fora de [0.0, 1.0]
}

impl TrustState {
    /// Retorna true apenas para estados operacionais confiáveis.
    pub fn is_trusted(&self) -> bool {
        matches!(self, TrustState::HighTrust | TrustState::Operational)
    }
}

pub struct VortexGate {
    pub_key: PublicKey,
}

impl VortexGate {
    pub fn new(pub_key: PublicKey) -> Self {
        VortexGate { pub_key }
    }

    /// Pipeline completo de 3 camadas:
    ///
    ///   Camada 1 — Protocol:   parse binário seguro + validação de CRC
    ///   Camada 2 — Signer LWE: verifica autenticidade do payload
    ///   Camada 3 — Engine:     avalia telemetria do payload autenticado
    ///
    /// Um pacote só chega na Camada 3 se passou pelas anteriores.
    pub fn process_packet(&self, raw: &[u8], sig: &Signature) -> TrustState {
        // Camada 1
        let (_header, payload) = match protocol::parse_packet(raw) {
            Ok(p)  => p,
            Err(e) => return TrustState::RejectedProtocol(format!("{:?}", e)),
        };

        // Camada 2
        if !signer_lwe::verify(&self.pub_key, payload, sig) {
            return TrustState::RejectedSignature;
        }

        // Camada 3 — payload carrega 2×f32 LE: [distance(4)] [entropy(4)]
        if payload.len() < 8 {
            return TrustState::RejectedProtocol("payload < 8 bytes".to_string());
        }
        let distance = f32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let entropy  = f32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);

        match TelemetryPacket::<Unverified>::new(distance, entropy).validate_bounds() {
            Ok(vp) => vp.execute_vector_eval(),
            Err(_) => TrustState::RejectedBounds,
        }
    }

    /// Inspeciona stream de texto antes de aceitar no pipeline.
    pub fn inspect_stream(&self, input: &str) -> Result<(), StreamThreat> {
        protocol::inspect_text_stream(input)
    }

    /// Avaliação direta de telemetria (mantida para compatibilidade com código legado).
    pub fn evaluate_fidelity(&self, distance: f32, entropy: f32) -> TrustState {
        match TelemetryPacket::<Unverified>::new(distance, entropy).validate_bounds() {
            Ok(vp) => vp.execute_vector_eval(),
            Err(_) => TrustState::RejectedBounds,
        }
    }
}

// -- TelemetryPacket (typestate preservado — estava correto) ------

impl TelemetryPacket<Unverified> {
    pub fn new(distance: f32, entropy: f32) -> Self {
        TelemetryPacket { distance, entropy, _marker: PhantomData }
    }

    pub fn validate_bounds(self) -> Result<TelemetryPacket<Verified>, &'static str> {
        if self.distance < 0.0 || self.distance > 1.0
        || self.entropy  < 0.0 || self.entropy  > 1.0 {
            return Err("bounds violation");
        }
        Ok(TelemetryPacket {
            distance: self.distance,
            entropy:  self.entropy,
            _marker:  PhantomData,
        })
    }
}

impl TelemetryPacket<Verified> {
    pub fn execute_vector_eval(&self) -> TrustState {
        if self.distance <= 0.2 && self.entropy <= 0.2 {
            TrustState::HighTrust
        } else if self.distance > 0.7 || self.entropy > 0.7 {
            TrustState::Fragile
        } else {
            TrustState::Operational
        }
    }
}
