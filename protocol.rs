// protocol.rs - Vortex DFS
// Reescrito para produção: parse seguro, CRC, detecção multi-padrão.
use crc32fast::Hasher;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct VortexPacket {
    pub sync_word:   u16,  // 0x5654 = "VT"
    pub command_id:  u16,
    pub payload_len: u32,
    pub crc:         u32,
}

pub const SYNC_WORD:   u16   = 0x5654;
pub const HEADER_SIZE: usize = 12;

#[derive(Debug, PartialEq)]
pub enum ParseError {
    BufferTooSmall,
    BadSyncWord,
    PayloadTooLarge,
    CrcMismatch { expected: u32, got: u32 },
}

/// Parse seguro — zero UB. ANTES: cast *const u8 com repr(packed) = UB garantido.
pub fn parse_packet(buf: &[u8]) -> Result<(VortexPacket, &[u8]), ParseError> {
    if buf.len() < HEADER_SIZE { return Err(ParseError::BufferTooSmall); }

    let sync_word   = u16::from_le_bytes([buf[0], buf[1]]);
    let command_id  = u16::from_le_bytes([buf[2], buf[3]]);
    let payload_len = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let crc         = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);

    if sync_word != SYNC_WORD { return Err(ParseError::BadSyncWord); }

    let plen = payload_len as usize;
    if plen > 65535 { return Err(ParseError::PayloadTooLarge); }
    if buf.len() < HEADER_SIZE + plen { return Err(ParseError::BufferTooSmall); }

    let payload = &buf[HEADER_SIZE..HEADER_SIZE + plen];

    let mut h = Hasher::new();
    h.update(&buf[0..8]);
    h.update(payload);
    let computed = h.finalize();
    if computed != crc { return Err(ParseError::CrcMismatch { expected: crc, got: computed }); }

    Ok((VortexPacket { sync_word, command_id, payload_len, crc }, payload))
}

#[derive(Debug, PartialEq)]
pub enum StreamThreat {
    LegacyTlsCipher(String),
    SqlInjectionPattern,
    OversizedInput,
}

/// Inspeção de stream. ANTES: contains() case-sensitive = bypassável.
/// AGORA: lowercase + múltiplos padrões + limite de tamanho.
pub fn inspect_text_stream(input: &str) -> Result<(), StreamThreat> {
    if input.len() > 8192 { return Err(StreamThreat::OversizedInput); }
    let lower = input.to_ascii_lowercase();

    const LEGACY_CIPHERS: &[&str] = &[
        "tls_rsa_with_aes_128_cbc_sha",
        "tls_rsa_with_aes_256_cbc_sha",
        "tls_rsa_with_rc4_128_sha",
        "tls_rsa_with_3des_ede_cbc_sha",
        "ssl_rsa_with_rc4_128_md5",
    ];
    for cipher in LEGACY_CIPHERS {
        if lower.contains(cipher) {
            return Err(StreamThreat::LegacyTlsCipher(cipher.to_string()));
        }
    }

    const SQL_PATTERNS: &[&str] = &[
        "' or '1'='1", "'; drop table", "union select", "exec xp_",
    ];
    for pattern in SQL_PATTERNS {
        if lower.contains(pattern) { return Err(StreamThreat::SqlInjectionPattern); }
    }

    Ok(())
}

/// Monta pacote com CRC calculado automaticamente.
pub fn build_packet(command_id: u16, payload: &[u8]) -> Vec<u8> {
    let payload_len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&SYNC_WORD.to_le_bytes());
    buf.extend_from_slice(&command_id.to_le_bytes());
    buf.extend_from_slice(&payload_len.to_le_bytes());
    let crc_offset = buf.len();
    buf.extend_from_slice(&[0u8; 4]);
    buf.extend_from_slice(payload);
    let mut h = Hasher::new();
    h.update(&buf[0..8]);
    h.update(payload);
    buf[crc_offset..crc_offset + 4].copy_from_slice(&h.finalize().to_le_bytes());
    buf
}
