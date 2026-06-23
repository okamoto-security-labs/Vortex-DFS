// signer_lwe.rs - Vortex DFS
// Assinatura Fiat-Shamir sobre LWE com matemática de lattice real.
//
// PRODUÇÃO: substitua por pqcrypto-dilithium (padrão NIST PQC).
// Esta implementação expõe os primitivos para fins de auditoria e aprendizado.
// Cargo.toml: pqcrypto-dilithium = "0.5"

pub const N:   usize = 16;   // dimensão do lattice (produção: >=512)
pub const Q:   i64   = 257;  // módulo primo      (produção: ~2^23)
pub const ETA: i64   = 2;    // amplitude do erro

#[derive(Clone)] pub struct SecretKey { s: Vec<i64> }
#[derive(Clone)] pub struct PublicKey  { pub a: Vec<Vec<i64>>, pub b: Vec<i64> }

pub struct Signature {
    pub z: Vec<i64>,
    pub w: Vec<i64>,
    pub c: i64,
}

fn pseudo_rand(seed: u64, idx: usize) -> i64 {
    let mut x = seed.wrapping_add(idx as u64).wrapping_add(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    ((x & 0x7FFFFFFFFFFFFFFF) % Q as u64) as i64
}

fn sample_error(seed: u64, idx: usize) -> i64 {
    (pseudo_rand(seed, idx) % (2 * ETA + 1)) - ETA
}

fn mod_q(x: i64) -> i64 { x.rem_euclid(Q) }

fn dist_circular(a: i64, b: i64) -> i64 {
    let d = (a - b).rem_euclid(Q);
    d.min(Q - d)
}

fn challenge_hash(data: &[u8]) -> i64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &byte in data { h ^= byte as u64; h = h.wrapping_mul(0x100000001b3); }
    ((h & 0x7FFFFFFFFFFFFFFF) % Q as u64) as i64
}

pub fn keygen(seed: u64) -> (SecretKey, PublicKey) {
    let s: Vec<i64> = (0..N).map(|i| sample_error(seed, i)).collect();
    let a: Vec<Vec<i64>> = (0..N)
        .map(|i| (0..N).map(|j| pseudo_rand(seed ^ 0xdeadbeef, i * N + j)).collect())
        .collect();
    let b: Vec<i64> = (0..N).map(|i| {
        let dot: i64 = a[i].iter().zip(s.iter()).map(|(a, s)| a * s).sum();
        mod_q(dot + sample_error(seed ^ 0xcafe, i))
    }).collect();
    (SecretKey { s }, PublicKey { a, b })
}

impl SecretKey {
    pub fn sign(&self, data: &[u8], pk: &PublicKey, nonce: u64) -> Signature {
        let y: Vec<i64> = (0..N).map(|i| pseudo_rand(nonce, i)).collect();
        let w: Vec<i64> = (0..N).map(|i| {
            mod_q(pk.a[i].iter().zip(y.iter()).map(|(a, y)| a * y).sum())
        }).collect();
        let c = challenge_hash(data);
        let z: Vec<i64> = y.iter().zip(self.s.iter())
            .map(|(&yi, &si)| mod_q(yi + c * si))
            .collect();
        Signature { z, w, c }
    }
}

pub fn verify(pk: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    if sig.c != challenge_hash(data) { return false; }
    let az: Vec<i64> = (0..N).map(|i| {
        mod_q(pk.a[i].iter().zip(sig.z.iter()).map(|(a, z)| a * z).sum())
    }).collect();
    let cb: Vec<i64> = pk.b.iter().map(|&bi| mod_q(sig.c * bi)).collect();
    let tolerance = sig.c * ETA + 1;
    (0..N).all(|i| dist_circular(mod_q(az[i] - cb[i]), sig.w[i]) <= tolerance)
}
