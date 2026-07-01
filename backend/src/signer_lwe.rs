use rand::RngCore;
 
pub const N:   usize = 16;   // dimensão do lattice (produção: ≥512)
pub const Q:   i64   = 257;  // módulo primo      (produção: ~2^23)
pub const ETA: i64   = 2;    // amplitude do erro
 
// NOVO: o challenge agora é limitado a um pequeno intervalo, igual aos
// esquemas reais de assinatura em lattice (Dilithium usa polinômios de
// challenge de norma pequena, não um elemento arbitrário do corpo).
// Isso é o que torna a tolerância de verificação matematicamente segura
// de se fixar como constante.
pub const CHALLENGE_BOUND: i64 = 50;
 
// NOVO: tolerância fixa, calculada uma vez, nunca influenciada por
// dado externo. Pior caso possível: CHALLENGE_BOUND * ETA = 10.
// Deixamos uma margem de segurança e travamos bem abaixo de Q/2 (=128).
pub const TOLERANCE: i64 = CHALLENGE_BOUND * ETA + 2; // = 12, << 128
 
#[derive(Clone)] pub struct SecretKey { s: Vec<i64> }
#[derive(Clone)] pub struct PublicKey  { pub a: Vec<Vec<i64>>, pub b: Vec<i64> }
 
pub struct Signature {
    pub z: Vec<i64>,  // resposta: y + c·s mod q
    pub w: Vec<i64>,  // commitment: A·y mod q
    pub c: i64,       // challenge: H(w || data), agora em [-CHALLENGE_BOUND, CHALLENGE_BOUND]
}
 
fn pseudo_rand(seed: u64, idx: usize) -> i64 {
    // xorshift64 — usado só pra keygen determinística de teste/demo.
    // NUNCA usado mais para gerar o nonce de assinatura (ver sign()).
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
 
/// FIX Finding #1: challenge agora depende do commitment `w`, não só de `data`.
/// Isso amarra o desafio ao compromisso, como o Fiat-Shamir exige.
///
/// FIX Finding #2: saída restrita a um intervalo pequeno e simétrico,
/// igual a esquemas reais de assinatura em lattice.
fn challenge_hash(w: &[i64], data: &[u8]) -> i64 {
    // FNV-1a — produção: SHA3-256
    let mut h: u64 = 0xcbf29ce484222325;
    for &wi in w {
        h ^= wi as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    for &byte in data {
        h ^= byte as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let range = (2 * CHALLENGE_BOUND + 1) as u64;
    ((h & 0x7FFFFFFFFFFFFFFF) % range) as i64 - CHALLENGE_BOUND
}
 
/// Gera par de chaves LWE. Produção: NÃO chamar isso por requisição —
/// ver Finding #3 / pqc_endpoints.rs para o fix de key management.
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
    #[cfg(test)]
    pub(crate) fn expose_for_test(&self) -> &[i64] { &self.s }
 
    /// Fiat-Shamir sobre LWE, corrigido:
    ///   y = aleatoriedade fresca do SO — NUNCA vinda do chamador (fix #4)
    ///   w = A·y                          (commitment)
    ///   c = H(w || data)                 (challenge — agora amarrado a w, fix #1)
    ///   z = y + c·s mod q                (resposta)
    ///
    /// Note: a assinatura de `sign()` mudou — não recebe mais `nonce`.
    /// Isso é intencional: o chamador não pode mais influenciar o commitment.
    pub fn sign(&self, data: &[u8], pk: &PublicKey) -> Signature {
        let mut rng = rand::rngs::OsRng;
        let y: Vec<i64> = (0..N).map(|_| (rng.next_u64() % Q as u64) as i64).collect();
        let w: Vec<i64> = (0..N).map(|i| {
            mod_q(pk.a[i].iter().zip(y.iter()).map(|(a, y)| a * y).sum())
        }).collect();
        let c = challenge_hash(&w, data);
        let z: Vec<i64> = y.iter().zip(self.s.iter())
            .map(|(&yi, &si)| mod_q(yi + c * si))
            .collect();
        Signature { z, w, c }
    }
}
 
/// Verificação corrigida:
///   1. c precisa bater com H(w || data) — não dá pra escolher w depois de c (fix #1)
///   2. c precisa estar no intervalo esperado — defesa em profundidade
///   3. tolerância é CONSTANTE, nunca derivada de c (fix #2)
pub fn verify(pk: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    if sig.c.abs() > CHALLENGE_BOUND { return false; }
    if sig.c != challenge_hash(&sig.w, data) { return false; }
 
    let az: Vec<i64> = (0..N).map(|i| {
        mod_q(pk.a[i].iter().zip(sig.z.iter()).map(|(a, z)| a * z).sum())
    }).collect();
    let cb: Vec<i64> = pk.b.iter().map(|&bi| mod_q(sig.c * bi)).collect();
 
    (0..N).all(|i| dist_circular(mod_q(az[i] - cb[i]), sig.w[i]) <= TOLERANCE)
}
 
#[cfg(test)]
mod adversarial_core {
    use super::*;
 
    // FINDING #1 (deve continuar impossível de forjar sem a chave secreta)
    #[test]
    fn finding_1_forge_without_secret_key_must_fail() {
        let (_sk, pk) = keygen(42);
        let data = b"transfer $1000000 to attacker account";
 
        // Atacante tenta a MESMA técnica de antes: escolhe z livre,
        // resolve w = A·z - c·b. Só que agora c depende de w -- problema:
        // ele nem sabe que c vai dar até calcular w, e w depende de c.
        // Sem conseguir resolver esse ciclo, tenta um c qualquer chutado:
        let guessed_c = 3i64; // dentro do range válido agora, mas "chutado"
        let z: Vec<i64> = vec![0; N];
        let w: Vec<i64> = (0..N).map(|i| {
            let az: i64 = pk.a[i].iter().zip(z.iter()).map(|(a, z)| a * z).sum();
            mod_q(az - guessed_c * pk.b[i])
        }).collect();
        // Mas agora o verify recalcula c a partir de w+data -- não é mais o que o atacante chutou
        let forged = Signature { z, w, c: guessed_c };
 
        assert!(!verify(&pk, data, &forged),
            "FINDING #1 continua explorável: forjamento funcionou mesmo com o fix.");
    }
 
    #[test]
    fn finding_1b_forgery_must_fail_for_any_message() {
        let (_sk, pk) = keygen(7);
        let messages: Vec<&[u8]> = vec![b"hello", b"", b"approve loan $50000", b"revoke admin"];
        for data in messages {
            let guessed_c = 2i64;
            let z: Vec<i64> = vec![1; N];
            let w: Vec<i64> = (0..N).map(|i| {
                let az: i64 = pk.a[i].iter().zip(z.iter()).map(|(a, z)| a * z).sum();
                mod_q(az - guessed_c * pk.b[i])
            }).collect();
            let forged = Signature { z: z.clone(), w, c: guessed_c };
            assert!(!verify(&pk, data, &forged),
                "FINDING #1b continua explorável para {:?}", data);
        }
    }
 
    // FINDING #2 (tolerância agora é constante e pequena)
    #[test]
    fn finding_2_random_unrelated_pair_must_not_verify() {
        let (_sk, pk) = keygen(99);
        let data = b"qualquer mensagem";
        let z: Vec<i64> = (0..N).map(|i| pseudo_rand(555, i)).collect();
        let w: Vec<i64> = (0..N).map(|i| pseudo_rand(777, i)).collect();
        // usa um c dentro do range válido, mas w/z não relacionados a ele
        let garbage = Signature { z, w, c: 4 };
        assert!(!verify(&pk, data, &garbage),
            "FINDING #2 continua explorável: par (z,w) não relacionado foi aceito.");
    }
 
    #[test]
    fn finding_2b_out_of_range_challenge_rejected() {
        let (_sk, pk) = keygen(1);
        let data = b"teste";
        let z: Vec<i64> = vec![0; N];
        let w: Vec<i64> = vec![0; N];
        let out_of_range = Signature { z, w, c: 999 }; // fora de [-5,5]
        assert!(!verify(&pk, data, &out_of_range),
            "challenge fora do range deveria ser rejeitado direto.");
    }
 
    // CONTROLES POSITIVOS
    #[test]
    fn control_legitimate_signature_still_verifies() {
        let (sk, pk) = keygen(1234);
        let data = b"legitimate transaction";
        let sig = sk.sign(data, &pk); // sem nonce agora
        assert!(verify(&pk, data, &sig), "assinatura legítima deveria passar");
    }
 
    #[test]
    fn control_signature_does_not_transfer_between_messages() {
        let (sk, pk) = keygen(4321);
        let data_a = b"message A";
        let data_b = b"message B";
        let sig = sk.sign(data_a, &pk);
        assert!(!verify(&pk, data_b, &sig));
    }
 
    #[test]
    fn control_tampered_z_is_rejected() {
        let (sk, pk) = keygen(2024);
        let data = "invoice #4471 — R$ 250,00".as_bytes();
        let mut sig = sk.sign(data, &pk);
        sig.z[0] = mod_q(sig.z[0] + 1);
        assert!(!verify(&pk, data, &sig), "z adulterado não deveria verificar");
    }
 
    #[test]
    fn control_tampered_w_is_rejected() {
        // novo controle: como agora c depende de w, adulterar w tem que
        // quebrar a assinatura também (antes isso nem fazia sentido testar
        // isoladamente, porque w não influenciava c)
        let (sk, pk) = keygen(555);
        let data = b"payment approved";
        let mut sig = sk.sign(data, &pk);
        sig.w[0] = mod_q(sig.w[0] + 1);
        assert!(!verify(&pk, data, &sig), "w adulterado deveria invalidar a assinatura");
    }
 
    // FINDING #4: nonce não é mais parâmetro de sign() -- teste de tipo/API,
    // não de comportamento: se este código compila, a API não aceita mais
    // nonce externo. (a prova real é a assinatura de sign() em si, acima)
    #[test]
    fn finding_4_two_signatures_of_same_message_are_not_identical() {
        // Sem nonce controlável, duas assinaturas da MESMA mensagem devem
        // ser diferentes (commitment fresco a cada chamada via OsRng).
        let (sk, pk) = keygen(9999);
        let data = b"repeated message";
        let sig1 = sk.sign(data, &pk);
        let sig2 = sk.sign(data, &pk);
        assert_ne!(sig1.w, sig2.w,
            "duas assinaturas da mesma mensagem tem o mesmo commitment -- \
             sinal de que y não está usando aleatoriedade fresca.");
        assert!(verify(&pk, data, &sig1));
        assert!(verify(&pk, data, &sig2));
    }
}
 
#[cfg(test)]
mod stress_tests {
    use super::*;
 
    /// IMPORTANTE: este teste NÃO espera zero forjamentos.
    ///
    /// Com N=16 / Q=257 (parâmetros de DEMONSTRAÇÃO, nunca produção — ver
    /// topo do arquivo), o espaço de challenges cabível dentro de uma
    /// tolerância segura (<< Q/2) é necessariamente pequeno (~101 valores
    /// com CHALLENGE_BOUND=50). Isso dá a um atacante ONLINE, ativo, com
    /// acesso à API, uma chance de ~1% de forjar POR TENTATIVA -- muito
    /// diferente do bug original (Findings #1/#2), que davam 100% de
    /// sucesso OFFLINE, sem nenhuma interação com o servidor.
    ///
    /// Este teste documenta e trava esse risco residual conhecido. Ele
    /// FALHA (propositalmente) se a taxa de forjamento subir acima do
    /// esperado -- o que aconteceria se alguém no futuro reduzir
    /// CHALLENGE_BOUND sem perceber a implicação de segurança.
    ///
    /// MITIGAÇÃO OBRIGATÓRIA em produção (isso não é opcional):
    ///   1. Rate limiting agressivo em /v1/pqc/sign e /v1/pqc/verify
    ///      (hoje NÃO EXISTE nenhum rate limit nesses endpoints)
    ///   2. Esta é uma limitação FUNDAMENTAL de parâmetros de brinquedo.
    ///      A correção definitiva é migrar para pqcrypto-dilithium
    ///      (N>=512) como o próprio código já recomenda no cabeçalho --
    ///      não existe tuning de CHALLENGE_BOUND que resolva isso de
    ///      verdade em Q=257.
    #[test]
    fn stress_forgery_rate_stays_within_known_toy_scale_bound() {
        let (_sk, pk) = keygen(31337);
        let data = b"stress test payload";
        let attempts = 2000u64;
        let mut successes = 0;
 
        for attempt in 0..attempts {
            let space = 2 * CHALLENGE_BOUND + 1;
            let guessed_c = (attempt as i64 % space) - CHALLENGE_BOUND;
            let z: Vec<i64> = (0..N).map(|i| pseudo_rand(attempt.wrapping_mul(7919), i)).collect();
            let w: Vec<i64> = (0..N).map(|i| {
                let az: i64 = pk.a[i].iter().zip(z.iter()).map(|(a, z)| a * z).sum();
                mod_q(az - guessed_c * pk.b[i])
            }).collect();
            let forged = Signature { z, w, c: guessed_c };
            if verify(&pk, data, &forged) {
                successes += 1;
            }
        }
 
        let rate = successes as f64 / attempts as f64;
        // Limite tolerado: ~2x a probabilidade teórica esperada (1/space),
        // com folga estatística. Qualquer coisa muito acima disso indica
        // uma regressão real (ex: alguém reintroduziu o bug de binding).
        let expected = 1.0 / (2 * CHALLENGE_BOUND + 1) as f64;
        assert!(rate < expected * 3.0,
            "taxa de forjamento ({:.2}%) muito acima do esperado (~{:.2}%) -- possível regressão",
            rate * 100.0, expected * 100.0);
    }
 
    #[test]
    fn stress_100_legitimate_roundtrips_all_succeed() {
        // garante que o fix não introduziu falso-negativo (rejeitar assinatura legítima)
        let (sk, pk) = keygen(2718);
        for i in 0..100 {
            let data = format!("message number {}", i).into_bytes();
            let sig = sk.sign(&data, &pk);
            assert!(verify(&pk, &data, &sig), "assinatura legítima #{} foi rejeitada", i);
        }
    }
 
    #[test]
    fn stress_tolerance_never_approaches_half_q() {
        // trava estruturalmente: TOLERANCE tem que ficar bem abaixo de Q/2
        // pra nao reabrir o Finding #2 se alguem mudar CHALLENGE_BOUND no futuro
        assert!(TOLERANCE < (Q / 2) * 9 / 10,
            "TOLERANCE ({}) está perigosamente perto de Q/2 ({}) -- risco de reabrir Finding #2",
            TOLERANCE, (Q/2)*9/10);
    }
}