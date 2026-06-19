# The silent bug that made our post-quantum signatures accept everything

*How a modular arithmetic oversight turned a cryptographic primitive into a no-op — and what we did about it.*

---

We were building Vortex DFS, a deterministic security layer for AI systems. The core idea: instead of heuristics, use mathematics. A packet either satisfies the laws of physics and cryptography, or it doesn't.

Part of that meant implementing a post-quantum signature scheme based on **Learning With Errors (LWE)** — the mathematical hardness assumption behind NIST's 2024 post-quantum standards. We wanted something auditable, something we could reason about, something that would fail loudly if it was wrong.

It didn't fail loudly. It failed silently. And it took a test case we almost didn't write to catch it.

---

## What we built

The scheme follows the Fiat-Shamir paradigm applied to LWE. The idea is elegant:

**Key generation:**
```
s ← small secret vector in Z_q^n
A ← random public matrix in Z_q^(n×n)
b = A·s mod q          (public key)
```

**Signing a message `data`:**
```
y ← random commitment vector
w = A·y mod q
c = H(data || w)       (challenge — hash binding)
z = y + c·s mod q      (response)
Signature: (z, c)
```

**Verification:**
```
Recompute: w' = A·z - c·b mod q
Check:     H(data || w') == c
```

The security intuition: an attacker who doesn't know `s` can't produce a `z` such that `A·z - c·b` hashes back to `c`. Solving that requires inverting the LWE problem — which is believed to be hard even for quantum computers.

We implemented this in Rust. The math looked right. The code compiled. The happy path test passed.

Then we wrote the test that almost didn't get written.

---

## The test we almost skipped

```rust
fn test_lwe_wrong_key_rejected() {
    let (sk1, pk1) = keygen(0xAAAA);
    let (_sk2, pk2) = keygen(0xBBBB);

    // Sign with sk2/pk2
    let sig = _sk2.sign(b"dados", &pk2, 0x1111);

    // Verify against pk1 — should FAIL
    assert!(!verify(&pk1, b"dados", &sig));
}
```

The assertion failed. A signature made with one keypair was accepted by a completely different public key.

The signature scheme that was supposed to be post-quantum secure was accepting any signature from any key.

---

## Finding the root cause

We added diagnostic output and ran the math in Python to isolate where the failure was happening.

```python
N = 16; Q = 257; ETA = 2

# With a typical challenge value c ≈ 245:
tol = c * ETA + 1
# tol = 245 * 2 + 1 = 491

# But Q = 257, so the entire ring Z_q spans [0, 256]
# Maximum circular distance in Z_q: Q // 2 = 128

print(f"tol={tol}, Q={Q}, tol > Q: {tol > Q}")
# tol=491, Q=257, tol > Q: True
```

The tolerance exceeded the size of the ring. We were checking whether the difference between two values in Z₂₅₇ was "small enough" — but our definition of small enough covered the entire space.

In practice: `verify()` was returning `True` for every input.

The root was in our verification function. The original version computed `A·z - c·b` and checked whether it was "close to" `w` using a tolerance of `c × ETA`:

```rust
// BEFORE — broken
let tolerance = sig.c * ETA + 1;
(0..N).all(|i| dist_circular(mod_q(az[i] - cb[i]), sig.w[i]) <= tolerance)
```

With `Q = 257` (a deliberately small parameter for a demo implementation) and `c` values that can reach up to `Q - 1 = 256`, the tolerance `c × ETA` can be `512` — more than double the entire modulus. The "check" was vacuously true.

---

## Why this happens mathematically

In a proper LWE-based signature scheme, the public key is `b = A·s + e`, where `e` is a small error vector. During verification:

```
A·z - c·b = A·(y + c·s) - c·(A·s + e)
           = A·y + c·A·s - c·A·s - c·e
           = A·y - c·e
           = w - c·e
```

So `A·z - c·b` isn't exactly `w` — it differs by `c·e`. The tolerance exists to absorb this error. But the error bound `c × ETA` only stays safely below `Q/2` when `Q` is large relative to `c × ETA`.

Production parameters (Dilithium uses `Q = 8,380,417`) make this gap enormous. Our demo parameter `Q = 257` collapsed it completely.

---

## The fix

We changed the approach. Instead of checking proximity in the ring, we use hash binding directly.

The key insight: if `b = A·s` (without the public error term), then `A·z - c·b = A·y = w` exactly. The verification becomes:

```
Recompute w' = A·z - c·b mod q
Accept iff H(data || w') == c
```

No tolerance. No approximation. The hash function does the work — if `w'` differs from `w` by even a single bit, the hash changes completely.

```rust
// AFTER — correct
pub fn verify(pk: &PublicKey, data: &[u8], sig: &Signature) -> bool {
    // Recompute w' = A·z - c·b mod q
    let az: Vec<i64> = (0..N).map(|i| {
        mq(pk.a[i].iter().zip(&sig.z).map(|(a, z)| a * z).sum())
    }).collect();
    let cb: Vec<i64> = pk.b.iter().map(|&bi| mq(sig.c * bi)).collect();
    let w_prime: Vec<i64> = (0..N).map(|i| mq(az[i] - cb[i])).collect();

    // Accept iff H(data || w') == c
    hash_commit(data, &w_prime) == sig.c
}
```

We also updated the key generation to remove the public error term, since we no longer need it and its presence was the source of the approximation problem:

```rust
// b = A·s  (exact — no error term)
let b: Vec<i64> = (0..N)
    .map(|i| mq(a[i].iter().zip(&s).map(|(a, s)| a * s).sum()))
    .collect();
```

---

## Verifying the fix

We ran the same test suite:

```
[OK] test_lwe_sign_verify            ← valid sig accepted
[OK] test_lwe_tampered_data_rejected ← modified data rejected
[OK] test_lwe_wrong_key_rejected     ← different keypair rejected ✓
```

And the adversarial cases in Python confirmed the math:

```python
# Same keypair → True  ✓
# Different keypair → False  ✓
# Tampered data → False  ✓
# Modified z → False  ✓
```

---

## What this means in practice

The original code looked correct. It used the right algorithm name, the right structure, the right variable names. It compiled without warnings. The happy-path test passed. A code reviewer without cryptography expertise would have approved it.

The failure was invisible until we explicitly tested the adversarial case: *what happens when you verify a signature made with the wrong key?*

In a deployed system, this would have meant that any packet — from any source, with any signature — would pass authentication. The post-quantum security layer would have been a no-op. Worse, it would have been a no-op that looked like it was working.

---

## Three lessons

**Test the adversarial case explicitly.** Happy-path tests don't find security bugs. For every authentication check, write the test that uses the wrong key, the wrong data, the tampered payload. If the test doesn't exist, the guarantee doesn't exist.

**Small parameters expose bugs that large parameters hide.** `Q = 257` made the overflow immediate and visible. With `Q = 8,380,417`, the same logical error might pass casual testing because the tolerance stays within bounds in typical cases — but could still be exploitable under crafted inputs. Use small parameters in tests to stress the boundaries.

**For production, use audited implementations.** The mathematics in our implementation is correct, but correct mathematics isn't the same as a secure implementation. Dilithium — the NIST-standardized lattice signature scheme — has been analyzed by hundreds of cryptographers over seven years. Use `pqcrypto-dilithium` in production. Our implementation is what you study to understand *why* it works. Theirs is what you deploy.

---

## The production path

If you're building on Vortex DFS and need production-grade post-quantum signatures today:

```toml
[dependencies]
pqcrypto-dilithium = "0.5"
pqcrypto-traits = "0.3"
```

```rust
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

let (pk, sk) = dilithium3::keypair();
let sig = dilithium3::detached_sign(message, &sk);
assert!(dilithium3::verify_detached_signature(&sig, message, &pk).is_ok());
```

Same mathematical foundation. NIST-standardized parameters. Seven years of public cryptanalysis.

---

## Conclusion

The bug was a single line — a tolerance calculation that exceeded the modulus. It rendered an entire cryptographic layer meaningless. It was caught by a test case that was almost skipped.

Security isn't about looking correct. It's about being provably incorrect when something is wrong.

Vortex DFS is built on that principle. Every packet gets a typed rejection reason. Every layer has an adversarial test. Every guarantee has a corresponding test that tries to break it.

The code is open source. Read it, break it, tell us what you find.

---

*Vortex DFS is built at Okamoto Security Labs. Apache 2.0.*  
*Source: [github.com/your-org/vortex-dfs](https://github.com)*
