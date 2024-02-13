//! An implementation of the `ML-KEM-768` post-quantum key encapsulation algorithm.

#![cfg_attr(not(feature = "std"), no_std)]

use cmov::{Cmov, CmovEq};
use rand_core::CryptoRngCore;
use sha3::{
    digest::{ExtendableOutput, FixedOutput, Update, XofReader},
    Shake128,
};
use sha3::{Sha3_256, Sha3_512, Shake256};

#[cfg(feature = "kem")]
pub use kem::*;

#[cfg(feature = "kem")]
mod kem;

#[cfg(feature = "xwing")]
pub mod xwing;

/// Generates an encapsulation key and a corresponding decapsulation key using the given RNG.
///
/// The decapsulation key must be kept secret.
pub fn key_gen(mut rng: impl CryptoRngCore) -> ([u8; 1184], [u8; 2400]) {
    let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
    rng.fill_bytes(&mut d);
    rng.fill_bytes(&mut z);
    kem_key_gen(d, z)
}

/// Generates an encapsulation key and a corresponding decapsulation key.
///
/// It implements ML-KEM.KeyGen according to FIPS 203 (DRAFT), Algorithm 15.
pub(crate) fn kem_key_gen(d: [u8; 32], z: [u8; 32]) -> ([u8; 1184], [u8; 2400]) {
    let (ek_pke, dk_pke) = pke_keygen(d);

    let mut dk = [0u8; 2400];
    dk[..1152].copy_from_slice(&dk_pke);
    dk[1152..1152 + 1184].copy_from_slice(&ek_pke);
    dk[1152 + 1184..1152 + 1184 + 32]
        .copy_from_slice(&Sha3_256::default().chain(ek_pke).finalize_fixed());
    dk[1152 + 1184 + 32..].copy_from_slice(&z);

    (ek_pke, dk)
}

/// Generates a ciphertext and an associated shared key from an encapsulation key and an RNG. If the
/// encapsulation key is not valid, returns `None`.
///
/// The shared key must be kept secret.
pub fn encapsulate(ek: &[u8; 1184], mut rng: impl CryptoRngCore) -> Option<([u8; 1088], [u8; 32])> {
    let mut m = [0u8; 32];
    rng.fill_bytes(&mut m);
    kem_encapsulate(ek, m)
}

/// Generate a ciphertext and associated shared key.
///
/// It implements ML-KEM.Encaps according to FIPS 203 (DRAFT), Algorithm 16.
pub(crate) fn kem_encapsulate(ek: &[u8; 1184], m: [u8; 32]) -> Option<([u8; 1088], [u8; 32])> {
    let mut h = [0u8; 32];
    Sha3_256::default().chain(ek).finalize_into((&mut h).into());

    let mut g = [0u8; 64];
    Sha3_512::default().chain(m).chain(h).finalize_into((&mut g).into());

    let (k, r) = g.split_at(32);
    let c = pke_encrypt(ek, m, r)?;

    Some((c, k.try_into().expect("should be 32 bytes")))
}

/// Generate a shared key from a decapsulation key and a ciphertext.  If the decapsulation key or
/// the ciphertext are not valid, returns `None`.
///
/// The shared key must be kept secret.  It implements ML-KEM.Decaps according to FIPS 203 (DRAFT),
/// Algorithm 17.
pub fn decapsulate(dk: &[u8; 2400], c: &[u8; 1088]) -> Option<[u8; 32]> {
    let (dk_pke, ek_pke) = dk.split_at(1152);
    let (ek_pke, h) = ek_pke.split_at(1184);
    let (h, z) = h.split_at(32);

    let m = pke_decrypt(dk_pke.try_into().expect("should be 1152 bytes"), c)?;

    let mut g = [0u8; 64];
    sha3::Sha3_512::default().chain(m).chain(h).finalize_into((&mut g).into());
    let (k_p, r) = g.split_at(32);

    let mut k_out = [0u8; 32];
    sha3::Shake128::default().chain(z).chain(c).finalize_xof_into(&mut k_out);
    let c1 = pke_encrypt(ek_pke.try_into().expect("should be 1184 bytes"), m, r)?;

    // Check c == c1
    let mut eq = 1;
    c.cmovne(&c1, 0, &mut eq);

    // Return k_p iff c == c1, k_out otherwise.
    for (x, y) in k_out.iter_mut().zip(k_p) {
        x.cmovnz(y, eq);
    }
    Some(k_out)
}

/// Generates a key pair for the underlying PKE from a 32-byte random seed.
///
/// It implements K-PKE.KeyGen according to FIPS 203 (DRAFT), Algorithm 12.
fn pke_keygen(d: [u8; 32]) -> ([u8; 1184], [u8; 1152]) {
    let g = sha3::Sha3_512::default().chain(d).finalize_fixed();
    let (rho, sigma) = g.split_at(32);

    let mut a = [[0; N]; K * K];
    for i in 0..K {
        for j in 0..K {
            // Note that this is consistent with Kyber round 3, rather than with
            // the initial draft of FIPS 203, because NIST signaled that the
            // change was involuntary and will be reverted.
            a[i * K + j] = sample_ntt(rho, j as u8, i as u8);
        }
    }

    let mut n = 0u8;
    let (mut s, mut e) = ([[0; N]; K], [[0; N]; K]);
    for s in s.iter_mut() {
        *s = ntt(sample_poly_cbd(sigma, n));
        n += 1;
    }
    for e in e.iter_mut() {
        *e = ntt(sample_poly_cbd(sigma, n));
        n += 1;
    }

    let mut t = [[0; N]; K]; // A ◦ s + e
    for i in 0..K {
        t[i] = e[i];
        for j in 0..K {
            t[i] = poly_add(t[i], ntt_mul(a[i * K + j], s[j]))
        }
    }

    let mut ek = [0; 1184];
    {
        let mut ek = ek.chunks_exact_mut(384);
        for (ek, t) in ek.by_ref().zip(t) {
            ek.copy_from_slice(&poly_byte_encode(t));
        }
        ek.into_remainder().copy_from_slice(rho);
    }

    let mut dk = [0; 1152];
    for (dk, s) in dk.chunks_exact_mut(384).zip(s) {
        dk.copy_from_slice(&poly_byte_encode(s));
    }

    (ek, dk)
}

/// Encrypts a plaintext message.
///
/// It implements K-PKE.Encrypt according to FIPS 203 (DRAFT), Algorithm 13.
fn pke_encrypt(ek: &[u8; 1184], m: [u8; 32], rnd: &[u8]) -> Option<[u8; 1088]> {
    let mut t = [[0; N]; K];
    let mut ek = ek.chunks_exact(384);
    for (t, ek) in t.iter_mut().zip(ek.by_ref()) {
        *t = poly_byte_decode(ek.try_into().expect("should be 384 bytes"))?;
    }
    let rho = ek.remainder();

    let mut at = [[0; N]; K * K];
    for i in 0..K {
        for j in 0..K {
            // Note that i and j are inverted, as we need the transposition of A.
            at[i * K + j] = sample_ntt(rho, i as u8, j as u8);
        }
    }

    let mut n = 0u8;
    let (mut r, mut e1) = ([[0; N]; K], [[0; N]; K]);
    for r in r.iter_mut() {
        *r = ntt(sample_poly_cbd(rnd, n));
        n += 1;
    }
    for e1 in e1.iter_mut() {
        *e1 = sample_poly_cbd(rnd, n);
        n += 1;
    }
    let e2 = sample_poly_cbd(rnd, n);

    let mut u = [[0; N]; K]; // NTT⁻¹(AT ◦ r) + e1
    for i in 0..K {
        u[i] = e1[i];
        for j in 0..K {
            u[i] = poly_add(u[i], inverse_ntt(ntt_mul(at[i * K + j], r[j])));
        }
    }

    let micro = ring_decode_and_decompress1(m)?;

    let mut v_ntt = [0; N]; // t⊺ ◦ r
    for (t, r) in t.iter().copied().zip(r.iter().copied()) {
        v_ntt = poly_add(v_ntt, ntt_mul(t, r))
    }
    let v = poly_add(poly_add(inverse_ntt(v_ntt), e2), micro);

    let mut c = [0; 1088];
    {
        let mut c = c.chunks_exact_mut(320);
        for (c, f) in c.by_ref().zip(u.iter().copied()) {
            c.copy_from_slice(&ring_compress_and_encode10(f));
        }
        c.into_remainder().copy_from_slice(&ring_compress_and_encode4(v));
    }
    Some(c)
}

/// Decrypts a ciphertext.
///
/// It implements K-PKE.Decrypt according to FIPS 203 (DRAFT), Algorithm 14.
fn pke_decrypt(dk: &[u8; 1152], c: &[u8; 1088]) -> Option<[u8; 32]> {
    let mut u = [[0; N]; K];
    let mut c = c.chunks_exact(320);
    for (u, c) in u.iter_mut().zip(c.by_ref()) {
        *u = ring_decode_and_decompress10(c.try_into().expect("should be 320 bytes"));
    }

    let c = c.remainder().try_into().expect("should be 128 bytes");
    let v = ring_decode_and_decompress4(c)?;

    let mut s = [[0; N]; K];
    for (s, dk) in s.iter_mut().zip(dk.chunks_exact(384)) {
        *s = poly_byte_decode(dk.try_into().expect("should be 384 bytes"))?;
    }

    let mut v1_ntt = [0; N];
    for (s, u) in s.into_iter().zip(u) {
        v1_ntt = poly_add(v1_ntt, ntt_mul(s, ntt(u)));
    }

    let w = poly_sub(v, inverse_ntt(v1_ntt));

    Some(ring_compress_and_encode1(w))
}

// ML-KEM global constants.
const Q: u16 = 3329;
const N: usize = 256;

// ML-KEM-768 parameters. The code makes assumptions based on these values,
// they can't be changed blindly.
const K: usize = 3;

/// FieldElement is an integer modulo q, an element of ℤ_q. It is always reduced.
type FieldElement = u16;

/// Checks that a value `a` is `< q`.
fn fe_check_reduced(a: FieldElement) -> Option<FieldElement> {
    (a < Q).then_some(a)
}

/// Reduce a value `a < 2q`.
fn fe_reduce_once(a: u16) -> FieldElement {
    let x = a.wrapping_sub(Q);
    x.wrapping_add((x >> 15).wrapping_mul(Q))
}

fn fe_add(a: FieldElement, b: FieldElement) -> FieldElement {
    fe_reduce_once(a.wrapping_add(b))
}

fn fe_sub(a: FieldElement, b: FieldElement) -> FieldElement {
    fe_reduce_once(a.wrapping_sub(b).wrapping_add(Q))
}

const BARRETT_MULTIPLIER: u64 = 5039; // 4¹² / q
const BARRETT_SHIFT: usize = 24; // log₂(4¹²)

/// Reduce a value `a < q²` using Barrett reduction, to avoid potentially variable-time division.
fn fe_reduce(a: u32) -> FieldElement {
    let quotient = ((a as u64).wrapping_mul(BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    fe_reduce_once(a.wrapping_sub(quotient.wrapping_mul(Q as u32)) as u16)
}

fn fe_mul(a: FieldElement, b: FieldElement) -> FieldElement {
    fe_reduce((a as u32).wrapping_mul(b as u32))
}

// Maps a field element uniformly to the range 0 to 2ᵈ-1, according to FIPS 203 (DRAFT), Definition
// 4.5.
fn compress(x: FieldElement, d: u8) -> u16 {
    // We want to compute (x * 2ᵈ) / q, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    // Barrett reduction produces a quotient and a remainder in the range [0, 2q),
    // such that dividend = quotient * q + remainder.
    let dividend = (x as u32) << d; // x * 2ᵈ
    let mut quotient =
        (((dividend as u64).wrapping_mul(BARRETT_MULTIPLIER)) >> BARRETT_SHIFT) as u32;
    let remainder = dividend.wrapping_sub(quotient.wrapping_mul(Q as u32));

    // Since the remainder is in the range [0, 2q), not [0, q), we need to
    // portion it into three spans for rounding.
    //
    //     [ 0,       q/2     ) -> round to 0
    //     [ q/2,     q + q/2 ) -> round to 1
    //     [ q + q/2, 2q      ) -> round to 2
    //
    // We can convert that to the following logic: add 1 if remainder > q/2,
    // then add 1 again if remainder > q + q/2.
    //
    // Note that if remainder > x, then ⌊x⌋ - remainder underflows, and the top
    // bit of the difference will be set.
    quotient = quotient.wrapping_add((Q as u32 / 2).wrapping_sub(remainder) >> 31 & 1);
    quotient += (Q as u32 + (Q as u32) / 2 - remainder) >> 31 & 1;

    // quotient might have overflowed at this point, so reduce it by masking.
    let mask = (1u32 << d) - 1;
    (quotient & mask) as u16
}

// Maps a number x between 0 and 2ᵈ-1 uniformly to the full range of field elements, according to
// FIPS 203 (DRAFT), Definition 4.6.
fn decompress(y: u16, d: u8) -> FieldElement {
    // We want to compute (y * q) / 2ᵈ, rounded to nearest integer, with 1/2
    // rounding up (see FIPS 203 (DRAFT), Section 2.3).

    let dividend = (y as u32).wrapping_mul(Q as u32);
    let mut quotient = dividend >> d; // (y * q) / 2ᵈ

    // The d'th least-significant bit of the dividend (the most significant bit
    // of the remainder) is 1 for the top half of the values that divide to the
    // same quotient, which are the ones that round up.
    quotient = quotient.wrapping_add((dividend >> (d - 1)) & 1);

    // quotient is at most (2¹¹-1) * q / 2¹¹ + 1 = 3328, so it didn't overflow.
    quotient as u16
}
// RingElement is a polynomial, an element of R_q, represented as an array according to FIPS 203
// (DRAFT), Section 2.4.
type RingElement = [FieldElement; N];

/// Adds two RingElements or NTTElements.
fn poly_add(a: [FieldElement; N], b: [FieldElement; N]) -> [FieldElement; N] {
    let mut out = [0; N];
    for ((o, a), b) in out.iter_mut().zip(a).zip(b) {
        *o = fe_add(a, b);
    }
    out
}

/// Subtracts two RingElements or NTTElements.
fn poly_sub(a: [FieldElement; N], b: [FieldElement; N]) -> [FieldElement; N] {
    let mut out = [0; N];
    for ((o, a), b) in out.iter_mut().zip(a).zip(b) {
        *o = fe_sub(a, b);
    }
    out
}

/// Returns the 384-byte encoding of the ring element.
///
/// It implements ByteEncode₁₂, according to FIPS 203 (DRAFT), Algorithm 4.
fn poly_byte_encode(f: RingElement) -> [u8; 384] {
    let mut out = [0u8; 384];
    for (p, o) in f.chunks_exact(2).zip(out.chunks_exact_mut(3)) {
        let x = (p[0] as u32) | (p[1] as u32) << 12;
        o[0] = x as u8;
        o[1] = (x >> 8) as u8;
        o[2] = (x >> 16) as u8;
    }
    out
}

/// Decodes the 384-byte encoding of a polynomial, checking that all the coefficients are
/// properly reduced. This achieves the "Modulus check" step of ML-KEM Encapsulation Input
/// Validation.
///
/// Also used in ML-KEM Decapsulation, where the input validation is not required, but
/// implicitly allowed by the specification.
///
/// It implements ByteDecode₁₂, according to FIPS 203 (DRAFT), Algorithm 5.
fn poly_byte_decode(b: [u8; 384]) -> Option<RingElement> {
    let mut out = [0; N];
    for (o, p) in out.chunks_exact_mut(2).zip(b.chunks_exact(3)) {
        let d = (p[0] as u32) | (p[1] as u32) << 8 | (p[2] as u32) << 16;
        const MASK_12: u32 = 0b1111_1111_1111;
        o[0] = fe_check_reduced((d & MASK_12) as u16)?;
        o[1] = fe_check_reduced((d >> 12) as u16)?;
    }
    Some(out)
}

/// Returns a 32-byte encoding of a ring element, compressing one coefficients per bit.
///
/// It implements Compress₁, according to FIPS 203 (DRAFT), Definition 4.5, followed by ByteEncode₁,
/// according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode1(f: RingElement) -> [u8; 32] {
    let mut b = [0; 32];
    for i in 0..N {
        b[i / 8] |= (compress(f[i], 1) << (i % 8)) as u8;
    }
    b
}

/// Decodes a 32-byte slice to a ring element where each bit is mapped to 0 or ⌈q/2⌋.
///
/// It implements ByteDecode₁, according to FIPS 203 (DRAFT), Algorithm 5, followed by Decompress₁,
/// according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress1(b: [u8; 32]) -> Option<RingElement> {
    let mut f = [0; N];
    for i in 0..N {
        let b_i = b[i / 8] >> (i % 8) & 1;
        f[i] = (b_i as u16) * 1665 // 0 decompresses to 0, and 1 to 1665
    }
    Some(f)
}

/// Returns a 128-byte encoding of a ring elements, compressing two coefficients per byte.
///
/// It implements Compress₄, according to FIPS 203 (DRAFT), Definition 4.5, followed by ByteEncode₄,
/// according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode4(f: RingElement) -> [u8; 128] {
    let mut b = [0; 128];
    for (b, f) in b.iter_mut().zip(f.chunks_exact(2)) {
        *b = (compress(f[0], 4) | compress(f[1], 4) << 4) as u8;
    }
    b
}

/// Decodes a 128-byte encoding of a ring element where each four bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₄, according to FIPS 203 (DRAFT), Algorithm 5, followed by Decompress₄,
/// according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress4(b: [u8; 128]) -> Option<RingElement> {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(2).zip(b) {
        f[0] = decompress((b & 0b1111) as u16, 4);
        f[1] = decompress((b >> 4) as u16, 4);
    }
    Some(f)
}

/// Returns a 320-byte encoding of a ring element, compressing four coefficients per five bytes.
///
/// It implements Compress₁₀, according to FIPS 203 (DRAFT), Definition 4.5, followed by
/// ByteEncode₁₀, according to FIPS 203 (DRAFT), Algorithm 4.
fn ring_compress_and_encode10(f: RingElement) -> [u8; 320] {
    let mut b = [0; 320];
    for (f, b) in f.chunks_exact(4).zip(b.chunks_exact_mut(5)) {
        let mut x = 0u64;
        x |= compress(f[0], 10) as u64;
        x |= (compress(f[1], 10) as u64) << 10;
        x |= (compress(f[2], 10) as u64) << 20;
        x |= (compress(f[3], 10) as u64) << 30;
        b[0] = (x) as u8;
        b[1] = (x >> 8) as u8;
        b[2] = (x >> 16) as u8;
        b[3] = (x >> 24) as u8;
        b[4] = (x >> 32) as u8;
    }
    b
}

/// Decode a 320-byte encoding of a ring element where each ten bits are mapped to an equidistant
/// distribution.
///
/// It implements ByteDecode₁₀, according to FIPS 203 (DRAFT), Algorithm 5, followed by
/// Decompress₁₀, according to FIPS 203 (DRAFT), Definition 4.6.
fn ring_decode_and_decompress10(b: [u8; 320]) -> RingElement {
    let mut f = [0; N];
    for (f, b) in f.chunks_exact_mut(4).zip(b.chunks_exact(5)) {
        let x = (b[0] as u64)
            | (b[1] as u64) << 8
            | (b[2] as u64) << 16
            | (b[3] as u64) << 24
            | (b[4] as u64) << 32;
        f[0] = decompress((x & 0b11_1111_1111) as u16, 10);
        f[1] = decompress((x >> 10 & 0b11_1111_1111) as u16, 10);
        f[2] = decompress((x >> 20 & 0b11_1111_1111) as u16, 10);
        f[3] = decompress((x >> 30 & 0b11_1111_1111) as u16, 10);
    }
    f
}

/// Draws a RingElement from the special Dη distribution given a stream of random bytes generated by
/// the PRF function, according to FIPS 203 (DRAFT), Algorithm 7 and Definition 4.1.
fn sample_poly_cbd(s: &[u8], b: u8) -> RingElement {
    let mut xof = [0u8; 128];
    Shake256::default().chain(s).chain([b]).finalize_xof_into(&mut xof);

    // sample_poly_cbd simply draws four (2η) bits for each coefficient, and adds the first two and
    // subtracts the last two.
    let mut f = [0; N];
    for (b, f) in xof.iter().zip(f.chunks_exact_mut(2)) {
        let (b_7, b_6, b_5, b_4) = (b >> 7, b >> 6 & 1, b >> 5 & 1, b >> 4 & 1);
        let (b_3, b_2, b_1, b_0) = (b >> 3 & 1, b >> 2 & 1, b >> 1 & 1, b & 1);
        f[0] = fe_sub((b_0 + b_1) as u16, (b_2 + b_3) as u16);
        f[1] = fe_sub((b_4 + b_5) as u16, (b_6 + b_7) as u16);
    }
    f
}

/// NTTElement is an NTT representation, an element of T_q, represented as an array according to
/// FIPS 203 (DRAFT), Section 2.4.
type NTTElement = [FieldElement; N];

/// GAMMAS are the values ζ^2BitRev7(i)+1 mod q for each index i.
const GAMMAS: [u16; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

/// Multiply two NTTElements.
///
/// It implements MultiplyNTTs, according to FIPS 203 (DRAFT), Algorithm 10.
fn ntt_mul(f: NTTElement, g: NTTElement) -> NTTElement {
    let mut h = [0; N];
    for i in 0..128 {
        let (a0, a1) = (f[2 * i], f[2 * i + 1]);
        let (b0, b1) = (g[2 * i], g[2 * i + 1]);
        h[2 * i] = fe_add(fe_mul(a0, b0), fe_mul(fe_mul(a1, b1), GAMMAS[i]));
        h[2 * i + 1] = fe_add(fe_mul(a0, b1), fe_mul(a1, b0));
    }
    h
}

/// ZETAS are the values ζ^BitRev7(k) mod q for each index k.
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Map a RingElement to its NTTElement representation.
///
/// It implements NTT, according to FIPS 203 (DRAFT), Algorithm 8.
fn ntt(mut f: RingElement) -> NTTElement {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..256).step_by(2 * len) {
            let zeta = ZETAS[k];
            k += 1;
            for j in start..(start + len) {
                let t = fe_mul(zeta, f[j + len]);
                f[j + len] = fe_sub(f[j], t);
                f[j] = fe_add(f[j], t);
            }
        }
        len /= 2;
    }
    f
}

/// Map a NTTElement back to the RingElement it represents.
///
/// It implements NTT⁻¹, according to FIPS 203 (DRAFT), Algorithm 9.
fn inverse_ntt(mut f: NTTElement) -> RingElement {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..256).step_by(2 * len) {
            let zeta = ZETAS[k];
            k -= 1;
            for j in start..(start + len) {
                let t = f[j];
                f[j] = fe_add(t, f[j + len]);
                f[j + len] = fe_mul(zeta, fe_sub(f[j + len], t));
            }
        }
        len *= 2;
    }

    for f in f.iter_mut() {
        *f = fe_mul(*f, 3303);
    }

    f
}

/// Draw a uniformly random nttElement from a stream of uniformly random bytes generated by the XOF
/// function, according to FIPS 203 (DRAFT), Algorithm 6 and Definition 4.2.
fn sample_ntt(rho: &[u8], ii: u8, jj: u8) -> NTTElement {
    let mut xof = Shake128::default().chain(rho).chain([ii, jj]).finalize_xof();

    // SampleNTT essentially draws 12 bits at a time from r, interprets them in
    // little-endian, and rejects values higher than q, until it drew 256
    // values. (The rejection rate is approximately 19%.)
    //
    // To do this from a bytes stream, it draws three bytes at a time, and
    // splits the second one between the high-order bits of the first value and
    // the low-order bits of the second values.
    //
    //               r₀              r₁              r₂
    //       |- - - - - - - -|- - - - - - - -|- - - - - - - -|
    //
    //                   d₁                      d₂
    //       |- - - - - - - - - - - -|- - - - - - - - - - - -|
    //
    //                         r₁%16   r₁>>4
    //                       |- - - -|- - - -|
    //
    // Note that in little-endian, a modulo operation keeps the "leftmost"
    // least-significant bits, while a right-shift keeps the "rightmost"
    // most-significant bits.

    let mut a = [0; N];
    let mut b = [0u8; 3];
    let mut j = 0;
    loop {
        xof.read(&mut b);
        let d = (b[0] as u32) | (b[1] as u32) << 8 | (b[2] as u32) << 16;
        const MASK12: u32 = 0b1111_1111_1111;

        let d1 = d & MASK12;
        if d1 < Q as u32 {
            a[j] = d1 as u16;
            j += 1;
        }

        if j >= N {
            break;
        }

        let d2 = d >> 12;
        if d2 < Q as u32 {
            a[j] = d2 as u16;
            j += 1;
        }

        if j >= N {
            break;
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand_chacha::ChaChaRng;
    use rand_core::SeedableRng;

    use super::*;

    #[test]
    fn add() {
        for a in 0..Q {
            for b in 0..Q {
                assert_eq!(fe_add(a, b), (a.wrapping_add(b) % Q));
            }
        }
    }

    #[test]
    fn sub() {
        for a in 0..Q {
            for b in 0..Q {
                assert_eq!(fe_sub(a, b), (a.wrapping_sub(b).wrapping_add(Q) % Q));
            }
        }
    }

    #[test]
    fn mul() {
        for a in 0..Q {
            for b in 0..Q {
                let c = ((a as u32).wrapping_mul(b as u32)) % Q as u32;
                assert_eq!(fe_mul(a, b), c as u16);
            }
        }
    }

    #[test]
    fn compress_decompress() {
        for bits in [1u8, 4, 10] {
            for a in 0..(1 << bits) {
                let f = decompress(a, bits);
                assert!(f < Q);
                let b = compress(f, bits);
                assert_eq!(a, b);
            }

            for a in 0..100u16 {
                let c = compress(a, bits);
                assert!(c < (1 << bits));
            }
        }
    }

    #[test]
    fn kem_decaps_test_vector() {
        // From the October 2023 version of PQC Intermediate Values available at
        // https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
        // Decapsulation -- ML-KEM-768.txt
        let dk = hex!("3456859BF707E672AC712B7E70F5427574597502B81DE8931C92A9C0D22A8E1773CB87472205A31C32206BA4BCF42259533CB3A19C0200860244A6C3F6921845B0A05850187A4310B3D5223AAAA0C79B9BBCFCCB3F751214EB0CFAC1A29ED8848A5A49BA84BA68E6B6F5057D493105FF38A9F44B4E7F6CBE7D216408F7B48605B270B253B001A5401C0C9127CC185B1B0CF92B99FBA0D95A295F873515520C86321B8C966C837AAB34B2BFFAB2A2A4301B356B26CDC4563802901B4762F284281A382E5F762BEF47B519A81A108657EBE962BE120B5FB3B9ED338CCF47B3A03952A16633F6E6B534E6B63D05706EFA0F94C03A2B856AE551422F9011F2589A41B96A2CD213C6999B09E91FF423CB106A1A920B84B811469497154223987F005C72F8AF388B090C639F8C774FC5A294C74A212C91A86C328AEBEA558AB43F8B873534FA2EF9E66CEF3C52CD471AB78375E745B9D0AA65D2278B9275AE5348B16CF62AC8065734E4BD77B80CCF897605EB76F485AF8A0B466557A83C0292CCF903EE7AA57C3B51AD660189B86139E380425B31A92689DF2431BFA7B69EAB1727451B29DA8B8BF851E1BC2D3A63134CA9663C57AEC6985CEBD56DB0447B136B017A974761C3C67D33772F9964E5434D643504332A3027294A078C599CB29163109CE3B56CE698B4D3F59E2956A1F03A4B955593F2D2457FFAAE9624A0711045B3F55292F20CC9D0CD791A21597B0F2CD980F3510F0B0239022000D735586EE6A73F3A3DCBD6BD1A85C86512ABF3C51CE00A0331F65360462C022329597A81C3F92FC17938C9138F4111387979C28F0334F90119221374DAB045929B49E43A9646A243F4464DAF811AB00630C75961BCD4AF5D99115A3749191BA8FD41CE0B3C89A695B4BB85064FD3AF95C9B4AEE09AC7B0CC69ECA36A004B6CD662A6D32795053EF0A03ADA3B98BFE3B46A79723E3A45AB3C31950669AD77072062CC3B504DF1334FD6909EAC7915F1D5AD16639F5FB564416454259134D565882CB381CBA58B76880767B50AC1B85795D7268433B371230ED4C72F99AB1AD1E595A459CF0A2334AA1463ADE4BDC9249605381857BB98095B41132946CA2457DFAA9149582AA19927B63689E2929AA41027BEF4921970BAD4A55490D91ABE251DEF4552CA88034106A02CE4B058F8B59624B67E063BF178B015E4281EB114A2BC2454943A4B4647122C42CBEA4E94154FD3E4B791F6290B782994206853D67000A633F320A8A374CA5D4038F9CA4244DCB02E9A84E1F7C8A821132B32B9A840557B34780665301724BA2606681D945E34D7CF941B8963CAA1001A491B8B2E43570E9AB95C0A57C503F0AB960B4856D0251574710FE5CB474284FC1049AA2A7B03694A1C763E99DAC6AD0BA8038B138A64432E349116A031E8C792781751BA473CBDF55720005ABDAA13D50182F0E633776BB0675C40472BAD1F9672769183D0CCC810BC25A8573220569F6AC4BAC22A1354D8B36C0580D0E5299E629C506CC7655546FF27810C97B51BA056BBF86ED9CB7C0A537F72D0CF9AD2C231E29EBF553F613CBB15B3721A20077E505FD390CB19F6488A107DEE1CAC58AB7034BA690300219595B3695C1234E8B57E33C8D3A048454A616DF3C9B56A6FF2026AF997725FC95579043BAE9399B6790D637B4FA820B0B2D2CAB607BAF6A372734C31EE0026F3C076D14A8E3EE66AAD8BBBCCEB9DC70C7B6BB0BB76C200C231601CA0873EC8710F4B18D57290B033727C601EDB71C2B0F0C21D553E0E7A4F77716839C7C8448ABB9F66A54E8A4B08A79D9A392CA1270031388BAD56217E32AEF55411974906A245C00712B3CBB1170685193FE25ACD7AC13D32073F3879A5D78375F0052CF79175BAB46D22370597BD06789EDD0711CC4243507A02B4FAADBB62250CC997AE0327AEB00DEB529192A64B1096A86B19674D0B0AF05C4AAE178C2C9A6442E94ED0A56033A11EE42632C0B4AA51D42150790F41062B77253C25BA4DE559761F0A90068389728BC977F70CF7BCCFBD883DF13C79F5F2C34312CB1D5A55D78C1B242096A8C0593CFB2753460BD30ABA306C74173995748385D00B3670E61324D87DE8A14450DC493768777FF0CE6810937A711229561A5EF2BB69861074E00BD93266E4B86269E18EEA2CAACB60A1358636CD7A7CA6BB682130241784B101EA5BFD6C3A07158621614736F6996D5A4E14963A12D836E533A0C8912DB7E11685A4A53D8285F08750DFF66DA27C23B97542DEFB99E470ACD5E647C940CB57301B43CC3E68E64E28B06770695EF609265E06C60F22CB875849E62BAB88CC10ECF622C379CB54F13D8B2BAC902B9AB02BB330B45AC8B741C2647AC45B5BF48A6D3FE039986CC940C60A94E66CF644531016A5272450824314B5662A0A909ABFB46FD27BAED3ABA8259361596882B08B2AC7233930FC3786738ED2F81EE638C45C3B9CFD1951DB5BCC1445C2C1625D57D57B53904B6A1AB681580755E89FA79775A657CD62B4426304BC0C711E2807A2C9E852D4B4359EE6B53E4675F523C90782572DC7368FB400C328C70FC846B5E98A4330BBB627BDD784B4DAF0B1F645944942B4C2B6225C8B31E989545522BA6F10396034CB1CA745977844D570894C611A5608A757416D6DE59963C32798C493EFD2264C231910E9A30090CA7B5384F231B89BA68A238190EF1A2A43CB01703470A0F061A70738944BCD9B7004F24797AECB88B1091CFED0590B0415453C39B6EC45B66305FAEA6B55A4B7967505FE3862A267ADBFE05B9181A06501893391650EAAA4A6D16853349276F98E0F44CD726615C61C16713094D8AB093CAC71F2803E7D39109EF5009C9C2CDAF7B7A6B37A33A49881F4BB5D7245A14C5042280C76A84E63F49D0D619D46D723BAA747A3BA90A6FB637A9A1DC02268FD5C043D18CBA1528AC8E225C1F923D1CC84F2E78E25DC3CCE9353C9DAC2AD726A79F64940801DD5701EFBDCB80A98A25993CD7F80591320B63172718647B976A98A771686F0120A053B0C4474604305890FECAF23475DDCC11BC08A9C5F592ABB1A153DB1B883C0507EB68F78E0A14DEBBFEEC621E10A69B6DAAFAA916B539533E508007C4188CE05C862D101D4DB1DF3C4502B8C8AE1457488A36EAD2665BFACB321760281DB9CA72C7614363404A0A8EABC058A23A346875FA96BB18AC2CCF093B8A855673811CED47CBE1EE81D2CF07E43FC4872090853743108865F02C5612AA87166707EE90FFD5B8021F0AA016E5DBCD91F57B3562D3A2BCFA20A4C03010B8AA144E6482804B474FEC1F5E138BE632A3B9C82483DC6890A13B1E8EE6AF714EC5EFAC3B1976B29DADB605B14D3732B5DE118596516858117E2634C4EA0CC");
        let ct = hex!("DFA6B9D72A63B420B89DDE50F7E0D56ECF876BFEF991FCE91C8D286FA6EABAC1730FD87741FE4AD717B282A21E235A55C3757D88D4CE62F414EB77EB9D357EE29D00087BF8110E5BBBC7C90419072EAE044BF7E183D43A94B2632AA14649619B70649521BC19370942EF70F36C34C8C23591EE0CA71A12D279E0F52D39ED0F913F8C262621FB242E680DEB307B0749C6B393A8EF66F8B04AAFA877B951AB93F598B4B2FAB04F88AC803984FF37E3FE74F3A616D5314EB3A826F874F8ECD3A5647D04942A57EFC09638470DC0A9DF40B317571D3984A78CF7D11751090722B3059E07591CC4A2ED9BA0DCE99BE9E5EE5DB8D698CDEB5814759BA977C90079CF2AFDE478069C513A60091A3A5D0111E22DE06CB145C14E22A214CB278C8152B0681BCAFF54D552B54A671C0DFEF775E7C54FEFC4853868C955971ABDAC2A76292CCCD4FD1C706B7D3614159673E9D7B29A2D3F63363129E7A21E803A460F2714E3E25922780AF38257CD1495ACD1E01980638DF58A153DAB07EFB5C7E78ADACF631956D69CCDA070459568BD9D11A2934BCF1643BC99468238910B1F742EBB3C03D39FD45CFB85BA309E29DD9B5CD560819EC729FCAC8B9D725E3E8ABEDE4B5298A8658EE3F781B0CE683CBB7335CD57EFE2204A8F197446D7314CDBF4C5D08CCC41F80857CC9571FBFB906060F7E17C8CEF0F274AFF83E393B15F2F9589A13AF4BC78E16CDDE62361D63B8DC903B70C01A43419CD2052150BD28719F61FF31F4A9BEC4DDBCEC1F8FB2EFBF37DFFFA4C7FECA8CE6D626BFDA16EE708D9206814A2EF988525615D4AC9BE608C4B03ABEE95B32A5DB74A96119A7E159AF99CD98E88EAF09F0D780E7C7E814B8E88B4F4E15FA54995D0ECBAD3EF046A4947F3E8B9E744241489B806FE9401E78BAFC8E882E9D6D0700F720C0024E7DA49061C5D18A62074040ABC0003200ED465231797930A2E2AA501F64862DDA13014A99F9D3270AA907EEB3FDBFF291600DF1F6B39684B11E396B70D86F90492E82B09BA25607B0C286FBC070182AC76FA7C859AAFEA87016AED22C3605A2789A1D439FD8D933342DAB745A3E550E7D77C01A6234BDA7D6BB19D495E6560FCE8396FC3C6E088ED60F5F2771416EA3BE5BE472B6404906C91E71D9A8672F390083655AB7D0EC6EDFE86789CE20BE2EA90CA5CC31416FB24CBAF94DA1468FE696BCDF5247CF117CBE9334076CA6896B2F6A016B1F7C73728807898D8B199756C2B0AA2457E1B4F7754C4576CE5645614EA15C1AE28B094EB217C7A7A41239576CBDA380EE68783432730AD5EBE7F51D6BE7FB02AB37BE0C96AAC9F3C790A18D159E6BABA71EC88C110FD84C336DF630F271CF79328B6C879DF7CDE0F70712220B1FBB9ACB48248D91F0E2B6E3BE40C2B221E626E7E330D9D83CC0668F7308591E14C7D72B841A6F05F3FDC139EECC1536765650B55A9CEC6BBF54CCEC5C3AC9A0E39F48F237BD4C660CB1A8D250BB6C8C010FEC34CC3D91599271C7531330F12A3E44FAFD905D2C6");
        let k_exp = hex!("BD7256B242F404869D662F80BF677A16C0C6FC1568CCA5B64582A01A6A142D71");

        assert_eq!(Some(k_exp), decapsulate(&dk, &ct));
    }

    #[test]
    fn kem_encaps_test_vector() {
        // From the October 2023 version of PQC Intermediate Values available at
        // https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
        // Encapsulation -- ML-KEM-768.txt
        let ek = hex!("1456A2EE8C3556054ABC79B4882C3190E5CA726AB402E5B09728C0F4F79C9FC2ADD828ABE432B1501B60F46CCBC86A3378C34895708A13671B20B389479AAA01C69D6B3B7D07D1C3AB54B91C580F5A336B30069A4F134FFD3764CE73A047E2844771742BF4710B972D4F6590A1C53A975368C271B670F1A4036441054A66E8815997512288552FD7149FFB705AAE133F8414060D0092FA8A1627D78AB2ABC6696288BAF5C60EF370827A7EFA72AE5C6741A5DA043D5940F121485372A98F472D60F05F74D95F01A1991E73A3E0A9536467A4738AB4CF385BA772827EB8CC058B3572E40B598444C181C7F6D9B760A7B907092E9C3351EA234E4449BD9B61A134654E2DA191FF0793961569D3594448BBC2586999A6671EFCA957F3A6699A4A1B2F4707ABA0B2DB20114FE68A4E2815AF3AAC4B8C6BE5648C50CC35C27C57288028D361708D302EEBB860BEE691F656A2550CB321E9293D7516C599817B766BA928B108779A1C8712E74C76841AC58B8C515BF4749BF715984445B2B53063384001E55F68867B1AF46CA70CA8EA74172DB80B5218BDE4F00A0E658DB5A18D94E1427AF7AE358CCEB238772FCC83F10828A4A367D42C4CB6933FDD1C1C7B86AD8B009657A96222D7BA92F527AF877970A83247F47A23FC2285118B57717715204674DA9C94B62BC7838CF87200156B26BA4671159931C49322D80671A0F332EAA2BBF893BE408B9EAC6A505483AA9075BD1368B51F99211F480A9C542A75B5BE08E43ADAF301DD729A85954010E64892A2AA4F15C0BD70B3D856494FF9BA0FE4CE12991CA06B5E3D0B2AF1F797B7A2B760910AE9F833D0D4267A58052C2990F161B886E251711C09D085C3D958B144192C9CC3224A460715B6784EB0B26F237187507D85C5110ACC71CE47198F254553356DAB448C38D243A7C02BE40C908C828D05C081DFAB8FC6B5CFE7D56E7317157DC053B2B3489986B081288871818585E09931095E3274A084115BE276438254A796270A7B4306F08B98D9C2AAECF7065E74446B7C696DBAAF8B4625A10B07827B4A8BABAB09B64AE1C375BB785441F319FB9AC2F14C95FFB252ABBB809C6909CD97706E40691CBA61C9252BD38A04311CA5BB2CA79578347505D0888851E082648BD003BE97C0F8F66759EC96A96A081C6822C4510559537042FC15F069A649B74A10961B354A1F625B04E25B293CF65FB4F53A80CC733D7A175775BF8A9ABB9201620E83A7F3E724D1287DBC44BDD5D85FC71545A927BEEDE537A7768735CC1486C7C3F31104DB67343F435D2D45554BAAC9CDB5822E8422AE8321C78ABE9F261FD4810A79E33E94E63B3341872C92253521997C084FBC060B8B125CCC88AC85AC5FE3168ACB059B3F119C4E050A20732F501BB9B3E687C846B5C2653F8886373E1004A2AB8D1BB970A7E571D8A46EE81B782F26942DD394FDD9A5E4C5631D985528604B1CC976275B6AC8A67CEEC10FFACBBA3D3BB141321DFC3C9231FC96E448B9AB847021E2C8D90C6BCAF2B1240783B62C79DEDC072A5763E660AF2C27C3F0C3C09207CAD990BB41A7BFCEC99F51596A0E83778F85C006AC6D1FE981B4C4BA1CB575A7D07AE2D31BA760095F74BC163841CF8FF77F894ABC6D261ED87A4530363B949C4AD24EFB3A56809478DDA2");
        let msg = hex!("40BE9DCAC16E9CA73D49D0C83F9D3D89BB71574A4219A0F393DFECE2988394C4");
        let ct_exp= hex!("778D6B03791ACAF56CAAFCC78CEE5CBCA1DE8737E9C7FF4AE5F384D344E08223C74C824CB5848520517C7F0EA0645EB6F889517AE5216B0CF41DDC3F0D1DF9BC6E4DECB236A5EA8B214F64266D3CDE08E0CB00E5D91F586706B1EE533D20476F4423B78F916B1726EEEA959FFB9AC634D04A94D09923CB0D4E730CCA4144E7C4884921652DA4928C68E644F673CFC57D3E87CF5BE581A89F9CB8F0FCE2782D681E5CE88AF58458C3D63D807572DE5AA8E1FAF2DCD14EDB7349565B7D3271DDBEB0B6CC7AFE08635784311159733C46E5FDC5E0CD36CE5685ACFB1AFE50ABB46F447521E60D9C8F0E4CA28C190ABB40C365F412471E95A8EA396D4BD8070EEB1F02B07C825367AA1EC0F10C3862416BB21AD6CA748A86E9829EFC1A0499093C85176D37F574C75CF5EDFA8D920D3268CB34C6A4BB0002869BC05D7C8FCC0658D4A01EACD74557A37D98A763074752DFDD6429881CAFF577D3A048031BD52C4E9726398590F9519FD59405D6B3C307AFCB168A985785D954A6D1DC1EA92E1EB6F946A4D99DD6CA307ABFD8362FABA98BB264C69C5F555D60883CC56019FEB4E8000C48B7E68CD667F00B5250CEF293A4A9E778726E62F120361E21AB3140464CDC6ABDE9EA05198D8B3BB671B9111A2F317582847CA5015664F22CDB08C143187BDE2129B54F34160295D75FE9A494FD7E67AAA76B57AAFFD89D01A71DF5C8158620298D582BBEFA6D09AC412A99AA3BE9C383504948C43DD5AF4127B1435804F44BAFA142BFC2A95D95FB2EF0641ABE71064DE51D6B9EC50857B8EEF7F48036313D0E936763B8F7BDE69B064DD5761D80EA6F1A8B37565753C579BBB895EFB9FCB3FC5FA3362E3774F0F77140B973CAE587BAD2F3B566A9C25A969347E5C54F87F1105E9C074867D94077CCAE3ABEA54520EDB51D9DAABE7848E78FDF66E07E2E22B30251931E890BAF1F5E177D4D9CEC9E4969481FD7C1335A0ED5879F34EF4BB4F66C28803CEA162BA461506D52EB3AE16951922B06825186C3D4CE1B51F3C92F3C52F2D04D1F13B2B17C9EEB882CCE0EB88B7EA9A1CE4E37415CC84C7BC436A4628386CC77D9AFD207911BD9BFD8A7FA05C275BE0C4C6A8FC0A61BDA1D67AE33B5310BE1290DC71C1418EB5744BF2842C1652173A49A692E71FE43258A205B3CAAB90C0304A51E77D01B404A01FAE2F83AB80C5DBF6CF518C001F46A633FA169B1BDB77A9D0B1E0C007835C09F6ABBA96F3F53564DA508EE8861A483A81749D4A44672B1EF1605F29D168B74B736B4F13501D7AD1213118A7832E666A50BE8010D54322A526CF7A4E543A79D0D98E004FBEC76EA3F7E887BDBAF50DADFDDDF3FFECF6D3F77EA4B9B16DC754F4A68E5EF32F6A137E7C9E3C3E8C2E236C7EBC45D46EC1677A5A8BB2668443B0BE8693DC257F13D8B9A90100B92B4D1761B819673832C32020671BFB3D0220A363E4BED6D649D3F7368CFE081E196A43D4708798E31BB2A2F61824674ABA2FC9DCD05DB84B8627AE11488886F921BC79AE1FD03");
        let k_exp = hex!("616E0B753A3B7F40FEF9A389F58F16BFBB04622941D2464BDAE767820DFAC38E");

        let (c, k) = kem_encapsulate(&ek, msg).expect("should encapsulate");
        assert_eq!(c, ct_exp);
        assert_eq!(k, k_exp);
    }

    #[test]
    fn kem_key_gen_test_vector() {
        // From the October 2023 version of PQC Intermediate Values available at
        // https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files
        // Key Generation -- ML-KEM-768.txt

        // Note that d == z in the vectors, which is unfortunate because—aside from
        // being confusing, as this would NOT be possible in practice—it makes it
        // impossible to detect e.g. a mistake swapping the two.
        let d = hex!("92AC7D1F83BAFAE6EE86FE00F95D813375772434860F5FF7D54FFC37399BC4CC");
        let z = hex!("92AC7D1F83BAFAE6EE86FE00F95D813375772434860F5FF7D54FFC37399BC4CC");
        let ek_exp = hex!("D2E69A05534A7232C5F1B766E93A5EE2EA1B26E860A3441ADEA91EDB782CABC8A5D011A21BC388E7F486F0B7993079AE3F1A7C85D27D0F492184D59062142B76A43734A90D556A95DC483DD82104ED58CA1571C39685827951434CC1001AA4C813261E4F93028E14CD08F768A454310C3B010C83B74D04A57BB977B3D8BCF3AAA78CA12B78F010D95134928A5E5D96A029B442A41888038B29C2F122B0B6B3AF121AEA29A05553BDF1DB607AFB17001860AF1823BCF03DB3B441DA163A28C523A5FB4669A64234A4BCD1217FF2635BD97680FF938DBCF10E9532A9A79A5B073A9E8DB2123D210FAEA200B664838E80071F2BA254AAC890A46E28EC342D92812B01593071657E7A3A4A75CB3D5279CE88405AC5ADACB2051E022EE0AC9BBFE32DEF98667ED347ADCB3930F3CAD031391B709A4E61B8DD4B3FB741B5BD60BF304015EE7546A24B59EADCA137C7125074726B7686EC551B7BC26BBDB20FC3783534E34EE1F1BC6B77AB49A6667846975778C3C536830450A3FA910259722F3F806E6EB4B9346763FEF0922BC4B6EB3826AFF24EADC6CF6E477C2E055CFB7A90A55C06D0B2A2F5116069E64A5B5078C0577BC8E7900EA71C341C02AD854EA5A01AF2A605CB2068D52438CDDC60B03882CC024D13045F2BA6B0F446AAA5958760617945371FD78C28A40677A6E72F513B9E0667A9BAF446C1BA931BA81834234792A2A2B2B3701F31B7CF467C80F1981141BB457793E1307091C48B5914646A60CE1A301543779D7C3342AD179796C2C440D99DF9D41B52E32625A82AA5F579A9920BFFBA964FA70DB259C85E68C813817B1347BF19814DA5E9364A4645E621923D955C211A55D355C816DA04730AA324085E622B51D6109B49F673ADD00E414755C8024AA0164F24556DED963D61143856CB4FF0567E3320730DBCBF12F66E2B70B20054A6DEA42614B50EF72B156F5149FC263DD7E039C55A3EE9827DF92C565D24C55E0A81C6494695344D948748AFBA9F762C0EA90BB724897902000775613949602C48C78A9440678C24086D326D79643BAF7036C66C7E026AAEFDA2807A60BD7FC91363BB0234A590984AA011F11D40268218A1588377B3D7671B8B99789919B86EE82B18EC22D4E80A1F27853D889419D460DEF7567AA4567969C43048C32B8462A9C9386EB3152A6976AA783CDD1A8C57A9B6BBD837A00624B58B4BA3DBB63BB8200E7BC88881BEBDA925BCA028E291AA1C22539CD04F90090D7F74108C32B8022C1591C881E76304E2408190E20F09A54FC23420E2620E9D87A3108A94FEEA72D5AB7FCFB972E6561B1A7B062F1A682E020AA2562812B296547B917824CDB88C582B5A6890177BC70C91ACAC9ABE290AEB2C34A7E2368955CB456A345368ABE3B91B47FC30B0233A09BA79FB11238AC508CCE61095F854C23204A8D36BFC2C6E05A72AF5244B17C12101E01451570EB110567E850E79C000142441FE4160027545F6290E85451B80234A9406C390B0CEA3C8335D4C6F8550B544C9343E61BA1C8489D1B0399739168AF740A481B0F5C3372530CA06B508ECE838AB78BEE1E597A9B14F6AEC7A3BD1AA8D10BAC23B9802902CD529AB6EF54DB3110CFB561E7E6948E65281250416C349C8100B3B4D3D0F62ACAD8D161175B134F7564937CD");
        let dk_exp = hex!("19D74AD5472A8B2BAAD2A56702C9B3B5510EF3924858061D57F90DD9A1A01FEC2F57C51A888805341B617C515539597750835C3ED7A033B039D72491332C5DF4A69B6DF26171877AD1E50AC50100BE4728786685DA7A739E843FF0D45922D7281E210D5E82B944652F4862CFB3D902DE60AFD0A164471B26144A1D7A38096503095911762EBA7962C4511D05A128F2781ECB3D1F5BB1244237611ABAB924991F8A2732E27032357920F197C7692D60A9444472258CB457C1B71B77995469F3A962F3ABA6699614FCCCEA741E21C600C4357BBFAB452927C3D441BF8ED73152F75C08F540E186ACCA3326F422C84B988D77E61AE61859CF8541F89209E4983040C5617654808852B649B899A399AEC2C8BBA8A542F345ABF2813F65E9A791D32CC2D76026FB8D0C94B657489ABB487DA4A2C0E3868D3CF47F1CBB2FA79C53CFF6264777C09B177C91315484D2B30B0CA21F55ADD23C57E1911C3F086BCAD21798486EB47B7C58577381C09F5252582D1B27A7D5B8E060CE78209CC82BAE4DA606800C8DB1268F7AD2B793A44F34612CCEA31CE7D796A65A2691D61500625F83E7BE57077EE9C1B8C1CAA137CC4B6573308C19668B24B01E966903ABBCB79B67BE0A3E3E058AADA189B9EA80359AC26F4C5C53735FE4FC35247337760CCA3529B8D266BB6C48010654CDBC5A3E9757524675ABC413130CC2701F28933EABB8392B0D6D059CFC3A30326C4FCC810B37A4748C1C53928A4913E48B186697162C33FFFB06DD5161C8639DB195C6CA64829B2B3A2E4C9683B66DF7FB1909904E00020DBA134E02A168D76AC076BB77D4DC8496B4BBE7B4690BA29B62A91ABE72BEF323A44C8903E482B60D99BA61D1BBCF9CB9673534C1D647662374EE2C7C5F0081BAD149F44206717684D9746B2048633AF7A68C6865FB590358D8CF821458369B0C31EB597CF5BE78EB480EA04E35FACC380372C8C0A04DE276B1A72121E596CBB25EF7536AD3804184A87BDFB5A769160BFBB0CA3C360790E5562BB78EFE0069C77483AD35CAC237C61DE78A7DB46FC917124CA17510DB7DA218890F448EF6318613A1C97C928E2B7B6A54617BCCB6CDF278AE542B56AD7BB5ECD8C46A66C4FA0950CE41352CB85711890458F299BF40BA6FF2C0713862268B5F08E49845B09443997AB29A62073C0D9818C020167D4749231C059E6F483F976817C90C20A9C937079C2D4BE30DA974A97E4BC53ED96A55169F4A23A3EA24BD8E01B8FAEB95D4E53FFFECB60802C388A40F4660540B1B1F8176C9811BB26A683CA789564A2940FCEB2CE6A92A1EE45EE4C31857C9B9B8B56A79D95A46CB393A31A2737BAFEA6C81066A672B34C10AA98957C91766B730036A56D940AA4EBCB758B08351E2C4FD19453BF3A6292A993D67C7ECC72F42F782E9EBAA1A8B3B0F567AB39421F6A67A6B8410FD94A721D365F1639E9DDABFD0A6CE1A4605BD2B1C9B977BD1EA32867368D6E639D019AC101853BC153C86F85280FC763BA24FB57A296CB12D32E08AB32C551D5A45A4A28F9ADC28F7A2900E25A40B5190B22AB19DFB246F42B24F97CCA9B09BEAD246E1734F446677B38B7522B780727C117440C9F1A024520C141A69CDD2E69A05534A7232C5F1B766E93A5EE2EA1B26E860A3441ADEA91EDB782CABC8A5D011A21BC388E7F486F0B7993079AE3F1A7C85D27D0F492184D59062142B76A43734A90D556A95DC483DD82104ED58CA1571C39685827951434CC1001AA4C813261E4F93028E14CD08F768A454310C3B010C83B74D04A57BB977B3D8BCF3AAA78CA12B78F010D95134928A5E5D96A029B442A41888038B29C2F122B0B6B3AF121AEA29A05553BDF1DB607AFB17001860AF1823BCF03DB3B441DA163A28C523A5FB4669A64234A4BCD1217FF2635BD97680FF938DBCF10E9532A9A79A5B073A9E8DB2123D210FAEA200B664838E80071F2BA254AAC890A46E28EC342D92812B01593071657E7A3A4A75CB3D5279CE88405AC5ADACB2051E022EE0AC9BBFE32DEF98667ED347ADCB3930F3CAD031391B709A4E61B8DD4B3FB741B5BD60BF304015EE7546A24B59EADCA137C7125074726B7686EC551B7BC26BBDB20FC3783534E34EE1F1BC6B77AB49A6667846975778C3C536830450A3FA910259722F3F806E6EB4B9346763FEF0922BC4B6EB3826AFF24EADC6CF6E477C2E055CFB7A90A55C06D0B2A2F5116069E64A5B5078C0577BC8E7900EA71C341C02AD854EA5A01AF2A605CB2068D52438CDDC60B03882CC024D13045F2BA6B0F446AAA5958760617945371FD78C28A40677A6E72F513B9E0667A9BAF446C1BA931BA81834234792A2A2B2B3701F31B7CF467C80F1981141BB457793E1307091C48B5914646A60CE1A301543779D7C3342AD179796C2C440D99DF9D41B52E32625A82AA5F579A9920BFFBA964FA70DB259C85E68C813817B1347BF19814DA5E9364A4645E621923D955C211A55D355C816DA04730AA324085E622B51D6109B49F673ADD00E414755C8024AA0164F24556DED963D61143856CB4FF0567E3320730DBCBF12F66E2B70B20054A6DEA42614B50EF72B156F5149FC263DD7E039C55A3EE9827DF92C565D24C55E0A81C6494695344D948748AFBA9F762C0EA90BB724897902000775613949602C48C78A9440678C24086D326D79643BAF7036C66C7E026AAEFDA2807A60BD7FC91363BB0234A590984AA011F11D40268218A1588377B3D7671B8B99789919B86EE82B18EC22D4E80A1F27853D889419D460DEF7567AA4567969C43048C32B8462A9C9386EB3152A6976AA783CDD1A8C57A9B6BBD837A00624B58B4BA3DBB63BB8200E7BC88881BEBDA925BCA028E291AA1C22539CD04F90090D7F74108C32B8022C1591C881E76304E2408190E20F09A54FC23420E2620E9D87A3108A94FEEA72D5AB7FCFB972E6561B1A7B062F1A682E020AA2562812B296547B917824CDB88C582B5A6890177BC70C91ACAC9ABE290AEB2C34A7E2368955CB456A345368ABE3B91B47FC30B0233A09BA79FB11238AC508CCE61095F854C23204A8D36BFC2C6E05A72AF5244B17C12101E01451570EB110567E850E79C000142441FE4160027545F6290E85451B80234A9406C390B0CEA3C8335D4C6F8550B544C9343E61BA1C8489D1B0399739168AF740A481B0F5C3372530CA06B508ECE838AB78BEE1E597A9B14F6AEC7A3BD1AA8D10BAC23B9802902CD529AB6EF54DB3110CFB561E7E6948E65281250416C349C8100B3B4D3D0F62ACAD8D161175B134F7564937CDECE9E246AAD11021A67B20EB8F7765AC2823A9D18C93EC282D6DBC53CD6DF57592AC7D1F83BAFAE6EE86FE00F95D813375772434860F5FF7D54FFC37399BC4CC");

        let (ek, dk) = kem_key_gen(d, z);
        assert_eq!(ek[0], ek_exp[0]);
        assert_eq!(dk, dk_exp);
    }

    #[test]
    fn round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(0xDEADBEEF);
        let (ek, dk) = key_gen(&mut rng);
        let (c, k) = encapsulate(&ek, &mut rng).expect("should encapsulate");
        let k_p = decapsulate(&dk, &c).expect("should decapsulate");
        assert_eq!(k, k_p);
    }
}
