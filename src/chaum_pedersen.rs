use secp256k1::{Error as SecpError, PublicKey, Secp256k1, SecretKey, Signing, Verification};

use crate::fiat_shamir;
use crate::types::ChaumPedersenProof as Proof;

/// Use Chaum-Pedersen to prove the relationship is a DH-triple: v = g^B and w = u^B
///
/// secp: Secp256k1 context for precaculated constants
/// y_pk: the generator `u` <- g^y
/// k: the prover's secret key
/// bt: the prover's randomness
pub fn prove<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    y_pk: &PublicKey,
    k: &SecretKey,
    bt: &SecretKey,
) -> Result<Proof, SecpError> {
    let k = k.clone();

    // v = g^k
    let kv = PublicKey::from_secret_key(secp, &k);

    // w = u^k
    let mut kw = y_pk.clone();
    kw.mul_assign(secp, k.as_ref())?;

    let c = fiat_shamir::transform(&kv, &kw);

    // bz = bt + k*c
    let mut bz = k.clone();
    bz.mul_assign(c.as_ref())?;
    bz.add_assign(bt.as_ref())?;

    // vt = g^bt
    let vt = PublicKey::from_secret_key(secp, bt);
    // wt = g^(y*bt)
    let mut wt = y_pk.clone();
    wt.mul_assign(secp, bt.as_ref())?;

    Ok((vt, wt, bz).into())
}

/// Use Chaum-Pedersen to verify the proof of a DH-triple: v = g^B and w = u^B
///
/// secp: Secp256k1 context for precalculated constants
/// y_pk: the generator `u` <- g^y
/// kp: the prover's public key `v` <- g^k
/// ky: the prover's public key `w` over the generator `u` <- g^(y*k)
/// proof: Chaum-Pedersen proof containing the tuple: (g^bt, g^(y*bt), bz = bt + k*c)
pub fn verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    y_pk: &PublicKey,
    kp: &PublicKey,
    ky: &PublicKey,
    proof: &Proof,
) -> Result<bool, SecpError> {
    let (vt, wt, bz) = proof.inner();

    // gbz = g^bz
    let gbz = PublicKey::from_secret_key(secp, bz);

    // ubz = u^bz
    let mut ubz = y_pk.clone();
    ubz.mul_assign(secp, bz.as_ref())?;

    let kp = kp.clone();
    let c = fiat_shamir::transform(&kp, ky);

    // vc = vt * v^c
    let mut vc = kp.clone();
    vc.mul_assign(secp, c.as_ref())?;
    vc = vc.combine(vt)?;

    // wc = wt * w^c
    let mut wc = ky.clone();
    wc.mul_assign(secp, c.as_ref())?;
    wc = wc.combine(wt)?;

    let valid = gbz.f() == vc.f() && ubz.f() == wc.f();
    Ok(valid)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1_sys::types::AlignedType;

    use super::*;

    #[test]
    fn test_prove_verify() {
        let mut rand_bytes = [0u8; 32];

        OsRng.fill_bytes(&mut rand_bytes);
        let y = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let k = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = prove(&secp, &y_pk, &k, &bt).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut ky = y_pk.clone();
        ky.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(verify(&secp, &y_pk, &kp, &ky, &proof).unwrap());
    }

    #[test]
    fn test_prove_verify_lo() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[3; 32]).unwrap();

        let k = SecretKey::from_slice(&[4; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = prove(&secp, &y_pk, &k, &bt).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut ky = y_pk.clone();
        ky.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(verify(&secp, &y_pk, &kp, &ky, &proof).unwrap());
    }

    #[test]
    fn test_prove_verify_hi() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[0xf1; 32]).unwrap();

        let k = SecretKey::from_slice(&[0xc1; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = prove(&secp, &y_pk, &k, &bt).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut ky = y_pk.clone();
        ky.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(verify(&secp, &y_pk, &kp, &ky, &proof).unwrap());
    }
}
