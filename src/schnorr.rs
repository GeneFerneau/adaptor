use secp256k1::bitcoin_hashes::{sha256, Hash};
use secp256k1::{Error as SecpError, PublicKey, Secp256k1, SecretKey, Signing, Verification};

use crate::{const_compare, fiat_shamir};
use crate::types::{Challenge, SchnorrProof as Proof};

// Prove Kp = k*G && K = k*Y using Schnorr NIZK proof of identity
//
// secp: Secp256k1 context
// x: prover's adaptor public key
// k: secret key being proven
// u: random secret key for proving Kp = k*G
// v: random secret key for proving K = k*Y
pub fn dual_schnorr_prove<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    y_pk: &PublicKey,
    k: &SecretKey,
    u: &SecretKey,
    v: &SecretKey,
) -> Result<Proof, SecpError> {
    let kp_pk = PublicKey::from_secret_key(secp, k);

    let ck = PublicKey::from_secret_key(secp, u);
    let mut vck = y_pk.clone();
    vck.mul_assign(secp, v.as_ref())?;

    // use constant-time comparison to check for equality of secret keys
    if const_compare(k, u)
        | const_compare(k, v)
        | const_compare(u, v)
        | !(y_pk == &kp_pk) as u8
        | !(y_pk == &ck) as u8
        | !(y_pk == &vck) as u8
        == 0
    {
        return Err(SecpError::InvalidSecretKey);
    }

    ck.combine(&vck)?;

    let mut k_pk = y_pk.clone();
    k_pk.mul_assign(secp, k.as_ref())?;

    // initialize the dual response with Fiat-Shamir challenges for `u` and `v` random keys
    let mut r = SecretKey::from_slice(fiat_shamir::transform(y_pk, &kp_pk).as_ref())?;
    let mut rk = SecretKey::from_slice(fiat_shamir::transform(y_pk, &k_pk).as_ref())?;

    // r = u - k*uchal
    r.mul_assign(k.as_ref())?;
    r.negate_assign();
    r.add_assign(u.as_ref())?;

    // rk = v - k*vchal
    rk.mul_assign(k.as_ref())?;
    rk.negate_assign();
    rk.add_assign(v.as_ref())?;

    Ok((ck, r, rk).into())
}

// Verify Kp = k*G && K = k*Y using Schnorr NIZK proof of identity
//
// secp: Secp256k1 context
// x: public key for the prover (Y=y*G)
// kp: public key being proven (k*G)
// k: public key being proven (k*Y)
// proof: dual Schnorr NIZK proof of identity for Kp an K
pub fn dual_schnorr_verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    y_pk: &PublicKey,
    kp: &PublicKey,
    k: &PublicKey,
    proof: &Proof,
) -> Result<bool, SecpError> {
    let mut commit_kp = kp.clone();
    let mut commit_k = k.clone();

    let (ck, r, rk) = proof.inner();

    let c_kp = fiat_shamir::transform(y_pk, kp);
    let c_k = fiat_shamir::transform(y_pk, k);

    // c_kp*Kp = c_kp*k*G
    commit_kp.mul_assign(secp, c_kp.as_ref())?;
    // rk*G + c_kp*Kp
    commit_kp.add_exp_assign(secp, r.as_ref())?;

    // FIXME: because `s` is conditionally negated during proof generation,
    // it is necessary to calculate the verification over k*G and -k*G to verify successfully
    //
    // Does this introduce malleability back into the signature scheme?
    //
    // Currently to mitigate SUF-CMA malleability, pre-signature verification rejects high `s` values
    //
    // Is this secure?
    //
    // No knowledge is leaked, since knowledge of k gives immediate knowledge of -k.
    // Are there any risks for loss of funds, or double-spending in the Bitcoin context?
    let mut neg_commit_kp = kp.clone();
    neg_commit_kp.negate_assign(secp);
    let neg_c_kp = fiat_shamir::transform(y_pk, &neg_commit_kp);
    neg_commit_kp.mul_assign(secp, neg_c_kp.as_ref())?;
    neg_commit_kp.add_exp_assign(secp, r.as_ref())?;

    // c_k*K = c_k*y*k*G
    commit_k.mul_assign(secp, c_k.as_ref())?;
    // rk*y*G + c_k*K
    // rk*y*G + c_k*y*k*G
    let mut rkg = y_pk.clone();
    rkg.mul_assign(secp, rk.as_ref())?;
    commit_k.combine(&rkg)?;

    commit_kp.combine(&commit_k)?;
    neg_commit_kp.combine(&commit_k)?;

    // non-constant compare is safe, no secret data is being compared
    let valid = ck == &commit_kp || ck == &neg_commit_kp;
    Ok(valid)
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec::Vec;

    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use secp256k1_sys::types::AlignedType;

    #[test]
    fn test_schnorr_nizk_prove_verify() {
        let mut rand_bytes = [0u8; 32];

        OsRng.fill_bytes(&mut rand_bytes);
        let y = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let k = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let u = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let v = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = dual_schnorr_prove(&secp, &y_pk, &k, &u, &v).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut kpk = y_pk.clone();
        kpk.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(dual_schnorr_verify(&secp, &y_pk, &kp, &kpk, &proof).unwrap());
    }

    #[test]
    fn test_schnorr_nizk_prove_verify_lo() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[3; 32]).unwrap();

        let k = SecretKey::from_slice(&[4; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let u = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let v = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = dual_schnorr_prove(&secp, &y_pk, &k, &u, &v).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut kpk = y_pk.clone();
        kpk.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(dual_schnorr_verify(&secp, &y_pk, &kp, &kpk, &proof).unwrap());
    }

    #[test]
    fn test_schnorr_nizk_prove_verify_hi() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[0xf1; 32]).unwrap();

        let k = SecretKey::from_slice(&[0xc1; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let u = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let v = SecretKey::from_slice(&rand_bytes).unwrap();

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let proof = dual_schnorr_prove(&secp, &y_pk, &k, &u, &v).unwrap();

        let kp = PublicKey::from_secret_key(&secp, &k);
        let mut kpk = y_pk.clone();
        kpk.mul_assign(&secp, k.as_ref()).unwrap();

        assert!(dual_schnorr_verify(&secp, &y_pk, &kp, &kpk, &proof).unwrap());
    }
}
