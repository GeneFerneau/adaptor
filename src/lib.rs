#![no_std]

use secp256k1::bitcoin_hashes::{sha256, Hash};
use secp256k1::{PublicKey, Secp256k1, SecretKey, Signing, Verification};

mod chaum_pedersen;
mod fiat_shamir;
mod schnorr;
mod types;

use types::PreSignature;

#[derive(Debug)]
pub enum Error {
    InvalidSignature,
}

/// Initial phase of creating an Adaptor signature
///
/// Pre-sign a message returning the partial signature, Adaptor public key,
/// and a NIZK proof that the same private key was used for the partial signature
/// and public key Y
pub fn pre_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    y_proof: &fischlin::Proof,
    x: &SecretKey,
    k: &SecretKey,
    bt: &SecretKey,
) -> Result<PreSignature, Error> {
    if !fischlin::fischlin_verify(secp, y_pk, y_proof).map_err(|_| Error::InvalidSignature)? {
        return Err(Error::InvalidSignature);
    }

    let mut k_pk = y_pk.clone();
    k_pk.mul_assign(secp, k.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    // r = f(K)
    let r = SecretKey::from_slice(&k_pk.f()).map_err(|_| Error::InvalidSignature)?;
    let mut rx = r.clone();

    // s~ = k^-1 * (H(m) + r*x)
    rx.mul_assign(x.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    let h = SecretKey::from_slice(&sha256::Hash::hash(msg).into_inner())
        .map_err(|_| Error::InvalidSignature)?;

    rx.add_assign(h.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    let mut s = k.clone();
    s.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    s.mul_assign(rx.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    // If `s` is high (> (q-1)/2), reject as invalid
    // Only use Positive ECDSA
    //
    // FIXME: find a way to allow conditionally negating `s` without
    // allowing malleability into the NIZK consistency proof
    // 
    // Negating `s` here will result in the negative version of the
    // reconstructed public key nonce `k`.
    //
    // Allowing `s` to be conditionally negated in normal Positive ECDSA is not
    // an issue, since only the affine x-coordinate of the reconstructed nonce
    // is compared to `r` (only the y-coordinate conveys signedness).
    //
    // However, for the NIZK proof to verify when that happens, it needs to verify
    // both against the negated and original public key nonce. It's not obvious
    // whether verifying the proof against the public key nonce and its negation
    // introduces any security vulnerabilities. Definitely smells like it will.
    if s.is_high().map_err(|_| Error::InvalidSignature)? {
        return Err(Error::InvalidSignature);
    }

    // proof = Py((Kp, K), k)
    let proof =
        chaum_pedersen::prove(secp, y_pk, k, bt).map_err(|_| Error::InvalidSignature)?;

    Ok(PreSignature {
        r,
        s,
        k: k_pk,
        proof: proof,
    })
}

/// Verify a partial Adaptor signature
pub fn pre_verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    y_proof: &fischlin::Proof,
    x_pk: &PublicKey,
    pre_sig: &PreSignature,
) -> Result<bool, Error> {
    if !fischlin::fischlin_verify(secp, y_pk, y_proof).map_err(|_| Error::InvalidSignature)? {
        return Ok(false);
    }

    let s = pre_sig.s();

    let mut negs = s.clone();
    negs.cond_negate_assign().map_err(|_| Error::InvalidSignature)?;

    if const_compare(&negs, s) != 0 {
        return Ok(false);
    }

    // u = H(m) * s^-1
    let mut u = s.clone();
    u.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    let h = SecretKey::from_slice(&sha256::Hash::hash(msg).into_inner())
        .map_err(|_| Error::InvalidSignature)?;
    u.mul_assign(h.as_ref()).map_err(|_| Error::InvalidSignature)?;

    // v = r * s^-1
    let mut v = s.clone();
    let r = pre_sig.r();
    v.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    v.mul_assign(r.as_ref()).map_err(|_| Error::InvalidSignature)?;

    // K' = u*G + v*X
    //    = (H(m) * s^-1 * G) + (r * s^-1 * x * G)
    let mut kp = x_pk.clone();
    kp.mul_assign(secp, v.as_ref()).map_err(|_| Error::InvalidSignature)?;
    kp.add_exp_assign(secp, u.as_ref()).map_err(|_| Error::InvalidSignature)?;

    // br = r == f(K)
    let ky = pre_sig.k();
    let fk = SecretKey::from_slice(&ky.f()).map_err(|_| Error::InvalidSignature)?;

    // b = Vy((K', K), proof)
    let valid_proof = chaum_pedersen::verify(secp, y_pk, &kp, ky, pre_sig.proof())
        .map_err(|_| Error::InvalidSignature)?;

    Ok(const_compare(r, &fk) == 0 && valid_proof)
}

fn const_compare(l: &SecretKey, r: &SecretKey) -> u8 {
    let mut sum = 0u8;
    for (lb, rb) in l.as_ref().iter().zip(r.as_ref().iter()) {
        sum |= lb ^ rb;
    }
    sum
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
    fn test_pre_sign_verify() {
        let mut rand_bytes = [0u8; 32];

        OsRng.fill_bytes(&mut rand_bytes);
        let y = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let x = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let k = SecretKey::from_slice(&rand_bytes).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];

        for s in vs.iter_mut() {
            OsRng.fill_bytes(&mut rand_bytes);
            *s = SecretKey::from_slice(&rand_bytes).unwrap();
        }

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::fischlin_prove(&secp, &y, &vs).unwrap();

        let msg = b"what a lovely tea party";
        if let Ok(mut pre_sig) = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt) {
            let x_pk = PublicKey::from_secret_key(&secp, &x);

            assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
        }
    }

    #[test]
    fn test_pre_sign_verify_lo() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[0xf1; 32]).unwrap();
        let x = SecretKey::from_slice(&[2; 32]).unwrap();
        let k = SecretKey::from_slice(&[3; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];

        for s in vs.iter_mut() {
            OsRng.fill_bytes(&mut rand_bytes);
            *s = SecretKey::from_slice(&rand_bytes).unwrap();
        }

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::fischlin_prove(&secp, &y, &vs).unwrap();

        let msg = b"Chancellor on brink of second bailout for banks";
        let mut pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        pre_sig.s.negate_assign();

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
    }

    #[test]
    fn test_pre_sign_verify_hi() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[1; 32]).unwrap();
        let x = SecretKey::from_slice(&[0xf1; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xf1; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];

        for s in vs.iter_mut() {
            OsRng.fill_bytes(&mut rand_bytes);
            *s = SecretKey::from_slice(&rand_bytes).unwrap();
        }

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::fischlin_prove(&secp, &y, &vs).unwrap();

        let msg = b"get that high shit outta here!";
        assert!(pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).is_err());
    }

    #[test]
    fn test_pre_sign_verify_malleability() {
        let mut rand_bytes = [0u8; 32];

        // ensure low `s` so that pre-signing creates a valid signature
        let y = SecretKey::from_slice(&[1; 32]).unwrap();
        let x = SecretKey::from_slice(&[2; 32]).unwrap();
        let k = SecretKey::from_slice(&[3; 32]).unwrap();

        OsRng.fill_bytes(&mut rand_bytes);
        let bt = SecretKey::from_slice(&rand_bytes).unwrap();

        let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];

        for s in vs.iter_mut() {
            OsRng.fill_bytes(&mut rand_bytes);
            *s = SecretKey::from_slice(&rand_bytes).unwrap();
        }

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::fischlin_prove(&secp, &y, &vs).unwrap();

        let msg = b"non-malleable signatures, secure signatures";

        let mut pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // negating `k` (k*y*G) still verifies, but does not allow changing the message or
        // signature information (r, s)
        pre_sig.k.negate_assign(&secp);
        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // unconditionally negate `s`
        // ensure that verification fails, and we have a SUF-CMA secure Positive ECDSA scheme
        pre_sig.s.negate_assign();
        // reset `k`
        pre_sig.k.negate_assign(&secp);

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
    }
}
