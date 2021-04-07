use secp256k1::bitcoin_hashes::{sha256, Hash};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature, Signing, Verification};

use crate::chaum_pedersen;
use crate::error::Error;
use crate::types::{EcdsaAdaptorSignature, EcdsaPreSignature};
use crate::util::const_compare;

/// Initial phase of creating an ECDSA adaptor signature
///
/// Pre-sign a message returning the partial signature, adaptor public key, and a NIZK proof that the
/// same private key was used for the partial signature and public key Y.
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// # use alloc::vec::Vec;
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// # use secp256k1_sys::types::AlignedType;
/// # use fischlin;
/// # use adaptor::ecdsa::{adapt, extract, pre_sign, pre_verify, verify};
///
/// let mut rand_bytes = [0u8; 32];
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let y = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let x = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let k = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let bt = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];
///
/// for s in vs.iter_mut() {
///     OsRng.fill_bytes(&mut rand_bytes);
///     *s = SecretKey::from_slice(&rand_bytes).unwrap();
/// }
///
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
/// let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();
///
/// let msg = b"what a lovely tea party";
///
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
/// ```
pub fn pre_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    y_proof: &fischlin::Proof,
    x: &SecretKey,
    k: &SecretKey,
    bt: &SecretKey,
) -> Result<EcdsaPreSignature, Error> {
    if !fischlin::verify(secp, y_pk, y_proof).map_err(|_| Error::InvalidSignature)? {
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

    // proof = Py((Kp, K), k)
    let proof = chaum_pedersen::prove(secp, y_pk, k, bt).map_err(|_| Error::InvalidSignature)?;

    Ok(EcdsaPreSignature {
        r,
        s,
        k: k_pk,
        proof: proof,
    })
}

/// Verify a partial ECDSA adaptor signature
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// # use alloc::vec::Vec;
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// # use secp256k1_sys::types::AlignedType;
/// # use fischlin;
/// # use adaptor::ecdsa::{adapt, extract, pre_sign, pre_verify, verify};
///
/// let mut rand_bytes = [0u8; 32];
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let y = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let x = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let k = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let bt = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];
///
/// for s in vs.iter_mut() {
///     OsRng.fill_bytes(&mut rand_bytes);
///     *s = SecretKey::from_slice(&rand_bytes).unwrap();
/// }
///
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
/// let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();
///
/// // create a pre-signature
/// let msg = b"magical internet money";
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// // verify the pre-signature is valid
/// assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
/// ```
pub fn pre_verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    y_proof: &fischlin::Proof,
    x_pk: &PublicKey,
    pre_sig: &EcdsaPreSignature,
) -> Result<bool, Error> {
    if !fischlin::verify(secp, y_pk, y_proof).map_err(|_| Error::InvalidSignature)? {
        return Ok(false);
    }

    let s = pre_sig.s();

    // u = H(m) * s^-1
    let mut u = s.clone();
    u.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    let h = SecretKey::from_slice(&sha256::Hash::hash(msg).into_inner())
        .map_err(|_| Error::InvalidSignature)?;
    u.mul_assign(h.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    // v = r * s^-1
    let mut v = s.clone();
    let r = pre_sig.r();
    v.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    v.mul_assign(r.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    // K' = u*G + v*X
    //    = (H(m) * s^-1 * G) + (r * s^-1 * x * G)
    let mut kp = x_pk.clone();
    kp.mul_assign(secp, v.as_ref())
        .map_err(|_| Error::InvalidSignature)?;
    kp.add_exp_assign(secp, u.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    // br = r == f(K)
    let ky = pre_sig.k();
    let fk = SecretKey::from_slice(&ky.f()).map_err(|_| Error::InvalidSignature)?;

    // b = Vy((K', K), proof)
    let valid_proof = chaum_pedersen::verify(secp, y_pk, &kp, ky, pre_sig.proof())
        .map_err(|_| Error::InvalidSignature)?;

    Ok(const_compare(r, &fk) == 0 && valid_proof)
}

/// Adapt an ECDSA pre-signature into a full signature, allowing any party
/// with the pre-signature to extract the witness `y`
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// # use alloc::vec::Vec;
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// # use secp256k1_sys::types::AlignedType;
/// # use fischlin;
/// # use adaptor::ecdsa::{adapt, extract, pre_sign, pre_verify, verify};
///
/// let mut rand_bytes = [0u8; 32];
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let y = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let x = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let k = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let bt = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];
///
/// for s in vs.iter_mut() {
///     OsRng.fill_bytes(&mut rand_bytes);
///     *s = SecretKey::from_slice(&rand_bytes).unwrap();
/// }
///
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
/// let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();
///
/// // create a pre-signature
/// let msg = b"first, they came for...";
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// // verify the pre-signature is valid
/// assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
///
/// // adapt the pre-signature into a full adaptor signature
/// let _adaptor_sig = adapt(&pre_sig, &y).unwrap();
/// ```
pub fn adapt(pre_sig: &EcdsaPreSignature, y: &SecretKey) -> Result<EcdsaAdaptorSignature, Error> {
    let r = pre_sig.r().clone();
    let sp = pre_sig.s();

    // s = s~ * y^-1
    let mut s = y.clone();
    s.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    s.mul_assign(sp.as_ref())
        .map_err(|_| Error::InvalidSignature)?;
    s.cond_negate_assign()
        .map_err(|_| Error::InvalidSignature)?;

    Ok((r, s).into())
}

/// Extract a witness `y` from an adaptor signature and pre-signature
///
/// The witness can be used to sign for contracts created under the statement (PublicKey) `Y = g^y`
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// # use alloc::vec::Vec;
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// # use secp256k1_sys::types::AlignedType;
/// # use fischlin;
/// # use adaptor::util::const_compare;
/// # use adaptor::ecdsa::{adapt, extract, pre_sign, pre_verify, verify};
///
/// let mut rand_bytes = [0u8; 32];
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let y = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let x = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let k = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let bt = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];
///
/// for s in vs.iter_mut() {
///     OsRng.fill_bytes(&mut rand_bytes);
///     *s = SecretKey::from_slice(&rand_bytes).unwrap();
/// }
///
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
/// let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();
///
/// // pre-sign a fake "funding" transaction
/// let tx = b"SOMEBTC_SCRIPT spending coin";
/// let pre_sig = pre_sign(&secp, tx.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// // pre-verify the "funding" transaction
/// assert!(pre_verify(&secp, tx.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
///
/// // adapt the pre-signature into a full signature
/// let adaptor_sig = adapt(&pre_sig, &y).unwrap();
///
/// // verify the "funding transaction" signed under `K = g^(y*k)`
/// assert!(verify(&secp, tx.as_ref(), &adaptor_sig, &x_pk).unwrap());
///
/// // extract the witness from the adaptor signature and pre-signature
/// let yp = extract(&secp, &adaptor_sig, &pre_sig, &y_proof).unwrap();
/// assert_eq!(const_compare(&y, &yp), 0);
/// ```
pub fn extract<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    sig: &EcdsaAdaptorSignature,
    pre_sig: &EcdsaPreSignature,
    proof: &fischlin::Proof,
) -> Result<SecretKey, Error> {
    let s = sig.s();
    let sp = pre_sig.s();

    let mut yp = s.clone();
    yp.inverse_assign().map_err(|_| Error::InvalidSignature)?;
    yp.mul_assign(sp.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    let mut neg_yp = yp.clone();
    neg_yp.negate_assign();

    let mut y_inv = yp.clone();
    y_inv
        .inverse_assign()
        .map_err(|_| Error::InvalidSignature)?;

    // test for the conditional negation when the signature was adapted
    // if `y^-1` is "high", i.e. negative, `s` was negated
    let (y, y_pk) = if y_inv.is_high().map_err(|_| Error::InvalidSignature)? {
        (neg_yp, PublicKey::from_secret_key(secp, &neg_yp))
    } else {
        (yp, PublicKey::from_secret_key(secp, &yp))
    };

    if fischlin::verify(secp, &y_pk, proof).map_err(|_| Error::InvalidSignature)? {
        Ok(y)
    } else {
        Err(Error::InvalidSignature)
    }
}

/// Verify the adaptor signature as a regular ECDSA signature
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// # use alloc::vec::Vec;
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, SecretKey, Secp256k1};
/// # use secp256k1_sys::types::AlignedType;
/// # use fischlin;
/// # use adaptor::ecdsa::{adapt, pre_sign, pre_verify, verify};
///
/// let mut rand_bytes = [0u8; 32];
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let y = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let x = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let k = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// OsRng.fill_bytes(&mut rand_bytes);
/// let bt = SecretKey::from_slice(&rand_bytes).unwrap();
///
/// let mut vs = [secp256k1::key::ONE_KEY; fischlin::R];
///
/// for s in vs.iter_mut() {
///     OsRng.fill_bytes(&mut rand_bytes);
///     *s = SecretKey::from_slice(&rand_bytes).unwrap();
/// }
///
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
/// let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();
///
/// // create a pre-signature
/// let msg = b"then, they came for me...";
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// // verify the pre-signature is valid
/// assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
///
/// // adapt the pre-signature into a full adaptor signature
/// let adaptor_sig = adapt(&pre_sig, &y).unwrap();
///
/// // verify the adaptor signature under the pre-signature public key `X = g^x`
/// assert!(verify(&secp, msg.as_ref(), &adaptor_sig, &x_pk).unwrap());
/// ```
pub fn verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    sig: &EcdsaAdaptorSignature,
    pk: &PublicKey,
) -> Result<bool, Error> {
    let message = Message::from(sha256::Hash::hash(msg));
    let signature = Signature::from(sig);
    Ok(secp.verify(&message, &signature, pk).is_ok())
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
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let msg = b"what a lovely tea party";
        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
    }

    #[test]
    fn test_pre_sign_verify_lo_hi() {
        let mut rand_bytes = [0u8; 32];

        let y = SecretKey::from_slice(&[0x66; 32]).unwrap();

        // test low `s` value
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
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let msg = b"Chancellor on brink of second bailout for banks";
        let mut pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        pre_sig.s.negate_assign();

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // test high `s` value
        let x = SecretKey::from_slice(&[0xf1; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xf1; 32]).unwrap();

        let mut pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        pre_sig.s.negate_assign();

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
    }

    #[test]
    fn test_pre_sign_verify_malleability() {
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
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let msg = b"non-malleable signatures, secure signatures";

        let mut pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // negating `k` (k*y*G) should not verify
        // it should not allow changing the message or signature information (r, s)
        pre_sig.k.negate_assign(&secp);
        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // ensure that verification fails, and we have a SUF-CMA secure Positive ECDSA scheme
        pre_sig.s.negate_assign();

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // reset `k`
        pre_sig.k.negate_assign(&secp);

        assert!(!pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());
    }

    #[test]
    fn test_adapt() {
        let mut rand_bytes = [0u8; 32];

        // test low `s` value
        let y = SecretKey::from_slice(&[66; 32]).unwrap();
        let x = SecretKey::from_slice(&[0x1f; 32]).unwrap();
        let k = SecretKey::from_slice(&[0x2f; 32]).unwrap();

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
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        // create a pre-signature
        let msg = b"first, they came for...";
        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // verify the pre-signature is valid
        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full adaptor signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the adaptor signature under the pre-signature public key `X = g^x`
        assert!(verify(&secp, msg.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // test low `s` value, high `y`
        let y = SecretKey::from_slice(&[0xa1; 32]).unwrap();
        let x = SecretKey::from_slice(&[1; 32]).unwrap();
        let k = SecretKey::from_slice(&[2; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // verify the pre-signature is valid
        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full adaptor signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the adaptor signature under the pre-signature public key `X = g^x`
        assert!(verify(&secp, msg.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // test high `s` value, low `y`
        let y = SecretKey::from_slice(&[1; 32]).unwrap();
        let x = SecretKey::from_slice(&[0xf1; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xf2; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // verify the pre-signature is valid
        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full adaptor signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the adaptor signature under the pre-signature public key `X = g^x`
        assert!(verify(&secp, msg.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // test high `s` value, high `y`
        let y = SecretKey::from_slice(&[0xfe; 32]).unwrap();
        let x = SecretKey::from_slice(&[0xd1; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xe2; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // verify the pre-signature is valid
        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full adaptor signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the adaptor signature under the pre-signature public key `X = g^x`
        assert!(verify(&secp, msg.as_ref(), &adaptor_sig, &x_pk).unwrap());
    }

    #[test]
    fn test_extract_low_s_low_y() {
        let mut rand_bytes = [0u8; 32];

        // test low `s` value
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
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        // pre-sign a fake "funding" transaction
        let tx = b"SOMEBTC_SCRIPT spending coin";
        let pre_sig = pre_sign(&secp, tx.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // pre-verify the "funding" transaction
        assert!(pre_verify(&secp, tx.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the "funding transaction" signed under `X = g^x`
        assert!(verify(&secp, tx.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // extract the witness from the adaptor signature and pre-signature
        let yp = extract(&secp, &adaptor_sig, &pre_sig, &y_proof).unwrap();
        assert_eq!(const_compare(&y, &yp), 0);
    }

    #[test]
    fn test_extract_low_s_high_y() {
        let mut rand_bytes = [0u8; 32];

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

        let y = SecretKey::from_slice(&[0x8f; 32]).unwrap();
        let x = SecretKey::from_slice(&[0x2; 32]).unwrap();
        let k = SecretKey::from_slice(&[0x1; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        // pre-sign a fake "funding" transaction
        let tx = b"SOMEBTC_SCRIPT spending coin";
        let pre_sig = pre_sign(&secp, tx.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // pre-verify the "funding" transaction
        assert!(pre_verify(&secp, tx.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the "funding transaction" signed under `X = g^x`
        assert!(verify(&secp, tx.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // extract the witness from the adaptor signature and pre-signature
        let yp = extract(&secp, &adaptor_sig, &pre_sig, &y_proof).unwrap();
        assert_eq!(const_compare(&y, &yp), 0);
    }

    #[test]
    fn test_extract_high_s_low_y() {
        let mut rand_bytes = [0u8; 32];

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

        // test high `s` value, low `y`
        let y = SecretKey::from_slice(&[0x2; 32]).unwrap();
        let x = SecretKey::from_slice(&[0xda; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xf5; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        // pre-sign a fake "funding" transaction
        let tx = b"SOMEBTC_SCRIPT spending coin";
        let pre_sig = pre_sign(&secp, tx.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // pre-verify the "funding" transaction
        assert!(pre_verify(&secp, tx.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the "funding transaction" signed under `X = g^x`
        assert!(verify(&secp, tx.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // extract the witness from the adaptor signature and pre-signature
        let yp = extract(&secp, &adaptor_sig, &pre_sig, &y_proof).unwrap();
        assert_eq!(const_compare(&y, &yp), 0);
    }

    #[test]
    fn test_extract_high_s_high_y() {
        let mut rand_bytes = [0u8; 32];

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

        // test high `s` value, high `y`
        let y = SecretKey::from_slice(&[0x8f; 32]).unwrap();
        let x = SecretKey::from_slice(&[0x91; 32]).unwrap();
        let k = SecretKey::from_slice(&[0xa1; 32]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);
        let y_proof = fischlin::prove(&secp, &y, &vs).unwrap();

        // pre-sign a fake "funding" transaction
        let tx = b"SOMEBTC_SCRIPT spending coin";
        let pre_sig = pre_sign(&secp, tx.as_ref(), &y_pk, &y_proof, &x, &k, &bt).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        // pre-verify the "funding" transaction
        assert!(pre_verify(&secp, tx.as_ref(), &y_pk, &y_proof, &x_pk, &pre_sig).unwrap());

        // adapt the pre-signature into a full signature
        let adaptor_sig = adapt(&pre_sig, &y).unwrap();

        // verify the "funding transaction" signed under `X = g^x`
        assert!(verify(&secp, tx.as_ref(), &adaptor_sig, &x_pk).unwrap());

        // extract the witness from the adaptor signature and pre-signature
        let yp = extract(&secp, &adaptor_sig, &pre_sig, &y_proof).unwrap();
        assert_eq!(const_compare(&y, &yp), 0);
    }
}
