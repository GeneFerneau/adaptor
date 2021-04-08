use secp256k1::bitcoin_hashes::{sha256, Hash, HashEngine};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature, Signing, Verification};

use crate::error::Error;
use crate::types::{SchnorrAdaptorSignature, SchnorrPreSignature};
use crate::util::const_compare;

/// Initial phase of creating a Schnorr adaptor signature
///
/// Pre-sign a message returning the partial signature
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// #
/// # use alloc::vec::Vec;
/// #
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, Secp256k1, SecretKey,};
/// # use secp256k1_sys::types::AlignedType;
/// #
/// # use adaptor::{SchnorrPreSignature, SchnorrAdaptorSignature};
/// # use adaptor::schnorr::pre_sign;
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
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
///
/// let msg = b"it's not about the money, it's about sending a message";
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &x, &k).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
/// ```
pub fn pre_sign<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    x: &SecretKey,
    k: &SecretKey,
) -> Result<SchnorrPreSignature, Error> {
    let x_pk = PublicKey::from_secret_key(secp, x);

    let mut gk_y = PublicKey::from_secret_key(secp, k);
    gk_y = gk_y.combine(y_pk).map_err(|_| Error::InvalidSignature)?;

    let mut r_hash = sha256::Hash::engine();
    r_hash.input(&x_pk.serialize());
    r_hash.input(&gk_y.serialize());
    r_hash.input(msg);

    let r = SecretKey::from_slice(&sha256::Hash::from_engine(r_hash).into_inner())
        .map_err(|_| Error::InvalidSignature)?;

    let mut s = x.clone();
    s.mul_assign(r.as_ref())
        .map_err(|_| Error::InvalidSignature)?;
    s.add_assign(k.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    Ok((r, s).into())
}

/// Verify a partial Schnorr adaptor signature
///
/// Example:
///
/// ```rust
/// # extern crate alloc;
/// #
/// # use alloc::vec::Vec;
/// #
/// # use rand::rngs::OsRng;
/// # use rand::RngCore;
/// # use secp256k1::{PublicKey, Secp256k1, SecretKey,};
/// # use secp256k1_sys::types::AlignedType;
/// #
/// # use adaptor::{SchnorrPreSignature, SchnorrAdaptorSignature};
/// # use adaptor::schnorr::{pre_sign, pre_verify};
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
/// let secp_size = Secp256k1::preallocate_size();
/// let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
/// secp_buf.resize(secp_size, AlignedType::default());
/// let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();
///
/// let y_pk = PublicKey::from_secret_key(&secp, &y);
///
/// let msg = b"it's not about the money, it's about sending a message";
/// let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &x, &k).unwrap();
/// let x_pk = PublicKey::from_secret_key(&secp, &x);
///
/// assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &x_pk, &pre_sig).unwrap());
/// ```
pub fn pre_verify<C: Signing + Verification>(
    secp: &Secp256k1<C>,
    msg: &[u8],
    y_pk: &PublicKey,
    x_pk: &PublicKey,
    pre_sig: &SchnorrPreSignature,
) -> Result<bool, Error> {
    let (r, s) = pre_sig.inner();

    let gs = PublicKey::from_secret_key(secp, s);
    let mut pkr = x_pk.clone();
    let mut ri = r.clone();
    ri.negate_assign();
    pkr.mul_assign(secp, ri.as_ref())
        .map_err(|_| Error::InvalidSignature)?;

    pkr = pkr.combine(&gs).map_err(|_| Error::InvalidSignature)?;
    pkr = pkr.combine(y_pk).map_err(|_| Error::InvalidSignature)?;

    let mut r_hash = sha256::Hash::engine();
    r_hash.input(&x_pk.serialize());
    r_hash.input(&pkr.serialize());
    r_hash.input(msg);

    let rp = SecretKey::from_slice(&sha256::Hash::from_engine(r_hash).into_inner())
        .map_err(|_| Error::InvalidSignature)?;

    Ok(const_compare(r, &rp) == 0)
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

        let secp_size = Secp256k1::preallocate_size();
        let mut secp_buf: Vec<AlignedType> = Vec::with_capacity(secp_size);
        secp_buf.resize(secp_size, AlignedType::default());
        let secp = Secp256k1::preallocated_new(&mut secp_buf[..]).unwrap();

        let y_pk = PublicKey::from_secret_key(&secp, &y);

        let msg = b"it's not about the money, it's about sending a message";
        let pre_sig = pre_sign(&secp, msg.as_ref(), &y_pk, &x, &k).unwrap();
        let x_pk = PublicKey::from_secret_key(&secp, &x);

        assert!(pre_verify(&secp, msg.as_ref(), &y_pk, &x_pk, &pre_sig).unwrap());
    }
}
