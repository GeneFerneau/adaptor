use crate::Error;
use secp256k1::{PublicKey, SecretKey, Signature};

/// Random challenge provided to the dual Schnorr NIZK proof
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Challenge([u8; 32]);

impl AsRef<[u8]> for Challenge {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Challenge {
    fn from(id: [u8; 32]) -> Self {
        Self(id)
    }
}

/// Dual Schnorr NIZK proof of knowledge of discrete logarithm exponent
#[derive(Copy, Clone, PartialEq)]
pub struct SchnorrProof((PublicKey, SecretKey, SecretKey));

impl SchnorrProof {
    pub fn inner(&self) -> &(PublicKey, SecretKey, SecretKey) {
        &self.0
    }
}

impl From<(PublicKey, SecretKey, SecretKey)> for SchnorrProof {
    fn from(t: (PublicKey, SecretKey, SecretKey)) -> Self {
        Self(t)
    }
}

/// Chaum-Pedersen NIZK proof of knowledge of DH-triple relationship
#[derive(Copy, Clone, PartialEq)]
pub struct ChaumPedersenProof((PublicKey, PublicKey, SecretKey));

impl ChaumPedersenProof {
    pub fn inner(&self) -> &(PublicKey, PublicKey, SecretKey) {
        &self.0
    }
}

impl From<(PublicKey, PublicKey, SecretKey)> for ChaumPedersenProof {
    fn from(t: (PublicKey, PublicKey, SecretKey)) -> Self {
        Self(t)
    }
}

/// Pre-signature for an ECDSA Adaptor signature
#[derive(Copy, Clone, PartialEq)]
pub struct EcdsaPreSignature {
    pub(crate) r: SecretKey,
    pub(crate) s: SecretKey,
    pub(crate) k: PublicKey,
    pub(crate) proof: ChaumPedersenProof,
}

impl EcdsaPreSignature {
    /// Get the `r`-component of the pre-signature
    pub fn r(&self) -> &SecretKey {
        &self.r
    }

    /// Get the `s`-component of the pre-signature
    pub fn s(&self) -> &SecretKey {
        &self.s
    }

    /// Get the adaptor nonce public key
    pub fn k(&self) -> &PublicKey {
        &self.k
    }

    /// Get the NIZK proof for the nonce public key
    ///
    /// Proves that the same private key was used to generate
    /// the nonce public key, and to create the partial signature
    pub fn proof(&self) -> &ChaumPedersenProof {
        &self.proof
    }
}

/// ECDSA adaptor signature
#[derive(Copy, Clone, PartialEq)]
pub struct EcdsaAdaptorSignature((SecretKey, SecretKey));

impl EcdsaAdaptorSignature {
    /// Get the `r`-component of the signature
    pub fn r(&self) -> &SecretKey {
        &self.0 .0
    }

    /// Get the `s`-component of the signature
    pub fn s(&self) -> &SecretKey {
        &self.0 .1
    }

    pub fn inner(&self) -> &(SecretKey, SecretKey) {
        &self.0
    }

    pub fn normalize(&mut self) -> Result<(), Error> {
        self.0
             .1
            .cond_negate_assign()
            .map_err(|_| Error::InvalidSecretKey)
    }
}

impl From<(SecretKey, SecretKey)> for EcdsaAdaptorSignature {
    fn from(rs: (SecretKey, SecretKey)) -> Self {
        Self(rs)
    }
}

impl From<&EcdsaAdaptorSignature> for Signature {
    fn from(sig: &EcdsaAdaptorSignature) -> Self {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(sig.r().as_ref());
        sig_bytes[32..].copy_from_slice(sig.s().as_ref());
        Self::from_compact(&sig_bytes).unwrap()
    }
}

impl From<&Signature> for EcdsaAdaptorSignature {
    fn from(sig: &Signature) -> Self {
        let sig_bytes = sig.serialize_compact();
        Self((
            SecretKey::from_slice(&sig_bytes[..32]).unwrap(),
            SecretKey::from_slice(&sig_bytes[32..]).unwrap(),
        ))
    }
}

impl From<Signature> for EcdsaAdaptorSignature {
    fn from(sig: Signature) -> Self {
        let sig_bytes = sig.serialize_compact();
        Self((
            SecretKey::from_slice(&sig_bytes[..32]).unwrap(),
            SecretKey::from_slice(&sig_bytes[32..]).unwrap(),
        ))
    }
}

/// Partial Schnorr adaptor signature
#[derive(Copy, Clone, PartialEq)]
pub struct SchnorrPreSignature((SecretKey, SecretKey));

impl SchnorrPreSignature {
    /// Get the `r`-component of the signature
    pub fn r(&self) -> &SecretKey {
        &self.0 .0
    }

    /// Get the `s`-component of the signature
    pub fn s(&self) -> &SecretKey {
        &self.0 .1
    }

    /// Get the inner signature tuple `(r, s)`
    pub fn inner(&self) -> &(SecretKey, SecretKey) {
        &self.0
    }
}

impl From<(SecretKey, SecretKey)> for SchnorrPreSignature {
    fn from(rs: (SecretKey, SecretKey)) -> Self {
        Self(rs)
    }
}

/// Schnorr adaptor signature
#[derive(Copy, Clone, PartialEq)]
pub struct SchnorrAdaptorSignature((SecretKey, SecretKey));

impl SchnorrAdaptorSignature {
    /// Get the `r`-component of the signature
    pub fn r(&self) -> &SecretKey {
        &self.0 .0
    }

    /// Get the `s`-component of the signature
    pub fn s(&self) -> &SecretKey {
        &self.0 .1
    }
}

impl From<(SecretKey, SecretKey)> for SchnorrAdaptorSignature {
    fn from(rs: (SecretKey, SecretKey)) -> Self {
        Self(rs)
    }
}

impl From<&SchnorrAdaptorSignature> for Signature {
    fn from(sig: &SchnorrAdaptorSignature) -> Self {
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(sig.r().as_ref());
        sig_bytes[32..].copy_from_slice(sig.s().as_ref());
        Self::from_compact(&sig_bytes).unwrap()
    }
}

impl From<&Signature> for SchnorrAdaptorSignature {
    fn from(sig: &Signature) -> Self {
        let sig_bytes = sig.serialize_compact();
        Self((
            SecretKey::from_slice(&sig_bytes[..32]).unwrap(),
            SecretKey::from_slice(&sig_bytes[32..]).unwrap(),
        ))
    }
}

impl From<Signature> for SchnorrAdaptorSignature {
    fn from(sig: Signature) -> Self {
        let sig_bytes = sig.serialize_compact();
        Self((
            SecretKey::from_slice(&sig_bytes[..32]).unwrap(),
            SecretKey::from_slice(&sig_bytes[32..]).unwrap(),
        ))
    }
}
