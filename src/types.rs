use secp256k1::{PublicKey, SecretKey};

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
pub struct PreSignature {
    pub(crate) r: SecretKey,
    pub(crate) s: SecretKey,
    pub(crate) k: PublicKey,
    pub(crate) proof: ChaumPedersenProof,
}

impl PreSignature {
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
