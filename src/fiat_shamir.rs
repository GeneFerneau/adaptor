use secp256k1::bitcoin_hashes::{sha256, Hash};
use secp256k1::PublicKey;

use crate::types::Challenge;

// Length of input to Fiat-Shamir transform for Schnorr NIZK
const FIAT_SHAMIR_IN_LEN: usize = 162;

// Generator for secp256k1, value 'g' defined in
// "Standards for Efficient Cryptography" (SEC2) 2.7.1.
//
// from secp256k1: secp256k1/src/group_impl.h
const SECP256K1_G: &[u8] = &[
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
    0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
    0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
    0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8,
];

// Use the Fiat-Shamir transform to compute a random challenge
//
// x: public key of the prover
// ck: random challenge public key
pub(crate) fn transform(x: &PublicKey, ck: &PublicKey) -> Challenge {
    let id = sha256::Hash::hash(&x.serialize());

    // Construct input for Fiat-Shamir transform
    // c = H(G || X || CK || ChalId)
    let mut c_in = [0u8; FIAT_SHAMIR_IN_LEN];

    c_in[..64].copy_from_slice(SECP256K1_G);
    c_in[64..97].copy_from_slice(&x.serialize());
    c_in[97..130].copy_from_slice(&ck.serialize());
    c_in[130..].copy_from_slice(&id.into_inner());

    sha256::Hash::hash(&c_in).into_inner().into()
}
