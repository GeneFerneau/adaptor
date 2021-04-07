use secp256k1::SecretKey;

pub fn const_compare(l: &SecretKey, r: &SecretKey) -> u8 {
    let mut sum = 0u8;
    for (lb, rb) in l.as_ref().iter().zip(r.as_ref().iter()) {
        sum |= lb ^ rb;
    }
    sum
}
