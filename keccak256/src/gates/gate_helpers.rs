use num_bigint::BigUint;
use pairing::arithmetic::FieldExt;
use std::convert::TryInto;

/// Convert a bigUint value to FieldExt
///
/// We assume the input value is smaller than the field size
pub fn biguint_to_f<F: FieldExt>(x: &BigUint) -> F {
    let mut x_bytes = x.to_bytes_le();
    assert!(
        x_bytes.len() <= 32,
        "expect len <=32 but got {}",
        x_bytes.len()
    );
    x_bytes.resize(32, 0);
    let x_bytes: [u8; 32] = x_bytes.try_into().unwrap();
    F::from_bytes(&x_bytes).unwrap()
}

pub fn f_to_biguint<F: FieldExt>(x: F) -> BigUint {
    BigUint::from_bytes_le(&x.to_bytes())
}

pub fn biguint_mod(x: &BigUint, modulus: u8) -> u8 {
    x.to_radix_le(modulus.into())
        .first()
        .copied()
        .unwrap_or_default()
}
