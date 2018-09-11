extern crate ed25519_dalek;
extern crate sha2;

use ed25519_dalek::{Signature,PublicKey};
use sha2::Sha256;


#[derive(Debug)]
pub struct Error(pub &'static str);

impl From<&'static str> for self::Error {
  fn from(val: &'static str) -> Self {
    self::Error(val)
  }
}

pub fn verify(input: &[u8; 128]) -> Result<[u8; 4], self::Error> {
  let message = &input[..32];

  let public_key = PublicKey::from_bytes(&input[32..64]).expect("public key should be correctly formed");
  let sig = Signature::from_bytes(&input[64..128]).unwrap();//expect("signature should be correctly formed");

  if public_key.verify::<Sha256>(message, &sig).is_ok() {
    Ok([0x00; 4])
  } else {
    Ok([0xff; 4])
  }
}

#[cfg(test)]
mod tests {
  extern crate hex;
  use super::*;

  #[test]
  fn case1() {
    let input_str = "\
        0000000000000000000000000000000000000000000000000000000000000000\
        daf13ebec6fd213c9d7ad1b55160fa13286632bc56697a2f14ffbf371908cb78\
        faf529b846f32720a66e3337ddd3302013094f916f4804fb1379f8afbeb72f7ce117c712ec8e100f3a666a1d96913246f7cd5caa1dfbc88f437e496f1afa0200";
    let input = hex::decode(input_str).unwrap();
    let expect: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
    let mut input_arr: [u8; 128] = [0; 128];
    input_arr.copy_from_slice(&input[..128]);

    assert_eq!(verify(&input_arr).unwrap(), expect);
  }
}
