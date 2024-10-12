use {
    crate::{address::TonAddress, format::TonFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    base64::{engine::general_purpose, Engine as _},
    core::{fmt, str::FromStr},
    crc16::{State, XMODEM},
    ed25519_dalek::PUBLIC_KEY_LENGTH,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonPublicKey(pub ed25519_dalek::VerifyingKey);

impl PublicKey for TonPublicKey {
    type SecretKey = ed25519_dalek::SecretKey;
    type Address = TonAddress;
    type Format = TonFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from(secret_key);
        let verifying_key: ed25519_dalek::VerifyingKey = (&signing_key).into();
        TonPublicKey(verifying_key)
    }

    fn to_address(&self, format: &Self::Format) -> Result<Self::Address, AddressError> {
        Self::Address::from_public_key(self, format)
    }
}

impl FromStr for TonPublicKey {
    type Err = PublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 48 {
            return Err(PublicKeyError::InvalidByteLength(s.len()));
        }

        let base64_bytes = general_purpose::STANDARD.decode(s).map_err(|error| {
            PublicKeyError::Crate("Failed to decode Base64 string", format!("{:?}", error))
        })?;

        let mut bytes: [u8; 32] = [0u8; PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(&base64_bytes[2..34]);

        let public_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|error| {
            PublicKeyError::Crate("Fail to create ed25519 public key", format!("{:?}", error))
        })?;

        Ok(TonPublicKey(public_key))
    }
}

impl fmt::Display for TonPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut extended_key = vec![0x3E, 0xE6];
        extended_key.extend_from_slice(self.0.as_bytes());

        let crc = State::<XMODEM>::calculate(&extended_key);
        let crc_bytes: [u8; 2] = crc.to_be_bytes();

        extended_key.extend_from_slice(&crc_bytes);

        write!(f, "{}", general_purpose::STANDARD.encode(&extended_key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anychain_core::PublicKey;
    use tonlib_core_anychain::mnemonic::{KeyPair, Mnemonic};

    #[test]
    fn test_public_key_from_str_official_demo() {
        // https://docs.ton.org/learn/overviews/addresses
        let base64_str = "Pubjns2gp7DGCnEH7EOWeCnb6Lw1akm538YYaz6sdLVHfRB2";
        let res = TonPublicKey::from_str(base64_str);
        assert!(res.is_ok());

        let public_key = res.unwrap();
        let expected_public_bytes: [u8; PUBLIC_KEY_LENGTH] = [
            227, 158, 205, 160, 167, 176, 198, 10, 113, 7, 236, 67, 150, 120, 41, 219, 232, 188,
            53, 106, 73, 185, 223, 198, 24, 107, 62, 172, 116, 181, 71, 125,
        ];
        assert_eq!(&expected_public_bytes, public_key.0.as_bytes());
    }

    #[test]
    fn test_public_key_from_from_secret_key() {
        let secret_bytes: [u8; 32] = [
            163, 27, 236, 35, 251, 127, 152, 172, 241, 108, 136, 153, 30, 28, 111, 7, 8, 203, 61,
            254, 254, 28, 22, 140, 180, 158, 52, 246, 207, 241, 80, 203,
        ];

        let expected_public_bytes: [u8; PUBLIC_KEY_LENGTH] = [
            255, 15, 68, 27, 88, 255, 216, 254, 24, 44, 59, 74, 151, 224, 27, 173, 74, 215, 116,
            208, 20, 174, 2, 249, 150, 2, 8, 207, 122, 238, 164, 144,
        ];
        // let secret_key = ed25519_dalek::SecretKey::from(&secret_bytes);
        let public_key: TonPublicKey = TonPublicKey::from_secret_key(&secret_bytes);
        assert_eq!(expected_public_bytes, public_key.0.to_bytes());

        // dbg!(public_key.to_string());
        // assert_eq public_key fmt
    }

    #[test]
    fn test_public_key_from_mnemonic() {
        let secret_bytes: [u8; PUBLIC_KEY_LENGTH] = [
            163, 27, 236, 35, 251, 127, 152, 172, 241, 108, 136, 153, 30, 28, 111, 7, 8, 203, 61,
            254, 254, 28, 22, 140, 180, 158, 52, 246, 207, 241, 80, 203,
        ];

        // let secret_key = ed25519_dalek::SecretKey::from(&secret_bytes);
        let public_key: TonPublicKey = TonPublicKey::from_secret_key(&secret_bytes);

        let mnemonic = "private two helmet history gravity disease impact slice because silent crunch mammal divert kind faint ketchup holiday soup drill during wash mandate fade mention";
        let mnemonic = Mnemonic::from_str(mnemonic, &None).unwrap();
        let keypair: KeyPair = mnemonic.to_key_pair().unwrap();

        assert_eq!(public_key.0.to_bytes(), keypair.public_key.as_slice());
    }
}
