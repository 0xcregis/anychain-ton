use {
    crate::{address::TonAddress, format::TonFormat},
    anychain_core::{Address, AddressError, PublicKey, PublicKeyError},
    base64::{engine::general_purpose, Engine as _},
    core::{fmt, str::FromStr},
    crc16::{State, XMODEM},
    curve25519_dalek::{constants::ED25519_BASEPOINT_POINT as G, Scalar},
    ed25519_dalek::PUBLIC_KEY_LENGTH,
    group::GroupEncoding,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TonPublicKey(pub ed25519_dalek::PublicKey);

impl PublicKey for TonPublicKey {
    type SecretKey = Scalar;
    type Address = TonAddress;
    type Format = TonFormat;

    fn from_secret_key(secret_key: &Self::SecretKey) -> Self {
        let public_key = secret_key * G;
        let public_key = public_key.to_bytes();
        let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key).unwrap();
        TonPublicKey(public_key)
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
            PublicKeyError::Crate("Failed to decode Base64 string", format!("{error:?}"))
        })?;

        let mut bytes: [u8; 32] = [0u8; PUBLIC_KEY_LENGTH];
        bytes.copy_from_slice(&base64_bytes[2..34]);

        let public_key = ed25519_dalek::PublicKey::from_bytes(&bytes).map_err(|error| {
            PublicKeyError::Crate("Fail to create ed25519 public key", format!("{error:?}"))
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
            86, 116, 231, 201, 13, 30, 196, 216, 177, 139, 138, 182, 253, 13, 46, 38, 217, 202,
            213, 121, 35, 151, 8, 131, 132, 240, 103, 30, 0, 46, 182, 136,
        ];
        let secret_key = Scalar::from_bytes_mod_order(secret_bytes);
        let public_key: TonPublicKey = TonPublicKey::from_secret_key(&secret_key);

        assert_eq!(expected_public_bytes, public_key.0.to_bytes());
    }
}
