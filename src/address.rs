use {
    crate::{format::TonFormat, public_key::TonPublicKey},
    anychain_core::{Address, AddressError, PublicKey},
    core::{
        fmt::{Display, Formatter, Result as FmtResult},
        str::FromStr,
    },
    tonlib_core::types::TonAddress as InnerTonAddress,
    tonlib_core::wallet::{TonWallet, WalletVersion, DEFAULT_WALLET_ID},
};

/// Represents a Solana address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonAddress {
    pub address: InnerTonAddress,
    pub format: TonFormat,
}

impl Address for TonAddress {
    type SecretKey = ed25519_dalek::SecretKey;
    type Format = TonFormat;
    type PublicKey = TonPublicKey;

    fn from_secret_key(
        secret_key: &Self::SecretKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        Self::PublicKey::from_secret_key(secret_key).to_address(format)
    }

    fn from_public_key(
        public_key: &Self::PublicKey,
        format: &Self::Format,
    ) -> Result<Self, AddressError> {
        let workchain_id = 0;
        let address = TonWallet::derive_address(
            workchain_id,
            WalletVersion::V4R2,
            public_key.0.as_bytes(),
            DEFAULT_WALLET_ID,
        )
        .map_err(|error| AddressError::Message(format!("{:?}", error)))?;

        Ok(Self {
            address,
            format: format.clone(),
        })
    }

    fn is_valid(address: &str) -> bool {
        if address.len() != 48 {
            return false;
        }
        InnerTonAddress::from_str(address).is_ok()
    }
}

impl FromStr for TonAddress {
    type Err = AddressError;

    fn from_str(addr: &str) -> Result<Self, Self::Err> {
        if addr.len() != 48 {
            return Err(AddressError::InvalidCharacterLength(addr.len()));
        }

        let address = InnerTonAddress::from_str(addr).map_err(|error| {
            AddressError::Message(format!("Failed to parse MsgAddress: {:?}", error))
        })?;
        Ok(Self {
            address,
            format: TonFormat::default(),
        })
    }
}

impl Display for TonAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.format {
            TonFormat::MainnetBounceable => {
                write!(f, "{}", self.address.to_base64_std_flags(false, false))
            }
            TonFormat::TestnetBounceable => {
                write!(f, "{}", self.address.to_base64_std_flags(false, true))
            }
            TonFormat::MainnetNonBounceable => {
                write!(f, "{}", self.address.to_base64_std_flags(true, false))
            }
            TonFormat::TestnetNonBounceable => {
                write!(f, "{}", self.address.to_base64_std_flags(true, true))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::address::TonAddress;
    use crate::format::TonFormat;
    use crate::public_key::TonPublicKey;
    use anychain_core::public_key::PublicKey;
    use core::str::FromStr;
    use ed25519_dalek::PUBLIC_KEY_LENGTH;

    #[test]
    fn test_address_from_str() {
        let a_str = "EQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlZH3";
        let b_str = "kQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlSp9";
        let c_str = "UQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322Ulcwy";
        let d_str = "0QA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

        let a_addr = TonAddress::from_str(a_str).unwrap();
        let b_addr = TonAddress::from_str(b_str).unwrap();
        let c_addr = TonAddress::from_str(c_str).unwrap();
        let d_addr = TonAddress::from_str(d_str).unwrap();

        let addr_bytes: [u8; 32] = [
            58, 91, 107, 41, 68, 158, 131, 248, 5, 31, 232, 241, 211, 124, 162, 66, 137, 190, 183,
            100, 149, 58, 124, 175, 1, 196, 117, 105, 223, 109, 148, 149,
        ];

        assert_eq!(addr_bytes, a_addr.address.hash_part);
        assert_eq!(addr_bytes, b_addr.address.hash_part);
        assert_eq!(addr_bytes, c_addr.address.hash_part);
        assert_eq!(addr_bytes, d_addr.address.hash_part);
    }

    #[test]
    fn test_address_formats() {
        let secret_bytes: [u8; PUBLIC_KEY_LENGTH] = [
            163, 27, 236, 35, 251, 127, 152, 172, 241, 108, 136, 153, 30, 28, 111, 7, 8, 203, 61,
            254, 254, 28, 22, 140, 180, 158, 52, 246, 207, 241, 80, 203,
        ];

        let secret_key = ed25519_dalek::SecretKey::from_bytes(&secret_bytes).unwrap();
        let public_key: TonPublicKey = TonPublicKey::from_secret_key(&secret_key);
        dbg!(&public_key.0.as_bytes());

        let a_addr = public_key
            .to_address(&TonFormat::MainnetBounceable)
            .unwrap();
        let b_addr = public_key
            .to_address(&TonFormat::TestnetBounceable)
            .unwrap();
        let c_addr = public_key
            .to_address(&TonFormat::MainnetNonBounceable)
            .unwrap();
        let d_addr: TonAddress = public_key
            .to_address(&TonFormat::TestnetNonBounceable)
            .unwrap();

        // When non_production is set to false, it means the address can be used in Mainnet
        // Mainnet uses a non-bounceable, production environment address c_str
        // Testnet uses a non-bounceable, test environment address d_str

        assert_eq!(
            a_addr.to_string(),
            "EQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlZH3"
        );
        assert_eq!(
            b_addr.to_string(),
            "kQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlSp9"
        );
        assert_eq!(
            c_addr.to_string(),
            "UQA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322Ulcwy"
        );
        assert_eq!(
            d_addr.to_string(),
            "0QA6W2spRJ6D+AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4"
        );
    }
}

#[test]
fn test_address_gen() {
    let sk = [163, 27, 236, 35, 251, 127, 152, 172, 241, 108, 136, 153, 30, 28, 111, 7, 8, 203, 61, 254, 254, 28, 22, 140, 180, 158, 52, 246, 207, 241, 80, 203];
    let sk = ed25519_dalek::SecretKey::from_bytes(&sk).unwrap();
    let pk = ed25519_dalek::PublicKey::from(&sk);
    
    let xsk = ed25519_dalek::ExpandedSecretKey::from(&sk);
    let msg = "e1e0c6e409ed279f8267a96c63c01d24bf5dc698d882ff1dce28c95acbeb8cb7";
    let msg = hex::decode(msg).unwrap();
    let sig = xsk.sign(&msg, &pk);
    let sig = sig.to_bytes();
    let sig = hex::encode(sig);
    println!("sig: {}", sig);

    let pk = TonPublicKey(pk);
    let addr = TonAddress::from_public_key(&pk, &TonFormat::TestnetNonBounceable).unwrap();

    println!("{}", addr);
}

#[test]
fn test_address_gen1() {
    let sk = [123, 119, 75, 83, 182, 162, 80, 116, 206, 83, 201, 219, 245, 142, 86, 18, 73, 192, 174, 111, 233, 125, 71, 235, 132, 32, 24, 20, 221, 35, 233, 242];
    let sk = ed25519_dalek::SecretKey::from_bytes(&sk).unwrap();
    let pk = ed25519_dalek::PublicKey::from(&sk);
    let pk_bytes = pk.to_bytes();
    println!("pk: {:?}", pk_bytes);
    
    let xsk = ed25519_dalek::ExpandedSecretKey::from(&sk);
    let msg = "4eb4e0616d6905c149c11f55f9efb1f63e02037e2c8c89f91e3f197ac46b47b2";
    let msg = hex::decode(msg).unwrap();
    let sig = xsk.sign(&msg, &pk);
    let sig = sig.to_bytes();
    let sig = hex::encode(sig);
    println!("sig: {}", sig);

    let pk = TonPublicKey(pk);
    let addr = TonAddress::from_public_key(&pk, &TonFormat::TestnetNonBounceable).unwrap();

    println!("{}", addr);
}

#[test]
fn test_address_gen2() {
    let pk = [123, 119, 75, 83, 182, 162, 80, 116, 206, 83, 201, 219, 245, 142, 86, 18, 73, 192, 174, 111, 233, 125, 71, 235, 132, 32, 24, 20, 221, 35, 233, 242];
    let pk = ed25519_dalek::PublicKey::from_bytes(&pk).unwrap();

    let pk = TonPublicKey(pk);
    let addr = TonAddress::from_public_key(&pk, &TonFormat::TestnetNonBounceable).unwrap();

    println!("{}", addr);
}