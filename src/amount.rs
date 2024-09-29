//! Definitions for the native TON token and its fractional gram.

use {
    anychain_core::{to_basic_unit_u64, Amount, AmountError},
    core::fmt,
    serde::{Deserialize, Serialize},
    std::ops::{Add, Sub},
};

/// Represents the amount of TON in GRAM
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TonAmount(pub u64);

pub enum Denomination {
    GRAM,
    TON,
}

impl Denomination {
    /// The number of decimal places more than one gram.
    /// There are 10^9 gram in one TON
    fn precision(self) -> u64 {
        match self {
            Denomination::GRAM => 0,

            Denomination::TON => 9,
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Denomination::GRAM => "GRAM",
                Denomination::TON => "TON",
            }
        )
    }
}

impl Amount for TonAmount {}

impl TonAmount {
    pub fn from_u64(gram: u64) -> Self {
        Self(gram)
    }

    pub fn from_u64_str(value: &str) -> Result<u64, AmountError> {
        match value.parse::<u64>() {
            Ok(gram) => Ok(gram),
            Err(error) => Err(AmountError::Crate("uint", format!("{:?}", error))),
        }
    }
    pub fn from_gram(gram_value: &str) -> Result<Self, AmountError> {
        let gram = Self::from_u64_str(gram_value)?;
        Ok(Self::from_u64(gram))
    }

    pub fn from_ton(ton_value: &str) -> Result<Self, AmountError> {
        let gram_value = to_basic_unit_u64(ton_value, Denomination::TON.precision());
        let gram = Self::from_u64_str(&gram_value)?;
        Ok(Self::from_u64(gram))
    }
}

impl Add for TonAmount {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0)
    }
}

impl Sub for TonAmount {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl fmt::Display for TonAmount {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    fn test_from_gram(gram_value: &str, expected_amount: &str) {
        let amount = TonAmount::from_gram(gram_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    fn test_from_ton(ton_value: &str, expected_amount: &str) {
        let amount = TonAmount::from_ton(ton_value).unwrap();
        assert_eq!(expected_amount, amount.to_string())
    }

    pub struct AmountDenominationTestCase {
        gram: &'static str,
        ton: &'static str,
    }

    const TEST_AMOUNTS: [AmountDenominationTestCase; 2] = [
        AmountDenominationTestCase {
            gram: "0",
            ton: "0",
        },
        AmountDenominationTestCase {
            gram: "1000000000",
            ton: "1",
        },
    ];

    #[test]
    fn test_gram_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_gram(amounts.gram, amounts.gram));
    }

    #[test]
    fn test_ton_conversion() {
        TEST_AMOUNTS
            .iter()
            .for_each(|amounts| test_from_ton(amounts.ton, amounts.gram));
    }

    fn test_addition(a: &str, b: &str, result: &str) {
        let a = TonAmount::from_gram(a).unwrap();
        let b = TonAmount::from_gram(b).unwrap();
        let result = TonAmount::from_gram(result).unwrap();

        assert_eq!(result, a.add(b));
    }

    fn test_subtraction(a: &str, b: &str, result: &str) {
        let a = TonAmount::from_gram(a).unwrap();
        let b = TonAmount::from_gram(b).unwrap();
        let result = TonAmount::from_gram(result).unwrap();

        assert_eq!(result, a.sub(b));
    }
    mod valid_arithmetic {
        use super::*;

        const TEST_VALUES: [(&str, &str, &str); 5] = [
            ("0", "0", "0"),
            ("1", "2", "3"),
            ("100000", "0", "100000"),
            ("123456789", "987654321", "1111111110"),
            ("1000000000000000", "2000000000000000", "3000000000000000"),
        ];

        #[test]
        fn test_valid_addition() {
            TEST_VALUES
                .iter()
                .for_each(|(a, b, c)| test_addition(a, b, c));
        }
    }
}
