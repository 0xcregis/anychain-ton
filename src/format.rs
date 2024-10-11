use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TonFormat {
    MainnetBounceable, // non_bounceable = false, non_production = false
    TestnetBounceable, // non_bounceable = false, non_production = true
    #[default]
    MainnetNonBounceable, // non_bounceable = true, non_production = false
    TestnetNonBounceable, // non_bounceable = true, non_production = true
}

impl Format for TonFormat {}

impl fmt::Display for TonFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TonFormat::MainnetBounceable => write!(f, "MainnetBounceable"),
            TonFormat::TestnetBounceable => write!(f, "TestnetBounceable"),
            TonFormat::MainnetNonBounceable => write!(f, "MainnetNonBounceable"),
            TonFormat::TestnetNonBounceable => write!(f, "TestnetNonBounceable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(
            TonFormat::MainnetBounceable.to_string(),
            "MainnetBounceable"
        );
        assert_eq!(
            TonFormat::TestnetBounceable.to_string(),
            "TestnetBounceable"
        );
        assert_eq!(
            TonFormat::MainnetNonBounceable.to_string(),
            "MainnetNonBounceable"
        );
        assert_eq!(
            TonFormat::TestnetNonBounceable.to_string(),
            "TestnetNonBounceable"
        );
    }
}
