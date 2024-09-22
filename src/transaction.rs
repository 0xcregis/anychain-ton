#![allow(unused_variables)]

use crate::{TonAddress, TonFormat, TonPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransactionParameters {
    pub token: Option<TonAddress>,
    pub from: TonAddress,
    pub to: TonAddress,
    pub amount: u64,
    pub blockhash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransaction {
    pub params: TonTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl FromStr for TonTransaction {
    type Err = TransactionError;
    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TonTransactionId(pub [u8; 64]);

impl fmt::Display for TonTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        todo!()
    }
}

impl TransactionId for TonTransactionId {}

impl Transaction for TonTransaction {
    type Address = TonAddress;
    type Format = TonFormat;
    type PublicKey = TonPublicKey;
    type TransactionParameters = TonTransactionParameters;
    type TransactionId = TonTransactionId;

    fn new(params: &Self::TransactionParameters) -> Result<Self, TransactionError> {
        Ok(TonTransaction {
            params: params.clone(),
            signature: None,
        })
    }

    fn sign(&mut self, rs: Vec<u8>, _: u8) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        todo!()
    }

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

#[test]
fn test_transaction() {}
