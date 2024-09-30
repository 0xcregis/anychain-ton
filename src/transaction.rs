use crate::{TonAddress, TonFormat, TonPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};

use num_bigint::BigUint;
use std::sync::Arc;
use tonlib_core::types::TonAddress as InnerTonAddress;
use tonlib_core::cell::{BagOfCells, Cell, CellBuilder, StateInitBuilder};
use tonlib_core::message::TransferMessage;
use tonlib_core::message::{CommonMsgInfo, TonMessage};
use tonlib_core::wallet::{WALLET_V4R2_CODE, WalletDataV4};


const DEFAULT_WALLET_ID: i32 = 0x29a9a317;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransactionParameters {
    pub token: Option<TonAddress>,
    pub from: TonAddress,
    pub to: TonAddress,
    pub amount: u64,
    pub seqno: u32,
    pub now: u32,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransaction {
    pub params: TonTransactionParameters,
    pub signature: Option<Vec<u8>>,
}

impl FromStr for TonTransaction {
    type Err = TransactionError;
    fn from_str(_tx: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TonTransactionId(pub [u8; 64]);

impl fmt::Display for TonTransactionId {
    fn fmt(&self, _f: &mut fmt::Formatter) -> fmt::Result {
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
        if rs.len() != 64 {
            return Err(TransactionError::Message(format!(
                "Invalid signature length {}",
                rs.len(),
            )));
        }
        self.signature = Some(rs);
        self.to_bytes()
    }

    fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        let to = &self.params.to.address;
        let amount = BigUint::from(self.params.amount);
        let transfer = CommonMsgInfo::new_default_internal(&to, &amount);
        let transfer = TransferMessage::new(transfer).build().unwrap();
        let transfer = Arc::new(transfer);

        let mut builder = CellBuilder::new();
        
        let _ = builder.store_i32(32, DEFAULT_WALLET_ID);
        let _ = builder.store_u32(32, self.params.now + 600);
        let _ = builder.store_u32(32, self.params.seqno);
        let _ = builder.store_u8(8, 0);
        let _ = builder.store_u8(8, 3); // send_mode
        let _ = builder.store_reference(&transfer);
        
        let cell = builder.build().unwrap();
        
        match &self.signature {
            Some(sig) => {
                let mut builder = CellBuilder::new();
                let _ = builder.store_slice(sig);
                let _ = builder.store_cell(&cell);
                let cell = builder.build().unwrap();

                let mut builder = CellBuilder::new();
                let _ = builder.store_u8(2, 2);
                let _ = builder.store_address(&InnerTonAddress::NULL);
                let _ = builder.store_address(&self.params.from.address);
                let _ = builder.store_coins(&BigUint::ZERO);
                
                /******************initialize account state for the first transaction*****************/
                if self.params.seqno == 0 {
                    let _ = builder.store_bit(true); // state init present
                    let _ = builder.store_bit(true); // state init in ref
                    let initial_data = WalletDataV4 {
                        seqno: 0,
                        wallet_id: DEFAULT_WALLET_ID,
                        public_key: self.params.public_key,
                    };
                    let initial_data: Cell = initial_data.try_into().unwrap();
                    let initial_data = Arc::new(initial_data);
                    let code = WALLET_V4R2_CODE.single_root().unwrap();
                    let state_init = StateInitBuilder::new(code, &initial_data).build().unwrap();
                    let _ = builder.store_child(state_init);
                }
                /************************************************************************************/
                
                let _ = builder.store_bit(true);
                let _ = builder.store_child(cell);
                let cell = builder.build().unwrap();

                let boc = BagOfCells::from_root(cell);
                let stream = boc.serialize(true).unwrap();
                
                Ok(stream)
            }
            None => {
                let stream = cell.cell_hash().to_vec();
                Ok(stream)
            }
        }
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}


// use base64::{engine::general_purpose, Engine as _};
// use toncenter::client::{ApiClientV2, Network, ApiKey};
// use tokio::runtime::Runtime;
// use std::time::SystemTime;

// #[test]
// fn test_tx_gen() {
//     let from = "0QD3efSsNH7xNTSMgqPuyKWaDvJZ9I49DarhD9nPOU4aS2jF";
//     let to = "0QA6W2spRJ6D-AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

//     let from = TonAddress::from_str(from).unwrap();
//     let to = TonAddress::from_str(to).unwrap();

//     let pk = [123, 119, 75, 83, 182, 162, 80, 116, 206, 83, 201, 219, 245, 142, 86, 18, 73, 192, 174, 111, 233, 125, 71, 235, 132, 32, 24, 20, 221, 35, 233, 242];

//     let params = TonTransactionParameters {
//         token: None,
//         from: from.clone(),
//         to: to.clone(),
//         amount: 1000000,
//         seqno: 1,
//         now: 1727590026 + 600,
//         public_key: pk,
//     };

//     let mut tx = TonTransaction::new(&params).unwrap();

//     let msg = tx.to_bytes().unwrap();
//     let msg = hex::encode(msg);

//     println!("msg: {}", msg);

//     let sig = "58bfa034e6e16f2cce93b3fa8784ce5a8548907070ae02839f7ce196528ac61a62e80db2f6a7f5c1a4a96e1d7e6687088c7ad0a7a56f80a1f4d804a966f7dc06";
//     let sig = hex::decode(sig).unwrap();

//     let tx = tx.sign(sig, 0).unwrap();
//     let tx = general_purpose::STANDARD.encode(&tx);
//     println!("tx: {}", tx);

//     let api_key = "a8b61ced4be11488cb6e82d65b93e3d4a29d20af406aed9688b9e0077e2dc742".to_string();
//     let api_client = ApiClientV2::new(Network::Testnet, Some(ApiKey::Header(api_key)));

//     Runtime::new().unwrap().block_on(async {
//         let response = api_client.send_boc(&tx).await;
//         println!("Response: {:#?}", response);
//     });
// }

// fn now() -> u32 {
//     SystemTime::now()
//     .duration_since(SystemTime::UNIX_EPOCH)
//     .unwrap()
//     .as_secs() as u32
// }

// #[test]
// fn test_now() {
//     println!("now: {}", now());
// }
