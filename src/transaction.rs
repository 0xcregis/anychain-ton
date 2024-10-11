use crate::{TonAddress, TonFormat, TonPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};

use num_bigint::BigUint;
use std::sync::Arc;
use tonlib_core_anychain::cell::{BagOfCells, Cell, CellBuilder, StateInitBuilder, EMPTY_ARC_CELL};
use tonlib_core_anychain::message::{JettonTransferMessage, TonMessage, TransferMessage};
use tonlib_core_anychain::wallet::{WalletDataV4, DEFAULT_WALLET_ID, WALLET_V4R2_CODE};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransactionParameters {
    pub jetton_wallet: Option<TonAddress>,
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

fn address_convert(address: &TonAddress) -> tonlib_core_anychain::TonAddress {
    tonlib_core_anychain::TonAddress::from_str(&address.address.to_string()).unwrap()
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
        /*
        let transfer = match &self.params.jetton_wallet {
            Some(jetton_wallet) => {
                let jetton_wallet = address_convert(&jetton_wallet);
                let to = address_convert(&self.params.to);
                let amount = BigUint::from(self.params.amount);

                let jetton_transfer = JettonTransferMessage {
                    query_id: 1,
                    amount,
                    destination: to,
                    response_destination: tonlib_core_anychain::TonAddress::NULL,
                    custom_payload: None,
                    forward_ton_amount: BigUint::from(1u64),
                    forward_payload: Arc::new(Cell::default()),
                    forward_payload_layout: tonlib_core_anychain::cell::EitherCellLayout::Native,
                }
                .build()
                .unwrap();

                let fee = BigUint::from(100000000u64);

                let transfer = TransferMessage::new(&jetton_wallet, &fee)
                    .with_data(jetton_transfer)
                    .build()
                    .unwrap();
                Arc::new(transfer)
            }
            None => {
                let to = address_convert(&self.params.to);
                let amount = BigUint::from(self.params.amount);
                let transfer = TransferMessage::new(&to, &amount).build().unwrap();
                Arc::new(transfer)
            }
        };

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
                let from = address_convert(&self.params.from);
                let mut builder = CellBuilder::new();
                let _ = builder.store_slice(sig);
                let _ = builder.store_cell(&cell);
                let cell = builder.build().unwrap();

                let mut builder = CellBuilder::new();
                let _ = builder.store_u8(2, 2);
                let _ = builder.store_address(&tonlib_core_anychain::TonAddress::NULL);
                let _ = builder.store_address(&from);
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
                } else {
                    let _ = builder.store_bit(false); // state init absent
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
         */
        todo!()
    }

    fn from_bytes(_tx: &[u8]) -> Result<Self, TransactionError> {
        todo!()
    }

    fn to_transaction_id(&self) -> Result<Self::TransactionId, TransactionError> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::{TonTransaction, TonTransactionParameters, Transaction};
    use crate::TonAddress;
    use base64::{engine::general_purpose, Engine as _};
    use std::time::SystemTime;
    use std::{fmt, str::FromStr};
    use tokio::runtime::Runtime;
    use toncenter::client::{ApiClientV2, ApiKey, Network};

    #[test]
    fn test_tx_gen() {
        let jetton_wallet = "kQBxhr6kc3yKfB3i91V2fFLP8HpwxwBt_Gw9lppe9icJkuWY";

        let from = "0QD3efSsNH7xNTSMgqPuyKWaDvJZ9I49DarhD9nPOU4aS2jF";
        let to = "0QA6W2spRJ6D-AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

        let jetton_wallet = TonAddress::from_str(jetton_wallet).unwrap();
        let from = TonAddress::from_str(from).unwrap();
        let to = TonAddress::from_str(to).unwrap();

        let pk = [
            123, 119, 75, 83, 182, 162, 80, 116, 206, 83, 201, 219, 245, 142, 86, 18, 73, 192, 174,
            111, 233, 125, 71, 235, 132, 32, 24, 20, 221, 35, 233, 242,
        ];

        let params = TonTransactionParameters {
            jetton_wallet: Some(jetton_wallet),
            from: from.clone(),
            to: to.clone(),
            amount: 10000000000,
            seqno: 12,
            now: 1728529359,
            public_key: pk,
        };

        let mut tx = TonTransaction::new(&params).unwrap();

        let msg = tx.to_bytes().unwrap();
        let msg = hex::encode(msg);

        println!("msg: {}", msg);

        let sig = "d7836dc4cc6d1405e861c9b1359047d87300b7fcdc83b06f02613ca0be691ef8bd6bf1e67642a8cd4ddf34a1d822558fbaee1196d3755c5756fc094837b13609";
        let sig = hex::decode(sig).unwrap();

        let tx = tx.sign(sig, 0).unwrap();
        let tx = general_purpose::STANDARD.encode(&tx);
        println!("tx: {}", tx);

        // let api_key = "a8b61ced4be11488cb6e82d65b93e3d4a29d20af406aed9688b9e0077e2dc742".to_string();
        // let api_client = ApiClientV2::new(Network::Testnet, Some(ApiKey::Header(api_key)));

        // Runtime::new().unwrap().block_on(async {
        //     let response = api_client.send_boc(&tx).await;
        //     println!("Response: {:#?}", response);
        // });
    }

    fn now() -> u32 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32
    }

    #[test]
    fn test_now() {
        println!("now: {}", now());
    }
}
