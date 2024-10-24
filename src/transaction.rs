use crate::{TonAddress, TonFormat, TonPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};

use num_bigint::BigUint;
use std::sync::Arc;
use tonlib_core_anychain::{
    cell::{BagOfCells, Cell, CellBuilder, EitherCellLayout, StateInitBuilder},
    message::{CommonMsgInfo, JettonTransferMessage, TonMessage, TransferMessage},
    wallet::{WalletDataV4, DEFAULT_WALLET_ID, WALLET_V4R2_CODE},
    TonAddress as InnerAddress,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransactionParameters {
    pub jetton_wallet: Option<TonAddress>,
    pub from: TonAddress,
    pub to: TonAddress,
    pub amount: u64,
    pub seqno: u32,
    pub comment: String,
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
        // here we create the cell of the comment
        let mut builder = CellBuilder::new();
        let _ = builder.store_u32(32, 0);
        let _ = builder.store_string(&self.params.comment);
        let comment = Arc::new(builder.build().unwrap());

        let transfer = match &self.params.jetton_wallet {
            Some(jetton_wallet) => {
                let jetton_wallet = &jetton_wallet.address;
                let to = &self.params.to.address;
                let amount = BigUint::from(self.params.amount);

                let jetton_transfer = Arc::new(
                    JettonTransferMessage {
                        query_id: 1,
                        amount,
                        destination: to.clone(),
                        response_destination: InnerAddress::NULL,
                        custom_payload: None,
                        forward_ton_amount: BigUint::from(1u64),
                        forward_payload: comment,
                        forward_payload_layout: EitherCellLayout::Native,
                    }
                    .build()
                    .unwrap(),
                );

                let fee = BigUint::from(100000000u64);

                let transfer = TransferMessage::new(CommonMsgInfo::new_internal_non_bounceable(
                    jetton_wallet,
                    &fee,
                ))
                .with_data(jetton_transfer)
                .build()
                .unwrap();

                Arc::new(transfer)
            }
            None => {
                let to = &self.params.to.address;
                let amount = BigUint::from(self.params.amount);
                let transfer =
                    TransferMessage::new(CommonMsgInfo::new_internal_non_bounceable(to, &amount))
                        .with_data(comment)
                        .build()
                        .unwrap();

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
                let from = &self.params.from.address;
                let mut builder = CellBuilder::new();
                let _ = builder.store_slice(sig);
                let _ = builder.store_cell(&cell);
                let cell = builder.build().unwrap();

                let mut builder = CellBuilder::new();
                let _ = builder.store_u8(2, 2);
                let _ = builder.store_address(&InnerAddress::NULL);
                let _ = builder.store_address(from);
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
    use crate::TonAddress;
    use crate::TonTransaction;
    use crate::TonTransactionParameters;
    use anychain_core::transaction::Transaction;
    use base64::{engine::general_purpose, Engine as _};
    use core::str::FromStr;
    use std::time::SystemTime;
    // use tokio::runtime::Runtime;
    // use toncenter::client::{ApiClientV2, ApiKey, Network};

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
            seqno: 14,
            comment: "mao".to_string(),
            now: 1728698931,
            public_key: pk,
        };

        let mut tx = TonTransaction::new(&params).unwrap();

        let msg = tx.to_bytes().unwrap();
        let msg = hex::encode(msg);

        assert_eq!(
            "90d45852d51697cb57390bb4ea2d512760b7650551007b3a883f7d9ef04aecae",
            msg
        );

        let sig = "fe260362985c26f876d26fb9bcfdf5b2ede940c30001b7931ce4535125b90e35f509c05947b9a8de224dfb9e1157799c95e5bcd702d4ca8fa3a507679471a001";
        let sig = hex::decode(sig).unwrap();

        let tx = tx.sign(sig, 0).unwrap();
        let tx = general_purpose::STANDARD.encode(&tx);

        assert_eq!("te6cckEBBAEA7AABRYgB7vPpWGj94mppGQVH3ZFLNB3ks+kcehtVwh+znnKcNJYMAQGc/iYDYphcJvh20m+5vP31su3pQMMAAbeTHORTUSW5DjX1CcBZR7mo3iJN+54RV3mcleW81wLUyo+jpQdnlHGgASmpoxdnCdyLAAAADgADAgFoMgA4w19SOb5FPg7xe6q7Piln+D04Y4A2/jYey00vexOEySAvrwgAAAAAAAAAAAAAAAAAAQMAdw+KfqUAAAAAAAAAAVAlQL5ACAB0ttZSiT0H8Ao/0eOm+USFE31uySp0+V4DiOrTvtspKgQEAAAAANrC3yKNt6A=", tx);

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

    #[ignore]
    #[test]
    fn test_now() {
        dbg!("now: {}", now());
    }
}
