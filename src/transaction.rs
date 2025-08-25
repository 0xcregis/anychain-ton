use crate::{TonAddress, TonFormat, TonPublicKey};
use anychain_core::{Transaction, TransactionError, TransactionId};
use std::{fmt, str::FromStr};

use base64::{engine::general_purpose::STANDARD, Engine};
use num_bigint::BigUint;
use std::sync::Arc;
use tonlib_core_anychain::{
    cell::{BagOfCells, Cell, CellBuilder, EitherCellLayout, StateInitBuilder},
    message::{CommonMsgInfo, JettonTransferMessage, TonMessage, TransferMessage, JETTON_TRANSFER},
    wallet::{WalletDataV4, DEFAULT_WALLET_ID, WALLET_V4R2_CODE},
    TonAddress as InnerAddress,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TonTransactionParameters {
    pub jetton_wallet: Option<TonAddress>,
    pub fee: Option<u64>,
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

fn store_comment(slice: &[u8], layer: u8) -> Arc<Cell> {
    let mut builder = CellBuilder::new();
    let cut = if layer == 0 { 123usize } else { 127usize };

    if slice.len() > cut {
        if layer == 0 {
            let _ = builder.store_u32(32, 0);
            let _ = builder.store_slice(&slice[..cut]);
        } else {
            let _ = builder.store_slice(&slice[..cut]);
        }
        let child = store_comment(&slice[cut..], layer + 1);
        let _ = builder.store_reference(&child);
    } else if layer == 0 {
        let _ = builder.store_u32(32, 0);
        let _ = builder.store_slice(slice);
    } else {
        let _ = builder.store_slice(slice);
    };

    let cell = builder.build().unwrap();
    Arc::new(cell)
}

fn load_comment(data: Arc<Cell>, layer: u8) -> Vec<u8> {
    let mut comment = if layer == 0 {
        data.data()[4..].to_vec()
    } else {
        data.data().to_vec()
    };

    if let Ok(child) = data.reference(0) {
        let child_comment = load_comment(child.clone(), layer + 1);
        comment.extend(child_comment);
    }

    comment
}

impl TonTransaction {
    fn deserialize(cell: &Arc<Cell>, layer: u8) -> Result<Self, TransactionError> {
        match layer {
            0 => {
                let mut parser = cell.parser();

                let _ = parser.load_u8(2);
                let _ = parser.load_address();

                let from = parser
                    .load_address()
                    .unwrap()
                    .to_base64_std_flags(true, true);
                let from = TonAddress::from_str(&from)?;

                let _ = parser.load_coins();

                let init = parser.load_bit().unwrap();

                let mut tx = match init {
                    true => Self::deserialize(cell.reference(1).unwrap(), layer + 1)?,
                    false => Self::deserialize(cell.reference(0).unwrap(), layer + 1)?,
                };

                tx.params.from = from;

                Ok(tx)
            }
            1 => {
                let mut parser = cell.parser();
                let mut sig = [0u8; 64];
                parser.load_slice(sig.as_mut_slice()).unwrap();

                let _ = parser.load_u32(32);
                let expire = parser.load_u32(32).unwrap();
                let seqno = parser.load_u32(32).unwrap();

                let mut tx = Self::deserialize(cell.reference(0).unwrap(), layer + 1)?;

                tx.params.now = expire - 600;
                tx.params.seqno = seqno;
                tx.signature = Some(sig.to_vec());

                Ok(tx)
            }
            2 => {
                let mut parser = cell.parser();
                let _ = parser.skip_bits(4);
                let _ = parser.load_address().unwrap();
                let to = parser
                    .load_address()
                    .unwrap()
                    .to_base64_std_flags(true, true);
                let to = TonAddress::from_str(&to)?;
                let amount = parser.load_coins().unwrap();

                let _ = parser.load_bit();
                let _ = parser.load_coins();
                let _ = parser.load_coins();
                let _ = parser.load_u64(64);
                let _ = parser.load_u32(32);

                let _ = parser.load_maybe_cell_ref();

                let data = parser.load_maybe_cell_ref().unwrap().unwrap();

                let mut parser = data.parser();
                let opcode = parser.load_u32(32).unwrap();

                let (jetton_amount, jetton_to, comment) = match opcode {
                    0 => {
                        // let len = parser.remaining_bytes();
                        // let mut comment = vec![0u8; len];
                        // let _ = parser.load_slice(&mut comment);
                        // let comment = String::from_utf8(comment).unwrap();
                        let comment = load_comment(data, 0);
                        let comment = String::from_utf8(comment).unwrap();
                        (None, None, comment)
                    }
                    JETTON_TRANSFER => {
                        let _ = parser.load_u64(64);
                        let amount = parser.load_coins().unwrap();
                        let to = parser
                            .load_address()
                            .unwrap()
                            .to_base64_std_flags(true, true);
                        let to = TonAddress::from_str(&to)?;

                        let _ = parser.load_address().unwrap();
                        let _ = parser.load_maybe_cell_ref();
                        let _ = parser.load_coins();

                        let data = parser.load_either_cell_or_cell_ref().unwrap();

                        let mut parser = data.parser();
                        let _ = parser.load_u32(32);

                        // let len = parser.remaining_bytes();
                        // let mut comment = vec![0u8; len];
                        // let _ = parser.load_slice(&mut comment);
                        // let comment = String::from_utf8(comment).unwrap();
                        let comment = load_comment(data, 0);
                        let comment = String::from_utf8(comment).unwrap();

                        (Some(amount), Some(to), comment)
                    }
                    _ => return Err(TransactionError::Message("Unrecognized opcode".to_string())),
                };

                let from = InnerAddress::null();
                let from = TonAddress {
                    address: from,
                    format: TonFormat::MainnetNonBounceable,
                };

                let params = match jetton_to {
                    // jetton transfer
                    Some(jetton_to) => TonTransactionParameters {
                        jetton_wallet: Some(to),
                        fee: None,
                        from,
                        to: jetton_to,
                        amount: *jetton_amount.unwrap().to_u64_digits().first().unwrap(),
                        seqno: 0,
                        comment,
                        now: 0,
                        public_key: [0u8; 32],
                    },
                    // TON transfer
                    None => TonTransactionParameters {
                        jetton_wallet: None,
                        fee: None,
                        from,
                        to,
                        amount: *amount.to_u64_digits().first().unwrap(),
                        seqno: 0,
                        comment,
                        now: 0,
                        public_key: [0u8; 32],
                    },
                };

                TonTransaction::new(&params)
            }
            _ => Err(TransactionError::Message(
                "Unsupport layer depth".to_string(),
            )),
        }
    }
}

impl FromStr for TonTransaction {
    type Err = TransactionError;
    fn from_str(tx: &str) -> Result<Self, Self::Err> {
        let tx = STANDARD
            .decode(tx)
            .map_err(|e| TransactionError::Message(e.to_string()))
            .unwrap();
        TonTransaction::from_bytes(&tx)
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
        let comment = self.params.comment.as_bytes();
        let comment = store_comment(comment, 0);

        let transfer = match &self.params.jetton_wallet {
            Some(jetton_wallet) => {
                let jetton_wallet = &jetton_wallet.address;
                let to = &self.params.to.address;
                let amount = BigUint::from(self.params.amount);

                let jetton_transfer = Arc::new(
                    JettonTransferMessage {
                        query_id: self.params.seqno as u64,
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

                let fee = match self.params.fee {
                    Some(fee) => BigUint::from(fee),
                    None => BigUint::from(100000000u64),
                };

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

                // layer 0
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

    fn from_bytes(tx: &[u8]) -> Result<Self, TransactionError> {
        let boc = BagOfCells::parse(tx).map_err(|e| TransactionError::Message(e.to_string()))?;
        Self::deserialize(boc.root(0).unwrap(), 0)
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
    use base64::{engine::general_purpose::STANDARD, Engine};
    use core::str::FromStr;
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

        let public_key = [
            123, 119, 75, 83, 182, 162, 80, 116, 206, 83, 201, 219, 245, 142, 86, 18, 73, 192, 174,
            111, 233, 125, 71, 235, 132, 32, 24, 20, 221, 35, 233, 242,
        ];

        let params = TonTransactionParameters {
            jetton_wallet: Some(jetton_wallet),
            fee: None,
            from: from.clone(),
            to: to.clone(),
            amount: 10000000000,
            seqno: 23,
            comment: "Pythagorus".to_string(),
            now: 1728698931,
            public_key,
        };

        let mut tx = TonTransaction::new(&params).unwrap();

        let sig = "fe260362985c26f876d26fb9bcfdf5b2ede940c30001b7931ce4535125b90e35f509c05947b9a8de224dfb9e1157799c95e5bcd702d4ca8fa3a507679471a001";
        let sig = hex::decode(sig).unwrap();

        let tx = tx.sign(sig, 0).unwrap();
        let tx = STANDARD.encode(&tx);

        let _ = TonTransaction::from_str(&tx).unwrap();

        // let api_key = "a8b61ced4be11488cb6e82d65b93e3d4a29d20af406aed9688b9e0077e2dc742".to_string();
        // let api_client = ApiClientV2::new(Network::Testnet, Some(ApiKey::Header(api_key)));

        // Runtime::new().unwrap().block_on(async {
        //     let response = api_client.send_boc(&tx).await;
        //     println!("Response: {:#?}", response);
        // });
    }
}
