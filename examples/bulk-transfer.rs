#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use base64::engine::{general_purpose, Engine};
use num_bigint::BigUint;
use num_traits::Zero;
use std::{sync::Arc, time::SystemTime};
use toncenter::client::{ApiClientV2, Network};
use tonlib_core_anychain::{
    cell::{BagOfCells, CellBuilder},
    message::TransferMessage,
    message::{CommonMsgInfo, TonMessage},
    mnemonic::KeyPair,
    mnemonic::Mnemonic,
    wallet::TonWallet,
    wallet::WalletVersion,
    TonAddress,
};

#[tokio::main]
async fn main() {
    let api_client = ApiClientV2::new(Network::Testnet, None);

    let address = "0QA6W2spRJ6D-AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

    let mut seqno = 0;
    match api_client.run_get_method(address, "seqno", &[]).await {
        Ok(info) => {
            if info.exit_code == 0 {
                let (_type, hex_value) = info.stack.first().unwrap();
                seqno = u32::from_str_radix(hex_value.trim_start_matches("0x"), 16).unwrap();
                println!("{}", seqno);
            }
        }
        Err(e) => {
            eprintln!("{:?}", e);
        }
    }

    let boc_str = build_bulk_transfer_boc(seqno, &create_bulk_transfer_input());

    match api_client.send_boc(&boc_str).await {
        Ok(response) => println!("Response: {:#?}", response),
        Err(e) => {
            eprintln!("{:?}", e);
        }
    }
}

#[derive(Debug, Clone)]
struct Recipient {
    address: String,
    amount: u64, // Assuming amount is in nano TON
    payload: String,
    send_mode: u8, // usually 3 for standard transfers
}

#[derive(Debug, Clone)]
struct BulkTransferInput {
    recipients: Vec<Recipient>,
}

fn create_bulk_transfer_input() -> BulkTransferInput {
    let recipients = vec![
        Recipient {
            address: String::from("0QCnTFjKMaAN93rIKvQygB_FOl_xD7uWtErohO616IOhRxks"),
            amount: 1000000, // 0.001
            payload: String::from("Payment 1"),
            send_mode: 3,
        },
        Recipient {
            address: String::from("0QD7J9I7i9xod_JLMi-knxFMIL2PAoXqL3Uf1j4GXj78NoF5"),
            amount: 1000000, // 0.001
            payload: String::from("Payment 2"),
            send_mode: 3,
        },
    ];

    BulkTransferInput { recipients }
}

#[allow(dead_code)]
fn build_bulk_transfer_boc(seqno: u32, inputs: &BulkTransferInput) -> String {
    let mnemoic_str = "private two helmet history gravity disease impact slice because silent crunch mammal divert kind faint ketchup holiday soup drill during wash mandate fade mention";
    let mnemonic = Mnemonic::from_str(mnemoic_str, &None).unwrap();
    let key_pair: KeyPair = mnemonic.to_key_pair().unwrap();
    println!(
        "sk = {:?}\npk = {:?}",
        key_pair.secret_key, key_pair.public_key
    );
    let wallet = TonWallet::derive_default(WalletVersion::HighloadV2R2, &key_pair).unwrap();
    dbg!(&inputs);

    /*
        let dest: TonAddress = "UQArwydSwhC0V8pMeBmezODPCTeqzPv56TvtprsbSgYziIVG"
            .parse()
            .unwrap();
        let value = BigUint::from(1_000u64); // 1e-06 TON
        let transfer_internal = CommonMsgInfo::new_internal_non_bounceable(&dest, &value);

        let body = "hello anychain";
        let transfer_body = CellBuilder::new()
            .store_uint(32, &BigUint::zero())
            .unwrap()
            .store_string(body)
            .unwrap()
            .build()
            .unwrap();

        let transfer = TransferMessage::new(transfer_internal)
            .with_data(Arc::new(transfer_body))
            .build()
            .unwrap();
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let body = wallet
            .create_external_body(now + 600, seqno, vec![Arc::new(transfer)])
            .unwrap();
        let signed = wallet.sign_external_body(&body).unwrap();
        let wrapped = wallet.wrap_signed_body(signed, false).unwrap();
        let boc = BagOfCells::from_root(wrapped);
        let tx = boc.serialize(true).unwrap();
        general_purpose::STANDARD.encode(&tx)
    */
    "foo".to_string()
}

#[test]
fn test() {
    let seqno = 0;
    let s = build_bulk_transfer_boc(seqno, &create_bulk_transfer_input());
    dbg!(s);
}
