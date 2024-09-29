use base64::engine::{general_purpose, Engine};
use num_bigint::BigUint;
use std::sync::Arc;
use std::time::SystemTime;
use tonlib_core::cell::{BagOfCells, CellBuilder};
use tonlib_core::message::TransferMessage;
use tonlib_core::message::{CommonMsgInfo, TonMessage};
use tonlib_core::mnemonic::KeyPair;
use tonlib_core::mnemonic::Mnemonic;
use tonlib_core::wallet::TonWallet;
use tonlib_core::wallet::WalletVersion;
use tonlib_core::TonAddress;

use toncenter::client::{ApiClientV2, Network, ApiKey};

#[tokio::main]
async fn main() {
    let api_key = "a8b61ced4be11488cb6e82d65b93e3d4a29d20af406aed9688b9e0077e2dc742".to_string();
    let api_client = ApiClientV2::new(Network::Testnet, Some(ApiKey::Header(api_key)));

    // let api_client = ApiClientV2::new(Network::Testnet, None);
    // let address = "0QA6W2spRJ6D-AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

    // match api_client.get_address_information(address).await {
    //     Ok(info) => println!("Address info: {:#?}", info),
    //     Err(e) => {
    //         eprintln!("{:?}", e);
    //     }
    // }

    let boc_str = build_simple_transfer_boc();

    // match api_client.send_boc(&boc_str).await {
    //     Ok(response) => println!("Response: {:#?}", response),
    //     Err(e) => {
    //         eprintln!("{:?}", e);
    //     }
    // }
}

fn build_simple_transfer_boc() -> String {
    let mnemoic_str = "private two helmet history gravity disease impact slice because silent crunch mammal divert kind faint ketchup holiday soup drill during wash mandate fade mention";
    let mnemonic = Mnemonic::from_str(mnemoic_str, &None).unwrap();
    let key_pair: KeyPair = mnemonic.to_key_pair().unwrap();
    println!("sk = {:?}\npk = {:?}", key_pair.secret_key, key_pair.public_key);
    // TODO: increase seqno each time
    let seqno = 16;
    let wallet = TonWallet::derive_default(WalletVersion::V4R2, &key_pair).unwrap();

    let dest: TonAddress = "UQArwydSwhC0V8pMeBmezODPCTeqzPv56TvtprsbSgYziIVG"
        .parse()
        .unwrap();
    let value = BigUint::from(1_000u64); // 1e-06 TON
    let transfer_internal = CommonMsgInfo::new_default_internal(&dest, &value);
    let transfer = TransferMessage::new(transfer_internal).build().unwrap();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    
    let body = wallet
        .create_external_body(
            now + 600,
            seqno,
            vec![Arc::new(transfer)],
        )
        .unwrap();
    let signed = wallet.sign_external_body(&body).unwrap();
    let wrapped = wallet.wrap_signed_body(signed, false).unwrap();
    let boc = BagOfCells::from_root(wrapped);
    let tx = boc.serialize(true).unwrap();

    general_purpose::STANDARD.encode(&tx)
}

#[test]
fn test() {
    let s = build_simple_transfer_boc();
}