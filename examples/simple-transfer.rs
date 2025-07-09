use base64::engine::{general_purpose, Engine};
use num_bigint::BigUint;
use num_traits::Zero;
use std::{sync::Arc, time::SystemTime};
use toncenter::client::{ApiClientV2, ApiKey, Network};
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
    let api_key = "a8b61ced4be11488cb6e82d65b93e3d4a29d20af406aed9688b9e0077e2dc742".to_string();
    let api_client = ApiClientV2::new(Network::Testnet, Some(ApiKey::Header(api_key)));

    // let api_client = ApiClientV2::new(Network::Testnet, None);
    let address = "0QA6W2spRJ6D-AUf6PHTfKJCib63ZJU6fK8BxHVp322UlXe4";

    // SmcRunResult { gas_used: 769, stack: [("num", "0x11")], exit_code: 0, extra: Some("1727601265.8202894:5:0.2830781684144622") }
    match api_client.run_get_method(address, "seqno", &[]).await {
        Ok(info) => {
            if info.exit_code == 0 {
                let (_type, hex_value) = info.stack.first().unwrap();
                let seqno: u64 =
                    u64::from_str_radix(hex_value.trim_start_matches("0x"), 16).unwrap();
                println!("{seqno}");
            }
        }
        Err(e) => {
            eprintln!("{e:?}");
        }
    }

    // match api_client.get_address_information(address).await {
    //     Ok(info) => println!("Address info: {:#?}", info),
    //     Err(e) => {
    //         eprintln!("{:?}", e);
    //     }
    // }

    // let boc_str = build_simple_transfer_boc();

    // match api_client.send_boc(&boc_str).await {
    //     Ok(response) => println!("Response: {:#?}", response),
    //     Err(e) => {
    //         eprintln!("{:?}", e);
    //     }
    // }
}

#[allow(dead_code)]
fn build_simple_transfer_boc() -> String {
    let mnemoic_str = "private two helmet history gravity disease impact slice because silent crunch mammal divert kind faint ketchup holiday soup drill during wash mandate fade mention";
    let mnemonic = Mnemonic::from_str(mnemoic_str, &None).unwrap();
    let key_pair: KeyPair = mnemonic.to_key_pair().unwrap();
    println!(
        "sk = {:?}\npk = {:?}",
        key_pair.secret_key, key_pair.public_key
    );
    // TODO: increase seqno each time
    let seqno = 23;
    let wallet = TonWallet::derive_default(WalletVersion::V4R2, &key_pair).unwrap();

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
}

#[test]
fn test() {
    let s = build_simple_transfer_boc();
    dbg!(s);
}

#[test]
fn test_build_transfer_body() {
    use tonlib_core_anychain::cell::CellBuilder;

    let body = "hello anychain";
    let cell = CellBuilder::new()
        .store_uint(32, &BigUint::zero())
        .unwrap()
        .store_string(body)
        .unwrap()
        .build();
    assert!(cell.is_ok());

    let cell = cell.unwrap();
    let cell_data_b64 = hex::encode(cell.data());
    assert_eq!("0000000068656c6c6f20616e79636861696e", cell_data_b64);
}
