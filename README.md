# anychain-ton

anychain-ton is a Rust library that provides a simple and unified interface for interacting with the Ton
blockchain.

## Features

- **Transaction Processing**: Functionality to create, sign, and broadcast transactions on the Ton network
- **Integration with Ton RPC API**: Interact with the Ton RPC API for querying account information, transaction
  details, etc.
- **Wallet Management**: Creating and managing Ton wallets, including keypair
  generation, public/private key management, etc.

## Installation

Add the following to your Cargo.toml file:

```toml
[dependencies]
anychain-ton = "0.1.7"
```

Then, run cargo build to download and compile the library.

## Usage

```shell
cargo build --example simple-transfer
cargo run --example simple-transfer
```

## License

anychain-ton released under the MIT License. See the [LICENSE](LICENSE) file for more information. 
