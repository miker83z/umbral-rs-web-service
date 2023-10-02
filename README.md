# Umbral-rs Web Service

`umbral-rs` is the implementation of the [Umbral](https://github.com/nucypher/umbral-doc/blob/master/umbral-doc.pdf) threshold proxy re-encryption (TPRE) scheme. See the [github repository](https://github.com/disnocen/umbral-rs) of the main project for more details.

**This web service enables the execution of the Umbral TPRE operations.**

## Install

- install `umbral-rs` via `cargo install --git https://github.com/disnocen/umbral-rs --branch feat_keydistrib`
- clone this repo
- modify the `toml` file to have the right path or `umbral-rs`: Default is:

```toml
umbral-rs = { path = "../umbral-rs" }
```

## Usage

To learn how to use the project, ass

1. in the folder of this repo do the following command to activate the server
   NOTE: hardcoded port `"8080"` in `main.rs`

```
cargo run
```

2. In the `examples` folder execute the scripts you want by reading/copying:

   - `client.txt` for examples 1 to 5
   - execute (or copy & execute lines one by one) the file `key_distrib.sh` for the key refresh part
