#![allow(unused_imports, dead_code, unused_variables)]

#[macro_use]
extern crate log;
extern crate tokio;
extern crate shadowsocks_crypto;


mod socks;
pub mod crypto;

pub mod config;

/// ss-local
pub mod client;
/// ss-remote
pub mod server;

