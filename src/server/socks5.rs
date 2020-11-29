// SOCKS Protocol Version 5
// https://tools.ietf.org/html/rfc1928
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::crypto::{CipherKind, CipherCategory, Cipher, available_ciphers, openssl_bytes_to_key, random_iv_or_salt};

use std::io;
use std::net::SocketAddr;


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ServerConfig {
    pub method: CipherKind,
    pub password: Vec<u8>,
    /// ss-remote socket addr
    pub bind_addr: SocketAddr,
}
