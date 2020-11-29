use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::crypto::{CipherKind, CipherCategory, Cipher, available_ciphers, openssl_bytes_to_key, random_iv_or_salt};

use std::io;
use std::net::SocketAddr;


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct HttpsClientConfig {
    pub method: CipherKind,
    pub password: Vec<u8>,
    /// ss-local socket addr
    pub bind_addr: SocketAddr,
    /// ss-remote socket addr
    pub remote_addr: SocketAddr,
}


pub struct HttpsClient {
    listener: TcpListener,
}