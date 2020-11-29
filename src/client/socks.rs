use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::crypto::{CipherKind, CipherCategory, Cipher, available_ciphers, openssl_bytes_to_key, random_iv_or_salt};
use crate::socks::{SOCKS_V4, SOCKS_V5};

use super::socks4::handle_socks4_incoming;
use super::socks5::handle_socks5_incoming;


use std::io;
use std::net::SocketAddr;


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SocksClientConfig {
    pub method: CipherKind,
    pub password: Vec<u8>,
    /// ss-local  socks server addr
    pub bind_addr: SocketAddr,
    /// ss-remote socks server addr
    pub server_addr: SocketAddr,
}


pub struct SocksClient {
    listener: TcpListener,
    socks_server_addr: SocketAddr,
    method: CipherKind,
    key: Vec<u8>,
}

impl SocksClient {
    pub async fn new(config: SocksClientConfig) -> io::Result<Self> {
        let addr = config.bind_addr;
        let listener = TcpListener::bind(addr).await?;
        info!("tcp listener listening at {:?}.", listener.local_addr()?);

        let socks_server_addr = config.server_addr;
        let method = config.method;
        let password = config.password;
        let key_len = method.key_len();

        let mut key = vec![0u8; key_len];
        openssl_bytes_to_key(&password, &mut key);

        Ok(Self { listener, socks_server_addr, method, key, })
    }
    
    pub async fn run_forever(&self) -> io::Result<()> {
        loop {
            let (stream, peer_addr) = self.listener.accept().await?;
            info!("got socks connection {:?}", peer_addr);
            

            let socks_server_addr = self.socks_server_addr;
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                if let Err(e) = handle_socks_incoming(stream, socks_server_addr).await {
                    error!("socks connection error: {}", e);
                }
            });
        }
    }
}

// T: AsyncRead + AsyncWrite + Unpin
async fn handle_socks_incoming(mut stream: TcpStream, socks_server_addr: SocketAddr) -> io::Result<()> {
    let mut pkt = [0u8; 1];
    let _amt = stream.read_exact(&mut pkt).await?;
    let ver = pkt[0];

    match ver {
        SOCKS_V4 => handle_socks4_incoming(stream, socks_server_addr).await,
        SOCKS_V5 => handle_socks5_incoming(stream, socks_server_addr).await,
        _        => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks version")),
    }
}
