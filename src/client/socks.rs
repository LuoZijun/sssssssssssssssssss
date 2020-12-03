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
    local_addr: SocketAddr,
    local_tcp_listener: TcpListener,

    remote_addr: SocketAddr,

    method: CipherKind,
    key: Vec<u8>,
}

impl SocksClient {
    pub async fn new(config: SocksClientConfig) -> io::Result<Self> {
        let local_addr = config.bind_addr;
        let local_tcp_listener = TcpListener::bind(local_addr).await?;
        info!("tcp listener listening at {:?}.", local_tcp_listener.local_addr()?);

        let remote_addr = config.server_addr;
        let method = config.method;
        let password = config.password;
        let key_len = method.key_len();

        let mut key = vec![0u8; key_len];
        openssl_bytes_to_key(&password, &mut key);

        Ok(Self { local_addr, local_tcp_listener, remote_addr, method, key, })
    }
    
    pub async fn run_forever(&self) -> io::Result<()> {
        loop {
            let (local_tcp_stream, peer_addr) = self.local_tcp_listener.accept().await?;
            info!("got socks connection {:?}", peer_addr);
            
            let remote_addr = self.remote_addr;
            tokio::spawn(async move {
                let _ = local_tcp_stream.set_nodelay(true);
                if let Err(e) = handle_socks_incoming(local_tcp_stream, remote_addr).await {
                    error!("socks connection error: {}", e);
                }
            });
        }
    }
}

// T: AsyncRead + AsyncWrite + Unpin
async fn handle_socks_incoming(mut local_tcp_stream: TcpStream, remote_addr: SocketAddr) -> io::Result<()> {
    let mut pkt = [0u8; 1];
    let _amt = local_tcp_stream.read_exact(&mut pkt).await?;
    let ver = pkt[0];

    match ver {
        SOCKS_V4 => handle_socks4_incoming(local_tcp_stream, remote_addr).await,
        SOCKS_V5 => handle_socks5_incoming(local_tcp_stream, remote_addr).await,
        _        => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks version")),
    }
}
