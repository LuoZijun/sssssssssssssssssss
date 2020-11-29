// SOCKS Protocol Version 5
// https://tools.ietf.org/html/rfc1928
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::crypto::{CipherKind, CipherCategory, Cipher, available_ciphers, openssl_bytes_to_key, random_iv_or_salt};

use crate::socks::*;

use std::io;
use std::net::SocketAddr;


// https://tools.ietf.org/html/rfc1928#section-3
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

// https://tools.ietf.org/html/rfc1928#section-4
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// https://tools.ietf.org/html/rfc1928#section-6
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// https://tools.ietf.org/html/rfc1928#section-7
// +----+------+------+----------+----------+----------+
// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
// +----+------+------+----------+----------+----------+
// | 2  |  1   |  1   | Variable |    2     | Variable |
// +----+------+------+----------+----------+----------+
pub async fn handle_socks5_incoming(mut stream: TcpStream, socks_server_addr: SocketAddr) -> io::Result<()> {
    let mut buffer = vec![0u8; 1 << 16]; // 32K

    // https://tools.ietf.org/html/rfc1928#section-3
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let amt = stream.read(&mut buffer).await?;
    if amt < 2 || amt > u8::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
    }
    let n_methods = buffer[0];
    if n_methods as usize > amt - 1 {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
    }
    let methods = &buffer[1..n_methods as usize];
    let no_auth = methods.iter().any(|&m| m == SOCKS_METHOD_NO_AUTH);
    if !no_auth {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "socks5 auth method no match"));
    }
    
    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+
    buffer[0] = SOCKS_V5;
    buffer[1] = SOCKS_METHOD_NO_AUTH;
    stream.write_all(&buffer[..2]).await?;


    // https://tools.ietf.org/html/rfc1928#section-4
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let amt = stream.read(&mut buffer).await?;
    if amt < 4 {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
    }

    let cmd   = buffer[1];
    let atype = buffer[3];

    if cmd != SOCKS_CMD_CONNECT {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks5 CMD"));
    }
    if atype != SOCKS_ATYP_IPV4 && atype != SOCKS_ATYP_DOMAIN_NAME && atype != SOCKS_ATYP_IPV6 {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks5 address type"));
    }

    // ss-remote
    let mut remote = TcpStream::connect(socks_server_addr).await?;
    let _ = remote.set_nodelay(true);

    let pkt = &buffer[3..amt];
    remote.write_all(&pkt).await?;

    // NOTE: 直接回复已就绪的 SOCKS-5 报文。
    buffer[0] = SOCKS_V5;
    buffer[1] = SOCKS_REP_SUCCEEDED;
    buffer[2] = 0x00;
    buffer[3] = 1;
    buffer[4] = 0;
    buffer[5] = 0;
    buffer[6] = 0;
    buffer[7] = 0;
    buffer[8] = 0;
    buffer[9] = 0;
    let pkt = &buffer[..10];
    stream.write_all(pkt).await?;


    // 中继就绪，拷贝数据。
    let (mut r1, mut w1) = stream.split();
    let (mut r2, mut w2) = remote.split();
    
    // tokio::join!(
    //     tokio::io::copy(&mut r1, &mut w2),
    //     tokio::io::copy(&mut r2, &mut w1),
    // );

    tokio::select! {
        _ = tokio::io::copy(&mut r1, &mut w2) => {

        },
        _ = tokio::io::copy(&mut r2, &mut w1) => {

        },
    };

    Ok(())
}