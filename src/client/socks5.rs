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
pub async fn handle_socks5_incoming(mut local_tcp_stream: TcpStream, remote_addr: SocketAddr) -> io::Result<()> {
    let mut buffer = [0u8; 1500];

    // https://tools.ietf.org/html/rfc1928#section-3
    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+
    let amt = local_tcp_stream.read(&mut buffer).await?;
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
    local_tcp_stream.write_all(&buffer[..2]).await?;


    // https://tools.ietf.org/html/rfc1928#section-4
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let amt = local_tcp_stream.read(&mut buffer).await?;
    if amt < 4 {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
    }

    let cmd   = buffer[1];
    let atype = buffer[3];

    match atype {
        SOCKS_ATYP_IPV4 => {
            if amt < 4 + 4 + 2 {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
            }
        },
        SOCKS_ATYP_DOMAIN_NAME => {
            let nlen = buffer[4] as usize; // DOMAIN-NAME LEN in octets
            if amt < 4 + 1 + nlen + 2 {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
            }
        },
        SOCKS_ATYP_IPV6 => {
            if amt < 4 + 16 + 2 {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks5 packet"));
            }
        },
        _ => return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks5 address type")),
    }

    match cmd {
        SOCKS_CMD_CONNECT       => handle_socks5_tcp_connect(local_tcp_stream, remote_addr, amt, &mut buffer).await,
        SOCKS_CMD_UDP_ASSOCIATE => handle_socks5_udp_associate(local_tcp_stream, remote_addr, amt, &mut buffer).await,
        _ => Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks5 CMD")),
    }
}


async fn handle_socks5_tcp_connect(mut local_tcp_stream: TcpStream, remote_addr: SocketAddr, req_pkt_len: usize, buffer: &mut [u8]) -> io::Result<()> {
    // ss-remote
    let mut remote_tcp_stream = TcpStream::connect(remote_addr).await?;
    let _ = remote_tcp_stream.set_nodelay(true);

    // NOTE: 先向 ss-remote 发送 PKT HDR，后续再发送 Payload，其实一起一次性发送更好。
    let pkt = &buffer[3..req_pkt_len];
    remote_tcp_stream.write_all(&pkt).await?;

    // NOTE: 直接回复已就绪的 SOCKS-5 报文。
    // https://tools.ietf.org/html/rfc1928#section-6
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    buffer[0] = SOCKS_V5;
    buffer[1] = SOCKS_REP_SUCCEEDED;
    buffer[2] = 0x00;
    buffer[3] = SOCKS_ATYP_IPV4;
    buffer[4] = 0;
    buffer[5] = 0;
    buffer[6] = 0;
    buffer[7] = 0;
    buffer[8] = 0;
    buffer[9] = 0;
    let pkt = &buffer[..10];
    local_tcp_stream.write_all(pkt).await?;


    // 中继就绪，拷贝数据。
    let (mut r1, mut w1) = local_tcp_stream.split();
    let (mut r2, mut w2) = remote_tcp_stream.split();
    
    // tokio::join!(
    //     tokio::io::copy(&mut r1, &mut w2),
    //     tokio::io::copy(&mut r2, &mut w1),
    // );

    tokio::select! {
        ret = tokio::io::copy(&mut r1, &mut w2) => {
            let _ = ret?;
        },
        ret = tokio::io::copy(&mut r2, &mut w1) => {
            let _ = ret?;
        },
    };

    Ok(())
}

async fn handle_socks5_udp_associate(mut local_tcp_stream: TcpStream, remote_addr: SocketAddr, req_pkt_len: usize, buffer: &mut [u8]) -> io::Result<()> {
    // https://tools.ietf.org/html/rfc1928#section-4
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let client_addr = {
        let atype = buffer[3];

        match atype {
            SOCKS_ATYP_IPV4 => {
                let a = buffer[4];
                let b = buffer[5];
                let c = buffer[6];
                let d = buffer[7];

                let e = buffer[8];
                let f = buffer[9];

                let port = u16::from_be_bytes([e, f]);
                
                SocketAddr::new(std::net::Ipv4Addr::new(a, b, c, d).into(), port)
            },
            SOCKS_ATYP_DOMAIN_NAME => {
                let nlen = buffer[4] as usize;
                let name = &buffer[5..nlen];

                let e = buffer[nlen + 0];
                let f = buffer[nlen + 1];

                let port = u16::from_be_bytes([e, f]);

                for ch in name.iter() {
                    match ch {
                        b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' | b'.' => { },
                        _ => {
                            // Maybe internationalized domain name
                            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid domain name (Non-ASCII)"));
                        }
                    }
                }

                let name = unsafe { std::str::from_utf8_unchecked(name) };

                let mut iter = tokio::net::lookup_host((name, port)).await?;

                match iter.next() {
                    Some(addr) => addr,
                    None => return Err(io::Error::new(io::ErrorKind::NotFound, "lookup host failed (NO-ADDR)")),
                }
            },
            SOCKS_ATYP_IPV6 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buffer[4..20]);

                let e = buffer[20];
                let f = buffer[21];

                let port = u16::from_be_bytes([e, f]);
                
                SocketAddr::new(std::net::Ipv6Addr::from(octets).into(), port)
            },
            _ => unreachable!(),
        }
    };
    
    // 步骤一：在本地建立 UDP Socket。
    let mut local_addr = local_tcp_stream.local_addr()?;
    local_addr.set_port(0);
    let local_udp_socket = UdpSocket::bind(local_addr).await?;
    let local_addr = local_udp_socket.local_addr()?;
    // NOTE: Client Request 中的 ADDR 不能使用全零来替代。
    local_udp_socket.connect(client_addr).await?;

    // 步骤二：向 Client 回复 ACK 报文。
    // 
    // https://tools.ietf.org/html/rfc1928#section-6
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    buffer[0] = SOCKS_V5;
    buffer[1] = SOCKS_REP_SUCCEEDED;
    buffer[2] = 0x00;      // RSV
    match local_addr {
        SocketAddr::V4(v4_addr) => {
            let ip_octets   = v4_addr.ip().octets();
            let port_octets = v4_addr.port().to_be_bytes();

            buffer[3] = SOCKS_ATYP_IPV4; // ATYP
            buffer[4..8].copy_from_slice(&ip_octets); // BND.ADDR

            buffer[8] = port_octets[0];               // BND.PORT
            buffer[9] = port_octets[1];
            let pkt = &buffer[..10];
            local_tcp_stream.write_all(pkt).await?;
        },
        SocketAddr::V6(v6_addr) => {
            let ip_octets   = v6_addr.ip().octets();
            let port_octets = v6_addr.port().to_be_bytes();

            buffer[3] = SOCKS_ATYP_IPV6;
            buffer[4..20].copy_from_slice(&ip_octets); // BND.ADDR

            buffer[20] = port_octets[0];               // BND.PORT
            buffer[21] = port_octets[1];
            let pkt = &buffer[..22];
            local_tcp_stream.write_all(pkt).await?;
        },
    }

    // 步骤三：将 local_udp_socket 收到的报文发送给 remote_udp_socket，反之亦然。
    let remote_udp_socket = {
        let mut local_addr = local_tcp_stream.local_addr()?;
        local_addr.set_port(0);

        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(remote_addr).await?;

        socket
    };

    // NOTE: 通过 Unsafe 可以共用一个 buffer。
    //       但是当前，我不清楚 `select!` 宏的实现是 是在一个线程内的实现，
    //       如果是的话，则可以安全的共用。
    let mut remote_buffer = [0u8; 1500];

    tokio::select! {
        ret1 = local_udp_socket.recv(buffer) => {
            // https://tools.ietf.org/html/rfc1928#section-7
            // +----+------+------+----------+----------+----------+
            // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +----+------+------+----------+----------+----------+
            // | 2  |  1   |  1   | Variable |    2     | Variable |
            // +----+------+------+----------+----------+----------+
            let amt = ret1?;
            // The FRAG field indicates whether or not this datagram is one of a number of fragments.
            // * Value of X'00' indicates that this datagram is standalone.
            // * Values between 1 and 127 indicate the fragment position within a fragment sequence.
            let fragment_seq = buffer[2];
            if fragment_seq != 0x00 {
                // NOTE: 这里，我们并不处理组装 FRAG_SEQ，因为没有必要, UDP 报文必须一次发完，否则需要重新组装的话，
                //       那么 UDP 的优势就会丧失。Client 应该把握好 PKT 大小，以便在 加了 SOCKS-5 UDP HDR 的情况下，
                //       仍然可以将整个 UDP 报文通过一个 MTU 发送出去。
                return Err(io::Error::new(io::ErrorKind::NotFound, "udp fragment sequence not implemented"));
            }
            let pkt = &buffer[3..amt];
            let len = remote_udp_socket.send(&pkt).await?;
            assert_eq!(len, pkt.len());
        },
        ret2 = remote_udp_socket.recv(&mut remote_buffer[3..]) => {
            let amt = 3 + ret2?;

            remote_buffer[0] = 0x00;
            remote_buffer[1] = 0x00;
            remote_buffer[2] = 0x00; // FRAG

            let pkt = &remote_buffer[..amt];
            let len = local_udp_socket.send(&pkt).await?;
            assert_eq!(len, pkt.len());
        },
    };

    Ok(())
}


