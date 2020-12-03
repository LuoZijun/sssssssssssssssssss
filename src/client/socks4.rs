// SOCKS: A protocol for TCP proxy across firewalls
// https://www.openssh.com/txt/socks4.protocol
// 
// SOCKS 4A: A  Simple Extension to SOCKS 4 Protocol
// https://www.openssh.com/txt/socks4a.protocol
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::net::ToSocketAddrs;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};

use crate::crypto::{CipherKind, CipherCategory, Cipher, available_ciphers, openssl_bytes_to_key, random_iv_or_salt};
use crate::socks::*;

use std::io;
use std::net::SocketAddr;


// 1) CONNECT
// 
// +----+----+----+----+----+----+----+----+----+----+....+----+
// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
// +----+----+----+----+----+----+----+----+----+----+....+----+
//    1    1      2              4           variable       1
// 
// +----+----+----+----+----+----+----+----+
// | VN | CD | DSTPORT |      DSTIP        |
// +----+----+----+----+----+----+----+----+
//    1    1      2              4

// 2) BIND
// 
// +----+----+----+----+----+----+----+----+----+----+....+----+
// | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
// +----+----+----+----+----+----+----+----+----+----+....+----+
//    1    1      2              4           variable       1
// 
// +----+----+----+----+----+----+----+----+
// | VN | CD | DSTPORT |      DSTIP        |
// +----+----+----+----+----+----+----+----+
//    1    1      2              4

pub async fn handle_socks4_incoming(mut local_tcp_stream: TcpStream, remote_addr: SocketAddr) -> io::Result<()> {
    let mut buffer = [0u8; 1024];
    let amt = local_tcp_stream.read(&mut buffer).await?;
    if amt < 8 {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks4 packet"));
    }
    let pkt = &buffer[..7];
    let cmd = pkt[0];
    let dst_port = [pkt[1], pkt[2]];
    let dst_ip = [pkt[3], pkt[4], pkt[5], pkt[6]];

    let mut offset = 7;
    while buffer[offset] != 0x00 {
        offset += 1;
        if offset >= amt {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks4 packet"));
        }
    }

    let name_pos_start: usize;
    let name_pos_end: usize;

    let has_domain_name = dst_ip[0] == 0 && dst_ip[1] == 0 && dst_ip[2] == 0 && dst_ip[3] != 0;
    if has_domain_name {
        // NOTE: SOCKS-4A 允许在报文尾部跟随 一个需要在 远端解析的域名。
        offset += 1;
        name_pos_start = offset;
        while buffer[offset] != 0x00 {
            offset += 1;
            if offset >= amt {
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "malformed socks4 packet"));
            }
        }
        
        name_pos_end = offset;

        #[allow(unused_assignments)]
        { offset += 1; }
        

        let name = &buffer[name_pos_start..name_pos_end];

        for ch in name.iter() {
            match ch {
                b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' | b'.' => { },
                _ => {
                    // Maybe internationalized domain name
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid domain name (Non-ASCII)"));
                }
            }
        }
        if name.len() > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "invalid domain name (NLEN > U8::MAX)"));
        }
    } else {
        name_pos_start = 0;
        name_pos_end = 0;
    }

    if cmd != SOCKS_CMD_CONNECT {
        return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "unsupported socks4 CMD"));
    }

    // NOTE: 直接回复已就绪的 SOCKS-4 报文。
    // +----+----+----+----+----+----+----+----+
    // | VN | CD | DSTPORT |      DSTIP        |
    // +----+----+----+----+----+----+----+----+
    //    1    1      2              4
    buffer[0] = 0; // VN is the version of the reply code and should be 0
    buffer[1] = SOCKS_REP_REQUEST_GRANTED;
    buffer[2] = 0;
    buffer[3] = 0;
    buffer[4] = 0;
    buffer[5] = 0;
    buffer[6] = 0;
    buffer[7] = 0;
    local_tcp_stream.write_all(&buffer[..8]).await?;

    // NOTE: ss-remote 只支持 类似于 SOCKS-5 的报文格式，因此，我们在重新组装下报文发送给 ss-remote。
    let mut remote_tcp_stream = TcpStream::connect(remote_addr).await?;
    let _ = remote_tcp_stream.set_nodelay(true);

    buffer[0] = SOCKS_ATYP_IPV4;
    if has_domain_name {
        buffer[0] = SOCKS_ATYP_DOMAIN_NAME;

        let name_len = name_pos_end - name_pos_start;

        // NOTE: 长度安全检查上面已经做过了，所以这里可以安全的转换类型。
        buffer[1] = name_len as u8;

        for i in 0..name_len {
            buffer[2 + i] = buffer[name_pos_start + i];
        }

        buffer[2 + name_len + 0] = dst_port[0];
        buffer[2 + name_len + 1] = dst_port[1];

        let total_len = 2 + name_len + 1 + 1;
        remote_tcp_stream.write_all(&buffer[..total_len]).await?;
    } else {
        buffer[1] = dst_ip[0];
        buffer[2] = dst_ip[1];
        buffer[3] = dst_ip[2];
        buffer[4] = dst_ip[3];

        buffer[5] = dst_port[0];
        buffer[6] = dst_port[1];
        remote_tcp_stream.write_all(&buffer[..7]).await?;
    }

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

