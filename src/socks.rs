// SOCKS: A protocol for TCP proxy across firewalls
// https://www.openssh.com/txt/socks4.protocol
// 
// SOCKS 4A: A  Simple Extension to SOCKS 4 Protocol
// https://www.openssh.com/txt/socks4a.protocol
// 
// SOCKS Protocol Version 5
// https://tools.ietf.org/html/rfc1928


// SOCKS5 CONNECT command
// SOCKS5 UDP ASSOCIATE command (partial)
// SOCKS4/4a CONNECT command

pub const SOCKS_V4: u8 = 0x04; // SOCKS-4、SOCKS-4A
pub const SOCKS_V5: u8 = 0x05; // SOCKS-5

pub const SOCKS_CMD_CONNECT: u8       = 0x01; // SOCKS-4、SOCKS-4A、SOCKS-5
pub const SOCKS_CMD_BIND: u8          = 0x02; // SOCKS-4、SOCKS-4A、SOCKS-5
pub const SOCKS_CMD_UDP_ASSOCIATE: u8 = 0x03; // SOCKS-5


// SOCKS-4 and SOCKS-4a Result Code:
// 
// CD is the result code with one of the following values:
// 
//     90: request granted
//     91: request rejected or failed
//     92: request rejected becasue SOCKS server cannot connect to identd on the client
//     93: request rejected because the client program and identd report different user-ids
pub const SOCKS_REP_REQUEST_GRANTED: u8  = 0x5a; // 90: request granted
pub const SOCKS_REP_REQUEST_REJECTED: u8 = 0x5b; // 91: request rejected or failed
pub const SOCKS_REP_CANNOT_CONNECT: u8   = 0x5c; // 92: request rejected becasue SOCKS server cannot connect to identd on the client
pub const SOCKS_REP_DFFERENT_USER_ID: u8 = 0x5d; // 93: request rejected because the client program and identd report different user-ids
// SOCKS-5 Reply Code:
// 
// o  X'00' succeeded
// o  X'01' general SOCKS server failure
// o  X'02' connection not allowed by ruleset
// o  X'03' Network unreachable
// o  X'04' Host unreachable
// o  X'05' Connection refused
// o  X'06' TTL expired
// o  X'07' Command not supported
// o  X'08' Address type not supported
// o  X'09' to X'FF' unassigned
pub const SOCKS_REP_SUCCEEDED: u8                         = 0x00;
pub const SOCKS_REP_GENERAL_SERVER_FAILURE: u8            = 0x01;
pub const SOCKS_REP_CONNECTION_NOT_ALLOWED_BY_RULESET: u8 = 0x02;
pub const SOCKS_REP_NETWORK_UNREACHABLE: u8               = 0x03;
pub const SOCKS_REP_HOST_UNREACHABLE: u8                  = 0x04;
pub const SOCKS_REP_CONNECTION_REFUSED: u8                = 0x05;
pub const SOCKS_REP_TTL_EXPIRED: u8                       = 0x06;
pub const SOCKS_REP_COMMAND_NOT_SUPPORTED: u8             = 0x07;
pub const SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED: u8        = 0x08;

// ATYP   address type of following address
// 
//     o  IP V4 address: X'01'
//     o  DOMAINNAME: X'03'
//     o  IP V6 address: X'04'
pub const SOCKS_ATYP_IPV4: u8        = 0x01;
pub const SOCKS_ATYP_DOMAIN_NAME: u8 = 0x03;
pub const SOCKS_ATYP_IPV6: u8        = 0x04;

// The values currently defined for METHOD are:
// 
//       o  X'00' NO AUTHENTICATION REQUIRED
//       o  X'01' GSSAPI
//       o  X'02' USERNAME/PASSWORD
//       o  X'03' to X'7F' IANA ASSIGNED
//       o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
//       o  X'FF' NO ACCEPTABLE METHODS
pub const SOCKS_METHOD_NO_AUTH: u8       = 0x00;
pub const SOCKS_METHOD_GSSAPI: u8        = 0x01;
pub const SOCKS_METHOD_PASSWD_AUTH: u8   = 0x02;
pub const SOCKS_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

