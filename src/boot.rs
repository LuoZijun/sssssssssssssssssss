use ss::client::SocksClientConfig;


pub fn boot_client() -> SocksClientConfig {
    // 设定日志等级
    if let Err(_) = std::env::var("RUST_LOG") {
        std::env::set_var("RUST_LOG", "debug");
    }
    env_logger::init();
    
    // 读取参数配置
    let bind_addr = "127.0.0.1:1080".parse::<std::net::SocketAddr>().unwrap();
    let server_addr = "127.0.0.1:65534".parse::<std::net::SocketAddr>().unwrap();

    let config = SocksClientConfig {
        method: ss::crypto::CipherKind::NONE,
        password: b"ilovecopy2$".to_vec(),
        bind_addr,
        server_addr,
    };

    config
}