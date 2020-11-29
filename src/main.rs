#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate tokio;
extern crate ss;


mod boot;

use ss::client::SocksClient;
use ss::client::SocksClientConfig;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rt = tokio::runtime::Runtime::new()?;

    let config = boot::boot_client();
    let client = rt.block_on(SocksClient::new(config))?;

    rt.block_on(client.run_forever())?;

    Ok(())
}

