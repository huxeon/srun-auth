use std::env;

use srun_auth::client::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let op = env::args().nth(1);
    let client = Client::new().await?;

    match op.as_deref() {
        Some("login") => {
            let username = env::args().nth(2).expect("Couldn't get username");
            let password = env::args().nth(3).expect("Couldn't get password");

            if !client.is_loggined() {
                client.login(&username, &password).await?;
            }
        }
        Some("logout") => {
            let username = env::args().nth(2).expect("Couldn't get username");

            if client.is_loggined() {
                client.logout(&username).await?;
            }
        }
        _ => println!(
            "{}",
            if client.is_loggined() {
                "online"
            } else {
                "offline"
            }
        ),
    }

    Ok(())
}
