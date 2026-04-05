use std::env;

use srun_auth::client::Client;

fn main() -> Result<(), ureq::Error> {
    let op = env::args().nth(1);
    let client = Client::new()?;

    match op.as_deref() {
        Some("login") => {
            let username = env::args().nth(2).expect("Couldn't get username");
            let password = env::args().nth(3).expect("Couldn't get password");

            if !client.is_loggined() {
                client.login(&username, &password)?;
            }
        }
        Some("logout") => {
            let username = env::args().nth(2).expect("Couldn't get username");

            if client.is_loggined() {
                client.logout(&username)?;
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
