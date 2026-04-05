use std::env;

fn main() {
    let (Some(username), Some(password)) = (env::args().nth(1), env::args().nth(2)) else {
        eprintln!("USAGE: srun-auth <USERNAME> <PASSWORD> [ACID]");
        return;
    };

    if let Err(err) = srun_auth::run(&username, &password, env::args().nth(3).as_deref()) {
        eprintln!("HTTP error: {}", err);
    }
}
