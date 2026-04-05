use ureq::Agent;

mod apis;
mod utils;

pub type Result<T> = std::result::Result<T, ureq::Error>;

pub fn run(username: &str, password: &str, acid: Option<&str>) -> Result<()> {
    let agent = Agent::new_with_defaults();

    let user_info = apis::get_user_info(&agent)?;
    if user_info.error == "ok" {
        return Ok(());
    }

    let acid = match acid {
        Some(x) => x,
        None => &apis::get_acid(&agent)?,
    };
    apis::login(&agent, username, password, &user_info.online_ip, acid)
}
