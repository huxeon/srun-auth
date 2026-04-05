use std::net::IpAddr;

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::Sha1;
use ureq::Agent;

use crate::utils::{fkbase64, xencode};

type HmacMd5 = Hmac<Md5>;

const SRUN_N: &str = "200";
const SRUN_TYPE: &str = "1";

#[derive(Deserialize)]
struct UserInfo {
    error: String,
    online_ip: IpAddr,
}

pub struct Client {
    agent: Agent,
    state: UserInfo,
}

impl Client {
    pub fn new() -> Result<Self, ureq::Error> {
        let agent = Agent::new_with_defaults();
        let state = get_user_info(agent.clone())?;

        Ok(Client { agent, state })
    }

    pub fn is_loggined(&self) -> bool {
        self.state.error == "ok"
    }

    pub fn login(&self, username: &str, password: &str) -> Result<(), ureq::Error> {
        if self.is_loggined() {
            return Ok(());
        }

        let token = self.get_token(username)?;
        let acid = get_acid(self.agent.clone())?;

        let info = json!( {
            "username": username,
            "password": password,
            "ip": self.state.online_ip,
            "acid": acid,
            "enc_ver": "srun_bx1",
        })
        .to_string();
        let info = format!("{{SRBX1}}{}", fkbase64(xencode(&info, &token)));

        let mut mac = HmacMd5::new_from_slice(token.as_bytes()).unwrap();
        mac.update(password.as_bytes());
        let hmd5 = hex::encode(mac.finalize().as_bytes());

        let sum = format!(
            "{0}{1}{0}{2}{0}{3}{0}{4}{0}{5}{0}{6}{0}{7}",
            token, username, hmd5, acid, self.state.online_ip, SRUN_N, SRUN_TYPE, info
        );
        let mut hasher = Sha1::new();
        hasher.update(sum);
        let chksum = hex::encode(hasher.finalize());

        self.agent
            .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
            .query_pairs([
                ("callback", "jsonp"),
                ("action", "login"),
                ("username", username),
                ("password", &format!("{{MD5}}{}", hmd5)),
                ("chksum", &chksum),
                ("info", &info),
                ("ac_id", &acid),
                ("ip", &self.state.online_ip.to_string()),
                ("n", SRUN_N),
                ("type", SRUN_TYPE),
            ])
            .call()?;

        Ok(())
    }

    pub fn logout(&self, username: &str) -> Result<(), ureq::Error> {
        let acid = get_acid(self.agent.clone())?;

        self.agent
            .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
            .query_pairs([
                ("callback", "jsonp"),
                ("action", "logout"),
                ("username", username),
                ("ac_id", &acid),
                ("ip", &self.state.online_ip.to_string()),
            ])
            .call()?;

        Ok(())
    }

    fn get_token(&self, username: &str) -> Result<String, ureq::Error> {
        let text = self
            .agent
            .get("https://w.xidian.edu.cn/cgi-bin/get_challenge")
            .query_pairs([
                ("callback", "jsonp"),
                ("username", username),
                ("ip", &self.state.online_ip.to_string()),
            ])
            .call()?
            .into_body()
            .read_to_string()?;

        let value: Value = serde_json::from_str(&text[6..text.len() - 1]).unwrap();
        Ok(value["challenge"].as_str().unwrap().to_string())
    }
}

fn get_acid(agent: Agent) -> Result<String, ureq::Error> {
    let text = agent
        .get("http://bing.com")
        .call()?
        .body_mut()
        .read_to_string()?;

    let re = Regex::new(r"/index_(\d+).html").unwrap();
    Ok(re.captures(&text).unwrap()[1].to_string())
}

fn get_user_info(agent: Agent) -> Result<UserInfo, ureq::Error> {
    let text = agent
        .get("https://w.xidian.edu.cn/cgi-bin/rad_user_info")
        .query("callback", "jsonp")
        .call()?
        .body_mut()
        .read_to_string()?;

    Ok(serde_json::from_str(&text[6..text.len() - 1]).unwrap())
}
