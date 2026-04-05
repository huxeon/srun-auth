use std::net::IpAddr;

use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use ureq::Agent;

use crate::{Result, utils};

type HmacMd5 = Hmac<Md5>;

const SRUN_N: &str = "200";
const SRUN_TYPE: &str = "1";

#[derive(Deserialize)]
pub struct UserInfo {
    pub error: String,
    pub online_ip: IpAddr,
}

pub fn get_user_info(agent: &Agent) -> Result<UserInfo> {
    let text = agent
        .get("https://w.xidian.edu.cn/cgi-bin/rad_user_info")
        .query("callback", "jsonp")
        .call()?
        .body_mut()
        .read_to_string()?;

    Ok(serde_json::from_str(&text[6..text.len() - 1]).unwrap())
}

pub fn login(agent: &Agent, username: &str, password: &str, ip: &IpAddr, acid: &str) -> Result<()> {
    let token = get_token(agent, username, ip)?;
    let info = json!( {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": acid,
        "enc_ver": "srun_bx1",
    })
    .to_string();
    let info = format!(
        "{{SRBX1}}{}",
        utils::fkbase64(utils::xencode(&info, &token))
    );

    let mut mac = HmacMd5::new_from_slice(token.as_bytes()).unwrap();
    mac.update(password.as_bytes());
    let hmd5 = hex::encode(mac.finalize().as_bytes());

    let sum = format!(
        "{0}{1}{0}{2}{0}{3}{0}{4}{0}{5}{0}{6}{0}{7}",
        token, username, hmd5, acid, ip, SRUN_N, SRUN_TYPE, info
    );
    let mut hasher = Sha1::new();
    hasher.update(sum);
    let chksum = hex::encode(hasher.finalize());

    agent
        .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
        .query_pairs([
            ("callback", "jsonp"),
            ("action", "login"),
            ("username", username),
            ("password", &format!("{{MD5}}{}", hmd5)),
            ("chksum", &chksum),
            ("info", &info),
            ("ac_id", acid),
            ("ip", &ip.to_string()),
            ("n", SRUN_N),
            ("type", SRUN_TYPE),
        ])
        .call()?;

    Ok(())
}

pub fn get_acid(agent: &Agent) -> Result<String> {
    let text = agent
        .get("http://bing.com")
        .call()?
        .body_mut()
        .read_to_string()?;

    let re = Regex::new(r"/index_(\d+).html").unwrap();
    Ok(re.captures(&text).unwrap()[1].to_string())
}

fn get_token(agent: &Agent, username: &str, ip: &IpAddr) -> Result<String> {
    let text = agent
        .get("https://w.xidian.edu.cn/cgi-bin/get_challenge")
        .query_pairs([
            ("callback", "jsonp"),
            ("username", username),
            ("ip", &ip.to_string()),
        ])
        .call()?
        .into_body()
        .read_to_string()?;

    let value: Value = serde_json::from_str(&text[6..text.len() - 1]).unwrap();
    Ok(value["challenge"].as_str().unwrap().to_string())
}
