use std::net::IpAddr;

use hmac::{Hmac, KeyInit, Mac};
use md5::{Digest, Md5};
use regex::Regex;
use reqwest::Client as HttpClient;
use serde::Deserialize;
use serde_json::json;
use sha1::Sha1;

use crate::utils::{fkbase64, xencode};

type HmacMd5 = Hmac<Md5>;

const SRUN_N: &str = "200";
const SRUN_TYPE: &str = "1";

#[derive(Deserialize)]
struct UserInfo {
    error: String,
    online_ip: IpAddr,
}

#[derive(Deserialize)]
struct Challenge {
    challenge: String,
}

pub struct Client {
    http_client: HttpClient,
    state: UserInfo,
}

impl Client {
    pub async fn new() -> anyhow::Result<Self> {
        let client = HttpClient::builder().no_proxy().build()?;
        let state = get_user_info(&client).await?;

        Ok(Client {
            http_client: client,
            state,
        })
    }

    pub fn is_loggined(&self) -> bool {
        self.state.error == "ok"
    }

    pub async fn login(&self, username: &str, password: &str) -> anyhow::Result<()> {
        if self.is_loggined() {
            return Ok(());
        }

        let token = self.get_token(username).await?;
        let acid = get_acid(&self.http_client).await?;

        let info = json!( {
            "username": username,
            "password": password,
            "ip": self.state.online_ip,
            "acid": acid,
            "enc_ver": "srun_bx1",
        })
        .to_string();
        let info = format!("{{SRBX1}}{}", fkbase64(xencode(&info, &token)));

        let mut mac = HmacMd5::new_from_slice(token.as_bytes())?;
        mac.update(password.as_bytes());
        let hmd5 = hex::encode(mac.finalize().as_bytes());

        let sum = format!(
            "{0}{1}{0}{2}{0}{3}{0}{4}{0}{5}{0}{6}{0}{7}",
            token, username, hmd5, acid, self.state.online_ip, SRUN_N, SRUN_TYPE, info
        );
        let mut hasher = Sha1::new();
        hasher.update(sum);
        let chksum = hex::encode(hasher.finalize());

        self.http_client
            .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
            .query(&[
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
            .send()
            .await?;

        Ok(())
    }

    pub async fn logout(&self, username: &str) -> anyhow::Result<()> {
        let acid = get_acid(&self.http_client).await?;

        self.http_client
            .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
            .query(&[
                ("callback", "jsonp"),
                ("action", "logout"),
                ("username", username),
                ("ac_id", &acid),
                ("ip", &self.state.online_ip.to_string()),
            ])
            .send()
            .await?;

        Ok(())
    }

    async fn get_token(&self, username: &str) -> anyhow::Result<String> {
        let text = self
            .http_client
            .get("https://w.xidian.edu.cn/cgi-bin/get_challenge")
            .query(&[
                ("callback", "jsonp"),
                ("username", username),
                ("ip", &self.state.online_ip.to_string()),
            ])
            .send()
            .await?
            .text()
            .await?;

        let info: Challenge = serde_json::from_str(&text[6..text.len() - 1])?;
        Ok(info.challenge)
    }
}

async fn get_acid(client: &HttpClient) -> anyhow::Result<String> {
    let text = client.get("http://bing.com").send().await?.text().await?;

    let re = Regex::new(r"/index_(\d+).html").unwrap();
    Ok(re.captures(&text).unwrap()[1].to_string())
}

async fn get_user_info(client: &HttpClient) -> anyhow::Result<UserInfo> {
    let text = client
        .get("https://w.xidian.edu.cn/cgi-bin/rad_user_info")
        .query(&[("callback", "jsonp")])
        .send()
        .await?
        .text()
        .await?;

    Ok(serde_json::from_str(&text[6..text.len() - 1])?)
}
