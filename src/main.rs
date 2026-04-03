use std::net::IpAddr;

use base64::{Engine, alphabet::Alphabet, engine::GeneralPurpose};
use hmac::{Hmac, KeyInit, Mac};
use md5::Md5;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};

type HmacMd5 = Hmac<Md5>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let ac_id = get_acid().await?;
    let ip = get_ip().await?;

    let token = get_challenge("25031212101", &ip).await?;
    let _ = login("25031212101", "167236", &ac_id, &ip, &token).await;

    Ok(())
}

async fn get_acid() -> anyhow::Result<String> {
    let client = Client::builder().no_proxy().build()?;
    let text = client.get("http://bing.com").send().await?.text().await?;

    let re = Regex::new(r"/index_(\d+).html").unwrap();
    Ok(re.captures(&text).unwrap()[1].to_string())
}

#[derive(Deserialize)]
struct UserInfo {
    error: String,
    online_ip: IpAddr,
}

async fn get_ip() -> anyhow::Result<IpAddr> {
    let client = Client::builder().no_proxy().build()?;
    let text = client
        .get("https://w.xidian.edu.cn/cgi-bin/rad_user_info")
        .query(&[("callback", "jsonp")])
        .send()
        .await?
        .text()
        .await?;

    let info: UserInfo = serde_json::from_str(&text[6..text.len() - 1])?;
    Ok(info.online_ip)
}

#[derive(Deserialize)]
struct Challenge {
    challenge: String,
}

async fn get_challenge(username: &str, ip: &IpAddr) -> anyhow::Result<String> {
    let client = Client::builder().no_proxy().build()?;
    let text = client
        .get("https://w.xidian.edu.cn/cgi-bin/get_challenge")
        .query(&[
            ("callback", "jsonp"),
            ("username", username),
            ("ip", &ip.to_string()),
        ])
        .send()
        .await?
        .text()
        .await?;

    let info: Challenge = serde_json::from_str(&text[6..text.len() - 1])?;
    Ok(info.challenge)
}

async fn login(
    username: &str,
    password: &str,
    acid: &str,
    ip: &IpAddr,
    token: &str,
) -> anyhow::Result<()> {
    let info = json!( {
        "username": username,
        "password": password,
        "ip": ip,
        "acid": acid,
        "enc_ver": "srun_bx1",
    })
    .to_string();
    let info = format!("{{SRBX1}}{}", fkbase64(xencode(&info, token)));
    dbg!(&info);

    let mut mac = HmacMd5::new_from_slice(token.as_bytes())?;
    mac.update(password.as_bytes());
    let hmd5 = hex::encode(mac.finalize().as_bytes());

    dbg!(&hmd5);

    let sum = format!(
        "{0}{1}{0}{2}{0}{3}{0}{4}{0}{5}{0}{6}{0}{7}",
        token, username, hmd5, acid, ip, 200, 1, info
    );
    let mut hasher = Sha1::new();
    hasher.update(sum);
    let chksum = hex::encode(hasher.finalize());
    dbg!(&chksum);

    let client = Client::builder().no_proxy().build()?;
    let resp = client
        .get("https://w.xidian.edu.cn/cgi-bin/srun_portal")
        .query(&[
            ("callback", "jsonp"),
            ("action", "login"),
            ("username", username),
            ("password", &format!("{{MD5}}{}", hmd5)),
            ("chksum", &chksum),
            ("info", &info),
            ("ac_id", acid),
            ("ip", &ip.to_string()),
            ("n", &200.to_string()),
            ("type", &1.to_string()),
        ])
        .send()
        .await?;

    dbg!(resp.text().await?);
    Ok(())
}

fn fkbase64<T: AsRef<[u8]>>(payload: T) -> String {
    const ALPHABET: &str = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

    let alphabet = Alphabet::new(ALPHABET).unwrap();
    let engine = GeneralPurpose::new(&alphabet, Default::default());

    engine.encode(payload)
}

fn xencode(msg: &str, key: &str) -> Vec<u8> {
    if msg.is_empty() {
        return vec![];
    }
    let mut msg = mix(msg.as_bytes(), true);
    let key = mix(key.as_bytes(), false);

    let len = msg.len();
    let last = len - 1;
    let mut right = msg[last];
    let c: u32 = 0x9e3779b9; // 0x9e3779b9 = 0x86014019 | 0x183639A0
    let mut d: u32 = 0;

    let count = 6 + 52 / msg.len();
    for _ in 0..count {
        d = d.wrapping_add(c);
        let e = d >> 2 & 3;
        for p in 0..=last {
            let left = msg[(p + 1) % len];
            right = ((right >> 5) ^ (left << 2))
                .wrapping_add((left >> 3 ^ right << 4) ^ (d ^ left))
                .wrapping_add(key[(p & 3) ^ e as usize] ^ right)
                .wrapping_add(msg[p]);
            msg[p] = right;
        }
    }
    splite(msg, false)
}

fn mix(buffer: &[u8], append_size: bool) -> Vec<u32> {
    let mut res: Vec<u32> = buffer
        .chunks(4)
        .map(|chunk| {
            u32::from_le_bytes(chunk.try_into().unwrap_or_else(|_| {
                let mut last_chunk = [0u8, 0, 0, 0];
                last_chunk[..chunk.len()].clone_from_slice(chunk);
                last_chunk
            }))
        })
        .collect();
    if append_size {
        res.push(buffer.len() as u32);
    }
    res
}

fn splite(buffer: Vec<u32>, include_size: bool) -> Vec<u8> {
    let len = buffer.len();
    let size_record = buffer[len - 1];
    if include_size {
        let size = ((len - 1) * 4) as u32;
        if size_record < size - 3 || size_record > size {
            return "".into();
        }
    }

    let mut buffer: Vec<u8> = buffer.iter().flat_map(|i| i.to_le_bytes()).collect();
    if include_size {
        buffer.truncate(size_record as usize);
    }
    buffer
}
