use std::{
    env::home_dir,
    fs,
    io::{Read},
    path::PathBuf,
};

use anyhow::{Ok, anyhow};
use base64::prelude::*;

use aes_gcm::{
    AeadCore, Aes256Gcm, Key, KeyInit,
    aead::{
        Aead, OsRng, rand_core::{RngCore}
    },
};
use argon2::{
    Argon2,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Felids {
    url_app: String,
    data:String,
}

pub fn home_dirr() -> anyhow::Result<PathBuf> {
    let home_dir = if let Some(h) = home_dir() {
        h
    } else {
        return Err(anyhow!("couldn't find home dir"));
    };

    Ok(home_dir)
}

pub fn _pre_() -> anyhow::Result<()> {
    let home_dir = home_dirr()?;
    fs::create_dir_all(home_dir.join("obsidian").to_string_lossy().to_string())?;
    Ok(())
}

pub fn pre_add (
    username_email: String,
    url_app: String,
    password: String,
    master_key: String
) -> anyhow::Result<()> {
    let data = enc(master_key, username_email, password)?; 

    let data = BASE64_STANDARD.encode(data);

    let cont = Felids {
        url_app: url_app,
        data:data,
    };

    let yaml = serde_yaml::to_string(&cont)?;

    fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;
    Ok(())
}

pub fn add (username_email: String , url_app: String , password: String , master_key: String) -> anyhow::Result<()> {
    let file = read_yaml()?;
    let data = BASE64_STANDARD.encode(enc(master_key, username_email, password)?);
    let cont = Felids {url_app:url_app , data:data};

    let vec = vec![file , cont];

    let yaml = serde_yaml::to_string(&vec)?;
    fs::write(home_dirr()?.join("obsidian/obs.yaml"), yaml)?;
    Ok(())
}

fn read_yaml() -> anyhow::Result<Felids> {
    let mut s = String::new();
    let mut o = fs::File::open(
        home_dirr()?
            .join("obsidian/obs.yaml")
            .to_string_lossy()
            .to_string(),
    )?;
    o.read_to_string(&mut s)?;

    let des_f: Felids = serde_yaml::from_str(&mut s)?;
    Ok(des_f)
}

fn enc(
    master_key: String,
    username_email: String,
    password: String,
) -> anyhow::Result<Vec<u8>> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let argon2 = Argon2::default();
    let mut out_master = [0u8; 32];

    argon2
        .hash_password_into(master_key.as_bytes(), &salt, &mut out_master)
        .map_err(|_| anyhow!("Couldn't hash master key"))?;

    let key = Key::<Aes256Gcm>::from_slice(&out_master);
    let cip = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let format = format!("{}|{}" , username_email , password);

    let enc = cip
        .encrypt(&nonce, format.as_bytes()).map_err(|_| anyhow!("Couldn't enc data"))?;
    
    let mut finsh = Vec::new();
    finsh.extend_from_slice(&salt);
    finsh.extend_from_slice(&nonce);
    finsh.extend_from_slice(&enc);

    Ok(finsh)
}
