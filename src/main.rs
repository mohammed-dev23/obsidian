mod backend;
mod dec_enc;
use colored::Colorize;
use std::{env::{args}, fs};
mod test;
use crate::{backend::safe::ArgsChecker, dec_enc::add};
use dec_enc::{home_dirr, pre_add , _pre_};

fn main() -> anyhow::Result<()> {
    let mut args = args();

    if args.len() <= 1 {
        println!(
            ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
            "Usge".bright_green().bold(),
            "obsidan".bright_blue().bold(),
            "get/add".bright_yellow().bold(),
            "username/email".bright_yellow().bold(),
            "passwored".bright_yellow().bold(),
            "url/app".bright_yellow().bold(),
            "master-key".bright_yellow().bold()
        )
    }

    match args.nth(1).checker("get/add".to_string())?.trim() {
        "add" => {
            let usernameoremail = args.next().checker("username/email".to_string())?;
            let passwored = args.next().checker("password".to_string())?;
            let url = args.next().checker("url/app".to_string())?;
            let master_key = args.next().checker("master-key".to_string())?;

            if fs::File::open(home_dirr()?.join("obsidian/obs.yaml").to_string_lossy().to_string()).is_err_and(|s| s.kind() == std::io::ErrorKind::NotFound) {
                _pre_()?;
                pre_add(usernameoremail, url, passwored, master_key)?;
            }
            else {
                add(usernameoremail, url, passwored, master_key)?;
            }
        }
        "get" => {
            let _url = args.next().checker("url/app".to_string())?;
            let _master_key = args.next().checker("master-key".to_string())?;
        }
        _ => {
            println!(
                ">>{}: [{}] [{}] [{}] [{}] [{}] [{}]",
                "Usge".bright_green().bold(),
                "obsidan".bright_blue().bold(),
                "get/add".bright_yellow().bold(),
                "username/email".bright_yellow().bold(),
                "passwored".bright_yellow().bold(),
                "url/app".bright_yellow().bold(),
                "master-key".bright_yellow().bold()
            )
        }
    }
    Ok(())
}
