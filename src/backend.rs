pub mod safe {
    use anyhow::anyhow;
    use colored::Colorize;

    use crate::dec_enc::read_yaml;

    pub trait Checkers {
        type Out;

        fn checker(self, res: String) -> Self::Out;
    }

    pub trait MasterKeyV {
        type Out;

        fn master_key_checker(self) -> Self::Out;
    }

    pub trait FileChecker {
        type Out;

        fn check_existing_url_apps(self, url_app: &str) -> Self::Out;
    }

    pub trait AnyHowErrHelper {
        fn pe(self) -> Self;
    }

    impl<T> Checkers for anyhow::Result<T> {
        type Out = anyhow::Result<T>;
        fn checker(self, res: String) -> Self::Out {
            match self {
                Ok(o) => return Ok(o),
                Err(_) => {
                    return Err(anyhow!("missing value [{}]", res));
                }
            }
        }
    }

    impl MasterKeyV for String {
        type Out = anyhow::Result<String>;

        fn master_key_checker(self) -> Self::Out {
            if self.len() >= 12 {
                return Ok(self);
            } else {
                return Err(anyhow!("The master key must be 12 checkters at least "));
            }
        }
    }

    impl FileChecker for String {
        type Out = anyhow::Result<String>;

        fn check_existing_url_apps(self, url_app: &str) -> Self::Out {
            let read_yaml = read_yaml()?;

            if let Some(o) = read_yaml.iter().find(|s| s.url_app == url_app) {
                return Err(anyhow!(
                    "the url/app does already exist try another one or add special symbols beside it ! <{}>",
                    o.url_app.to_string().bright_yellow().bold()
                ));
            } else {
                return Ok(self);
            }
        }
    }

    impl<T> AnyHowErrHelper for anyhow::Result<T> {
        fn pe(self) -> Self {
            if let Err(e) = &self {
                eprintln!(
                    ">>{}: due to [{}]",
                    "Error".bright_red(),
                    e.to_string().bright_red().bold()
                );
            }
            self
        }
    }
}

pub mod parser {
    use anyhow::{Ok, anyhow};

    pub fn parse_input() -> anyhow::Result<Vec<String>> {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let data: Vec<String> = input.split_whitespace().map(|s| s.to_string()).collect();
        return Ok(data);
    }

    pub trait Token {
        fn get_token(&self, index: usize) -> anyhow::Result<String>;
    }

    impl Token for Vec<String> {
        fn get_token(&self, index: usize) -> anyhow::Result<String> {
            if self.is_empty() && index == 0 {
                return Ok(String::new());
            }

            if let Some(d) = self.get(index) {
                return Ok(d.to_string());
            } else {
                return Err(anyhow!("Couldn't get data from the parser!"));
            }
        }
    }
}
