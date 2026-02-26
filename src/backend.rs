pub mod safe {
    use anyhow::{anyhow};
    
    pub trait ArgsChecker {
        type Out;

        fn checker(self, res: String) -> Self::Out;
    } 

    impl ArgsChecker for Option<String> {
        type Out = anyhow::Result<String>;
        fn checker(self, res: String) -> Self::Out {
            if let Some(o) = self {
                return Ok(o);
            } else {
                return Err(anyhow!("missing value [{}]" , res));
            }
        }
    }
}
