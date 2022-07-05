use std::fs;
use std::path::Path;

use serde_derive::Deserialize;

pub(crate) static CONFIG: &str = "mallog.toml";

#[derive(Deserialize)]
pub(crate) struct ConfigTargets {
    pub alloc: String,
    // pub realloc: String,
    pub free: String,
}

#[derive(Deserialize)]
pub(crate) struct Config {
    pub targets: ConfigTargets,
}

pub(crate) fn read_config<P: AsRef<Path>>(path: P) -> Result<Config, String> {
    let name = path.as_ref().to_str().unwrap().to_owned();
    let file = fs::read_to_string(path).map_err(|e| format!("Error loading {}: file read error: {}", &name, e))?;
    let cfg = toml::from_str(&file).map_err(|e| format!("Error loading {}: toml error: {}", &name, e))?;
    logln!("Read config: {}", &name);
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load() {
        let res = toml::from_str::<Config>(r#"
            [targets]
            alloc = "malloc" #, "calloc", "memalign"]
            #realloc = "realloc"
            free = "free"
        "#);
        if let Err(ref err) = res {
            eprintln!("[config::load] test error: {}", *err);
        }
        assert!(res.is_ok());
    }
}
