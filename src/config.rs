use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde_derive::Deserialize;

pub(crate) static CONFIG: &str = "allog.toml";

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ConfigAllocator {
    Malloc,
    Talloc,
}

#[derive(Deserialize)]
pub(crate) struct Config {
    pub allocator: ConfigAllocator,
    pub targets: HashMap<String, String>,
}

impl Config {
    pub(crate) fn get_target(&self, target: &'static str) -> &str {
        self.targets.get(target).map(String::as_ref).unwrap_or(target)
    }
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
            allocator = "malloc"

            [targets]
            malloc = "malloc"
            calloc = "calloc"
            memalign = "memalign"
            realloc = "realloc"
            reallocarray = "reallocarray"
            free = "free"
        "#);
        if let Err(ref err) = res {
            eprintln!("[config::load] test error: {}", *err);
        }
        assert!(res.is_ok());
    }
}
