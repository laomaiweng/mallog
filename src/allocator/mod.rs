use std::convert::From;

mod malloc;

use super::config::{Config, ConfigAllocator};

pub(crate) trait AllocatorOps {
    fn init(&mut self, config: &Config) -> Result<(), String>;
    fn fini(&mut self) -> Result<(), String>;
}

pub(crate) struct Noop;

impl AllocatorOps for Noop {
    fn init(&mut self, _config: &Config) -> Result<(), String> {Ok(())}
    fn fini(&mut self) -> Result<(), String> {Ok(())}
}

pub(crate) enum Allocator {
    Noop(Noop),
    Malloc(malloc::Malloc),
}

impl AllocatorOps for Allocator {
    fn init(&mut self, config: &Config) -> Result<(), String> {
        match self {
            Allocator::Noop(noop) => noop.init(config),
            Allocator::Malloc(malloc) => malloc.init(config),
        }
    }

    fn fini(&mut self) -> Result<(), String> {
        match self {
            Allocator::Noop(noop) => noop.fini(),
            Allocator::Malloc(malloc) => malloc.fini(),
        }
    }
}

impl From<&ConfigAllocator> for Allocator {
    fn from(ca: &ConfigAllocator) -> Self {
        match ca {
            ConfigAllocator::malloc => Allocator::Malloc(malloc::Malloc::new()),
            _ => Allocator::Noop(Noop{}),
        }
    }
}
