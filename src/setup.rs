use std::env;
use std::fs;

use ctor::{ctor, dtor};
use frida_gum::interceptor::Interceptor;
use serde_json;

use super::{GUM, ThreadState, State};
use super::allocator::{Allocator, AllocatorOps};
use super::config;

static OUTPUT: &str = "allog.json";

fn init() -> Result<(), String> {
    // Keep this at the top otherwise you'll get segfaults.
    Interceptor::obtain(&GUM);

    // Load the config and instanciate the allocator model.
    let config = config::read_config(env::var("ALLOG_CONFIG")
                                        .unwrap_or_else(|_| config::CONFIG.to_string())
                                    )?;
    let allocator = Allocator::from(&config.allocator);

    // Setup the initializer for the thread-local state.
    ThreadState::init();

    // Create the global state.
    State::create(allocator);
    let mut state = State::get().unwrap();

    // Initialize the allocator state. This will install the hooks.
    state.allocator.init(&config)?;

    logln!("Initialized!");
    Ok(())
}

fn fini() -> Result<(), String> {
    // Explicitly take ownership of the guards, so we may display a meaningful message.
    if let Some(lock) = State::try_get() {
        let mut state = lock.unwrap();

        // Finalize the allocator state. This will remove the hooks.
        state.allocator.fini()?;

        // Dump the events.
        let output = env::var("ALLOC_TRACE_OUTPUT").unwrap_or_else(|_| OUTPUT.to_string());
        let f = fs::File::create(&output)
            .map_err(|e| format!("Error opening trace output {}: {}", output, e))?;
        serde_json::to_writer_pretty(f, &state.trace)
            .map_err(|e| format!("Error serializing trace: {}", e))?;

        // Clear the storage.
        State::reset();

        logln!("Finalized!");
    }

    Ok(())
}

#[ctor]
fn ctor() {
    if let Err(err) = init() {
        elogln!("{}", err);
    }
}

#[dtor]
fn dtor() {
    if let Err(err) = fini() {
        elogln!("{}", err);
    }
}
