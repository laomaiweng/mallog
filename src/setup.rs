use std::env;
use std::fs;
use std::ptr;

use ctor::{ctor, dtor};
use frida_gum::{interceptor::{Interceptor, InvocationListener}, Module, NativePointer};
use serde_json;

use super::{GUM, MyNativePointer, HookGuard, ListenerGuard, ThreadState, State};
use super::config;

static OUTPUT: &str = "mallog.json";

/// Hook a function with Frida Interceptor, returning a guard.
#[allow(dead_code)]
fn hook_function(interceptor: &mut Interceptor, name: &str, addr: MyNativePointer, hook: MyNativePointer) -> Result<HookGuard, String> {
    interceptor.replace(addr.into(), hook.into(), NativePointer(ptr::null_mut()))
        .map_err(|e| format!("Failed to hook function {}: {}", name, e))?;
    logln!("Hooked {} @ {:p} with function @ {:p}", name, addr, hook);
    Ok(HookGuard(addr))
}

/// Attach to a function with Frida Interceptor, returning a guard.
fn attach_listener<I: InvocationListener>(interceptor: &mut Interceptor, addr: MyNativePointer, listener: &mut I) -> ListenerGuard {
    ListenerGuard(interceptor.attach(addr.into(), listener).into())
}

fn init() -> Result<(), String> {
    // Keep this at the top otherwise you'll get segfaults.
    let mut interceptor = Interceptor::obtain(&GUM);

    // Load config and get required symbols.
    let config = config::read_config(env::var("MALLOC_TRACE_CONFIG")
                                        .unwrap_or_else(|_| config::CONFIG.to_string())
                                    )?;
    let alloc_function_addr = Module::find_export_by_name(None, &config.targets.alloc)
                                .ok_or_else(|| "Missing alloc symbol!".to_owned())?.into();
    logln!("Found export: {} @ {:p}", config.targets.alloc, alloc_function_addr);
    let free_function_addr = Module::find_export_by_name(None, &config.targets.free)
                                .ok_or_else(|| "Missing free symbol!".to_owned())?.into();
    logln!("Found export: {} @ {:p}", config.targets.free, free_function_addr);

    // Setup the initializer for the thread-local state.
    ThreadState::create();

    // Create the global state.
    State::create();
    let mut state = State::get().unwrap();

    // Attach listeners.
    // Don't store the guards in the state just yet: we want them to be dropped if something fails.
    let alloc_guard = attach_listener(&mut interceptor, alloc_function_addr, &mut state.alloc);
    logln!("Attached the alloc listener.");
    let free_guard = attach_listener(&mut interceptor, free_function_addr, &mut state.free);
    logln!("Attached the free listener.");

    // All fallible operations are done, move the guards into the state now.
    state.alloc.guard = Some(alloc_guard);
    state.free.guard = Some(free_guard);

    logln!("Initialized!");
    Ok(())
}

fn fini() -> Result<(), String> {
    // Explicitly take ownership of the guards, so we may display a meaningful message.
    if let Some(lock) = State::try_get() {
        let mut state = lock.unwrap();

        state.alloc.guard.take();
        logln!("Detached the alloc listener after {} allocs.", state.alloc.count);

        state.free.guard.take();
        logln!("Detached the free listener after {} frees.", state.free.count);

        // Dump the events.
        let output = env::var("MALLOC_TRACE_OUTPUT").unwrap_or_else(|_| OUTPUT.to_string());
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
