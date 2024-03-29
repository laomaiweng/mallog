use std::collections::HashMap;

use frida_gum::interceptor::InvocationContext;
use serde_derive::Serialize;

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// A callstack as a vector of return addresses.
#[derive(Serialize)]
pub struct Callstack(Vec<usize>);

impl Callstack {
    pub fn capture(context: &InvocationContext<'_>) -> Self {
        Callstack(context.cpu_context().backtrace_accurate())
    }

    pub fn id(&self) -> usize {
        self.0.iter().fold(0, |id, frame| id ^ frame)
    }
}

/// Allocator event: alloc.
#[derive(Serialize)]
pub struct AllocEvent {
    pub timestamp: u64,
    pub address: usize,
    pub size: usize,
    pub callstack: usize,
}

/// Allocator event: realloc.
#[derive(Serialize)]
pub struct ReallocEvent {
    pub timestamp: u64,
    pub old_address: usize,
    pub new_address: usize,
    pub size: usize,
    pub callstack: usize,
}

/// Allocator event: free.
#[derive(Serialize)]
pub struct FreeEvent {
    pub timestamp: u64,
    pub address: usize,
    pub callstack: usize,
}

/// Allocator event.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Event {
    Alloc(AllocEvent),
    Realloc(ReallocEvent),
    Free(FreeEvent),
    // Custom
}

/// Trace metadata.
#[derive(Serialize)]
struct TraceMeta {
    callstack: HashMap<usize, Callstack>,
}

/// Complete trace output.
#[derive(Serialize)]
pub struct Trace {
    events: Vec<Event>,
    meta: TraceMeta,
}

impl Trace {
    pub fn new() -> Self {
        Trace {
            events: Vec::new(),
            meta: TraceMeta {
                callstack: HashMap::new(),
            },
        }
    }

    pub fn add_event(&mut self, mut event: Event, callstack: Option<Callstack>) {
        // Update the event.
        let cid = callstack.as_ref().map_or(0, |cs| cs.id());
        match event {
            Event::Alloc(ref mut alloc) => {
                alloc.timestamp = get_timestamp();
                alloc.callstack = cid;
            },
            Event::Realloc(ref mut realloc) => {
                realloc.timestamp = get_timestamp();
                realloc.callstack = cid;
            },
            Event::Free(ref mut free) => {
                free.timestamp = get_timestamp();
                free.callstack = cid;
            },
        }
        self.events.push(event);
        if let Some(cs) = callstack {
            self.meta.callstack.entry(cid).or_insert(cs);
        }
    }
}
