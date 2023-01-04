use frida_gum::{interceptor::{Interceptor, InvocationContext, InvocationListener}, Module};

use crate::{GUM, EventListener, ListenerGuard, State, attach_listener};
use crate::config::Config;
use crate::trace::{Callstack, Event};
use super::AllocatorOps;

pub(crate) struct Malloc {
    alloc: MallocAllocListener,
    free: MallocFreeListener,
}

impl Malloc {
    pub(crate) fn new() -> Self {
        Malloc {
            alloc: MallocAllocListener::new(),
            free: MallocFreeListener::new(),
        }
    }
}

impl AllocatorOps for Malloc {
    fn init(&mut self, config: &Config) -> Result<(), String> {
        let mut interceptor = Interceptor::obtain(&GUM);

        // Find required symbols.
        let alloc_function_addr = Module::find_export_by_name(None, &config.targets.alloc)
                                    .ok_or_else(|| "Missing alloc symbol!".to_owned())?.into();
        logln!("Found export: {} @ {:p}", config.targets.alloc, alloc_function_addr);
        let free_function_addr = Module::find_export_by_name(None, &config.targets.free)
                                    .ok_or_else(|| "Missing free symbol!".to_owned())?.into();
        logln!("Found export: {} @ {:p}", config.targets.free, free_function_addr);

        // Attach listeners.
        // Don't store the guards in the allocator state just yet: we want them to be dropped if something fails.
        let alloc_guard = attach_listener(&mut interceptor, alloc_function_addr, &mut self.alloc);
        logln!("Attached the alloc listener.");
        let free_guard = attach_listener(&mut interceptor, free_function_addr, &mut self.free);
        logln!("Attached the free listener.");

        // All fallible operations are done, move the guards into the allocator state now.
        self.alloc.guard = Some(alloc_guard);
        self.free.guard = Some(free_guard);

        Ok(())
    }
    fn fini(&mut self) -> Result<(), String> {
        self.alloc.guard.take();
        logln!("Detached the alloc listener after {} allocs.", self.alloc.count);

        self.free.guard.take();
        logln!("Detached the free listener after {} frees.", self.free.count);

        Ok(())
    }
}

/// Alloc listener.
struct MallocAllocListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl MallocAllocListener {
    fn new() -> Self {
        MallocAllocListener {
            guard: None,
            count: 0,
        }
    }
}

impl EventListener for MallocAllocListener {}

// /!\: These functions feel very unsafe, as each holds a mutable reference to the listener, while
//      also mutably accessing STATE which contains the listener!
//      Rust's borrow checker is probably confused by the unsafe magic done by Interceptor::attach
//      with the listener.
//      We don't really care, but must make sure to *NOT* access the listener within the STATE.
impl InvocationListener for MallocAllocListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending alloc for this thread.
        let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                      //would save us having to store it in the
                                                      //thread state

        self.push_pending_alloc(context.arg(0), callstack);
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Dequeue the last pending alloc for this thread, and add it to the global queue.
        if let Some((mut alloc, callstack)) = self.pop_pending_alloc() {
            alloc.address = context.return_value();
            let mut state = State::get().unwrap();
            state.trace.add_event(Event::alloc(alloc), Some(callstack));
            self.count += 1;
        }
    }
}

/// Free listener.
struct MallocFreeListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl MallocFreeListener {
    fn new() -> Self {
        MallocFreeListener {
            guard: None,
            count: 0,
        }
    }
}

impl EventListener for MallocFreeListener {}

// /!\: See the warning above the impl of InvocationListener for MallocAllocListener.
impl InvocationListener for MallocFreeListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending free for this thread.
        self.push_pending_free(context.arg(0));
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Dequeue the last pending free for this thread, and add it to the global queue.
        if let Some(free) = self.pop_pending_free() {
            let callstack = Callstack::capture(&context);
            let mut state = State::get().unwrap();
            state.trace.add_event(Event::free(free), Some(callstack));
            self.count += 1;
        }
    }
}
