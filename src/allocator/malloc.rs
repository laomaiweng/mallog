use std::default::Default;

use frida_gum::interceptor::{Interceptor, InvocationContext, InvocationListener};

use crate::{GUM, EventListener, ListenerGuard, attach_target, detach_target};
use crate::config::Config;
use crate::trace::Callstack;
use super::AllocatorOps;

//TODO: reallocarray
#[derive(Default)]
pub(crate) struct Malloc {
    malloc: MallocListener,
    calloc: CallocListener,
    memalign: MemalignListener,
    realloc: ReallocListener,
    free: FreeListener,
}

impl AllocatorOps for Malloc {
    fn init(&mut self, config: &Config) -> Result<(), String> {
        let mut interceptor = Interceptor::obtain(&GUM);

        // Attach listeners for the malloc API. Failures are ignored.
        self.malloc.guard = attach_target(&mut interceptor, config, "malloc", &mut self.malloc);
        self.calloc.guard = attach_target(&mut interceptor, config, "calloc", &mut self.calloc);
        self.memalign.guard = attach_target(&mut interceptor, config, "memalign", &mut self.memalign);
        self.realloc.guard = attach_target(&mut interceptor, config, "realloc", &mut self.realloc);
        self.free.guard = attach_target(&mut interceptor, config, "free", &mut self.free);

        Ok(())
    }
    fn fini(&mut self) -> Result<(), String> {
        detach_target("malloc", &mut self.malloc.guard, self.malloc.count);
        detach_target("calloc", &mut self.calloc.guard, self.calloc.count);
        detach_target("memalign", &mut self.memalign.guard, self.memalign.count);
        detach_target("realloc", &mut self.realloc.guard, self.realloc.count);
        detach_target("free", &mut self.free.guard, self.free.count);

        Ok(())
    }
}

/// Malloc listener.
#[derive(Default)]
struct MallocListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl EventListener for MallocListener {}

// /!\: These functions feel very unsafe, as each holds a mutable reference to the listener, while
//      also mutably accessing STATE which contains the listener!
//      Rust's borrow checker is probably confused by the unsafe magic done by Interceptor::attach
//      with the listener.
//      We don't really care, but must make sure to *NOT* access the listener within the STATE.
impl InvocationListener for MallocListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending alloc for this thread.
        let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                      //would save us having to store it in the
                                                      //thread state

        self.queue_pending_alloc(context.arg(0), callstack);
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Complete the last pending alloc for this thread.
        self.complete_pending_alloc(context.return_value());
        self.count += 1;
    }
}

/// Calloc listener.
#[derive(Default)]
struct CallocListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl EventListener for CallocListener {}

// /!\: See the warning above the impl of InvocationListener for MallocListener.
impl InvocationListener for CallocListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending alloc for this thread.
        let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                      //would save us having to store it in the
                                                      //thread state

        let nmemb = context.arg(0);
        let size = context.arg(1);
        if let Some(total) = nmemb.checked_mul(size) {
            //TODO: store nmemb & size in metadata
            self.queue_pending_alloc(total, callstack);
        } else {
            //TODO: record event for overflow
        }
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Complete the last pending alloc for this thread.
        self.complete_pending_alloc(context.return_value());
        self.count += 1;
    }
}

/// Memalign listener.
#[derive(Default)]
struct MemalignListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl EventListener for MemalignListener {}

// /!\: See the warning above the impl of InvocationListener for MallocListener.
impl InvocationListener for MemalignListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending alloc for this thread.
        let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                      //would save us having to store it in the
                                                      //thread state

        let alignment = context.arg(0);
        let size = context.arg(1);
        self.queue_pending_alloc(size, callstack);
        //TODO: store alignment in metadata
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Complete the last pending alloc for this thread.
        self.complete_pending_alloc(context.return_value());
        self.count += 1;
    }
}

/// Realloc listener.
#[derive(Default)]
struct ReallocListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl EventListener for ReallocListener {}

// /!\: See the warning above the impl of InvocationListener for MallocListener.
impl InvocationListener for ReallocListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending realloc for this thread.
        let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                      //would save us having to store it in the
                                                      //thread state

        self.queue_pending_realloc(context.arg(0), context.arg(1), callstack);
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Complete the last pending realloc for this thread.
        self.complete_pending_realloc(context.return_value());
        self.count += 1;
    }
}

/// Free listener.
#[derive(Default)]
struct FreeListener {
    guard: Option<ListenerGuard>,
    count: usize,
}

impl EventListener for FreeListener {}

// /!\: See the warning above the impl of InvocationListener for MallocListener.
impl InvocationListener for FreeListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        // Queue a pending free for this thread.
        self.queue_pending_free(context.arg(0));
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        // Complete the last pending free for this thread.
        let callstack = Callstack::capture(&context);
        self.complete_pending_free(callstack);
        self.count += 1;
    }
}
