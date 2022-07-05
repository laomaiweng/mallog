use frida_gum::interceptor::{InvocationListener, InvocationContext};

use super::{ListenerGuard, Callstack, AllocEvent, FreeEvent, Event, ThreadState, State};

fn get_timestamp() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// Alloc listener.
pub(crate) struct AllocListener {
    pub guard: Option<ListenerGuard>,
    pub count: usize,
}

impl AllocListener {
    pub fn new() -> Self {
        AllocListener {
            guard: None,
            count: 0,
        }
    }
}

// /!\: These functions feel very unsafe, as each holds a mutable reference to the listener, while
//      also mutably accessing STATE which contains the listener!
//      Rust's borrow checker is probably confused by the unsafe magic done by Interceptor::attach
//      with the listener.
//      We don't really care, but must make sure to *NOT* access the listener within the STATE.
impl InvocationListener for AllocListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        if let Some(mut thread) = ThreadState::get() {
            // Queue a pending alloc for this thread.
            let callstack = Callstack::capture(&context); //TODO: can we capture in on_leave()?
                                                          //would save us having to store it in the
                                                          //thread state
            thread.pending_allocs.push((
                AllocEvent {
                    timestamp: 0,
                    address: 0,
                    size: context.arg(0),
                    callstack: 0,
                },
                callstack
            ));
        }
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        if let Some(mut thread) = ThreadState::get() {
            // Dequeue the last pending alloc for this thread, and add it to the global queue.
            let (mut alloc, callstack) = thread.pending_allocs.pop().unwrap();
            let cid = callstack.id();
            alloc.timestamp = get_timestamp();
            alloc.address = context.return_value();
            alloc.callstack = cid;
            let mut state = State::get().unwrap();
            state.trace.events.push(Event::Alloc(alloc));
            state.trace.meta.callstack.entry(cid).or_insert(callstack);
            self.count += 1;
        }
    }
}

/// Free listener.
pub(crate) struct FreeListener {
    pub guard: Option<ListenerGuard>,
    pub count: usize,
}

impl FreeListener {
    pub fn new() -> Self {
        FreeListener {
            guard: None,
            count: 0,
        }
    }
}

// /!\: See the warning above the impl of InvocationListener for AllocListener.
impl InvocationListener for FreeListener {
    fn on_enter(&mut self, context: InvocationContext<'_>) {
        if let Some(mut thread) = ThreadState::get() {
            // Queue a pending free for this thread.
            thread.pending_frees.push(FreeEvent {
                timestamp: 0,
                address: context.arg(0),
                callstack: 0,
            });
        }
    }

    fn on_leave(&mut self, context: InvocationContext<'_>) {
        if let Some(mut thread) = ThreadState::get() {
            // Dequeue the last pending free for this thread, and add it to the global queue.
            let callstack = Callstack::capture(&context);
            let cid = callstack.id();
            let mut free = thread.pending_frees.pop().unwrap();
            free.timestamp = get_timestamp();
            free.callstack = cid;
            let mut state = State::get().unwrap();
            state.trace.events.push(Event::Free(free));
            state.trace.meta.callstack.entry(cid).or_insert(callstack);
            self.count += 1;
        }
    }
}
