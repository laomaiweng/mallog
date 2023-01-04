use std::cell::{RefCell, RefMut};
use std::fmt;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::sync::{LockResult, RwLock, RwLockWriteGuard};

use frida_gum::{Gum, interceptor::{Interceptor, InvocationListener}};
use jemallocator::Jemalloc;
use lazy_static::lazy_static;
use state::{LocalStorage, Storage};

#[macro_use] mod log; // Declare first so other modules may use the macros.
mod allocator;
mod config;
#[cfg(not(test))] // Don't bring the setup code into scope for tests.
mod setup;
mod trace;

use allocator::Allocator;
use trace::{AllocEvent, Callstack, FreeEvent, Trace};

// Don't shit where you eat: use a non-malloc global allocator.
#[global_allocator]
static ALLOCATOR: Jemalloc = Jemalloc;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

/// Newtype native address, for strong typedness.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
struct MyNativeAddress(pub u64); // Assume the target is 64bits.

impl MyNativeAddress {
    #[allow(dead_code)]
    fn offset(&self, offset: u64) -> Self {
        MyNativeAddress(self.0 + offset)
    }
}

impl fmt::LowerHex for MyNativeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

/// Conversion from pointer to address.
impl From<MyNativePointer> for MyNativeAddress {
    fn from(mnp: MyNativePointer) -> MyNativeAddress {
        let MyNativePointer(ptr) = mnp;
        MyNativeAddress(unsafe { mem::transmute(ptr) })
    }
}

/// Newtype native pointer with Send+Sync, for storage into the global state.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct MyNativePointer(pub *mut c_void);
unsafe impl Send for MyNativePointer {}
unsafe impl Sync for MyNativePointer {}

impl MyNativePointer {
    #[allow(dead_code)]
    fn null() -> Self {
        MyNativePointer(ptr::null_mut())
    }
}

impl fmt::Pointer for MyNativePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Pointer::fmt(&self.0, f)
    }
}

/// Conversion from address to pointer.
impl From<MyNativeAddress> for MyNativePointer {
    fn from(mna: MyNativeAddress) -> MyNativePointer {
        let MyNativeAddress(addr) = mna;
        MyNativePointer(unsafe { mem::transmute(addr) })
    }
}

/// Conversion from MyNativePointer to Frida's non-Send+Sync NativePointer.
impl From<MyNativePointer> for frida_gum::NativePointer {
    fn from(mnp: MyNativePointer) -> frida_gum::NativePointer {
        let MyNativePointer(ptr) = mnp;
        frida_gum::NativePointer(ptr)
    }
}

/// Conversion from Frida's non-Send+Sync NativePointer to MyNativePointer.
impl From<frida_gum::NativePointer> for MyNativePointer {
    fn from(np: frida_gum::NativePointer) -> MyNativePointer {
        let frida_gum::NativePointer(ptr) = np;
        MyNativePointer(ptr)
    }
}

/// A guard type for a Frida Interceptor hook, that reverts the hook when dropped.
struct HookGuard(MyNativePointer);

impl Drop for HookGuard {
    fn drop(&mut self) {
        let mut interceptor = Interceptor::obtain(&GUM);
        interceptor.revert(self.0.into());
    }
}

/// Hook a function with Frida Interceptor, returning a guard.
#[allow(dead_code)]
fn hook_function(interceptor: &mut Interceptor, name: &str, addr: MyNativePointer, hook: MyNativePointer) -> Result<HookGuard, String> {
    interceptor.replace(addr.into(), hook.into(), frida_gum::NativePointer(ptr::null_mut()))
        .map_err(|e| format!("Failed to hook function {}: {}", name, e))?;
    logln!("Hooked {} @ {:p} with function @ {:p}", name, addr, hook);
    Ok(HookGuard(addr))
}

/// Hooked function info.
#[allow(dead_code)]
struct Hook<T> {
    function: T,
    count: usize,
    ignored: usize,
    guard: Option<HookGuard>,
}

impl<T> Hook<T> {
    #[allow(dead_code)]
    fn new(function: T) -> Self {
        Hook {
            function,
            count: 0,
            ignored: 0,
            guard: None,
        }
    }
}

/// A guard type for a Frida Interceptor listener attachment, that detaches the listener when dropped.
struct ListenerGuard(MyNativePointer);

impl Drop for ListenerGuard {
    fn drop(&mut self) {
        let mut interceptor = Interceptor::obtain(&GUM);
        interceptor.detach(self.0.into());
    }
}

/// Attach to a function with Frida Interceptor, returning a guard.
fn attach_listener<I: InvocationListener>(interceptor: &mut Interceptor, addr: MyNativePointer, listener: &mut I) -> ListenerGuard {
    ListenerGuard(interceptor.attach(addr.into(), listener).into())
}

trait EventListener {
    fn push_pending_alloc(&self, size: usize, callstack: Callstack) {
        if let Some(mut thread) = ThreadState::get() {
            thread.pending_allocs.push((
                AllocEvent {
                    timestamp: 0,
                    address: 0,
                    size,
                    callstack: 0,
                },
                callstack
            ));
        }
    }

    fn pop_pending_alloc(&self) -> Option<(AllocEvent, Callstack)> {
        ThreadState::get().and_then(|mut thread| thread.pending_allocs.pop())
    }

    fn push_pending_free(&self, address: usize) {
        if let Some(mut thread) = ThreadState::get() {
            thread.pending_frees.push(FreeEvent {
                timestamp: 0,
                address,
                callstack: 0,
            });
        }
    }

    fn pop_pending_free(&self) -> Option<FreeEvent> {
        ThreadState::get().and_then(|mut thread| thread.pending_frees.pop())
    }
}

/// Thread-local state.
struct ThreadState {
    pending_allocs: Vec<(AllocEvent, Callstack)>,
    pending_frees: Vec<FreeEvent>,
}

impl ThreadState {
    fn init() {
        THREAD_STATE.set(|| RefCell::new(ThreadState {
            pending_allocs: Vec::new(),
            pending_frees: Vec::new(),
        }));
    }

    fn get<'a>() -> Option<RefMut<'a, Self>> {
        // This should only fail in 2 circumstances:
        // * when the current thread is already holding a borrow on its thread-local state,
        //   which means it's re-entering from within our code because an allocator event occurred,
        //   which means we probably don't want to trace that event
        // * during libc finalization, after TLS has been torn down
        // So when this function fails, we can safely ignore it and not log an allocator event.
        THREAD_STATE.try_get().and_then(|cell| cell.try_borrow_mut().ok())
    }
}

/// Global state.
struct State {
    allocator: Allocator,
    trace: Trace,
}

impl State {
    fn create(allocator: Allocator) {
        STATE.set(RwLock::new(State {
            allocator,
            trace: Trace::new(),
        }));
    }

    fn get<'a>() -> LockResult<RwLockWriteGuard<'a, Self>> {
        STATE.get().write()
    }

    fn try_get<'a>() -> Option<LockResult<RwLockWriteGuard<'a, Self>>> {
        Some(STATE.try_get()?.write())
    }

    fn reset() {
        // Replace the previous state with a dummy one.
        Self::create(Allocator::Noop(allocator::Noop{}));
    }
}

static THREAD_STATE: LocalStorage<RefCell<ThreadState>> = LocalStorage::new();
static STATE: Storage<RwLock<State>> = Storage::new();
