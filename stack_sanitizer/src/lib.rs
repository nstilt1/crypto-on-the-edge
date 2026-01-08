//! Heap-based stack zeroization module. This module uses Rust-Lang's `psm`
//! crate to switch stacks to a stack that is allocated on the heap
//! (`ZeroizingHeapStack`) and then executes a callback function on that
//! stack. You can reuse this stack as many times as you want, and when it is
//! dropped, it will be zeroized.

use core::panic::UnwindSafe;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use psm::psm_stack_manipulation;

#[cfg(any(target_family = "wasm", target_os = "hermit"))]
#[path = "alloc.rs"]
mod heap_struct;

#[cfg(not(any(target_family = "wasm", target_os = "hermit")))]
#[path = "mmap.rs"]
mod heap_struct;

pub use heap_struct::ZeroizingHeapStack;

#[deprecated(note = "Stack switching backend disabled (psm_stack_manipulation! expanded to `no`). Falling back to running crypto_fn() on the current stack.")]
#[allow(dead_code)]
pub const _STACK_SWITCHING_DISABLED_WARNING: () = ();

/// Executes a closure on a provided zeroizing heap-based stack.
///
/// This function does not clear CPU registers.
///
/// # Arguments
///
/// * `zeroizing_heap_stack` - the heap-based stack you plan on using
/// for running the closure. `psm` recommends at least `4 KiB` of stack space,
/// but the total size cannot overflow an `isize`. Also, some architectures
/// might consume more memory in the stack, such as SPARC.
///
/// * `crypto_fn` - the code to run while on the switched stack.
///
/// ## Panicking
///
/// This function does not panic, but it can segfault.
///
/// ## Segfaults
///
/// This code will cause a segmentation fault if your closure consumes
/// more stack space than what you have allocated.
///
/// ## Debugging
///
/// Using `#[inline(never)]` on the closure's function definition(s) could
/// make it easier to debug as the function(s) should then show up in
/// backtraces.
///
/// # Returns
///
/// This function returns the returned value from the closure.
///
/// # Safety
///
/// * The stack needs to be large enough for `crypto_fn()` to execute
/// without overflowing.
///
/// * For `nostd`, you should use `panic = 'abort'` to avoid unwinding
/// on the switched stack. Unwinding across stack boundaries could cause
/// undefined behavior. `nostd` code must not unwind or return control
/// flow by any other means.
pub unsafe fn switch_stacks<F, R>(zeroizing_heap_stack: &mut ZeroizingHeapStack, crypto_fn: F) -> R
where
    F: FnOnce() -> R + UnwindSafe,
{
    let mut opt_callback = Some(crypto_fn);
    let mut ret = None;
    let ret_ref = &mut ret;

    let dyn_callback: &mut dyn FnMut() = &mut || {
        let taken_callback = opt_callback.take().unwrap();
        *ret_ref = Some(taken_callback());
    };
    _switch_stacks(zeroizing_heap_stack, dyn_callback);
    ret.unwrap()
}

psm_stack_manipulation! {
    yes {
        fn _switch_stacks(zeroizing_heap_stack: &mut ZeroizingHeapStack, crypto_fn: &mut dyn FnMut()) {
            unsafe {
                let (stack_base, allocated_stack_size) = zeroizing_heap_stack.stack_area();
                let panic = psm::on_stack(stack_base, allocated_stack_size, move || {
                    catch_unwind(AssertUnwindSafe(crypto_fn)).err()
                });
                if let Some(p) = panic {
                    resume_unwind(p);
                }
            }
        }
    }

    no {
        // Emit a warning at compile time when this branch is selected.
        const _: () = {
            let _ = $crate::_STACK_SWITCHING_DISABLED_WARNING;
        };
        
        fn _switch_stacks(zeroizing_heap_stack: &mut ZeroizingHeapStack, crypto_fn: &mut dyn FnMut()) {
            let _ = zeroizing_heap_stack;
            crypto_fn();
        }
    }
}
