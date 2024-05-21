#![doc = include_str!("../README.md")]
// MIT License
//
// Copyright (c) 2024 oberrich <oberrich.llvm@proton.me>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#![feature(asm_const, maybe_uninit_uninit_array, maybe_uninit_array_assume_init)]
use std::collections::HashMap;

use const_fnv1a_hash::fnv1a_hash_str_64;
use exe::{Address, ImageExportDirectory, ThunkData};
use once_cell::sync::Lazy;
use phnt::ext::NtCurrentTeb;
use phnt::ffi::LDR_DATA_TABLE_ENTRY;

/// [`32 bytes`    msabi](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170#calling-convention-defaults): shadow stack space  
/// [`8 bytes`    isa](https://www.felixcloutier.com/x86/call): return address  
pub const STACK_ALLOC: usize = 40;
/// Register width is equivalent to pointer width on targeted platforms
pub const REGISTER_WIDTH: usize = core::mem::size_of::<usize>();
/// `4c 8b d1        mov r10, rcx`  
/// `b8  _  _  _  _  mov eax, {sysno}`
pub const PROLOGUE_BYTES: u32 = u32::from_ne_bytes([0x4C, 0x8B, 0xD1, 0xB8]);
/// `0f 05 syscall`  
pub const SYSCALL_BYTES: u16 = u16::from_ne_bytes([0x0F, 0x05]);

pub fn get_ntdll_base() -> *mut std::ffi::c_void {
    unsafe {
        let teb = &*NtCurrentTeb();
        let peb = &*teb.ProcessEnvironmentBlock;
        let ldr_data = &*peb.Ldr;
        let ldr_entry =
            &*(ldr_data.InLoadOrderModuleList.Flink.read().Flink as *const LDR_DATA_TABLE_ENTRY);
        ldr_entry.DllBase
    }
}

pub static SSN_MAP: Lazy<HashMap<u64, u32>> = Lazy::new(|| unsafe {
    let mut ssn_map = HashMap::new();
    let ntdll_base = get_ntdll_base() as *const u8;
    let image = exe::PtrPE::from_memory(ntdll_base).unwrap_unchecked();
    let export_directory = ImageExportDirectory::parse(&image).unwrap_unchecked();

    for (name, thunk) in export_directory.get_export_map(&image).unwrap_unchecked() {
        if let ThunkData::Function(thunk) = thunk {
            let thunk_bytes = thunk.as_ptr(&image).unwrap_unchecked();
            if (thunk_bytes as *const u32).read_unaligned() == PROLOGUE_BYTES
                && (thunk_bytes.add(0x12) as *const u16).read_unaligned() == SYSCALL_BYTES
            {
                let sysno: u32 = (thunk_bytes.add(4) as *const u32).read_unaligned();
                ssn_map.insert(fnv1a_hash_str_64(name), sysno);
            }
        }
    }
    ssn_map
});

// TODO(chore): Document, document, document...
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! syscall {
   (@subst_tts $_:tt $x:expr) => {$x};

   (@count_tts) => { 0 };
   (@count_tts $odd:tt $($a:tt $   b:tt)*) => {(syscall!(@count_tts $($a)*) << 1) | 1 };
   (@count_tts         $($a:tt $even:tt)*) => { syscall!(@count_tts $($a)*) << 1 };

   ($fun:ident($($args:expr$(,)?)*)) => {{
      #[allow(unreachable_code, unused_unsafe, unused_mut, unused_assignments, unused_variables)]
      unsafe {
         if cfg!(feature="windows-syscall-use-linked") {
            $fun($($args,)*) as NTSTATUS
         } else {
            use core::{sync::atomic::{AtomicUsize, Ordering}, mem::MaybeUninit, arch::asm};

            // Attempting to directly invoke the function enforces that both the types as well
            // as the number of arguments are compatible with the function prototype.
            //
            // Syscalls with arbitrary arguments are only allowed when the `windows-syscall-typesafe` feature
            // is disabled or the `windows-syscall-use-linked` feature is active (debug builds)
            if cfg!(feature="windows-syscall-typesafe") {
               if false {
                  $fun($($args,)*);
               }
            }

            const FUN_HASH: u64 = const_fnv1a_hash::fnv1a_hash_str_64(stringify!($fun));
            static mut SSN: AtomicUsize = AtomicUsize::new(!0usize);
            if SSN.load(Ordering::Acquire) == !0 {
               SSN.store(*(*$crate::SSN_MAP).get(&FUN_HASH).unwrap_unchecked() as usize, Ordering::Release);
            }

            syscall!(@bind $($args)*) as NTSTATUS
         }
      }
   }};


   // Syscalls without stack arguments are directly emitted
   (@bind $($r1:tt)?)                  => { syscall!(@emit [$($r1)?]) };
   (@bind $r1:tt $r2:tt)               => { syscall!(@emit [$r1 $r2]) };
   (@bind $r1:tt $r2:tt $r3:tt)        => { syscall!(@emit [$r1 $r2 $r3]) };
   (@bind $r1:tt $r2:tt $r3:tt $r4:tt) => { syscall!(@emit [$r1 $r2 $r3 $r4]) };

   // Stack arguments are bound to be in reverse order
   (@bind $r1:tt $r2:tt $r3:tt $r4:tt $($rest:tt)+) => {
      syscall!(@bind_stack $r1 $r2 $r3 $r4 [$($rest)+])
   };

   (@bind_stack $r1:tt $r2:tt $r3:tt $r4:tt [$head:tt $($rest:tt)*] $($reversed:expr)* ) => {
      syscall!(@bind_stack $r1 $r2 $r3 $r4 [$($rest)*] $head $($reversed)*)
   };

   (@bind_stack $r1:tt $r2:tt $r3:tt $r4:tt [] $($stack:tt)*) => {
      syscall!(@emit [$r1 $r2 $r3 $r4] $($stack)*)
   };

   // Emits the actual syscall instruction
   (@emit [$($register:expr)*] $($stack:expr)*) => {{
      let [arg1, arg2, arg3, arg4, mut status] = {
         let mut data = MaybeUninit::<usize>::uninit_array::<5>();
         let mut data_len: usize = 0;
         // Initialize stack args if and only if they were used, thus
         // avoiding unnecessary register allocations
         $(
            data[data_len] = MaybeUninit::new($register as usize);
            data_len += 1;
         )*
         // "`status` always remains uninitialized"
         assert!(data_len <= 4);
         MaybeUninit::array_assume_init(data)
      };

      asm!(
         $(syscall!(@subst_tts $stack "push {:r}"), )*
         "sub rsp, {stack_alloc}",
         "syscall",
         "add rsp, {stack_dealloc}",
         // Allocate temp registers for stack args
         $(in(reg) $stack, )*
         // Bind arg[1; 4] to their respective register
         inout("r10") arg1 => _,
         inout("rdx") arg2 => _,
         inout("r8")  arg3 => _,
         inout("r9")  arg4 => _,
         // `SSN` -> `rax` -> `raw_status`
         inlateout("rax") SSN.load(Ordering::Acquire) => status,
         // `rcx` preserves rip
         out("rcx") _,
         // `r11` preserves rflags
         out("r11") _,
         // Flags are preserved
         options(preserves_flags),
         stack_alloc   = const $crate::STACK_ALLOC,
         stack_dealloc = const $crate::STACK_ALLOC + $crate::REGISTER_WIDTH * syscall!(@count_tts $($stack)*),
      );

      status
   }};
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use phnt::ffi::{NtClose, HANDLE, NTSTATUS};

    extern "C" {
        fn NtTestAlert() -> NTSTATUS;

        fn NtNArgs0() -> NTSTATUS;
        fn NtNArgs1(_1: usize) -> NTSTATUS;
        fn NtNArgs2(_1: usize, _2: usize) -> NTSTATUS;
        fn NtNArgs3(_1: usize, _2: usize, _3: usize) -> NTSTATUS;
        fn NtNArgs4(_1: usize, _2: usize, _3: usize, _4: usize) -> NTSTATUS;
        fn NtNArgs5(_1: usize, _2: usize, _3: usize, _4: usize, _5: usize) -> NTSTATUS;
        fn NtNArgs6(_1: usize, _2: usize, _3: usize, _4: usize, _5: usize, _6: usize) -> NTSTATUS;
    }

    fn call_nt_close(handle: HANDLE) -> NTSTATUS {
        syscall!(NtClose(handle))
    }

    #[test]
    fn basic() {
        const STATUS_INVALID_HANDLE: i32 = 0xC0000008u32 as i32;
        const INVALID_HANDLE: *mut std::ffi::c_void = core::ptr::null_mut();
        assert_eq!(call_nt_close(INVALID_HANDLE), STATUS_INVALID_HANDLE);

        const STATUS_SUCCESS: i32 = 0x00000000i32;
        assert_eq!(syscall!(NtTestAlert()), STATUS_SUCCESS);
    }

    #[test]
    fn dispatching() {
        // TODO(chore): Use `trybuild` or something instead of this meme to test dispatching
        if false {
            syscall!(NtNArgs0());
            syscall!(NtNArgs1(1));
            syscall!(NtNArgs2(1, 2));
            syscall!(NtNArgs3(1, 2, 3));
            syscall!(NtNArgs4(1, 2, 3, 4));
            syscall!(NtNArgs5(1, 2, 3, 4, 5));
            syscall!(NtNArgs6(1, 2, 3, 4, 5, 6));
        }
    }
}
