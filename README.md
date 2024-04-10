[Windows syscalls for Rust][windows-syscall]
========================================

[![windows-syscall GitHub Actions][github.img]][github]
[![windows-syscall on crates.io][crates-io.img]][crates-io]
[![windows-syscall on docs.rs][docs-rs.img]][docs-rs]

The `syscall!` macro provides a type-safe way to invoke a Windows system service.

This crate only implements calls to `ntoskrnl` services, if you require `win32k` services please create an issue and let me know.

This crate only implements x86_64 arch, if you need x86 (32-bit) implemented create an issue and let me know.

### Example

```rust
extern "C" {
    pub fn NtClose(Handle: HANDLE) -> NTSTATUS;
}

fn main() {
   assert_eq!(syscall!(NtClose(HANDLE::new(0xvalid))), STATUS_SUCCESS);
   assert_eq!(syscall!(NtClose(HANDLE::default())), STATUS_INVALID_HANDLE);
}
```

**crate version:** 0.0.x aka work-in-progress.

[github]: https://github.com/oberrich/windows-syscall/actions/workflows/rust.yml
[github.img]: https://github.com/oberrich/windows-syscall/actions/workflows/rust.yml/badge.svg
[crates-io]: https://crates.io/crates/windows-syscall
[crates-io.img]: https://img.shields.io/crates/v/windows-syscall.svg
[docs-rs]: https://docs.rs/windows-syscall
[docs-rs.img]: https://docs.rs/windows-syscall/badge.svg

[windows-syscall]: https://github.com/oberrich/windows-syscall
