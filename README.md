[windows-syscall][windows-syscall]: Windows [`syscall`][x86-syscall]s for Rust
========================================

[![windows-syscall GitHub Actions][github.img]][github]
[![windows-syscall on crates.io][crates-io.img]][crates-io]
[![windows-syscall on docs.rs][docs-rs.img]][docs-rs]

The [`syscall!` macro][syscall-macro] provides a type-safe way to invoke a Windows system service.

#### Available Features

| Feature | Description |
| --- | --- |
| `windows-syscall-typesafe` *(default)*| The macro attempts calling the provided function in a dead branch, ensuring type-safety *(enabled by default).* |
| *`windows-syscall-use-linked`* | The macro directly invokes the provided function instead of performing an inline syscall. This is only useful for testing/debugging and is equivalent to directly calling the function. |

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

#### Platform Support

| Arch |  |
| --- | --- |
| x86_64 *(64-bit)* | ✅ **Yes**  |
| x86 *(32-bit)* | ❌ No *(on request)*
| AArch64 | ❌ No *(on request)*

*This crate only implements calls to [`ntoskrnl` services][syscall-table-nt], if you require [`win32k` services][syscall-table-win32k] or an additional architecture please [create an issue][create-issue] and let me know!*


**crate version:** 0.0.x aka work-in-progress.

[github]: https://github.com/oberrich/windows-syscall/actions/workflows/rust.yml
[github.img]: https://github.com/oberrich/windows-syscall/actions/workflows/rust.yml/badge.svg
[crates-io]: https://crates.io/crates/windows-syscall
[crates-io.img]: https://img.shields.io/crates/v/windows-syscall.svg
[docs-rs]: https://docs.rs/windows-syscall
[docs-rs.img]: https://docs.rs/windows-syscall/badge.svg

[syscall-macro]: https://docs.rs/windows-syscall/latest/windows_syscall/macro.syscall.html

[windows-syscall]: https://github.com/oberrich/windows-syscall
[create-issue]: https://github.com/oberrich/windows-syscall/issues/new

[x86-syscall]: https://www.felixcloutier.com/x86/syscall

[syscall-table-nt]: https://j00ru.vexillium.org/syscalls/nt/64/
[syscall-table-win32k]: https://j00ru.vexillium.org/syscalls/win32k/64/