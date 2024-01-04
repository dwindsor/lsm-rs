# lsm-rs

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Example Output
```json
{
  "device": 0,
  "inode": 48537,
  "path": "/usr/sbin/sshd",
  "type": "Exec"
}

{
  "device": 0,
  "inode": 48562,
  "path": "/usr/sbin/unix_chkpwd",
  "type": "Exec"
}

{
  "device": 0,
  "inode": 5395,
  "path": "/usr/bin/pkla-check-authorization",
  "type": "Exec"
}
```

