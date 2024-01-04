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
  "device": "0",
  "group": "dave",
  "inode": "5046",
  "path": "/usr/bin/id",
  "type": "Exec",
  "user": "dave"
},
{
  "device": "0",
  "group": "dave",
  "inode": "5032",
  "path": "/usr/bin/hostnamectl",
  "type": "Exec",
  "user": "dave"
},
{
  "device": "0",
  "group": "polkitd",
  "inode": "5395",
  "path": "/usr/bin/pkla-check-authorization",
  "type": "Exec",
  "user": "polkitd"
},
```

