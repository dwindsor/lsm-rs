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
  "LsmEvent": {
    "Data": {
      "Device": "0",
      "Group": "dave",
      "Inode": "5463",
      "Path": "/usr/bin/fedora-third-party",
      "User": "dave"
    },
    "Meta": {
      "Type": "Exec"
    }
  }
},
{
  "LsmEvent": {
    "Data": {
      "Device": "0",
      "Group": "root",
      "Inode": "47524",
      "Path": "/usr/libexec/packagekitd",
      "User": "root"
    },
    "Meta": {
      "Type": "Exec"
    }
  }
},
{
  "LsmEvent": {
    "Data": {
      "Device": "0",
      "Group": "dave",
      "Inode": "5585",
      "Path": "/usr/bin/sed",
      "User": "dave"
    },
    "Meta": {
      "Type": "Exec"
    }
  }
},
```

