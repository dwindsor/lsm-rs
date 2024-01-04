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
      "Group": "polkitd",
      "Inode": "5395",
      "Path": "/usr/bin/pkla-check-authorization",
      "User": "polkitd"
    },
    "Meta": {
      "SecurityHook": "security_bprm_check",
      "Type": "Exec"
    }
  }
},
{
  "LsmEvent": {
    "Data": {
      "Device": "0",
      "Group": "root",
      "Inode": "29927",
      "Path": "/usr/lib/systemd/systemd-hostnamed",
      "User": "root"
    },
    "Meta": {
      "SecurityHook": "security_bprm_check",
      "Type": "Exec"
    }
  }
},
{
  "LsmEvent": {
    "Data": {
      "Device": "0",
      "Group": "dave",
      "Inode": "47415",
      "Path": "/usr/libexec/grepconf.sh",
      "User": "dave"
    },
    "Meta": {
      "SecurityHook": "security_bprm_check",
      "Type": "Exec"
    }
  }
}
```

