# zon-lb
Simple ebpf/xdp based L3/4 load balancer written in Rust.

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

## Troubleshooting build errors
### After updating the rust toolchains
After running the `rustup update` make sure that the commands from
[aya prerequisites](https://aya-rs.dev/book/start/development/#prerequisites) are
run again especially:
- update bpf-linker: cargo install bpf-linker
- cargo install cargo-generate
### Broken dependencies
By default, cargo will not fetch the latest lib sources if the repo is update upstream.
To overcome this run the `cargo update` command in the workspace directory and in the
bpf directory - which is also a workspace due to different toolchain.
