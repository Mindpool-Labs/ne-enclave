# NeuronEdge Enclave guest image — Buildroot

This directory holds the `BR2_EXTERNAL` tree that `crates/ne-image`
drives to build the guest kernel (`vmlinux`) + rootfs (`rootfs.ext4`)
for NeuronEdge Enclave microVMs.

## Pinned Buildroot version

The image build is pinned to Buildroot **`2025.05`** — the tag validated
for the standard guest image and used by the CI `e2e` job
(`.github/workflows/ne-ci.yml`, `env.BUILDROOT_VERSION`). Bump both together.

## Local build

```sh
# 1. Clone Buildroot at the pinned tag (once).
git clone --depth 1 --branch 2025.05 \
  https://gitlab.com/buildroot.org/buildroot.git ~/buildroot

# 2. Cross-compile the guest agent (baked into the rootfs).
rustup target add x86_64-unknown-linux-musl
cargo build -p ne-guest-agent --release --target x86_64-unknown-linux-musl

# 3. Build the image. Artifacts land under
#    target/images/standard/images/ (vmlinux, rootfs.ext4).
cargo run -p ne-image -- build --template standard --buildroot ~/buildroot
```

The `standard` template maps to
`external/configs/ne_standard_defconfig`. The rootfs boots
read-only; `external/board/firecracker/post-build.sh` mounts a writable
tmpfs at `/workspace` (the guest agent's jail root) via the guest
`inittab`.
