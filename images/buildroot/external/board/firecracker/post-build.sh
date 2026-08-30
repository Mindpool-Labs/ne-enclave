#!/bin/sh
# Buildroot post-build hook. Runs AFTER the rootfs tree is staged
# under $TARGET_DIR but BEFORE it's packed into the ext4 image.
#
# Base image scope:
#   - Layer in a tiny init that mounts /proc + /sys, starts the
#     guest agent on vsock, then drops to a shell so the operator
#     can probe interactively if needed.
#   - If the cross-compiled ne-guest-agent binary exists at
#     $NE_GUEST_AGENT_BIN (set by the caller of ne-image),
#     copy it into the rootfs at /usr/local/bin/ne-guest-agent.
#     Otherwise warn and continue — the rootfs is still bootable
#     and we can iterate without forcing the agent build to run
#     before the buildroot pipeline is proven.

set -eu
TARGET_DIR="$1"

# ----- guest agent binary ------------------------------------------
if [ -n "${NE_GUEST_AGENT_BIN:-}" ] && [ -f "${NE_GUEST_AGENT_BIN}" ]; then
  install -D -m 0755 "${NE_GUEST_AGENT_BIN}" \
    "${TARGET_DIR}/usr/local/bin/ne-guest-agent"
  echo "post-build: installed guest agent from ${NE_GUEST_AGENT_BIN}"
else
  echo "post-build: NE_GUEST_AGENT_BIN unset or missing; rootfs ships without agent"
fi

# ----- workspace mount point ----------------------------------------
# The rootfs boots read-only, so /workspace must exist as a directory
# in the packed image; the inittab below mounts a writable tmpfs over
# it at boot. The guest agent's jail root (JAIL_ROOT=/workspace) writes
# here.
mkdir -p "${TARGET_DIR}/workspace"
echo "post-build: created /workspace mount point"

# ----- writable machine-id ------------------------------------------
# rootfs is read-only, so /etc/machine-id can't be rewritten at runtime.
# Replace it with a symlink into the writable /run tmpfs; the fork
# identity-reset path writes the symlink target. Seed an all-zero
# placeholder so the base image always has a readable machine-id.
mkdir -p "${TARGET_DIR}/run"
rm -f "${TARGET_DIR}/etc/machine-id"
ln -s /run/machine-id "${TARGET_DIR}/etc/machine-id"
echo "post-build: linked /etc/machine-id -> /run/machine-id"

# ----- init wrapper -------------------------------------------------
# Buildroot's busybox-init reads /etc/inittab. Append our agent
# launch + a console getty so an operator can also poke around.
cat > "${TARGET_DIR}/etc/inittab" <<'EOF'
::sysinit:/bin/mount -t proc proc /proc
::sysinit:/bin/mount -t sysfs sysfs /sys
::sysinit:/bin/mount -t devtmpfs devtmpfs /dev
::sysinit:/bin/mkdir -p /dev/pts
::sysinit:/bin/mount -t devpts devpts /dev/pts
::sysinit:/bin/mount -t tmpfs -o size=64m,mode=1777 tmpfs /workspace
::sysinit:/bin/mount -t tmpfs -o size=4m,mode=0755 tmpfs /run
::sysinit:/bin/sh -c '[ -e /run/machine-id ] || echo 00000000000000000000000000000000 > /run/machine-id'

# NeuronEdge Enclave guest agent (vsock listener) — supervised by init.
# If the binary isn't present (early iteration), this line silently
# fails and the rest of init continues.
::respawn:/usr/local/bin/ne-guest-agent

# Console getty for interactive debugging.
ttyS0::respawn:/sbin/getty -L 115200 ttyS0 vt100

# Shutdown handling.
::ctrlaltdel:/sbin/reboot
::shutdown:/bin/umount -a -r
::shutdown:/sbin/swapoff -a
EOF

echo "post-build: wrote /etc/inittab"
