# Experimental QEMU suspend/resume (runtime-rs)

This opt-in implementation maps containerd task Pause/Resume to a private VM
checkpoint. It keeps the shim, containerd task, sandbox resources and block
devices allocated. The guest process resumes from its saved memory; it is not
recreated with CreateContainer.

This code needs end-to-end validation on a Linux x86_64 KVM host before use with
important workloads. It is not a Kubernetes integration or a durable recovery
mechanism for host reboots or shim failures.

## Configuration

Build and install the modified **Rust** shim. The Go runtime does not implement
this option. In the configuration selected by that shim, set:

```toml
[hypervisor.qemu]
enable_vm_suspend = true             # defaults to false
vm_suspend_path = "/var/lib/kata-containers/suspend"
shared_fs = "none"
block_device_driver = "virtio-blk-pci"
vm_rootfs_driver = "virtio-blk-pci"
enable_virtio_mem = false
enable_hugepages = false
enable_guest_swap = false

[runtime]
static_sandbox_resource_mgmt = true
use_passfd_io = false
```

Keep factory `enable_template` disabled. This implementation reuses the QEMU
save/incoming-migration operations used by templating, but saves a running VM's
full RAM and device state in a per-sandbox checkpoint. A factory template is an
initial boot state and cannot resume an existing application.

Provision the checkpoint base directory on local ext4, XFS or Btrfs:

```sh
sudo install -d -o root -g root -m 0700 /var/lib/kata-containers/suspend
```

Use a canonical absolute path. The directory contains guest RAM (including any
application secrets). The implementation creates private subdirectories and
0600 checkpoint files; it does not encrypt checkpoints. Allocate disk space for
the VM's RAM and device state, plus the previous checkpoint during a subsequent
suspend. RAM-backed filesystems are rejected. SELinux must allow QEMU access to
this directory; the implementation does not change host policy.

The existing save/load transport uses `exec:cat`. QEMU seccomp `spawn=deny` is
therefore rejected. If using QEMU seccomp, configure its spawn policy explicitly
to permit this transport. No seccomp settings are changed automatically.

## Supported experiment

- One container per sandbox; launch with `ctr run --detach --null-io`.
- x86_64 QEMU, ordinary guests, fixed CPU/memory allocation, no rootless mode.
- Block-backed container rootfs (for example the already configured EROFS
  snapshotter). Neither EROFS nor virtio-fs is the checkpoint storage format.
- No guest networking devices, shared filesystem devices, VFIO, or vhost-user
  devices. No active or retained exec sessions at suspension. A completed
  synchronous `ctr tasks exec` removes its exec session and is suitable for
  inspecting the container before/after suspension.
- No device removal/replacement or resource resizing between checkpoints.
  Resume before kill/delete or other guest RPCs.

Keep the same QEMU binary, kernel, rootfs and attached block device contents for
the duration of the experiment. Do not reuse the checkpoint for another VM or
modify its block devices while suspended. Restoring requires the original vsock
CID to be available; if another VM takes it, restore fails without deleting the
checkpoint.

## Interactive timing and continuity test

Use an image already present in the selected containerd namespace and EROFS
snapshotter. It must provide `sh`, `cat`, `mkdir`, `mv`, and `sleep`.

```sh
sudo python3 tests/functional/qemu-suspend.py \
  --runtime YOUR_CONFIGURED_RUST_KATA_RUNTIME \
  --image YOUR_LOCAL_IMAGE --snapshotter erofs
```

The script creates a direct containerd container with an in-memory counter,
suspends it, prints elapsed milliseconds and waits for Enter before resuming.
It verifies that the source QEMU PID exited, that containerd retained a paused
task, and that guest boot identity, application identity and counter continuity
survive restore. It performs two cycles by default (`--cycles N`), then checks
normal kill/delete. On failure it leaves the task for inspection. `--no-prompt`
is available for automated runs.

When `--runtime-config-path` is supplied, the script also verifies a newly
published QEMU migration checkpoint (`QEVM`, format version 3), records its size
and SHA256, and checks that the replacement QEMU was launched with
`-incoming defer -S`. The checkpoint must remain unchanged during resume. These
checks run outside the timed Pause/Resume RPCs; hashing reads the checkpoint
into the host page cache, so these runs are functional checks, not cold-cache
latency benchmarks. Checkpoint inspection requires Python 3.11 or later.

Factory template cloning remains disabled. This experiment reuses `save_vm()`
and `boot_from_template()` to save and load a private running-VM checkpoint.
The migration-file header and command line alone do not prove application
continuity; the workload checks are required too.

For exact comparisons of selected application state, use the stronger test:

```sh
sudo python3.11 tests/functional/qemu-suspend-state.py \
  --namespace YOUR_CONTAINERD_NAMESPACE \
  --runtime YOUR_CONFIGURED_RUST_KATA_RUNTIME \
  --runtime-config-path /path/to/configuration-qemu-runtime-rs.toml \
  --image YOUR_LOCAL_IMAGE --snapshotter erofs \
  --evidence-dir /path/to/new-evidence-directory
```

This requires `bash` and coreutils in the image. It performs two automatic
cycles and compares a fresh challenge response from the main process before
and after each suspend: a random shell variable, command-driven counter, guest
boot ID, PID/start time, and an unlinked open file's inode, flags and offset.
The next read must return the next unread line and advance the saved offset
exactly. It writes the observations and checkpoint evidence to
`state-proof.json`. It verifies these selected fields, not a byte-for-byte
comparison of all guest RAM.

For an existing compatible task:

```sh
time ctr tasks pause CONTAINER_ID
read -r -p 'Press Enter to resume: '
time ctr tasks resume CONTAINER_ID
```

The Rust shim also logs `suspend_duration_ms` and `resume_duration_ms` on
successful requests. Script timings include the containerd RPC round trip;
runtime log timings cover the runtime operation. No latency figures are claimed
until this is run on the target host.

## Code path and failure handling

1. `VirtContainerManager::pause_container` selects the opt-in path, checks the
   container/exec/I/O restrictions and suspends the agent transport. Default
   pause still calls the guest's PauseContainer cgroup freezer.
2. `QemuInner::suspend_vm` sends QMP `stop`, then calls `save_vm`, which sends
   `migrate` and waits for completion. Unlike factory templates,
   `x-ignore-shared` is not enabled: RAM must be included. The checkpoint is
   synced and committed before QEMU is terminated and reaped.
3. Intentional QEMU exit is excluded from the sandbox exit notification. The
   host releases that QEMU process's anonymous RAM and vCPU threads. The shim,
   disks and reclaimable checkpoint file cache remain; this does not promise
   that all sandbox memory disappears from host accounting immediately.
4. `QemuInner::restore_vm` starts a new QEMU with `-S -incoming defer`, preserves
   the vsock CID and replays hotplugged blocks in order, reserving each slot.
   `boot_from_template` sends `migrate-incoming` and waits for completion.
   Only then are the disks' PCI paths checked against the source paths, while
   the CPUs remain stopped. Before migration restores PCI bridge bus numbers,
   QEMU's `query-pci` can omit devices behind those bridges.
5. The manager reapplies host cgroups, updates the exposed QEMU PID, sends QMP
   `cont`, reconnects the agent and sets the task Running. WaitProcess, health
   checks and the OOM subscription reconnect; mutating RPCs and byte streams
   are not replayed. OOM event delivery is best effort across disconnection.

Checkpoint failure cancels migration and resumes the original VM. Restore
failure keeps the task paused and retains the checkpoint for a retry. If agent
reconnection fails after QEMU starts, another Resume reconnects to that same
VM. The topology ledger lives in the shim: persistent checkpoint files alone
are insufficient to recover after losing the shim.

## Validation

On Linux, run:

```sh
cargo test -p kata-types --lib test_vm_suspend
cargo test -p agent suspend_tests
cargo test -p hypervisor qemu::inner::suspend::tests
sudo -E cargo test -p hypervisor qemu::inner::suspend::tests -- --ignored
```

The root-only QMP fixture tests cover successful source termination without an
exit event, save failure rollback, and retaining the checkpoint when restore
cannot start. The unprivileged restore fixtures cover two-disk replay before
migration, PCI validation after loading, rejecting missing or misplaced disks,
and preserving ordinary hotplug's immediate PCI lookup. They do not simulate a
real QEMU migration stream. The interactive
test above is required to validate actual guest restoration and measure latency.
