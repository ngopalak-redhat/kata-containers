// Copyright (c) 2026 Kata Contributors
// SPDX-License-Identifier: Apache-2.0

//! Private, full-RAM checkpoints for a live sandbox. Unlike factory templates,
//! these are never cloned or shared between sandboxes.

use super::*;
use anyhow::{bail, ensure};
use nix::sys::statfs::{statfs, BTRFS_SUPER_MAGIC, EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC};
use std::fs::{DirBuilder, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum SuspendState {
    Running,
    Suspended,
}

pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "checkpoint directory must not be a symlink"
    );
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o077 == 0,
        "checkpoint directory must be root-owned with mode 0700"
    );
    Ok(())
}

fn remove_socket(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket(),
                "refusing to remove non-socket {}",
                path.display()
            );
            fs::remove_file(path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

impl QemuInner {
    fn suspend_directory(&self) -> PathBuf {
        Path::new(&self.config.vm_suspend_path).join(&self.id)
    }

    pub(super) fn prepare_suspend_storage(&mut self) -> Result<()> {
        ensure!(
            cfg!(target_arch = "x86_64"),
            "VM suspend currently requires x86_64"
        );
        ensure!(
            matches!(
                self.config.shared_fs.shared_fs.as_deref(),
                None | Some("none")
            ),
            "VM suspend requires shared_fs=none"
        );
        ensure!(
            self.config.boot_info.vm_rootfs_driver == VIRTIO_BLK_PCI
                && self.config.blockdev_info.block_device_driver == VIRTIO_BLK_PCI,
            "VM suspend requires virtio-blk-pci for rootfs and block devices"
        );
        ensure!(
            !self.config.security_info.confidential_guest && !self.config.security_info.rootless,
            "VM suspend does not support confidential or rootless guests"
        );
        ensure!(
            !self.config.memory_info.enable_hugepages
                && !self.config.memory_info.enable_virtio_mem
                && !self.config.memory_info.enable_guest_swap,
            "VM suspend does not support hugepages, virtio-mem or guest swap"
        );
        ensure!(
            !self.config.factory.enable_template
                && !self.config.vm_template.boot_from_template
                && !self.config.vm_template.boot_to_be_template,
            "VM suspend cannot be combined with the VM factory"
        );
        ensure!(
            self.config.debug_info.extra_monitor_socket.is_empty(),
            "VM suspend does not support an extra monitor socket"
        );
        ensure!(
            !self
                .config
                .security_info
                .seccomp_sandbox
                .as_deref()
                .unwrap_or_default()
                .split(',')
                .any(|option| option.trim() == "spawn=deny"),
            "VM suspend uses exec migration; QEMU seccomp spawn=deny is incompatible"
        );
        ensure!(
            !self.id.is_empty()
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid sandbox ID for checkpoint directory"
        );
        let base = Path::new(&self.config.vm_suspend_path);
        ensure!(base.is_absolute(), "vm_suspend_path must be absolute");
        // Administrators provision this root-owned directory on local disk.
        // Do not create a directory through an untrusted parent or use tmpfs.
        private_directory(base)?;
        ensure!(
            fs::canonicalize(base)? == base,
            "vm_suspend_path must be canonical"
        );
        let kind = statfs(base)?.filesystem_type();
        ensure!(
            [EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, BTRFS_SUPER_MAGIC].contains(&kind),
            "vm_suspend_path must be on ext4, XFS or Btrfs, not memory-backed storage"
        );
        DirBuilder::new()
            .mode(0o700)
            .create(self.suspend_directory())
            .context("create private checkpoint directory (existing directories are not reused)")?;
        self.owns_suspend_directory = true;
        self.config.vm_template.device_state_path = self
            .suspend_directory()
            .join("state")
            .to_string_lossy()
            .into_owned();
        Ok(())
    }

    pub(super) fn validate_suspend_device(&self, device: &DeviceType) -> Result<()> {
        ensure!(
            self.suspend_state == SuspendState::Running,
            "resume the VM before changing devices"
        );
        match device {
            DeviceType::BlockModern(_) => Ok(()),
            DeviceType::Vsock(_) | DeviceType::PortDevice(_) if self.qmp.is_none() => Ok(()),
            _ => bail!("device is not supported by VM suspend: {device}"),
        }
    }

    pub(super) async fn restore_suspend_checkpoint(&mut self) -> Result<()> {
        // Recreate devices before loading their state, but only query their
        // PCI paths after migration restores the bridge bus configuration.
        // Keep the source paths in the ledger unchanged, including on failure.
        for device in self.suspend_hotplug_devices.clone() {
            let DeviceType::BlockModern(ref block) = device else {
                bail!("only block devices may be hotplugged with VM suspend");
            };
            ensure!(
                block.lock().await.config.pci_path.is_some(),
                "checkpoint block device has no recorded PCI address"
            );
            self.hotplug_device(device).await?;
        }
        self.boot_from_template()
            .await
            .context("load suspended VM checkpoint")?;

        let qmp = self
            .qmp
            .as_mut()
            .context("no QMP for restored PCI validation")?;
        for device in &self.suspend_hotplug_devices {
            let DeviceType::BlockModern(block) = device else {
                bail!("only block devices may be hotplugged with VM suspend");
            };
            let (index, expected) = {
                let block = block.lock().await;
                (block.config.index, block.config.pci_path.clone())
            };
            let node = block_node_name(index);
            let restored = qmp
                .get_device_by_qdev_id(&node)
                .with_context(|| format!("query restored PCI address for {node}"))?;
            ensure!(
                expected.as_ref() == Some(&restored),
                "restored block device {node} PCI address differs from checkpoint: expected {expected:?}, got {restored:?}"
            );
            info!(
                sl!(),
                "verified restored block device {} PCI path: {}", node, restored
            );
        }
        Ok(())
    }

    pub(super) async fn retire_qemu(&mut self) -> Result<()> {
        self.retiring.store(true, AtomicOrdering::SeqCst);
        let mut process = self.qemu_process.lock().await;
        if let Some(child) = process.as_mut() {
            child.kill().await.context("terminate checkpointed QEMU")?;
            child.wait().await.context("reap checkpointed QEMU")?;
        }
        process.take();
        self.qmp.take();
        Ok(())
    }

    async fn cancel_suspend(&mut self) -> Result<()> {
        let qmp = self.qmp.as_mut().context("no source QMP for rollback")?;
        qmp.cancel_migration()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match qmp.execute_query_migrate().await?.status {
                None
                | Some(
                    MigrationStatus::none
                    | MigrationStatus::completed
                    | MigrationStatus::failed
                    | MigrationStatus::cancelled,
                ) => break,
                _ => ensure!(
                    Instant::now() < deadline,
                    "timed out cancelling checkpoint migration"
                ),
            }
            sleep(Duration::from_millis(20)).await;
        }
        Ok(())
    }

    pub(crate) async fn suspend_vm(&mut self) -> Result<()> {
        ensure!(self.config.enable_vm_suspend, "VM suspend is disabled");
        if self.suspend_state == SuspendState::Suspended {
            return Ok(());
        }
        ensure!(
            !self.suspend_topology_changed,
            "VM suspend cannot restore a topology after device removal"
        );
        for device in &self.suspend_hotplug_devices {
            ensure!(
                matches!(device, DeviceType::BlockModern(_)),
                "unsupported hotplug topology for VM suspend"
            );
        }
        private_directory(&self.suspend_directory())?;
        let checkpoint = self.suspend_directory().join("state");
        let pending = self.suspend_directory().join("state.next");
        // Remove only our own incomplete checkpoint, left by an earlier failure.
        if pending.exists() {
            fs::remove_file(&pending)?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        self.pause_vm()?; // QMP stop: no guest CPU runs while we serialize RAM.
        self.config.vm_template.device_state_path = pending.to_string_lossy().into_owned();
        let saved = async {
            // boot_to_be_template stays false: x-ignore-shared would omit RAM.
            self.save_vm().await?;
            file.sync_all().context("sync checkpoint")?;
            fs::rename(&pending, &checkpoint)?;
            File::open(self.suspend_directory())?.sync_all()?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        self.config.vm_template.device_state_path = checkpoint.to_string_lossy().into_owned();
        if let Err(error) = saved {
            self.cancel_suspend()
                .await
                .with_context(|| format!("checkpoint failed ({error:#}); rollback failed"))?;
            self.resume_vm()
                .context("resume source after checkpoint failure")?;
            return Err(error.context("checkpoint failed; source VM resumed"));
        }
        // Only a durable, complete checkpoint permits releasing guest RAM.
        self.suspend_state = SuspendState::Suspended;
        self.retire_qemu().await?;
        // This is only a cache hint. The VM's anonymous RAM is gone after reap;
        // any remaining file cache is reclaimable by the host kernel.
        let result =
            unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
        if result != 0 {
            warn!(sl!(), "checkpoint cache eviction hint failed: {}", result);
        }
        Ok(())
    }

    pub(crate) async fn restore_vm(&mut self) -> Result<()> {
        ensure!(self.config.enable_vm_suspend, "VM suspend is disabled");
        if self.suspend_state == SuspendState::Running {
            // Also permits recovery when checkpoint rollback or agent reconnect
            // failed after a previous request. No second QEMU is launched.
            return self.cancel_suspend().await;
        }
        ensure!(
            Path::new(&self.config.vm_template.device_state_path).is_file(),
            "checkpoint is missing"
        );
        ensure!(
            Path::new(&self.config.path).is_file(),
            "QEMU binary is missing"
        );
        // A cancelled request can leave the source or a provisional destination
        // alive. Reap it before acquiring the original CID or opening disks.
        self.retire_qemu().await?;
        remove_socket(Path::new(&get_qmp_socket_path(&self.id)))?;
        remove_socket(&Path::new(&get_jailer_root(&self.id)).join("console.sock"))?;
        self.retiring = Arc::new(AtomicBool::new(true));
        self.config.vm_template.boot_from_template = true;
        let result = self.start_vm(0).await;
        self.config.vm_template.boot_from_template = false;
        if let Err(error) = result {
            self.retire_qemu()
                .await
                .context("clean up failed restore")?;
            return Err(error.context("restore failed; checkpoint retained for retry"));
        }
        self.suspend_state = SuspendState::Running;
        self.retiring.store(false, AtomicOrdering::SeqCst);
        Ok(())
    }

    pub(super) fn cleanup_suspend(&self) -> Result<()> {
        let directory = self.suspend_directory();
        if directory.exists() {
            private_directory(&directory)?;
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::driver::{BlockConfigModern, BlockDeviceModern};
    use serde_json::{json, Value};
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::Mutex as StdMutex;

    // Model query-pci's omission of bridge children before incoming migration
    // restores PCI_SECONDARY_BUS. Consume JSON as a stream because add-fd's
    // SCM_RIGHTS message is not newline terminated.
    fn restore_peer(
        directory: &Path,
        initially_loaded: bool,
        wrong_slot: bool,
        missing_device: bool,
    ) -> (Qmp, Arc<StdMutex<Vec<Value>>>) {
        let listener = UnixListener::bind(directory.join("restore.sock")).unwrap();
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let recorded = requests.clone();
        std::thread::spawn(move || {
            let (mut writer, _) = listener.accept().unwrap();
            writeln!(writer, "{}", json!({"QMP": {"version": {"qemu": {"major": 10, "minor": 1, "micro": 0}, "package": "test"}, "capabilities": []}})).unwrap();
            let reader = io::BufReader::new(writer.try_clone().unwrap());
            let mut loaded = initially_loaded;
            let mut devices = Vec::new();
            let mut fdset = 0;
            for request in serde_json::Deserializer::from_reader(reader).into_iter::<Value>() {
                let Ok(request) = request else { break };
                recorded.lock().unwrap().push(request.clone());
                let response = match request["execute"].as_str().unwrap() {
                    "qmp_capabilities" | "blockdev-add" => json!({}),
                    "query-fdsets" => json!([]),
                    "add-fd" => {
                        fdset += 1;
                        json!({"fdset-id": fdset, "fd": 100 + fdset})
                    }
                    "device_add" => {
                        let args = &request["arguments"];
                        assert_eq!(args["bus"], "pci-bridge-0");
                        let slot = i64::from_str_radix(args["addr"].as_str().unwrap(), 16).unwrap();
                        assert!(!devices.iter().any(|d: &Value| d["slot"] == slot));
                        devices.push(json!({
                            "bus": 1, "slot": slot, "function": 0, "qdev_id": args["id"],
                            "class_info": {"class": 256}, "id": {"vendor": 6900, "device": 4097},
                            "irq_pin": 1, "regions": []
                        }));
                        json!({})
                    }
                    "migrate-incoming" => {
                        assert_eq!(devices.len(), 2, "both disks must exist before loading");
                        loaded = true;
                        json!({})
                    }
                    "query-migrate" => json!({"status": "completed"}),
                    "query-pci" => {
                        let range = json!({"base": 0, "limit": 0});
                        let mut bridge = json!({"bus": {
                            "number": 0, "secondary": if loaded {1} else {0},
                            "subordinate": if loaded {1} else {0},
                            "io_range": range, "memory_range": range, "prefetchable_range": range
                        }});
                        if loaded {
                            let mut visible = devices.clone();
                            if wrong_slot {
                                visible[0]["slot"] = json!(3);
                            }
                            if missing_device {
                                visible.clear();
                            }
                            bridge["devices"] = json!(visible);
                        }
                        json!([{"bus": 0, "devices": [{
                            "bus": 0, "slot": 2, "function": 0, "qdev_id": "pci-bridge-0",
                            "class_info": {"class": 1540}, "id": {"vendor": 6900, "device": 1},
                            "irq_pin": 0, "regions": [], "pci_bridge": bridge
                        }]}])
                    }
                    other => panic!("unexpected restore QMP command: {}", other),
                };
                if writeln!(
                    writer,
                    "{}",
                    json!({"return": response, "id": request["id"]})
                )
                .is_err()
                {
                    break;
                }
            }
        });
        let mut qmp = Qmp::new(directory.join("restore.sock").to_str().unwrap()).unwrap();
        qmp.init_pci_bridges(1);
        (qmp, requests)
    }

    fn restore_fixture(directory: &Path, qmp: Qmp) -> QemuInner {
        let (notify, _) = mpsc::channel(1);
        let mut vm = QemuInner::new(notify);
        vm.qmp = Some(qmp);
        vm.config.enable_vm_suspend = true;
        vm.config.vm_template.boot_from_template = true;
        vm.config.vm_template.device_state_path = directory.join("state").to_string_lossy().into();
        vm.config.blockdev_info.block_device_driver = VIRTIO_BLK_PCI.into();
        for index in 1..=2 {
            let path = directory.join(format!("disk-{index}"));
            fs::write(&path, vec![0u8; 512]).unwrap();
            vm.suspend_hotplug_devices
                .push(DeviceType::BlockModern(Arc::new(Mutex::new(
                    BlockDeviceModern {
                        config: BlockConfigModern {
                            index,
                            path_on_host: path.to_string_lossy().into(),
                            is_direct: Some(false),
                            pci_path: Some(
                                PciPath::try_from(format!("02/0{index}").as_str()).unwrap(),
                            ),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                ))));
        }
        vm
    }

    #[tokio::test]
    async fn restore_defers_pci_discovery_until_checkpoint_loaded() {
        let directory = tempfile::tempdir().unwrap();
        let (qmp, requests) = restore_peer(directory.path(), false, false, false);
        let mut vm = restore_fixture(directory.path(), qmp);
        vm.restore_suspend_checkpoint().await.unwrap();
        let calls = requests.lock().unwrap();
        let commands: Vec<_> = calls
            .iter()
            .map(|r| r["execute"].as_str().unwrap())
            .collect();
        assert_eq!(
            commands,
            [
                "qmp_capabilities",
                "query-fdsets",
                "add-fd",
                "blockdev-add",
                "device_add",
                "add-fd",
                "blockdev-add",
                "device_add",
                "migrate-incoming",
                "query-migrate",
                "query-pci",
                "query-pci",
            ]
        );
        let slots: Vec<_> = calls
            .iter()
            .filter(|r| r["execute"] == "device_add")
            .map(|r| r["arguments"]["addr"].as_str().unwrap())
            .collect();
        assert_eq!(slots, ["01", "02"]);
    }

    #[tokio::test]
    async fn restore_rejects_wrong_or_missing_pci_path_without_changing_ledger() {
        for missing in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let (qmp, requests) = restore_peer(directory.path(), false, !missing, missing);
            let mut vm = restore_fixture(directory.path(), qmp);
            let error = vm.restore_suspend_checkpoint().await.unwrap_err();
            if missing {
                assert!(format!("{error:#}").contains("query restored PCI address for drive-1"));
            } else {
                assert!(error
                    .to_string()
                    .contains("PCI address differs from checkpoint"));
            }
            for (i, device) in vm.suspend_hotplug_devices.iter().enumerate() {
                let DeviceType::BlockModern(block) = device else {
                    unreachable!()
                };
                assert_eq!(
                    block
                        .lock()
                        .await
                        .config
                        .pci_path
                        .as_ref()
                        .unwrap()
                        .to_string(),
                    format!("02/0{}", i + 1)
                );
            }
            assert!(!requests
                .lock()
                .unwrap()
                .iter()
                .any(|r| r["execute"] == "cont"));
        }
    }

    #[tokio::test]
    async fn ordinary_hotplug_still_discovers_pci_path_immediately() {
        let directory = tempfile::tempdir().unwrap();
        let (qmp, requests) = restore_peer(directory.path(), true, false, false);
        let mut vm = restore_fixture(directory.path(), qmp);
        vm.config.vm_template.boot_from_template = false;
        let device = vm.suspend_hotplug_devices[0].clone();
        let DeviceType::BlockModern(block) = &device else {
            unreachable!()
        };
        block.lock().await.config.pci_path = None;
        vm.hotplug_device(device.clone()).await.unwrap();
        assert_eq!(
            block
                .lock()
                .await
                .config
                .pci_path
                .as_ref()
                .unwrap()
                .to_string(),
            "02/01"
        );
        assert_eq!(
            requests.lock().unwrap().last().unwrap()["execute"],
            "query-pci"
        );
    }

    // Exercise the actual stop/save/rollback sequence without a KVM guest.
    // This QMP peer writes a fixture, not a valid QEMU migration stream.
    fn qmp_peer(directory: &Path, fail: bool) -> (Qmp, Arc<StdMutex<Vec<String>>>) {
        let socket = directory.join("test-qmp.sock");
        let pending = directory.join("state.next");
        let listener = UnixListener::bind(&socket).unwrap();
        let commands = Arc::new(StdMutex::new(Vec::new()));
        let recorded = commands.clone();
        std::thread::spawn(move || {
            let (mut writer, _) = listener.accept().unwrap();
            writeln!(writer, "{}", serde_json::json!({"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}, "package": "test"}, "capabilities": []}})).unwrap();
            let reader = io::BufReader::new(writer.try_clone().unwrap());
            let mut cancelled = false;
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                let command = request["execute"].as_str().unwrap();
                recorded.lock().unwrap().push(command.to_owned());
                let response = match command {
                    "query-fdsets" => serde_json::json!([]),
                    "migrate" => {
                        fs::write(&pending, b"checkpoint fixture").unwrap();
                        serde_json::json!({})
                    }
                    "migrate_cancel" => {
                        cancelled = true;
                        serde_json::json!({})
                    }
                    "query-migrate" => {
                        serde_json::json!({"status": if cancelled { "cancelled" } else if fail { "failed" } else { "completed" }})
                    }
                    "qmp_capabilities" | "stop" | "cont" => serde_json::json!({}),
                    other => panic!("unexpected QMP command: {}", other),
                };
                if writeln!(
                    writer,
                    "{}",
                    serde_json::json!({"return": response, "id": request["id"]})
                )
                .is_err()
                {
                    break;
                }
            }
        });
        (Qmp::new(socket.to_str().unwrap()).unwrap(), commands)
    }

    async fn source_vm(directory: &Path, qmp: Qmp) -> (QemuInner, mpsc::Receiver<()>) {
        let (notify, waiter) = mpsc::channel(1);
        let mut vm = QemuInner::new(notify.clone());
        vm.id = "sandbox".into();
        vm.config.enable_vm_suspend = true;
        vm.config.vm_suspend_path = directory.parent().unwrap().to_string_lossy().into_owned();
        vm.config.vm_template.device_state_path =
            directory.join("state").to_string_lossy().into_owned();
        vm.qmp = Some(qmp);
        let mut child = Command::new("sleep")
            .arg("60")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        tokio::spawn(log_qemu_stderr(
            child.stderr.take().unwrap(),
            notify,
            vm.retiring.clone(),
        ));
        vm.qemu_process = Mutex::new(Some(child));
        (vm, waiter)
    }

    // Directory ownership validation intentionally requires root, as does Kata.
    #[tokio::test]
    #[ignore = "requires root; run with cargo test -p hypervisor -- --ignored"]
    async fn checkpoint_reaps_source_without_reporting_task_exit() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("sandbox");
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let (qmp, commands) = qmp_peer(&dir, false);
        let (mut vm, mut waiter) = source_vm(&dir, qmp).await;
        vm.suspend_vm().await.unwrap();
        assert_eq!(vm.suspend_state, SuspendState::Suspended);
        assert!(vm.qemu_process.lock().await.is_none());
        assert_eq!(fs::read(dir.join("state")).unwrap(), b"checkpoint fixture");
        assert!(!dir.join("state.next").exists());
        assert!(
            tokio::time::timeout(Duration::from_millis(50), waiter.recv())
                .await
                .is_err()
        );
        let calls = commands.lock().unwrap().clone();
        assert_eq!(&calls[2..], &["stop", "migrate", "query-migrate"]);
        assert!(!calls.contains(&"migrate-set-capabilities".into()));
        // A failed destination launch must preserve the committed checkpoint.
        vm.config.path = "/nonexistent/qemu-suspend-test".into();
        assert!(vm.restore_vm().await.is_err());
        assert_eq!(vm.suspend_state, SuspendState::Suspended);
        assert!(dir.join("state").is_file());
    }

    #[tokio::test]
    #[ignore = "requires root; run with cargo test -p hypervisor -- --ignored"]
    async fn failed_checkpoint_resumes_original_process() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("sandbox");
        DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let (qmp, commands) = qmp_peer(&dir, true);
        let (mut vm, _) = source_vm(&dir, qmp).await;
        let pid = vm.get_vmm_master_tid().await.unwrap();
        assert!(vm.suspend_vm().await.is_err());
        assert_eq!(vm.get_vmm_master_tid().await.unwrap(), pid);
        assert_eq!(vm.suspend_state, SuspendState::Running);
        assert!(!dir.join("state").exists());
        assert!(commands.lock().unwrap().ends_with(&[
            "migrate_cancel".into(),
            "query-migrate".into(),
            "cont".into()
        ]));
        vm.stop_vm().await.unwrap();
    }

    #[test]
    fn migration_shell_paths_are_quoted() {
        let path = "/disk/a 'quote'; $(touch unwanted)\nstate";
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf %s {}", shell_quote(path)))
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, path.as_bytes());
    }

    #[test]
    fn socket_cleanup_refuses_regular_files_and_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        fs::write(&path, b"keep").unwrap();
        assert!(remove_socket(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"keep");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(remove_socket(&link).is_err());
    }
}
