# Copyright (c) 2026 Kata Contributors
# SPDX-License-Identifier: Apache-2.0
"""Read-only checkpoint evidence shared by the QEMU suspend smoke tests.

This verifies migration-file and process evidence. It is not a migration-stream
parser; restored application-state checks provide the separate continuity proof.
"""

import hashlib
import os
from pathlib import Path
import stat
import struct


class CheckpointAudit:
    def __init__(self, config_path, sandbox_id):
        try:
            import tomllib
        except ModuleNotFoundError as error:
            raise RuntimeError("checkpoint verification requires Python 3.11 or later") from error
        config = tomllib.loads(Path(config_path).read_text())
        qemu = config["hypervisor"]["qemu"]
        if not qemu.get("enable_vm_suspend"):
            raise RuntimeError("checkpoint verification requires enable_vm_suspend=true")
        if (config.get("factory", {}).get("enable_template", False)
                or qemu.get("boot_to_be_template", False)
                or qemu.get("boot_from_template", False)):
            raise RuntimeError("this experiment requires factory/template boot options disabled")
        self.path = Path(qemu["vm_suspend_path"]) / sandbox_id / "state"
        if self.path.exists():
            raise RuntimeError(f"new task already has a checkpoint: {self.path}")
        self.previous = None
        self.saved = None

    @staticmethod
    def _identity(metadata):
        return (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_size)

    def before_suspend(self):
        self.previous = self._identity(self.path.stat()) if self.path.exists() else None

    def _inspect(self):
        fd = os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 8:
                raise RuntimeError("checkpoint is not a nonempty regular file")
            header = stream.read(8)
            # QEMU v10.1.0 migration/savevm.h and qemu_savevm_state_header():
            # big-endian QEMU_VM_FILE_MAGIC and QEMU_VM_FILE_VERSION.
            magic, version = struct.unpack(">II", header)
            if magic != 0x5145564D or version != 3:
                raise RuntimeError(f"unexpected QEMU migration header: {header.hex()}")
            digest = hashlib.sha256(header)
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
            if self._identity(before) != self._identity(os.fstat(stream.fileno())):
                raise RuntimeError("checkpoint changed while being inspected")
        return dict(path=str(self.path), size_bytes=before.st_size, inode=before.st_ino,
                    device=before.st_dev, mtime_ns=before.st_mtime_ns,
                    magic="QEVM", version=version, sha256=digest.hexdigest())

    def suspended(self):
        if self.path.with_name("state.next").exists():
            raise RuntimeError("an unfinished state.next checkpoint remains")
        if self.previous == self._identity(self.path.stat()):
            raise RuntimeError("suspend did not publish a new checkpoint")
        self.saved = self._inspect()
        return dict(checkpoint=self.saved, factory_template_enabled=False,
                    method="private-running-VM-checkpoint")

    def resumed(self, qemu_pid):
        if self.saved is None or self._inspect() != self.saved:
            raise RuntimeError("checkpoint changed or disappeared during resume")
        argv = Path(f"/proc/{qemu_pid}/cmdline").read_bytes().rstrip(b"\0").split(b"\0")
        incoming = any(argv[i:i + 2] == [b"-incoming", b"defer"] for i in range(len(argv) - 1))
        if not incoming or b"-S" not in argv:
            raise RuntimeError("restored QEMU was not started with -incoming defer -S")
        return dict(incoming_defer=True, start_paused=True, checkpoint_unchanged=True,
                    qemu_argv=[arg.decode(errors="replace") for arg in argv])
