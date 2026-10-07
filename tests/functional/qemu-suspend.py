#!/usr/bin/env python3
# Copyright (c) 2026 Kata Contributors
# SPDX-License-Identifier: Apache-2.0
"""Interactive, direct-containerd smoke test for runtime-rs QEMU suspend.

Requires an already configured opt-in runtime, EROFS snapshotter and a locally
available image with sh, cat, mkdir, mv, sleep. Leaves the container for inspection
on failure; removes it after a successful test. Does not create Kubernetes pods.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="already pulled image reference")
    parser.add_argument("--runtime", required=True, help="containerd runtime using the patched Rust shim")
    parser.add_argument("--runtime-config-path", help="explicit Kata config passed through containerd runtime options")
    parser.add_argument("--ctr", default="ctr", help="ctr binary path (useful with sudo secure_path)")
    parser.add_argument("--address", default="/run/containerd/containerd.sock")
    parser.add_argument("--evidence-file", type=Path, help="record the task identity before creation for failure recovery")
    parser.add_argument("--command-timeout", type=int, default=600)
    parser.add_argument("--snapshotter", default="erofs")
    parser.add_argument("--namespace", default="default")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--no-prompt", action="store_true", help="resume automatically after a short pause")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run on the Linux Kata host as root")
    if args.cycles < 1:
        parser.error("--cycles must be positive")
    if args.command_timeout < 1:
        parser.error("--command-timeout must be positive")
    cid = "kata-suspend-" + uuid.uuid4().hex[:12]
    base = [args.ctr, "--address", args.address, "--namespace", args.namespace]
    if args.evidence_file:
        args.evidence_file.write_text(json.dumps(dict(container_id=cid, namespace=args.namespace,
            address=args.address, runtime=args.runtime, config=args.runtime_config_path)) + "\n")

    def ctr(*command):
        return subprocess.run(base + list(command), input="", text=True,
                              stdout=subprocess.PIPE, check=True,
                              timeout=args.command_timeout).stdout.strip()

    def task():
        for row in ctr("tasks", "list").splitlines()[1:]:
            values = row.split()
            if values[0] == cid:
                return int(values[1]), values[2].upper()
        raise RuntimeError(f"task {cid} disappeared")

    def identity(pid):
        try:
            # Include start time so PID reuse is not mistaken for the old VM.
            stat = Path(f"/proc/{pid}/stat").read_text()
            return stat.rsplit(")", 1)[1].split()[19]
        except FileNotFoundError:
            return None

    def probe():
        result = ctr("tasks", "exec", "--exec-id", "probe-" + uuid.uuid4().hex[:8],
                     cid, "sh", "-c", "cat /tmp/suspend-probe/token /proc/sys/kernel/random/boot_id /tmp/suspend-probe/pid /tmp/suspend-probe/count")
        values = result.splitlines()
        if len(values) != 4:
            raise RuntimeError(f"unexpected probe result: {result!r}")
        return values[:3], int(values[3])

    print(f"Creating {cid}", flush=True)
    runtime_options = ["--runtime-config-path", args.runtime_config_path] if args.runtime_config_path else []
    try:
        ctr("run", "--detach", "--null-io", "--runtime", args.runtime, *runtime_options,
        "--snapshotter", args.snapshotter, args.image, cid, "sh", "-c",
        "mkdir -p /tmp/suspend-probe; "
        "cat /proc/sys/kernel/random/uuid > /tmp/suspend-probe/token; "
        "echo $$ > /tmp/suspend-probe/pid; n=0; "
        "while :; do n=$((n+1)); echo $n > /tmp/suspend-probe/next; "
        "mv /tmp/suspend-probe/next /tmp/suspend-probe/count; sleep 1; done")
        time.sleep(2)
        for cycle in range(1, args.cycles + 1):
            before, count = probe()  # ctr removes this exec before returning.
            pid, state = task()
            if state != "RUNNING" or "qemu" not in Path(f"/proc/{pid}/comm").read_text():
                raise RuntimeError("expected a running task backed by QEMU")
            source = identity(pid)
            started = time.monotonic_ns()
            ctr("tasks", "pause", cid)
            suspend_ms = (time.monotonic_ns() - started) / 1_000_000
            if task()[1] != "PAUSED" or identity(pid) == source:
                raise RuntimeError("suspend did not leave a PAUSED task with source QEMU gone")
            print(f"Suspended: {suspend_ms:.3f} ms; source QEMU {pid} exited.", flush=True)
            if args.no_prompt:
                time.sleep(2)
            else:
                input("Press Enter to resume the same container: ")
            started = time.monotonic_ns()
            ctr("tasks", "resume", cid)
            resume_ms = (time.monotonic_ns() - started) / 1_000_000
            restored_pid, state = task()
            if state != "RUNNING" or identity(restored_pid) is None:
                raise RuntimeError("resume did not restore a running QEMU task")
            time.sleep(2)
            after, new_count = probe()
            if before != after or new_count <= count:
                raise RuntimeError("guest/container identity changed or in-memory counter did not advance")
            print(json.dumps(dict(cycle=cycle, suspend_ms=suspend_ms, resume_ms=resume_ms,
                                  source_qemu_pid=pid, restored_qemu_pid=restored_pid,
                                  count_before=count, count_after=new_count)), flush=True)
        ctr("tasks", "kill", "--signal", "SIGKILL", cid)
        deadline = time.monotonic() + 15
        while task()[1] != "STOPPED":
            if time.monotonic() > deadline:
                raise RuntimeError("task did not stop after SIGKILL")
            time.sleep(0.1)
        ctr("tasks", "delete", cid)
        ctr("containers", "delete", cid)
    except BaseException:
        print(f"Left {cid} in namespace {args.namespace} for inspection. "
              "Resume it before kill/delete if it is PAUSED.", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
