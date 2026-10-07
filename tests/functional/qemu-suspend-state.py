#!/usr/bin/env python3
# Copyright (c) 2026 Kata Contributors
# SPDX-License-Identifier: Apache-2.0
"""Verify application and kernel file-descriptor state across QEMU suspend.

Requires Linux root, Python 3.11+, the opt-in Rust shim, and an image with bash
and coreutils.
Uses a new direct-containerd task, with no Kubernetes resources. Successful runs
delete their task; failures retain it and save evidence for inspection.
"""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

from qemu_suspend_checks import CheckpointAudit


WORKLOAD = r'''
dir=/dev/shm/kata-state-proof
mkdir -p "$dir"
# These values are generated on each process start, not supplied in argv or
# recovered from files. The counter changes only in response to a request.
secret=$(cat /proc/sys/kernel/random/uuid)
first=$(cat /proc/sys/kernel/random/uuid)
second=$(cat /proc/sys/kernel/random/uuid)
third=$(cat /proc/sys/kernel/random/uuid)
counter=0
printf '%s\n' "$first" "$second" "$third" > "$dir/data"
exec 8< "$dir/data"
rm "$dir/data"
IFS= read -r last_read <&8

report() {
    read -r boot_id < /proc/sys/kernel/random/boot_id
    read -r -a process_stat < "/proc/$$/stat"
    fd_pos= fd_inode= fd_flags=
    while read -r key value; do
        case "$key" in
            pos:) fd_pos=$value ;;
            ino:) fd_inode=$value ;;
            flags:) fd_flags=$value ;;
        esac
    done < "/proc/$$/fdinfo/8"
    link=$(readlink "/proc/$$/fd/8")
    [[ ! -e "$dir/data" ]]
    printf '%s\n' "$nonce" "$secret" "$boot_id" "$$" "${process_stat[21]}" \
        "$counter" "$fd_pos" "$fd_inode" "$fd_flags" "$link" "$last_read" \
        "$first" "$second" "$third" > "$dir/reply.next"
    mv "$dir/reply.next" "$dir/reply"
}

touch "$dir/ready"
while :; do
    if [[ -f "$dir/request" ]]; then
        read -r operation nonce < "$dir/request"
        rm "$dir/request"
        case "$operation" in
            snapshot) ;;
            bump) counter=$((counter + 17)) ;;
            read) IFS= read -r last_read <&8; counter=$((counter + 1)) ;;
            *) exit 20 ;;
        esac
        report
    fi
    sleep 0.05
done
'''

REQUEST = r'''
dir=/dev/shm/kata-state-proof
for ((i=0; i<200; i++)); do
    [[ -f "$dir/ready" ]] && break
    sleep 0.05
done
[[ -f "$dir/ready" ]]
rm -f "$dir/reply"
printf '%s %s\n' "$1" "$2" > "$dir/request.next"
mv "$dir/request.next" "$dir/request"
for ((i=0; i<200; i++)); do
    if [[ -f "$dir/reply" ]]; then
        cat "$dir/reply"
        rm "$dir/reply"
        exit 0
    fi
    sleep 0.05
done
exit 21
'''

FIELDS = (
    "nonce", "memory_secret", "boot_id", "guest_pid", "start_ticks",
    "counter", "fd_position", "fd_inode", "fd_flags", "fd_target", "last_read",
    "first_line", "second_line", "third_line",
)


def ensure(condition, message):
    if not condition:
        raise RuntimeError(message)


def same_state(left, right):
    """The nonce must change; every recorded state field must stay identical."""
    ensure(left["nonce"] != right["nonce"], "response did not use a fresh challenge")
    changed = [key for key in FIELDS[1:] if left[key] != right[key]]
    ensure(not changed, f"state changed across suspend: {changed}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ctr", default="ctr")
    parser.add_argument("--address", default="/run/containerd/containerd.sock")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--runtime", required=True)
    parser.add_argument("--runtime-config-path", required=True)
    parser.add_argument("--image", required=True, help="already present in this namespace")
    parser.add_argument("--snapshotter", default="erofs")
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--command-timeout", type=int, default=120)
    parser.add_argument("--suspended-seconds", type=float, default=5)
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run on the Linux Kata host as root")
    if args.command_timeout <= 0 or args.suspended_seconds < 0:
        parser.error("invalid timeout or suspended duration")
    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    cid = "kata-state-" + uuid.uuid4().hex[:12]
    audit = CheckpointAudit(args.runtime_config_path, cid)
    base = [args.ctr, "--address", args.address, "--namespace", args.namespace]
    record = dict(container_id=cid, namespace=args.namespace, runtime=args.runtime,
                  config=args.runtime_config_path, image=args.image, cycles=[])

    def save():
        (args.evidence_dir / "state-proof.json").write_text(json.dumps(record, indent=2) + "\n")

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

    def host_identity(pid):
        try:
            stat = Path(f"/proc/{pid}/stat").read_text()
            return dict(pid=pid, start_ticks=stat.rsplit(")", 1)[1].split()[19])
        except FileNotFoundError:
            return None

    def request(operation):
        nonce = uuid.uuid4().hex
        response = ctr("tasks", "exec", "--exec-id", "probe-" + nonce[:12],
                       cid, "bash", "-ceu", REQUEST, "state-request", operation, nonce)
        values = response.splitlines()
        ensure(len(values) == len(FIELDS), f"unexpected response: {response!r}")
        state = dict(zip(FIELDS, values))
        ensure(state["nonce"] == nonce, "received a stale response")
        ensure(state["fd_target"].endswith("/data (deleted)"), "FD does not refer to unlinked file")
        return state

    save()
    try:
        print(f"Creating {cid}", flush=True)
        ctr("run", "--detach", "--null-io", "--runtime", args.runtime,
            "--runtime-config-path", args.runtime_config_path,
            "--snapshotter", args.snapshotter, args.image, cid, "bash", "-ceu", WORKLOAD)
        initial = request("snapshot")
        record["initial"] = initial
        ensure(initial["counter"] == "0", "initial counter is not zero")
        ensure(initial["last_read"] == initial["first_line"], "first read failed")
        first_bump = request("bump")
        baseline = request("bump")
        ensure(first_bump["counter"] == "17" and baseline["counter"] == "34", "counter did not advance")
        ensure(baseline["memory_secret"] == initial["memory_secret"], "workload restarted")
        record["prepared"] = baseline
        save()

        for cycle, expected_key in enumerate(("second_line", "third_line"), 1):
            before = request("snapshot")
            same_state(baseline, before)
            pid, status = task()
            ensure(status == "RUNNING", f"unexpected task status: {status}")
            ensure("qemu" in Path(f"/proc/{pid}/comm").read_text(), "task PID is not QEMU")
            source = host_identity(pid)
            result = dict(cycle=cycle, before=before, source_qemu=source)
            record["cycles"].append(result)
            save()
            audit.before_suspend()
            start = time.monotonic_ns()
            ctr("tasks", "pause", cid)
            result["suspend_ms"] = (time.monotonic_ns() - start) / 1_000_000
            ensure(task()[1] == "PAUSED", "containerd task is not paused")
            ensure(host_identity(pid) != source, "source QEMU is still alive")
            result["source_qemu_exited"] = True
            result["save"] = audit.suspended()
            save()
            print(f"Cycle {cycle}: suspended; source QEMU {pid} exited", flush=True)
            time.sleep(args.suspended_seconds)
            ensure(task()[1] == "PAUSED", "task changed state while suspended")
            ensure(host_identity(pid) != source, "source QEMU reappeared")
            start = time.monotonic_ns()
            ctr("tasks", "resume", cid)
            result["resume_ms"] = (time.monotonic_ns() - start) / 1_000_000
            restored_pid, status = task()
            restored = host_identity(restored_pid)
            ensure(status == "RUNNING" and restored is not None and restored != source,
                   "resume did not create a new running QEMU process")
            result["restored_qemu"] = restored
            result["restore"] = audit.resumed(restored_pid)

            after = request("snapshot")
            result["after"] = after
            save()
            same_state(before, after)
            advanced = request("read")
            result["after_read"] = advanced
            save()
            ensure(advanced["last_read"] == before[expected_key], "open FD did not continue at saved position")
            ensure(int(advanced["counter"]) == int(before["counter"]) + 1, "memory counter did not continue")
            ensure(int(advanced["fd_position"]) == int(before["fd_position"]) + len(before[expected_key]) + 1,
                   "FD position did not advance by exactly one line")
            for key in ("memory_secret", "boot_id", "guest_pid", "start_ticks", "fd_inode", "fd_target"):
                ensure(advanced[key] == before[key], f"identity changed during read: {key}")
            baseline = advanced
            result["passed"] = True
            save()
            print(json.dumps(dict(cycle=cycle, state_identical=True, counter=after["counter"],
                                  fd_position=after["fd_position"], next_read_matches=True,
                                  suspend_ms=result["suspend_ms"], resume_ms=result["resume_ms"])), flush=True)

        ctr("tasks", "kill", "--signal", "SIGKILL", cid)
        deadline = time.monotonic() + 15
        while task()[1] != "STOPPED":
            ensure(time.monotonic() < deadline, "test task did not stop")
            time.sleep(.1)
        ctr("tasks", "delete", cid)
        ctr("containers", "delete", cid)
        record["passed"] = True
        record["cleaned_up"] = True
        save()
        print(f"PASS: exact recorded process state survived both cycles. Evidence: {args.evidence_dir}", flush=True)
    except BaseException as error:
        record["error"] = str(error)
        save()
        print(f"Retained {cid} in namespace {args.namespace}; evidence: {args.evidence_dir}", file=sys.stderr)
        raise


if __name__ == "__main__":
    main()
