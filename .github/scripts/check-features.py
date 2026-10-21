#!/usr/bin/env python3
"""Check every distinct public feature configuration (Python 3.11+)."""
import argparse
import os
from pathlib import Path
import subprocess
import tomllib


def configurations(features):
    unique = {}
    names = list(features)
    for mask in range(1 << len(names)):
        selected = [name for i, name in enumerate(names) if mask & (1 << i)]
        active = set(selected)
        while True:
            expanded = active | {
                dependency
                for name in active
                for dependency in features[name]
                if dependency in features
            }
            if expanded == active:
                break
            active = expanded
        key = tuple(sorted(active))
        if key not in unique or len(selected) < len(unique[key]):
            unique[key] = selected
    return unique.values()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["check", "test", "doc"])
    parser.add_argument("--toolchain")
    parser.add_argument("--release", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    manifest = tomllib.loads((root / "Cargo.toml").read_text())
    cargo = ["cargo"] + (["+" + args.toolchain] if args.toolchain else [])
    logs = root / "target" / "feature-checks"
    logs.mkdir(parents=True, exist_ok=True)
    count = 0
    for selected in configurations(manifest["features"]):
        label = ",".join(selected) or "default"
        command = cargo + [args.command, "--no-default-features", "--locked"]
        if args.release:
            command += ["--release"]
        if args.command == "check":
            command += ["--lib"]
        elif args.command == "test":
            command += ["--all-targets"]
        else:
            command += ["--no-deps"]
        if selected:
            command += ["--features", ",".join(selected)]
        log = logs / f"{args.command}-{args.toolchain or 'stable'}-{label}.log"
        env = dict(os.environ)
        if args.command == "doc":
            env["RUSTDOCFLAGS"] = (env.get("RUSTDOCFLAGS", "") + " -D warnings").strip()
        with log.open("w") as output:
            result = subprocess.run(command, cwd=root, env=env, stdout=output, stderr=subprocess.STDOUT)
        print(f"{args.command}: {label}: {'PASS' if result.returncode == 0 else 'FAIL'}", flush=True)
        if result.returncode:
            print(log.read_text(), flush=True)
            raise SystemExit(result.returncode)
        count += 1
    print(f"Verified {count} distinct feature configurations.")


if __name__ == "__main__":
    main()
