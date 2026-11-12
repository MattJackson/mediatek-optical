#!/usr/bin/env python3
"""Check every distinct public feature configuration (Python 3.11+)."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tomllib


def unused_aliases(features, root):
    """Features that only enable other features and that no source gates on.

    Such an alias compiles exactly like the features it names, so it adds no
    distinct configuration. It is still passed whenever its features are all
    active, so `required-features` may name either form.
    """
    sources = "\n".join(
        path.read_text(errors="replace")
        for directory in ("src", "tests", "examples", "benches")
        for path in (root / directory).rglob("*.rs")
    )
    return {
        name
        for name, dependencies in features.items()
        if dependencies
        and all(dependency in features for dependency in dependencies)
        and not re.search(r'feature\s*=\s*"' + re.escape(name) + '"', sources)
    }


def configurations(features, aliases=frozenset()):
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
        key = tuple(sorted(active - aliases))
        if key not in unique or len(selected) < len(unique[key]):
            unique[key] = selected
    return [
        selected
        + sorted(
            alias
            for alias in aliases
            if alias not in selected and set(features[alias]) <= set(key)
        )
        for key, selected in unique.items()
    ]


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
    features = manifest["features"]
    for selected in configurations(features, unused_aliases(features, root)):
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
