"""Reuse a successful protected-branch CI run for identical package inputs."""
import argparse
import json
import os
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


# Shipped in the crate (Cargo.toml `include`) and defines the CI feature matrix,
# so a change to it is a package change even though it lives under .github/.
PACKAGED_CI_FILES = {'.github/scripts/check-features.py'}


def same_package_source(base):
    # --no-renames: a rename src/x -> .github/x must list the src/ path too.
    changed = command('git', 'diff', '--name-only', '--no-renames', base, 'HEAD', '--').splitlines()
    return all(p.startswith('.github/') and p not in PACKAGED_CI_FILES for p in changed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--branch', choices=['dev', 'qa'], required=True)
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    runs = json.loads(command('gh', 'api', f'repos/{repo}/actions/workflows/ci.yml/runs?branch={args.branch}&event=push&status=success&per_page=30'))['workflow_runs']
    for run in runs:
        if run.get('conclusion') != 'success' or run.get('head_branch') != args.branch or run.get('event') != 'push':
            continue
        try:
            command('git', 'fetch', '--no-tags', 'origin', run['head_sha'])
        except subprocess.CalledProcessError:
            # A force-pushed run's commit may no longer be fetchable; it cannot
            # match, so examine the older runs instead of aborting the scan.
            continue
        if same_package_source(run['head_sha']):
            print(f'Package inputs match successful {args.branch} CI {run["id"]} at {run["head_sha"]}')
            return
    raise RuntimeError('No successful protected-branch CI matches these package inputs')


if __name__ == '__main__':
    main()
