"""Reuse a successful protected-branch CI run for identical package inputs."""
import argparse
import json
import os
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def same_package_source(base):
    return all(p.startswith('.github/') for p in command('git', 'diff', '--name-only', base, 'HEAD', '--').splitlines())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--branch', choices=['dev', 'qa'], required=True)
    args = parser.parse_args()
    repo = os.environ['GITHUB_REPOSITORY']
    runs = json.loads(command('gh', 'api', f'repos/{repo}/actions/workflows/ci.yml/runs?branch={args.branch}&event=push&status=success&per_page=30'))['workflow_runs']
    for run in runs:
        if run.get('conclusion') != 'success' or run.get('head_branch') != args.branch or run.get('event') != 'push':
            continue
        command('git', 'fetch', '--no-tags', 'origin', run['head_sha'])
        if same_package_source(run['head_sha']):
            print(f'Package inputs match successful {args.branch} CI {run["id"]} at {run["head_sha"]}')
            return
    raise RuntimeError('No successful protected-branch CI matches these package inputs')


if __name__ == '__main__':
    main()
