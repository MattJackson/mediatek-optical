import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('proof', Path(__file__).with_name('verify-source.py'))
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)

class SourceProof(unittest.TestCase):
    def test_only_ci_changes_can_reuse_a_build(self):
        for paths, expected in [('', True), ('.github/workflows/ci.yml', True), ('src/lib.rs', False), ('Cargo.toml', False), ('Cargo.lock', False), ('.github/ci.yml\nREADME.md', False)]:
            with self.subTest(paths=paths), patch.object(proof, 'command', return_value=paths):
                self.assertEqual(proof.same_package_source('qa'), expected)

    def test_shipped_ci_script_is_package_source(self):
        with patch.object(proof, 'command', return_value='.github/scripts/check-features.py'):
            self.assertFalse(proof.same_package_source('qa'))
        with patch.object(proof, 'command', return_value='.github/scripts/verify-source.py'):
            self.assertTrue(proof.same_package_source('qa'))

    def test_diff_is_requested_without_rename_detection(self):
        with patch.object(proof, 'command', return_value='') as run:
            proof.same_package_source('qa')
        self.assertIn('--no-renames', run.call_args.args)

    def test_rename_into_github_dir_is_a_package_change(self):
        def git(*args):
            subprocess.check_call(('git', '-c', 'user.name=t', '-c', 'user.email=t@t', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null', *args), cwd=repo, stdout=subprocess.DEVNULL)
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / 'src').mkdir()
            (Path(repo) / 'src/x.rs').write_text('fn main() {}\n' * 20)
            git('init', '-q')
            git('add', '.')
            git('commit', '-q', '-m', 'base')
            (Path(repo) / '.github').mkdir()
            git('mv', 'src/x.rs', '.github/x.rs')
            git('commit', '-q', '-m', 'rename')
            cwd = os.getcwd()
            os.chdir(repo)
            try:
                self.assertFalse(proof.same_package_source('HEAD~1'))
            finally:
                os.chdir(cwd)

    def test_failed_or_unrelated_runs_never_qualify(self):
        records = [dict(conclusion='failure', head_branch='qa', event='push'), dict(conclusion='success', head_branch='dev', event='push'), dict(conclusion='success', head_branch='qa', event='pull_request')]
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/repo'), patch('sys.argv', ['proof', '--branch', 'qa']), patch.object(proof, 'command', return_value=json.dumps(dict(workflow_runs=records))):
            with self.assertRaisesRegex(RuntimeError, 'No successful'):
                proof.main()

if __name__ == '__main__':
    unittest.main()
