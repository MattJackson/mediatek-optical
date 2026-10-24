import importlib.util
import json
import os
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

    def test_failed_or_unrelated_runs_never_qualify(self):
        records = [dict(conclusion='failure', head_branch='qa', event='push'), dict(conclusion='success', head_branch='dev', event='push'), dict(conclusion='success', head_branch='qa', event='pull_request')]
        with patch.dict(os.environ, GITHUB_REPOSITORY='owner/repo'), patch('sys.argv', ['proof', '--branch', 'qa']), patch.object(proof, 'command', return_value=json.dumps(dict(workflow_runs=records))):
            with self.assertRaisesRegex(RuntimeError, 'No successful'):
                proof.main()

if __name__ == '__main__':
    unittest.main()
