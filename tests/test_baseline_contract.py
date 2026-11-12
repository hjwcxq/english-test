"""固定来源及独立预期完整性检查，不把自洽检查当作应用业务验收。"""

import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / 'business' / 'vocabulary' / 'v1'
EXPECTED_BUNDLE_DIGEST = 'fc2319ba638801590426b5ed42110f1c74780ce03662d6b90d3a80422e5a5149'
# 固定自 evidence/vocabulary-baseline/20261111/export/manifest.json 的原始字节。
EXPECTED_MANIFEST_SHA256 = '3ff45a67d818bffe25a1d0d884d03cda066c5e87eeee469c82fbc983214e3a3b'
EXPECTED_BUNDLE_FILES = {
    'acceptance-vectors.json',
    'content.json',
    'docs/01_办公室AI智能背词助教终端_功能性需求.md',
    'docs/02_同济附中_上海高考高分分级词库构建方案与核心词表.md',
    'manifest.json',
    'policy.json',
    'product-spec.json',
}


class FrozenBaselineTests(unittest.TestCase):
    def test_export_preserves_every_source_file(self):
        manifest_bytes = (BUNDLE / 'manifest.json').read_bytes()
        self.assertEqual(hashlib.sha256(manifest_bytes).hexdigest(), EXPECTED_MANIFEST_SHA256)
        manifest = json.loads(manifest_bytes)
        self.assertEqual(manifest['bundle_digest'], EXPECTED_BUNDLE_DIGEST)
        self.assertEqual(
            {path.relative_to(BUNDLE).as_posix() for path in BUNDLE.rglob('*') if path.is_file()},
            EXPECTED_BUNDLE_FILES,
        )
        for name, expected in manifest['files'].items():
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256((BUNDLE / name).read_bytes()).hexdigest(), expected)

    def test_source_only_content_is_not_marked_as_ready_quiz(self):
        content = json.loads((BUNDLE / 'content.json').read_text(encoding='utf-8'))
        self.assertEqual(len(content['entries']), 60)
        self.assertEqual(len(content['targets']), 61)
        self.assertTrue(all(target['quiz_ready'] is False for target in content['targets']))

    def test_all_independent_cases_are_retained(self):
        vectors = json.loads((BUNDLE / 'acceptance-vectors.json').read_text(encoding='utf-8'))
        self.assertEqual(len(vectors['scenarios']), 21)
        self.assertEqual(sum(len(scenario['cases']) for scenario in vectors['scenarios']), 37)


if __name__ == '__main__':
    unittest.main()
