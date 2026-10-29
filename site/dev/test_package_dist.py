#!/usr/bin/env python3
"""Small packaging contract tests: python3 -I site/dev/test_package_dist.py."""
import gzip
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("package_dist", Path(__file__).resolve().parents[1] / "package_dist.py")
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


def snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


class PackageTest(unittest.TestCase):
    def test_deterministic_copy_and_gzip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "build"
            (source / "data" / "nested").mkdir(parents=True)
            (source / "assets").mkdir()
            (source / "empty").mkdir()
            originals = {
                "data/summary.json": b'{"count": 3}\n',
                "data/nested/unicode.json": '{"name": "caf\u00e9"}\n'.encode(),
                "assets/other.json": b'{"unchanged":true}',
                "data/keep.bin": b"\x00\xff\x02",
                "index.html": b"<html>same</html>\n",
                "config.json": b'{"data_path":"data/","nested":{"keep":true}}',
            }
            for name, data in originals.items():
                (source / name).write_bytes(data)
            first, second = root / "first", root / "second"
            totals = packager.package(source, first)
            self.assertEqual(totals, packager.package(source, second))
            self.assertEqual(snapshot(first), snapshot(second))
            self.assertEqual(snapshot(source), originals)
            self.assertTrue((first / "empty").is_dir())
            for name, data in originals.items():
                if name.startswith("data/") and name.endswith(".json"):
                    self.assertFalse((first / name).exists())
                    gz = (first / (name + ".gz")).read_bytes()
                    self.assertEqual(gzip.decompress(gz), data)
                    self.assertEqual(gz[:10], b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff")
                elif name != "config.json":
                    self.assertEqual((first / name).read_bytes(), data)
            self.assertEqual(json.loads((first / "config.json").read_bytes()),
                             {"data_path": "data/", "nested": {"keep": True}, "data_compression": "gzip"})
            self.assertEqual(totals["bytes"], sum(len(b) for b in snapshot(first).values()))
            self.assertEqual(totals["files"], len(originals))
            self.assertEqual(totals["gzip_files"], 2)
            with self.assertRaisesRegex(ValueError, "fresh"):
                packager.package(source, first)
            with self.assertRaisesRegex(ValueError, "outside"):
                packager.package(source, source / "dist")

    def test_analysis_left_out(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "build"
            (source / "data" / "stats").mkdir(parents=True)
            (source / "data" / "stats" / "trends.json").write_text("{}")
            (source / "data" / "summary.json").write_text(json.dumps({
                "as_of": "2026-10-22", "trends_2026": {"x": 1}, "key_results": [], "momentum_aggregates": [], "headline": {}, "stats": ["a"],
                "counts": {"findings": 5, "incidents": 2, "stats_tables": 3},
                "quality": [{"metric": "precision", "value": 1}, {"metric": "incident_entity_link_precision", "value": 0.5}]}))
            (source / "data" / "firms.json").write_text(json.dumps([{"firm_id": "a", "momentum": {}, "momentum_excluding_token_only": {}, "audit_type_comparison": {}, "engagements": 3}]))
            out = root / "out"
            packager.package(source, out)
            self.assertFalse((out / "data" / "stats").exists())
            summary = json.loads(gzip.decompress((out / "data" / "summary.json.gz").read_bytes()))
            self.assertEqual(summary, {"as_of": "2026-10-22", "counts": {"findings": 5}, "quality": [{"metric": "precision", "value": 1}]})
            firms = json.loads(gzip.decompress((out / "data" / "firms.json.gz").read_bytes()))
            self.assertEqual(firms, [{"firm_id": "a", "engagements": 3}])

    def test_config_creation_and_size_limits(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "build"
            source.mkdir()
            packager.package(source, root / "created")
            self.assertEqual(json.loads((root / "created/config.json").read_bytes()), {"data_compression": "gzip"})
            # Tiny budgets exercise the actual failure paths without large fixtures.
            with patch.object(packager, "MAX_FILE_BYTES", 1), self.assertRaisesRegex(ValueError, "File exceeds"):
                packager.package(source, root / "oversize-file")
            with patch.object(packager, "MAX_TOTAL_BYTES", 1), self.assertRaisesRegex(ValueError, "Expanded output exceeds"):
                packager.package(source, root / "oversize-total")


if __name__ == "__main__":
    unittest.main()
