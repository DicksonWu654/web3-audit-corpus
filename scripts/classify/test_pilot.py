#!/usr/bin/env python3
"""Offline pilot contract checks. Synthetic responses stay in a temporary tree.

python3 -I -S scripts/classify/test_pilot.py
Only the real unlabelled validation sample and taxonomy are copied as inputs;
no labels, production predictions, other findings, CLI model calls or shell runner.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, canonical, normalize_text, read_jsonl, write_jsonl, write_text
from pilot_make import CONFIGS, FINDINGS_MARKER, PILOT, PROMPT, SAMPLE, prepare
from pilot_collect import check_batch, retryable_capacity


class PilotContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = ("".join(canonical(dict(finding_uid=f"finding:synthetic-{i}", title=f"Synthetic finding {i}", body_text="Synthetic evidence. "*300)) + "\n" for i in range(300))).encode()
        cls.taxonomy = (ROOT / "schema/taxonomy.yaml").read_bytes()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="taxonomy-pilot-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / SAMPLE).parent.mkdir(parents=True)
        (self.root / SAMPLE).write_bytes(self.sample)
        (self.root / "schema").mkdir()
        (self.root / "schema/taxonomy.yaml").write_bytes(self.taxonomy)
        self.manifest, self.leaves = prepare(self.root)
        self.name = next(iter(CONFIGS))
        self.batch = self.manifest["configs"][self.name]["batches"][0]

    @staticmethod
    def response(i):
        # Deliberately synthetic structural fixture, never a semantic annotation.
        return dict(i=i, leaf="unclassified.insufficient_evidence",
                    confidence=i / 100, rationale="Synthetic parser fixture only")

    def cli(self, *args):
        return subprocess.run([sys.executable, "-I", "-B", "-S", str(Path(__file__).with_name("pilot_collect.py")),
                               "--root", str(self.root), *args], capture_output=True, text=True)

    def test_paired_evidence_and_short_index_bindings(self):
        source = read_jsonl(self.sample)
        shared = PROMPT + canonical(json.loads(self.taxonomy))
        all_maps = {}
        for name, (_, _, limit) in CONFIGS.items():
            observed = []
            for batch in self.manifest["configs"][name]["batches"]:
                prompt = (self.root / PILOT / batch["prompt"]).read_text()
                self.assertTrue(prompt.startswith(shared + "\n\nBATCH REFERENCE"))
                rows = read_jsonl(prompt.split(FINDINGS_MARKER, 1)[1].encode())
                indexes = read_jsonl((self.root / PILOT / batch["index_map"]).read_bytes())
                self.assertEqual([r["i"] for r in rows], list(range(1, 101)))
                self.assertEqual([r["i"] for r in indexes], list(range(1, 101)))
                offset = (batch["k"] - 1) * 100
                for row, index, original in zip(rows, indexes, source[offset:offset + 100]):
                    self.assertEqual(set(row), {"i", "title", "body"})
                    self.assertEqual(set(index), {"i", "finding_uid"})
                    self.assertEqual(index["finding_uid"], original["finding_uid"])
                    self.assertEqual(row["title"], normalize_text(original["title"]))
                    self.assertEqual(row["body"], normalize_text(original["body_text"])[:limit])
                    self.assertLessEqual(len(row["body"]), limit)
                observed.extend(indexes)
                if name in {"C_sol6_low_3000", "D_sol61_medium_3000"}:
                    other = self.root / PILOT / "B_luna_medium_3000" / f"batch_{batch['k']}.md"
                    self.assertEqual(prompt, other.read_text())
            all_maps[name] = observed
        for value in all_maps.values():
            self.assertEqual(value, all_maps[self.name])
        self.assertEqual(len({r["finding_uid"] for r in all_maps[self.name]}), 300)

    def test_idempotence_and_source_preservation(self):
        before = {p: p.read_bytes() for p in (self.root / PILOT).rglob("*") if p.is_file()}
        prepare(self.root)
        prepare(self.root, verify=True)
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        self.assertEqual((self.root / SAMPLE).read_bytes(), self.sample)
        self.assertEqual((self.root / "schema/taxonomy.yaml").read_bytes(), self.taxonomy)

    def test_tampering_is_rejected_without_overwrite(self):
        paths = [self.root / SAMPLE, self.root / "schema/taxonomy.yaml",
                 self.root / PILOT / self.batch["prompt"],
                 self.root / PILOT / self.batch["index_map"],
                 self.root / PILOT / "manifest.json"]
        for path in paths:
            original = path.read_bytes()
            changed = original + b"\n"
            path.write_bytes(changed)
            try:
                with self.assertRaises(ValueError):
                    prepare(self.root, verify=True)
                with self.assertRaises(ValueError):
                    prepare(self.root)
                self.assertEqual(path.read_bytes(), changed)
            finally:
                path.write_bytes(original)

    def test_strict_rows_preserve_other_valid_indexes(self):
        rows = [self.response(i) for i in range(1, 101)]
        rows[1]["confidence"] = True
        rows[2]["leaf"] = "not.a.leaf"
        rows[3]["i"] = True
        rows[4]["confidence"] = float("nan")
        rows[5]["confidence"] = 1.1
        rows[6]["rationale"] = "word " * 21
        rows[8].pop("rationale")
        rows[9]["i"] = "10"
        text = "".join(json.dumps(r) + "\n" for r in rows)
        text += json.dumps(self.response(1)) + "\n"
        text += json.dumps(self.response(8))[:-1] + ', "i":8}\n'
        text += json.dumps(self.response(101)) + "\n```\n[]\n"
        output = self.root / "synthetic_invalid.jsonl"
        write_text(output, text)
        accepted, status, expected = check_batch(self.root, self.batch, self.leaves, output)
        self.assertFalse(status["complete"])
        self.assertEqual(len(accepted), 90)
        self.assertEqual(set(accepted), {expected[i] for i in range(11, 101)})
        self.assertTrue(status["errors"])
        self.assertIn("duplicate_index", status["rejected_or_missing"][expected[1]])
        self.assertIn("duplicate_json_key", status["rejected_or_missing"][expected[8]])

    def test_all_configs_collect_in_sample_order(self):
        source = read_jsonl(self.sample)
        for name, config in self.manifest["configs"].items():
            for batch in config["batches"]:
                write_jsonl(self.root / PILOT / batch["output"],
                            [self.response(i) for i in range(100, 0, -1)])
        result = self.cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in CONFIGS:
            path = self.root / PILOT / name / "predictions.jsonl"
            rows = read_jsonl(path.read_bytes())
            self.assertEqual(len(rows), 300)
            self.assertEqual([r["finding_uid"] for r in rows], [r["finding_uid"] for r in source])
            for offset, row in enumerate(rows):
                self.assertEqual(set(row), {"finding_uid", "leaf", "confidence"})
                self.assertEqual(row["confidence"], (offset % 100 + 1) / 100)
            self.assertTrue(json.loads(path.with_name("status.json").read_text())["complete"])
        result = self.cli("--check-batch", self.name, "1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_outputs_are_incomplete(self):
        result = self.cli("--config", self.name)
        self.assertEqual(result.returncode, 1, result.stderr)
        status = json.loads((self.root / PILOT / self.name / "status.json").read_text())
        self.assertFalse(status["complete"])
        self.assertEqual(status["accepted"], 0)
        self.assertEqual((self.root / PILOT / self.name / "predictions.jsonl").read_bytes(), b"")
        self.assertEqual(self.cli("--check-batch", self.name, "1").returncode, 1)

    def test_verified_plan_uses_exact_models_and_paths(self):
        result = self.cli("--list-batches")
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = [line.split("\t") for line in result.stdout.splitlines()]
        self.assertEqual(len(lines), 12)
        for name, model, effort, k, prompt, output in lines:
            self.assertEqual((model, effort), CONFIGS[name][:2])
            self.assertEqual(Path(prompt), self.root / PILOT / name / f"batch_{k}.md")
            self.assertEqual(Path(output), self.root / PILOT / name / f"out_{k}.jsonl")

    def test_capacity_diagnostics_ignore_prompt_and_respect_guard(self):
        prompt = self.root / PILOT / self.batch["prompt"]
        log = self.root / "synthetic_capacity.log"
        cases = [
            ("ERROR: server is at capacity", True),
            ("ERROR: 429 Too Many Requests", True),
            ("ERROR: 503 Service Unavailable", True),
            ("ERROR: stream disconnected before completion", True),
            ("ERROR: authentication failed", False),
            ("ERROR: server is at capacity; usage limit reached", False),
            ("ERROR: server is at capacity; quota exhausted", False),
            ("ERROR: server is at capacity; guard blocked this launch", False),
            ("ERROR: server is at capacity; unknown reset mechanism", False),
            ("", False),
        ]
        for diagnostic, expected in cases:
            write_text(log, "user\n" + prompt.read_text() + "\n" + diagnostic + "\n")
            self.assertEqual(retryable_capacity(log, prompt), expected, diagnostic)
        write_text(log, "ERROR: server is at capacity\n")
        self.assertEqual(self.cli("--retryable-capacity", str(log), str(prompt)).returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
