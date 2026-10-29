"""Regression fixtures and guarded, deterministic inspection/ID-sequence census.

Run: python3 -I scripts/findings/parsers/chainlight_secure3_test.py
Run with --evaluate to print the inspected SHA/name manifest and corpus metrics.
Expected sequences were transcribed from printed indexes and independently
extracted original-PDF detail headings, not parser output.
The legacy theori-audit PDF requires missing-font OCR; its printed index lists
four issues and nine separate recommendations.
"""
import json
from pathlib import Path
import sys
import unittest
from collections import Counter

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT, read_snapshot, digest
from core import Report, finish, severity
from parsers import chainlight, secure3

# SHA, printed-ID prefix, count, era, separate recommendation count.
SAMPLES = {
    "chainlight": [
        ("b247625fd238edb107581759a19ad7b5273c4c3ecf5c4910115f2bdd56255ceb","BUGFIX",8,"2024-bug-fix-review",0),
        ("55ca9949583049c791501020f7f8da2c5eab48abb775f701b122fe20f288fc79","BUGFIX2",4,"2025-bug-fix-review",0),
        ("0219c05985328acfc262a87f7efe34004cad866fe15760f5463a5d9e485d40df","STARFLEIT",7,"2023-cards",0),
        ("89e479c4dc401dc3b238dc4bed382e50a4af8e17464badda3b153404bff932f2","THE-BIFROST",4,"legacy-ocr-recovered",9),
        ("9f4e79fe4f783188d2439a2573aa51598dca424423c63dd655831e13f74f3dcd","EMBLEMVAULT",9,"2025-cards",0),
        ("20c04b76fd7b6a7d184cdb70dd277c3a18ad10d744c46f68c5bb95b55c8ba366","MOCA",6,"2024-cards",0),
        ("9ebe5bb3d0533e4488f14e8855553424aa002b4b7bbdb215d21bb0ddbbf3c9b5","TAOFI",9,"2025-cards",0),
        ("8156f92c9faf7dc4b4af1d4df8ba0234fb624d03a9784dbfad904bb9b17089c5","WORLDCOIN-ORB",3,"2025-orb-ko",0),
        ("b3a9613e551b17c1f76634fcea28d429a369b3aa75e1fbf0b0a937202693f78e","WORLDCOIN-ORB",3,"2025-orb-en",0),
        ("37eb7eb36ac1d8b07d80500646d038cd82dc136175a65a42a14c4394b11d639d","",0,"2026-explicit-zero",0),
        ("cc30f70428be8f0957d0927c189cb4fc3f69f5f70401f934b45a0c5be41757a9","GLUWASA",1,"2026-cards",0),
        ("b165b328ee9c5ff4a6715a279b393771c25ca3516ef1e97d5a5ea5a8a978532d","CTCLOAN",7,"2026-cards",0),
        ("4eb44e33e00dd0440edb1a7aac8ca6fad636d8deeeedba8d15b0e9d2906df896","GLUWANFT",4,"2026-cards",0),
        ("ab9b1e556a6a71d4c35bffa5c09dde7d1bf9b8648a61c1011265f4ca07f5266d","GLUWASOULBOUND",1,"2026-cards",0),
        ("7e46ec551a72a38ef80aea88994dc9e91b843056e5db5daec17059a0ba503159","SPACESTAKING",6,"2025-26-cards",0),
        ("9538570b960d6e98872e88c521cfe57c22d4e02ff2be19613d790a49f4f20aa6","SPACEAIRDROP",5,"2026-cards",0),
        ("5192cc0410dd15afbc61366636b6119ffc30d6b9821678c1fce8657ed5349108","",0,"2026-explicit-zero",0),
        ("8301768fd3702540c2d512771db4a95fa291b0d367d87f25bcd60e387926acab","THE-DEZSWAP",6,"2022-23-legacy-cards",3),
        ("7c5c4ccec4f09b25aa1dd60ebf2f710a218804f40c3856ffd9cbddc3ca47d50d","THE-KORE",8,"2023-wrapped-risk",0),
        ("75c5ee6d8d05ee34e2fd8983d2934b40e0396a52fb0a43d05f841e84f5c3574f","Issue #",13,"2022-legacy-issues",4),
        ("947c70152a0894268c746b6718c3ea9452a5e17876fc1247ca6309ec86af35cf","TERRACLASSIC",7,"2023-cards",0),
        ("ba21deeddefea3d95efd39e2f5d6114906603ca2540a400dab6a99ed2ff43718","TERRASWAP",7,"2023-cards",0),
        # Newly integrated client copies: TOC/detail IDs KROMA-001..025
        # and KROMA-VALIDATOR-V2-001..007 were checked in the originals.
        ("c84f608aaf451fb7f0910605bc4fd25e0a75d082473c031c873e35d2942e291a","KROMA",25,"2023-kroma-cards",0),
        ("7f364dd94bc70e60a3df7b244232bc90cca9c0f10ae7a9ef75705c77ea9d24d9","KROMA-VALIDATOR-V2",7,"2024-kroma-validator-cards",0),
    ],
    "secure3": [
        ("ae2728da28967d1a6fc9e9ab2919e015ca2341fc2b0807bc60434ac00fe8179d","UNW",18,"competitive",0),
        ("670404e695f61131a967a9db0ecf58355a1dc2826a6307236efdf687cbde99c0","MNT",22,"2024-mantle-contest",0),
        ("1b02a60ec0e9d485b62f21b6e83a7769f9e7af6b01a59b496a4c5c883427df35","MNT",54,"2024-mantle-tectonic",0),
        ("4ba456c43710e7b40315c68ae79b0f023aa6fd79a9a32c5dd4f61546c62c9037","MTC",140,"2023-mantle-dual-prefix",0),
        ("038acaefc449acdd85e2b81844b159d11267afaa095b12eaac82bbb0661a2efd","MNT",33,"2024-mantle-contest-final",0),
        ("941bd223a5626ca0ce1fe2f09444810932da9470db792055c2fbb27a04e259cd","CCS",15,"competitive",0),
        ("d51882134eb0aa62e71419022db8b353f5482730c5cff207c2fa1121799b75ab","CLD",7,"chart-severity-conflict",0),
        ("0f0205b2b90b36f3db5daa1938ccd42096955bc3022c28618b785c5142f12346","EPL",6,"chart",0),
        ("fd49006fe825a9777eda477011659062f49a37410d8a6b412654f8f8a9b174c2","FTM",6,"move-competitive",0),
        ("253970b9aa4a5c1fdf96aaa1cf0a74995935bd71960a7d2ffef32e833fd5d2ad","LYM",4,"competitive",0),
        ("0de1be655a68acfe2ee646ce1681db120852319bfe3432204ee6110f96e6c3a0","P12",22,"chart-severity-conflict",0),
        ("946ffe0d0d61642390cf59c13eef066d1b2ff98edd199e6b62b8a9ffd727f4bd","PAR",5,"interim",0),
        ("6a21505f5c3fabb3486a8f3e2c13060dc19c23381b483d87d5d9c30fc4f68648","SMV",11,"competitive",0),
        ("d1c1dc7b63358712d373cf7517b634cbc6e077c875e51ae3ac8f85f401bea82f","SLD",9,"chart-information-label",0),
    ],
}


# Printed front indexes and detail headings deliberately skip native issue numbers.
NATIVE_NUMBERS = {
    "b247625fd238edb107581759a19ad7b5273c4c3ecf5c4910115f2bdd56255ceb": (1, 2, 3, 4, 7, 8, 9, 10),
    "55ca9949583049c791501020f7f8da2c5eab48abb775f701b122fe20f288fc79": (1, 2, 4, 5),
}

# Secure3 source checks: UniWhale index p2 and details pp8-38 print UNW-1..18
# (UNW-10 wraps). Mantle April details pp9-104 print MNT-1..22; the prose
# mention of MNT-32 is not a finding. Tectonic details pp12-153 print MNT-1..54.
# Mantle v1 details pp23-155 print MTC-1..68, then pp156-334 MTL-1..72.
# Its index wraps MTC-21, but the detail is present on p71. Final contest
# details pp11-124 print MNT-1..33, including IDs absent from single-line TOC
# extraction (1,7,9,22,32). There are no native detail-ID gaps in these five PDFs.
NATIVE_IDS = {
    "4ba456c43710e7b40315c68ae79b0f023aa6fd79a9a32c5dd4f61546c62c9037":
        tuple(f"MTC-{i}" for i in range(1, 69)) + tuple(f"MTL-{i}" for i in range(1, 73)),
}

def fixture(text,firm):
    return Report(text,{"file_format":"pdf","text_sha256":digest(text.encode()),
                        "pages":[{"page":1,"start":0,"end":len(text),"text":text}]},firm)


def evaluate():
    # read_snapshot applies the holdout boundary BEFORE any cache text is read.
    docs={d["row"]["sha256"]:d for d in read_snapshot() if d["row"]["firm_id"] in SAMPLES}
    result={}
    for firm,samples in SAMPLES.items():
        parser=chainlight if firm=="chainlight" else secure3
        entries=[]
        for sha,prefix,n,era,recs in samples:
            if sha not in docs:
                raise ValueError("Inspected sample is no longer eligible")
            meta=json.loads((ROOT/"local-cache/fulltext"/(sha+".pages.json")).read_text())
            text=(ROOT/"local-cache/fulltext"/(sha+".txt")).read_bytes().decode()
            assert digest(text.encode())==meta["text_sha256"]
            report=Report(text,meta,firm)
            cs=finish(report,parser.parse(report))
            expected=[prefix+str(i) if prefix.endswith("#") else prefix+"-"+(str(i).zfill(3) if firm=="chainlight" else str(i)) for i in NATIVE_NUMBERS.get(sha, range(1,n+1))]
            expected = list(NATIVE_IDS.get(sha, expected))
            assert len(expected) == n
            actual=[c.printed_id for c in cs if c.record_kind=="formal_finding"]
            summary=parser.printed_counts(report)
            counts=Counter(c.normalized or severity(c.severity_raw) for c in cs if c.record_kind=="formal_finding")
            match=all(counts[k]==v for k,v in summary["counts"].items()) if summary else None
            for c in cs:
                assert c.end>c.start and text[c.start:c.end].strip()
                assert "Disclaimer\nThis report is subject" not in text[c.start:c.end]
                if prefix=="THE-KORE":
                    assert "Recommendations" in text[c.start:c.end]
                    assert "Fix" in text[c.start:c.end]
            if summary:
                for p in summary["evidence"]:
                    assert text[p["start"]:p["end"]]==p["text"]
            entries.append({"sha256":sha,"filename":docs[sha]["row"]["filename"],"era":era,
                            "expected_printed_ids":expected,"actual_printed_ids":actual,
                            "id_sequence_complete":actual==expected,"recommendations":sum(c.record_kind=="recommendation" for c in cs),
                            "expected_recommendations":recs,"summary_match":match,"summary_counts":summary["counts"] if summary else None,
                            "parsed_counts":dict(counts),"unknown_risk":counts["unknown"]})
        comparable=[e for e in entries if e["summary_match"] is not None]
        without=[e for e in entries if e["summary_match"] is None]
        result[firm]={"inspected_documents":len(entries),"eligible_documents":sum(d["row"]["firm_id"]==firm for d in docs.values()),
                      "complete_id_sequences":sum(e["id_sequence_complete"] for e in entries),
                      "no_summary_complete_id_sequences":sum(e["id_sequence_complete"] for e in without),"no_summary_documents":len(without),
                      "summary_matching":sum(e["summary_match"] for e in comparable),"summary_comparable":len(comparable),"manifest":entries}
    return result


class Regression(unittest.TestCase):
    def test_wrapped_empty_heading_and_information(self):
        text="P12-10:\nWrapped title\nnext title line\nCategory    Severity    Code Reference    Status\nLogical    Information    x.sol    Reported\n\nCode\nbody body body\nDisclaimer\nThis report is subject to terms.\n"
        cs=finish(fixture(text,"secure3"),secure3.parse(fixture(text,"secure3")))
        self.assertEqual([(c.printed_id,c.title,c.normalized,c.status_raw) for c in cs],[("P12-10","Wrapped title next title line","info","Reported")])
        self.assertNotIn("Disclaimer",text[cs[0].start:cs[0].end])

    def test_bidi_orb_and_end(self):
        text="\u202d4.2.1. WORLDCOIN-ORB-001: Wrapped\u202c\n\u202dtitle\u202c\n ID Code    WORLDCOIN-ORB-001   Severity    Low\n Type   Thing\nBody detail remains here and this is long enough.\n5. Analysis Result\nnot finding\n"
        cs=finish(fixture(text,"chainlight"),chainlight.parse(fixture(text,"chainlight")))
        self.assertEqual(cs[0].title,"Wrapped title")
        self.assertEqual(cs[0].severity_raw,"Low")
        self.assertNotIn("5. Analysis",text[cs[0].start:cs[0].end])

    def test_summary_is_not_a_detail(self):
        text="Table of Contents\nRecommendation #1: Foo ............... 7\n#1 ABC-001 Foo       9\nFinding Breakdown by Severity\nCritical     0\nHigh     0\nLow    2\n"
        self.assertEqual(chainlight.parse(fixture(text,"chainlight")),[])

    @unittest.skipUnless((ROOT/'data/holdout/gold_sha256.txt').is_file(), 'Requires locally acquired corpus and holdout inputs')
    def test_real_cache_sequences_and_source_conflicts(self):
        result=evaluate()
        for firm,res in result.items():
            self.assertEqual(res["eligible_documents"],res["inspected_documents"])
            for e in res["manifest"]:
                self.assertEqual(e["recommendations"],e["expected_recommendations"])
                if e["era"]!="legacy-missing-body-glyphs":
                    self.assertTrue(e["id_sequence_complete"],e["filename"])
                self.assertEqual(e["unknown_risk"],0)
        conflicts=[e["filename"] for e in result["secure3"]["manifest"] if e["summary_match"] is False]
        self.assertEqual(sorted(conflicts),["ClearDAO_final_Secure3_Audit_Report.pdf","Secure3_P12_security_audit_report.pdf"])


if __name__=="__main__":
    if "--evaluate" in sys.argv:
        print(json.dumps(evaluate(),ensure_ascii=False,sort_keys=True,indent=2))
    else:
        unittest.main()
