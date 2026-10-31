"""Compare string and directional Schema policies with pinned oasdiff 1.35.0."""

import argparse
import json
from itertools import product
from pathlib import Path
import subprocess
import tempfile

from reference import REFERENCE_COMMIT, REFERENCE_VERSION, execute, yaml_text
from schema_reference import SCHEMA_OPTIONS, document


def cases():
    ordinary = {"type": "object", "required": ["id"], "properties": {"id": {"type": "integer"}}}
    read = dict(ordinary, properties={"id": {"type": "integer", "readOnly": True}})
    write = dict(ordinary, properties={"id": {"type": "integer", "writeOnly": True}})
    # Each tuple fixes our request/response exits and the reference's observed
    # request/response exits. Intentional policy differences remain in the data.
    scenarios = [
        ("pattern-narrowed", {"type": "string", "pattern": "^[a-z]+$"}, {"type": "string", "pattern": "^[a-f]+$"}, (1, 0), (0, 0)),
        ("pattern-widened", {"type": "string", "pattern": "^[a-f]+$"}, {"type": "string", "pattern": "^[a-z]+$"}, (0, 1), (0, 0)),
        ("pattern-equivalent", {"type": "string", "pattern": "^(a|b)$"}, {"type": "string", "pattern": "^[ab]$"}, (0, 0), (0, 0)),
        ("pattern-added", {"type": "string"}, {"type": "string", "pattern": "cat"}, (1, 0), (0, 0)),
        ("pattern-removed", {"type": "string", "pattern": "cat"}, {"type": "string"}, (0, 1), (0, 0)),
        ("pattern-anchored", {"type": "string", "pattern": "a"}, {"type": "string", "pattern": "^a$"}, (1, 0), (0, 0)),
        ("read-only-removed", read, ordinary, (1, 0), (1, 0)),
        ("read-only-added", ordinary, read, (0, 0), (0, 0)),
        ("write-only-added", ordinary, write, (0, 1), (0, 1)),
        ("write-only-removed", write, ordinary, (0, 0), (0, 0)),
        ("format-stable", {"type": "string", "format": "uuid"}, {"type": "string", "format": "uuid"}, (0, 0), (0, 0)),
        ("format-changed", {"type": "string", "format": "uuid"}, {"type": "string", "format": "email"}, (2, 2), (1, 1)),
        ("format-added", {"type": "string"}, {"type": "string", "format": "uuid"}, (2, 2), (1, 0)),
        ("format-removed", {"type": "string", "format": "uuid"}, {"type": "string"}, (2, 2), (0, 1)),
    ]
    for version in ("3.0.3", "3.1.1"):
        for direction_index, direction in enumerate(("request", "response")):
            for label, before, after, expected, oracle in scenarios:
                yield version + "/" + direction + "/" + label, document(before, direction, version), document(after, direction, version), expected[direction_index], (0 if version == "3.1.1" and direction == "request" and label == "read-only-removed" else oracle[direction_index])


def reason(name):
    if "/pattern-" in name:
        return "bounded language inclusion; the pinned default breaking profile has no finding for these pattern fixtures"
    if "/format-" in name:
        return "changed format annotations require client policy; no format assertion is inferred"
    return "directional requiredness retains constraints on present values and does not ban fields"


def execute_ours(binary, arguments):
    result = subprocess.run([str(binary), *arguments], capture_output=True, encoding="utf-8", timeout=30)
    if result.returncode not in (0, 1, 2):
        raise RuntimeError(result.stderr)
    return result.returncode, json.loads(result.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ours", type=Path)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = Path(__file__).resolve().parents[1] / "_build/native/debug/build/cmd/oas-auth-diff"
    ours = args.ours.resolve() if args.ours else next((p for p in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if p.is_file()), None)
    if ours is None:
        raise SystemExit("build the native CLI or pass --ours")
    reference = args.reference.resolve()
    if subprocess.check_output([str(reference), "--version"], encoding="utf-8").strip() != "oasdiff version " + REFERENCE_VERSION:
        raise SystemExit("unexpected reference version")
    scenarios = list(cases())
    results = []
    with tempfile.TemporaryDirectory(prefix="oas-string-reference-") as directory:
        for formats, (name, baseline, candidate, expected, oracle) in product(product(("json", "yaml"), repeat=2), scenarios):
            before, after = (Path(directory) / (label + "." + kind) for label, kind in zip(("before", "after"), formats))
            before.write_text(yaml_text(baseline) if formats[0] == "yaml" else json.dumps(baseline), encoding="utf-8")
            after.write_text(yaml_text(candidate) if formats[1] == "yaml" else json.dumps(candidate), encoding="utf-8")
            own_exit, own = execute_ours(ours, ["breaking", str(before), str(after), "--format", "json"])
            ref_exit, ref = execute(reference, ["breaking", str(before), str(after), "--format", "json", *SCHEMA_OPTIONS])
            results.append({"case": name, "input_formats": formats, "expected_exit": expected, "reference_expected_exit": oracle,
                            "ours_exit": own_exit, "reference_exit": ref_exit,
                            "documented_difference": reason(name) if expected != oracle else None,
                            "ours_report": own, "reference_findings": ref,
                            "passed": own_exit == expected and ref_exit == oracle
                            and (expected != 1 or any(f["witness_verified"] for f in own["findings"]))
                            and (oracle != 1 or any(f["level"] == 3 for f in ref))
                            and (expected != 2 or any(d["code"] == "compat.format" for d in own["diagnostics"]))})
    failures = [r for r in results if not r["passed"]]
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "semantic_cases": len(scenarios), "total": len(results), "passed": len(results) - len(failures),
              "documented_differences": sum(r["documented_difference"] is not None for r in results),
              "cases": results, "differences": failures}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} string/direction reference: {}/{} passed; {} documented differences".format(REFERENCE_VERSION, report["passed"], report["total"], report["documented_differences"]))
    if failures:
        print(json.dumps([{k: r[k] for k in ("case", "ours_exit", "expected_exit", "reference_exit", "reference_expected_exit")} for r in failures[:16]], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
