"""Compare request/response Schema cases against pinned oasdiff 1.35.0."""

import argparse
import copy
import json
from itertools import product
from pathlib import Path
import subprocess
import tempfile

from reference import REFERENCE_COMMIT, REFERENCE_OPTIONS, REFERENCE_VERSION, execute, yaml_text


def document(schema, direction, version):
    media = {"application/json": {"schema": schema}}
    operation = {"responses": {"200": {"description": "Order"}}}
    if direction == "request":
        operation["requestBody"] = {"content": media}
    else:
        operation["responses"]["200"]["content"] = media
    return {"openapi": version, "info": {"title": "Order payloads", "version": "1.0.0"},
            "paths": {"/orders": {"post": operation}}}


def cases():
    for version in ("3.0.3", "3.1.1"):
        wide = {"type": "string", "enum": ["read", "write"]}
        narrow = {"type": "string", "enum": ["read"]}
        optional = {"type": "object", "properties": {"id": {"type": "integer"}}}
        required = dict(optional, required=["id"])
        nullable = {"type": "string", "nullable": True} if version.startswith("3.0") else {"type": ["string", "null"]}
        changes = [
            ("enum-narrowed", wide, narrow, 1, 0),
            ("enum-widened", narrow, wide, 0, 1),
            ("property-required", optional, required, 1, 0),
            ("property-optional", required, optional, 0, 1),
            ("number-to-integer", {"type": "number"}, {"type": "integer"}, 1, 0),
            ("integer-to-number", {"type": "integer"}, {"type": "number"}, 0, 1),
            ("nullable-removed", nullable, {"type": "string"}, 1, 0),
            ("nullable-added", {"type": "string"}, nullable, 0, 1),
            ("array-items-narrowed", {"type": "array", "items": wide}, {"type": "array", "items": narrow}, 1, 0),
            ("enum-reordered", wide, {"type": "string", "enum": ["write", "read"]}, 0, 0),
            ("description-edited", {"type": "string"}, {"type": "string", "description": "Updated"}, 0, 0),
        ]
        for direction in ("request", "response"):
            for label, before, after, request_exit, response_exit in changes:
                expected = request_exit if direction == "request" else response_exit
                yield version + "/" + direction + "/" + label, document(before, direction, version), document(after, direction, version), expected
        # A shared component edit must be observed at an unchanged $ref site.
        before = document({"$ref": "#/components/schemas/Order"}, "request", version)
        before["components"] = {"schemas": {"Order": wide}}
        after = copy.deepcopy(before)
        after["components"]["schemas"]["Order"] = narrow
        yield version + "/request/component-enum", before, after, 1


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
    version = subprocess.check_output([str(reference), "--version"], encoding="utf-8").strip()
    if version != "oasdiff version " + REFERENCE_VERSION:
        raise SystemExit("unexpected reference version: " + version)
    scenarios = list(cases())
    results = []
    with tempfile.TemporaryDirectory(prefix="oas-schema-reference-") as directory:
        for (before_format, after_format), (name, baseline, candidate, expected) in product(product(("json", "yaml"), repeat=2), scenarios):
            before, after = Path(directory) / ("before." + before_format), Path(directory) / ("after." + after_format)
            before.write_text(yaml_text(baseline) if before_format == "yaml" else json.dumps(baseline), encoding="utf-8")
            after.write_text(yaml_text(candidate) if after_format == "yaml" else json.dumps(candidate), encoding="utf-8")
            ours_exit, ours_report = execute(ours, ["breaking", str(before), str(after), "--format", "json"])
            reference_exit, reference_report = execute(reference, ["breaking", str(before), str(after), "--format", "json", *REFERENCE_OPTIONS])
            ours_operations = sorted({(x["http_method"], x["path"]) for x in ours_report["findings"]})
            reference_operations = sorted({(x["operation"], x["path"]) for x in reference_report if x["level"] == 3})
            findings = ours_report["findings"]
            results.append({"case": name, "input_formats": [before_format, after_format],
                            "expected_exit": expected, "ours_exit": ours_exit, "reference_exit": reference_exit,
                            "ours_findings": findings, "reference_findings": reference_report,
                            "passed": ours_exit == reference_exit == expected and ours_operations == reference_operations
                            and all(x["rule_id"] in {"request-schema-narrowed", "response-schema-widened"} for x in findings)})
    differences = [r for r in results if not r["passed"]]
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "reference_options": REFERENCE_OPTIONS, "scope": "schema-type-enum-required-items",
              "semantic_cases": len(scenarios), "total": len(results), "passed": len(results) - len(differences),
              "cases": results, "differences": differences}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} Schema reference: {}/{} cases passed".format(REFERENCE_VERSION, report["passed"], report["total"]))
    if differences:
        print(json.dumps(differences[:8], ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
