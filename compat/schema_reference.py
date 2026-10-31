"""Compare request/response Schema cases against pinned oasdiff 1.35.0."""

import argparse
import copy
import json
from itertools import product
from pathlib import Path
import subprocess
import tempfile

from reference import REFERENCE_COMMIT, REFERENCE_OPTIONS, REFERENCE_VERSION, execute, yaml_text

SCHEMA_OPTIONS = [*REFERENCE_OPTIONS, "--flatten-allof"]


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
            ("allof-required", {"allOf": [optional]}, {"allOf": [optional, {"required": ["id"]}]}, 1, 0),
            ("allof-required-reverse", {"allOf": [optional, {"required": ["id"]}]}, {"allOf": [optional]}, 0, 1),
            ("anyof-branch-removed", {"anyOf": [{"type": "string"}, {"type": "integer"}]}, {"anyOf": [{"type": "string"}]}, 1, 0),
            ("oneof-branch-removed", {"oneOf": [{"type": "string"}, {"type": "integer"}]}, {"oneOf": [{"type": "string"}]}, 1, 0),
            ("oneof-reordered", {"oneOf": [{"type": "string"}, {"type": "integer"}]}, {"oneOf": [{"type": "integer"}, {"type": "string"}]}, 0, 0),
            ("minimum-raised", {"type": "number", "minimum": -2}, {"type": "number", "minimum": 2}, 1, 0),
            ("minimum-lowered", {"type": "number", "minimum": 2}, {"type": "number", "minimum": -2}, 0, 1),
            ("maximum-lowered", {"type": "number", "maximum": 8}, {"type": "number", "maximum": 3}, 1, 0),
            ("maximum-raised", {"type": "number", "maximum": 3}, {"type": "number", "maximum": 8}, 0, 1),
            ("minimum-added", {"type": "number"}, {"type": "number", "minimum": 3}, 1, 0),
            ("maximum-removed", {"type": "number", "maximum": 3}, {"type": "number"}, 0, 1),
            ("length-min-raised", {"type": "string", "minLength": 1}, {"type": "string", "minLength": 3}, 1, 0),
            ("length-min-lowered", {"type": "string", "minLength": 3}, {"type": "string", "minLength": 1}, 0, 1),
            ("length-max-lowered", {"type": "string", "maxLength": 8}, {"type": "string", "maxLength": 3}, 1, 0),
            ("length-max-raised", {"type": "string", "maxLength": 3}, {"type": "string", "maxLength": 8}, 0, 1),
            ("items-min-raised", {"type": "array", "items": {}, "minItems": 1}, {"type": "array", "items": {}, "minItems": 3}, 1, 0),
            ("items-min-lowered", {"type": "array", "items": {}, "minItems": 3}, {"type": "array", "items": {}, "minItems": 1}, 0, 1),
            ("items-max-lowered", {"type": "array", "items": {}, "maxItems": 8}, {"type": "array", "items": {}, "maxItems": 3}, 1, 0),
            ("items-max-raised", {"type": "array", "items": {}, "maxItems": 3}, {"type": "array", "items": {}, "maxItems": 8}, 0, 1),
            ("properties-min-raised", {"type": "object", "minProperties": 1}, {"type": "object", "minProperties": 3}, 1, 0),
            ("properties-max-raised", {"type": "object", "maxProperties": 3}, {"type": "object", "maxProperties": 8}, 0, 1),
        ]
        inclusive = {"type": "number", "minimum": 3}
        exclusive = dict(inclusive, exclusiveMinimum=True) if version.startswith("3.0") else {"type": "number", "exclusiveMinimum": 3}
        changes.append(("minimum-exclusive", inclusive, exclusive, 1, 0))
        changes.append(("minimum-inclusive", exclusive, inclusive, 0, 1))
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
            reference_exit, reference_report = execute(reference, ["breaking", str(before), str(after), "--format", "json", *SCHEMA_OPTIONS])
            ours_operations = sorted({(x["http_method"], x["path"]) for x in ours_report["findings"]})
            reference_operations = sorted({(x["operation"], x["path"]) for x in reference_report if x["level"] == 3})
            findings = ours_report["findings"]
            # v1.35.0 treats a 3.1 numeric exclusiveMinimum -> minimum switch
            # as a separate bound addition/removal. Instance inclusion permits
            # these two directions; preserve and test the disagreement.
            known_difference = name in {"3.1.1/request/minimum-inclusive", "3.1.1/response/minimum-exclusive"}
            reference_expected = 1 if known_difference else expected
            results.append({"case": name, "input_formats": [before_format, after_format],
                            "expected_exit": expected, "ours_exit": ours_exit, "reference_exit": reference_exit,
                            "reference_expected_exit": reference_expected,
                            "documented_difference": "3.1 numeric exclusivity is classified as separate bound addition/removal" if known_difference else None,
                            "ours_findings": findings, "reference_findings": reference_report,
                            "passed": ours_exit == expected and reference_exit == reference_expected
                            and ours_operations == ([("POST", "/orders")] if expected else [])
                            and reference_operations == ([("POST", "/orders")] if reference_expected else [])
                            and all(x["rule_id"] in {"request-schema-narrowed", "response-schema-widened"} for x in findings)})
    differences = [r for r in results if not r["passed"]]
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "reference_options": SCHEMA_OPTIONS, "scope": "schema-type-enum-required-items-composition-bounds",
              "semantic_cases": len(scenarios), "total": len(results), "passed": len(results) - len(differences),
              "documented_differences": sum(r["documented_difference"] is not None for r in results),
              "cases": results, "differences": differences}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} Schema reference: {}/{} cases passed".format(REFERENCE_VERSION, report["passed"], report["total"]))
    if differences:
        print(json.dumps(differences[:8], ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
