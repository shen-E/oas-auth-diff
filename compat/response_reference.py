"""Compare status/header contract cases with checksum-pinned oasdiff 1.35.0."""

import argparse
import copy
import json
from itertools import product
from pathlib import Path
import subprocess
import tempfile

from reference import REFERENCE_COMMIT, REFERENCE_OPTIONS, REFERENCE_VERSION, execute, yaml_text


def document(responses, version):
    return {"openapi": version, "info": {"title": "Order responses", "version": "1.0.0"},
            "paths": {"/orders": {"get": {"responses": responses}}}}


def cases():
    response = {"description": "Order"}
    for version in ("3.0.3", "3.1.1"):
        status_cases = [
            ("success-removed", {"200": response}, {"201": response}, 1),
            ("success-added", {"200": response}, {"200": response, "201": response}, 0),
            ("error-removed", {"200": response, "400": response}, {"200": response}, 0),
            ("error-added", {"200": response}, {"200": response, "400": response}, 0),
            ("success-to-range", {"200": response}, {"2XX": response}, 1),
            ("range-to-success", {"2XX": response}, {"200": response}, 0),
            ("success-to-default", {"200": response}, {"default": response}, 1),
            ("default-to-success", {"default": response}, {"200": response}, 0),
        ]
        for name, before, after, expected in status_cases:
            yield version + "/" + name, document(before, version), document(after, version), expected
        optional = {"schema": {"type": "string"}}
        required = dict(optional, required=True)
        nullable = {"type": "string", "nullable": True} if version.startswith("3.0") else {"type": ["string", "null"]}
        header_cases = [
            ("optional-removed", {"X-ID": optional}, {}, 0),
            ("required-removed", {"X-ID": required}, {}, 1),
            ("became-optional", {"X-ID": required}, {"X-ID": optional}, 1),
            ("became-required", {"X-ID": optional}, {"X-ID": required}, 0),
            ("case-renamed", {"X-ID": required}, {"x-id": required}, 0),
            ("nullable-added", {"X-ID": optional}, {"X-ID": {"schema": nullable}}, 1),
            ("nullable-removed", {"X-ID": {"schema": nullable}}, {"X-ID": optional}, 0),
            ("type-generalized", {"X-ID": {"schema": {"type": "integer"}}}, {"X-ID": {"schema": {"type": "number"}}}, 1),
            ("type-specialized", {"X-ID": {"schema": {"type": "number"}}}, {"X-ID": {"schema": {"type": "integer"}}}, 0),
        ]
        for name, before, after, expected in header_cases:
            yield version + "/header/" + name, document({"200": dict(response, headers=before)}, version), document({"200": dict(response, headers=after)}, version), expected
        baseline = document({"200": dict(response, headers={"X-ID": {"$ref": "#/components/headers/Identifier"}})}, version)
        baseline["components"] = {"headers": {"Identifier": required}}
        candidate = copy.deepcopy(baseline)
        candidate["components"]["headers"]["Identifier"] = optional
        yield version + "/header/component", baseline, candidate, 1


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
    with tempfile.TemporaryDirectory(prefix="oas-response-reference-") as directory:
        for formats, (name, baseline, candidate, expected) in product(product(("json", "yaml"), repeat=2), scenarios):
            before, after = (Path(directory) / (side + "." + format) for side, format in zip(("before", "after"), formats))
            for path, value, format in ((before, baseline, formats[0]), (after, candidate, formats[1])):
                path.write_text(yaml_text(value) if format == "yaml" else json.dumps(value), encoding="utf-8")
            ours_code, ours_report = execute(ours, ["breaking", str(before), str(after), "--format", "json"])
            reference_code, reference_report = execute(reference, ["breaking", str(before), str(after), "--format", "json", *REFERENCE_OPTIONS])
            ours_operations = sorted({(x["http_method"], x["path"]) for x in ours_report["findings"]})
            reference_operations = sorted({(x["operation"], x["path"]) for x in reference_report if x["level"] == 3})
            results.append({"case": name, "input_formats": formats, "expected_exit": expected,
                            "ours_exit": ours_code, "reference_exit": reference_code,
                            "ours_findings": ours_report["findings"], "reference_findings": reference_report,
                            "passed": ours_code == reference_code == expected and ours_operations == reference_operations})
    differences = [r for r in results if not r["passed"]]
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "reference_options": REFERENCE_OPTIONS, "semantic_cases": len(scenarios),
              "total": len(results), "passed": len(results) - len(differences), "cases": results, "differences": differences}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} response reference: {}/{} passed".format(REFERENCE_VERSION, report["passed"], report["total"]))
    if differences:
        print(json.dumps(differences[:6], ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
