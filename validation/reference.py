"""Check OpenAPI validation cases against fixed oasdiff 1.35.0 verdicts."""

import argparse
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compat"))
from reference import REFERENCE_COMMIT, REFERENCE_VERSION, yaml_text


def document(version):
    return {"openapi": version, "info": {"title": "Orders", "version": "1.0.0"},
            "paths": {"/orders": {"get": {"responses": {"200": {"description": "Order"}}}}}}


def cases():
    for version in ("3.0.3", "3.1.1"):
        base = document(version)
        yield version + "/valid", base, 0
        for name, keys, value in (
            ("title-type", ["info", "title"], 42),
            ("version-type", ["info", "version"], 42),
            ("missing-response-description", ["paths", "/orders", "get", "responses", "200"], {}),
            ("empty-responses", ["paths", "/orders", "get", "responses"], {}),
            ("bad-body-required", ["paths", "/orders", "get", "requestBody"], {"required": "yes", "content": {}}),
            ("bad-security-scheme", ["components"], {"securitySchemes": {"A": {"type": "apiKey", "in": "body", "name": "key"}}}),
            ("undefined-security-scheme", ["security"], [{"Missing": []}]),
        ):
            bad = copy.deepcopy(base)
            target = bad
            for key in keys[:-1]: target = target[key]
            target[keys[-1]] = value
            yield version + "/" + name, bad, 1
        for name, keys in (("missing-info", ["info"]), ("missing-title", ["info", "title"]), ("missing-version", ["info", "version"])):
            bad = copy.deepcopy(base)
            target = bad
            for key in keys[:-1]: target = target[key]
            del target[keys[-1]]
            yield version + "/" + name, bad, 1
        bad = copy.deepcopy(base)
        bad["paths"]["/orders"]["get"]["operationId"] = "orders"
        bad["paths"]["/orders"]["post"] = {"operationId": "orders", "responses": {"200": {"description": "ok"}}}
        yield version + "/duplicate-operation-id", bad, 1
        for label, schema, expected in (("valid-schema", {"type": "string", "minLength": 1}, 0),
                                       ("bad-schema-type", {"type": 9}, 1),
                                       ("bad-required", {"type": "object", "required": [9]}, 1),
                                       ("negative-length", {"type": "string", "minLength": -1}, 1)):
            changed = copy.deepcopy(base)
            changed["paths"]["/orders"]["get"]["responses"]["200"]["content"] = {"application/json": {"schema": schema}}
            yield version + "/" + label, changed, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ours", type=Path)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = Path(__file__).resolve().parents[1] / "_build/native/debug/build/cmd/oas-auth-diff"
    ours = args.ours.resolve() if args.ours else next((p for p in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if p.is_file()), None)
    if ours is None: raise SystemExit("build the native CLI or pass --ours")
    reference = args.reference.resolve()
    if subprocess.check_output([str(reference), "--version"], encoding="utf-8").strip() != "oasdiff version " + REFERENCE_VERSION:
        raise SystemExit("unexpected reference version")
    scenarios = list(cases())
    results = []
    with tempfile.TemporaryDirectory(prefix="oas-validation-reference-") as directory:
        for name, value, expected in scenarios:
            for format in ("json", "yaml"):
                path = Path(directory) / ("api." + format)
                path.write_text(yaml_text(value) if format == "yaml" else json.dumps(value), encoding="utf-8")
                own = subprocess.run([str(ours), "validate", str(path), "--format", "json"], capture_output=True, encoding="utf-8", timeout=30)
                oracle = subprocess.run([str(reference), "validate", str(path), "--format", "json", "--fail-on", "ERR", "--allow-external-refs=false"], capture_output=True, encoding="utf-8", timeout=30)
                if oracle.returncode not in (0, 1, 102): raise RuntimeError(oracle.stderr)
                # The upstream loader exits 102 for some malformed declarations;
                # our strict loader reports a parsed schema violation as 1.
                reference_verdict = 0 if oracle.returncode == 0 else 1
                results.append({"case": name, "input_format": format, "expected_exit": expected,
                                "ours_exit": own.returncode, "reference_exit": oracle.returncode,
                                "ours_report": json.loads(own.stdout), "reference_report": oracle.stdout,
                                "reference_stderr": oracle.stderr,
                                "passed": own.returncode == reference_verdict == expected})
    differences = [r for r in results if not r["passed"]]
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "semantic_cases": len(scenarios), "total": len(results), "passed": len(results) - len(differences),
              "reference_loader_failure_exit": 102, "cases": results, "differences": differences}
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} validation reference: {}/{} passed".format(REFERENCE_VERSION, report["passed"], report["total"]))
    if differences:
        print(json.dumps(differences[:6], ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
