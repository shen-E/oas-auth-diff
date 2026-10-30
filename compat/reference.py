"""Compare the endpoint/required-parameter profile with pinned oasdiff 1.35.0."""

import argparse
import copy
import json
import re
from itertools import product
from pathlib import Path
import subprocess
import tempfile


REFERENCE_VERSION = "1.35.0"
REFERENCE_COMMIT = "a4ba100f880c7579765c5e63915a99bf1acc6967"
REFERENCE_OPTIONS = ["--fail-on", "ERR", "--flatten-params"]
RULE_EQUIVALENTS = {
    "endpoint-removed": "api-path-removed-without-deprecation",
    "request-parameter-added-required": "new-required-request-parameter",
    "request-parameter-became-required": "request-parameter-became-required",
}


def document(parameters=None, version="3.1.1"):
    operation = {"responses": {"200": {"description": "Orders"}}}
    if parameters is not None:
        operation["parameters"] = parameters
    return {"openapi": version, "info": {"title": "Order parameters", "version": "1.0.0"},
            "paths": {"/orders": {"get": operation}}}


def parameter(position="query", required=False, name="tenant"):
    return {"name": name, "in": position, "required": required, "schema": {"type": "string"}}


def yaml_text(value, indent=0):
    """Encode these JSON fixtures as block YAML without a parser dependency."""
    pad = " " * indent
    if isinstance(value, dict) and value:
        lines = []
        for key, item in value.items():
            if isinstance(item, (dict, list)) and item:
                lines.append(pad + json.dumps(key) + ":\n" + yaml_text(item, indent + 2))
            else:
                lines.append(pad + json.dumps(key) + ": " + json.dumps(item) + "\n")
        return "".join(lines)
    if isinstance(value, list) and value:
        return "".join(pad + "-\n" + yaml_text(item, indent + 2) for item in value)
    return pad + json.dumps(value) + "\n"


def cases():
    for version in ("3.0.3", "3.1.1"):
        for position in ("query", "header", "cookie"):
            optional, required = parameter(position), parameter(position, True)
            for label, before, after, expected in (
                ("add-required", [], [required], 1),
                ("become-required", [optional], [required], 1),
                ("become-optional", [required], [optional], 0),
                ("add-optional", [], [optional], 0),
                ("unchanged", [required], [required], 0),
            ):
                yield version + "/" + position + "/" + label, document(before, version), document(after, version), expected
        before = document([parameter(required=True)], version)
        removed = copy.deepcopy(before)
        removed["paths"] = {}
        yield version + "/endpoint-removed", before, removed, 1
        yield version + "/endpoint-added", removed, before, 0
        inherited = document(version=version)
        inherited["paths"]["/orders"]["parameters"] = [parameter(required=False)]
        overridden = copy.deepcopy(inherited)
        overridden["paths"]["/orders"]["get"]["parameters"] = [parameter(required=True)]
        yield version + "/operation-override", inherited, overridden, 1
        yield version + "/operation-override-reverse", overridden, inherited, 0
        referenced = document([{"$ref": "#/components/parameters/Tenant"}], version)
        referenced["components"] = {"parameters": {"Tenant": parameter(required=True)}}
        yield version + "/component-parameter", document(version=version), referenced, 1
        lower = document([parameter("header", True, "x-id")], version)
        upper = document([parameter("header", True, "X-ID")], version)
        yield version + "/header-case", lower, upper, 0
        reordered = document([parameter(name="first"), parameter(name="second")], version)
        reverse = document(list(reversed(reordered["paths"]["/orders"]["get"]["parameters"])), version)
        yield version + "/parameter-order", reordered, reverse, 0
        original = document([parameter("path", True, "id")], version)
        original["paths"]["/orders/{id}"] = original["paths"].pop("/orders")
        renamed = copy.deepcopy(original)
        renamed["paths"]["/orders/{order_id}"] = renamed["paths"].pop("/orders/{id}")
        renamed["paths"]["/orders/{order_id}"]["get"]["parameters"][0]["name"] = "order_id"
        yield version + "/path-parameter-rename", original, renamed, 0
        enlarged = copy.deepcopy(renamed)
        enlarged["paths"]["/orders/{order_id}"]["get"]["parameters"].append(parameter(required=True))
        yield version + "/rename-with-required-query", original, enlarged, 1


def execute(binary, command):
    result = subprocess.run([str(binary), *command], capture_output=True, encoding="utf-8", timeout=30)
    if result.returncode not in (0, 1):
        raise RuntimeError("{} exited {}: {}".format(binary.name, result.returncode, result.stderr))
    return result.returncode, json.loads(result.stdout or "[]")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ours", type=Path, help="native executable; defaults to the local MoonBit build")
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.ours:
        ours = args.ours.resolve()
    else:
        build = Path(__file__).resolve().parents[1] / "_build/native/debug/build/cmd/oas-auth-diff"
        ours = next((path for path in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if path.is_file()), None)
        if ours is None:
            raise SystemExit("build cmd/oas-auth-diff --target native or pass --ours")
    reference = args.reference.resolve()
    version = subprocess.check_output([str(reference), "--version"], encoding="utf-8").strip()
    if version != "oasdiff version " + REFERENCE_VERSION:
        raise SystemExit("expected oasdiff version " + REFERENCE_VERSION + "; got " + version)
    catalog = json.loads(subprocess.check_output([str(reference), "checks", "changelog", "--format", "json"], encoding="utf-8"))
    validate = json.loads(subprocess.check_output([str(reference), "checks", "validate", "--format", "json"], encoding="utf-8"))
    results = []
    scenarios = list(cases())
    formats = [("json", "json"), ("yaml", "json"), ("json", "yaml"), ("yaml", "yaml")]
    with tempfile.TemporaryDirectory(prefix="oas-parameter-reference-") as directory:
        for (before_format, after_format), (name, baseline, candidate, expected) in product(formats, scenarios):
            before, after = Path(directory) / ("before." + before_format), Path(directory) / ("after." + after_format)
            before.write_text(yaml_text(baseline) if before_format == "yaml" else json.dumps(baseline), encoding="utf-8")
            after.write_text(yaml_text(candidate) if after_format == "yaml" else json.dumps(candidate), encoding="utf-8")
            ours_code, ours_report = execute(ours, ["breaking", str(before), str(after), "--format", "json"])
            reference_code, reference_report = execute(reference, ["breaking", str(before), str(after), "--format", "json", *REFERENCE_OPTIONS])
            ours_operations = sorted({(x["http_method"], x["path"]) for x in ours_report["findings"]})
            reference_operations = sorted({(x["operation"], x["path"]) for x in reference_report if x["level"] == 3})
            # The tools display different sides of a renamed template. Keep the
            # raw paths in the report and compare their actual route identity.
            normalized_ours = sorted({(verb, re.sub(r"\{[^{}]+\}", "{}", path)) for verb, path in ours_operations})
            normalized_reference = sorted({(verb, re.sub(r"\{[^{}]+\}", "{}", path)) for verb, path in reference_operations})
            ours_rules = sorted({x["rule_id"] for x in ours_report["findings"]})
            reference_rules = sorted({x["id"] for x in reference_report if x["level"] == 3})
            results.append({"case": name, "input_formats": [before_format, after_format], "expected_exit": expected, "ours_exit": ours_code,
                            "reference_exit": reference_code, "ours_rules": ours_rules, "reference_rules": reference_rules,
                            "ours_operations": ours_operations, "reference_operations": reference_operations,
                            "passed": ours_code == reference_code == expected
                            and normalized_ours == normalized_reference
                            and sorted(RULE_EQUIVALENTS[x] for x in ours_rules) == reference_rules})
    differences = [case for case in results if not case["passed"]]
    mapped = {reference_id: local_id for local_id, reference_id in RULE_EQUIVALENTS.items()}
    report = {"reference_version": REFERENCE_VERSION, "reference_commit": REFERENCE_COMMIT,
              "reference_options": REFERENCE_OPTIONS,
              "reference_changelog_checks": len(catalog), "reference_validate_checks": len(validate),
              "scope": "endpoint-removal-and-required-parameters", "semantic_cases": len(scenarios), "input_format_pairs": len(formats), "cases": results,
              "reference_scope": {
                  "changelog": [{"id": rule["id"], "local_rule": mapped.get(rule["id"]),
                                 "status": "parameter-matrix" if rule["id"] in mapped else "outside-this-matrix"} for rule in catalog],
                  "validate": [{"id": rule["id"], "status": "outside-this-matrix"} for rule in validate],
              },
              "total": len(results), "passed": len(results) - len(differences), "differences": differences}
    if args.output:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("oasdiff {} reference: {}/{} cases passed".format(REFERENCE_VERSION, report["passed"], report["total"]))
    if differences:
        print(json.dumps(differences, ensure_ascii=False, indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
