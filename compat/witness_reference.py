"""Validate CLI Schema witnesses independently with jsonschema 4.25.1."""

import argparse
import copy
from decimal import Decimal
from importlib.metadata import version
import json
from pathlib import Path
import subprocess
import tempfile

from jsonschema import Draft4Validator, Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT4, DRAFT202012
from schema_reference import cases
from string_reference import cases as string_cases


def legacy_types(value):
    # These fixtures contain no arbitrary data carrying a nullable annotation.
    if isinstance(value, dict):
        result = {k: legacy_types(v) for k, v in value.items() if k != "nullable"}
        if value.get("nullable") is True and isinstance(value.get("type"), str):
            result["type"] = [value["type"], "null"]
        return result
    if isinstance(value, list):
        return [legacy_types(v) for v in value]
    return value


def validator(document, direction):
    legacy = document["openapi"].startswith("3.0")
    document = legacy_types(document) if legacy else copy.deepcopy(document)
    document = directional_fixture(document, direction)
    specification = DRAFT4 if legacy else DRAFT202012
    registry = Registry().with_resource("urn:fixture", Resource(document, specification))
    pointer = "/paths/~1orders/post/" + ("requestBody" if direction == "request" else "responses/200") + "/content/application~1json/schema"
    cls = Draft4Validator if legacy else Draft202012Validator
    return cls({"$ref": "urn:fixture#" + pointer}, registry=registry)


def directional_fixture(value, direction):
    # The interoperability fixtures use unconditional property annotations.
    # Retain properties and their assertions; adapt only the required names.
    if isinstance(value, dict):
        result = {k: directional_fixture(v, direction) for k, v in value.items()}
        if isinstance(value.get("required"), list) and isinstance(value.get("properties"), dict):
            flag = "readOnly" if direction == "request" else "writeOnly"
            result["required"] = [name for name in value["required"]
                                  if value["properties"].get(name, {}).get(flag) is not True]
        return result
    if isinstance(value, list):
        return [directional_fixture(v, direction) for v in value]
    return value


def instance(value):
    # JSON Schema integers are mathematical integers, including a token '1e0'.
    if isinstance(value, Decimal) and value == value.to_integral_value():
        return int(value)
    if isinstance(value, list):
        return [instance(v) for v in value]
    if isinstance(value, dict):
        return {k: instance(v) for k, v in value.items()}
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ours", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build = Path(__file__).resolve().parents[1] / "_build/native/debug/build/cmd/oas-auth-diff"
    ours = args.ours.resolve() if args.ours else next((p for p in (build / "oas-auth-diff.exe", build / "oas-auth-diff") if p.is_file()), None)
    if ours is None:
        raise SystemExit("build the native CLI or pass --ours")
    results = []
    with tempfile.TemporaryDirectory(prefix="oas-instance-witness-") as directory:
        before, after = Path(directory) / "before.json", Path(directory) / "after.json"
        scenarios = list(cases()) + [(n, b, a, expected) for n, b, a, expected, _ in string_cases()]
        for name, baseline, candidate, expected in scenarios:
            before.write_text(json.dumps(baseline), encoding="utf-8")
            after.write_text(json.dumps(candidate), encoding="utf-8")
            completed = subprocess.run([str(ours), "breaking", str(before), str(after), "--format", "json"],
                                       capture_output=True, encoding="utf-8", timeout=30)
            report = json.loads(completed.stdout, parse_float=Decimal)
            direction = name.split("/")[1]
            source, target = (baseline, candidate) if direction == "request" else (candidate, baseline)
            source_validator, target_validator = validator(source, direction), validator(target, direction)
            witnesses = [instance(f["witness"]) for f in report["findings"] if f["witness_verified"]]
            results.append({"case": name, "witnesses": len(witnesses), "passed": completed.returncode == expected
                            and (expected != 1 or bool(witnesses))
                            and all(source_validator.is_valid(w) and not target_validator.is_valid(w) for w in witnesses)})
    report = {"validator": "jsonschema " + version("jsonschema"), "total": len(results),
              "passed": sum(r["passed"] for r in results), "witnesses": sum(r["witnesses"] for r in results), "cases": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Independent Schema witnesses: {passed}/{total} cases, {witnesses} witnesses".format(**report))
    if not all(r["passed"] for r in results):
        print([r for r in results if not r["passed"]])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
