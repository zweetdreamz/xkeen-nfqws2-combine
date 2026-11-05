"""Branch-aware phase gate summary, run from the tested tree after coverage run.

Development-only; never included in the router deployment manifest.
Uses coverage's public JSON report rather than summing rounded percentages.
"""
import json
import os
from pathlib import Path
import tempfile


def summarize(report):
    selectors = {
        "kdn": lambda path: path.startswith("tools/router/kdn/"),
        "engine": lambda path: path.startswith("tools/router/kdn/engine/"),
        "phase3_kdn": lambda path: path.startswith("tools/router/kdn/") and "/engine/" not in path,
        "jobs": lambda path: path.startswith("tools/router/kdn/jobs/"),
        "api": lambda path: path.startswith("tools/router/kdn/web/api/"),
        "errors": lambda path: path == "tools/router/kdn/common/errors.py",
        "logsetup": lambda path: path == "tools/router/kdn/common/logsetup.py",
        "total": lambda path: True,
    }
    result = {}
    for name, selected in selectors.items():
        rows = [item["summary"] for path, item in report["files"].items() if selected(path.replace("\\", "/"))]
        statements = sum(row["num_statements"] for row in rows)
        branches = sum(row["num_branches"] for row in rows)
        covered = sum(row["covered_lines"] + row["covered_branches"] for row in rows)
        denominator = statements + branches
        result[name] = {"statements": statements, "branches": branches, "covered": covered,
                        "percent": 100.0 * covered / denominator if denominator else 100.0}
    return result


THRESHOLDS = {
    "strict": {"kdn": 90.5, "total": 88.5, "engine": 90.0},
    # User decision02.11.2026: a relative10% reduction for finishing phase5.
    "phase5-fast": {"kdn": 81.45, "total": 79.65, "engine": 81.0},
    # P6.1/P6.2 only: same relative reduction, not cumulative with phase5.
    "phase6-fast": {"kdn": 81.45, "total": 79.65, "engine": 81.0},
}


def meets_thresholds(groups, profile="strict"):
    if profile not in THRESHOLDS:
        raise ValueError('unknown coverage gate profile')
    minimum = THRESHOLDS[profile]
    return (groups["kdn"]["percent"] >= minimum["kdn"] and groups["total"]["percent"] >= minimum["total"]
            and ("engine" not in groups or groups["engine"]["percent"] >= minimum["engine"]))


def main():
    import coverage
    coverage_data = coverage.Coverage()
    coverage_data.load()
    with tempfile.TemporaryDirectory(prefix="kdn-coverage-") as directory:
        path = Path(directory) / "report.json"
        coverage_data.json_report(outfile=str(path))
        groups = summarize(json.loads(path.read_text(encoding="utf-8")))
    print("PHASE3_COVERAGE " + json.dumps(groups, sort_keys=True))
    profile = os.environ.get('KDN_COVERAGE_PROFILE', 'strict')
    print('COVERAGE_GATE_PROFILE ' + profile)
    return 0 if meets_thresholds(groups, profile) else 1


if __name__ == "__main__":
    raise SystemExit(main())
